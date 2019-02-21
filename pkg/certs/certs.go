package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme"
)

var (
	DefaultCertsBasePath = "/var/lib/nginx-controller/domains"

	AccountPath = "/var/lib/nginx-controller/account"
)

type Manager struct {
	acmeClient  *acme.Client
	acmeAccount *acme.Account

	ctx context.Context

	httpTokens    map[string]string
	httpTokenLock *sync.Mutex
	email         string
	renewBefore   time.Duration

	httpServer *http.Server
}

func NewManager(ctx context.Context, email string, acmeUri string) (*Manager, error) {
	m := &Manager{
		acmeClient: &acme.Client{
			DirectoryURL: acmeUri,
		},
		ctx:           ctx,
		httpTokens:    make(map[string]string),
		httpTokenLock: &sync.Mutex{},
		email:         email,
		renewBefore:   time.Hour * 24 * 30,
	}

	if err := os.MkdirAll(AccountPath, 0755); err != nil {
		logrus.WithError(err).Error("Failed to create controller base path")
		return nil, err
	}

	if err := os.MkdirAll(DefaultCertsBasePath, 0755); err != nil {
		logrus.WithError(err).Error("Failed to create controller certs base path")
		return nil, err
	}

	rootMux := http.NewServeMux()
	rootMux.Handle("/", http.HandlerFunc(m.HTTP01ChallengeHandler))
	hs := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", 8402),
		Handler: rootMux,
	}
	m.httpServer = hs
	if err := m.ensureAccount(email); err != nil {
		return nil, err
	}

	go func() {
		if err := m.httpServer.ListenAndServe(); err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"addr": m.httpServer.Addr,
			}).Error("Failed to listen with HTTP server for HTTP-01 challenge")
		}
	}()

	return m, nil
}

func (m *Manager) ensureAccount(email string) error {
	needsRegister := false
	accountFilePath := filepath.Join(AccountPath, "account.json")
	accountFile, err := os.Open(accountFilePath)
	defer accountFile.Close()
	if err != nil && os.IsNotExist(err) {
		needsRegister = true
	} else if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"accountFilePath": accountFilePath,
		}).Error("Failed to open account.json")
		return err
	}

	keyFilePath := filepath.Join(AccountPath, "private.key")
	keyFile, err := os.Open(keyFilePath)
	defer keyFile.Close()
	if err != nil && os.IsNotExist(err) {
		needsRegister = true
	} else if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"keyFilePath": keyFilePath,
			"email":       email,
		}).Error("Failed to open private.key for account")
		return err
	}

	if needsRegister {
		logrus.WithFields(logrus.Fields{
			"email": email,
		}).Info("We need to register an new account")
		accountFile.Close()
		keyFile.Close()

		os.Remove(accountFilePath)
		os.Remove(keyFilePath)

		accountFile, err = os.Create(accountFilePath)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"accountFilePath": accountFilePath,
				"email":           email,
			}).Error("Failed creating the account.json")
			return err
		}

		keyFile, err = os.Create(keyFilePath)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"keyFilePath": keyFilePath,
				"email":       email,
			}).Error("Failed creating the private.key")
			return err
		}

		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"email": email,
				"curve": "P384",
			}).Error("Failed to generate private key for account")
			return err
		}
		m.acmeClient.Key = privateKey
		if err := writeKey(keyFile, privateKey); err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"keyFilePath": keyFilePath,
				"email":       email,
			}).Error("Failed to write private key")
			return err
		}

		m.acmeAccount = &acme.Account{
			Contact: []string{fmt.Sprintf("mailto:%s", email)},
		}

		m.acmeAccount, err = m.acmeClient.Register(m.ctx, m.acmeAccount, acme.AcceptTOS)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"email": email,
			}).Error("Failed to register account")
			return err
		}
		if err := json.NewEncoder(accountFile).Encode(m.acmeAccount); err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"email": email,
			}).Error("Failed to marshal account data")
			return err
		}
	} else {
		logrus.Info("Using existing ACME account")
		key, err := readKey(keyFile)
		if err != nil {
			return err
		}
		m.acmeClient.Key = key
		m.acmeAccount = &acme.Account{}
		if err := json.NewDecoder(accountFile).Decode(m.acmeAccount); err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) RenewalForDomain(domain string) bool {
	certPath := filepath.Join(DefaultCertsBasePath, domain, "cert.pem")
	keyPath := filepath.Join(DefaultCertsBasePath, domain, "key.pem")
	if !checkCertValid(certPath) {
		derBytes, err := loadCertBundle(certPath)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"domain":   domain,
				"certPath": certPath,
			}).Error("Failed to load PEM pundle")
		}
		var certBytes []byte
		for _, b := range derBytes {
			cert, err := x509.ParseCertificate(b)
			if err == nil {
				for _, name := range cert.DNSNames {
					if name == domain {
						certBytes = b
						break
					}
				}
			}
		}

		if len(certBytes) > 0 {
			if err := m.acmeClient.RevokeCert(m.ctx, nil, certBytes, acme.CRLReasonSuperseded); err != nil {
				logrus.WithError(err).WithFields(logrus.Fields{
					"domain":   domain,
					"certPath": certPath,
				}).Error("Failed to revoke certificate")
			}
			newCerts, err := m.requestCertificate(domain, certPath, keyPath)
			if err != nil {
				logrus.WithError(err).WithFields(logrus.Fields{
					"certPath": certPath,
					"domain":   domain,
				}).Error("Failed to request certificate")
			}
			return newCerts
		} else {
			logrus.WithFields(logrus.Fields{
				"certPath": certPath,
				"domain":   domain,
			}).Error("Couldn't find certificate for domain in PEM bundle")
		}
	}
	return false
}

func (m *Manager) CertForDomain(domain string) (certPath string, keyPath string, newCerts bool, err error) {

	certPath = filepath.Join(DefaultCertsBasePath, domain, "cert.pem")
	keyPath = filepath.Join(DefaultCertsBasePath, domain, "key.pem")
	domainFolder := filepath.Join(DefaultCertsBasePath, domain)
	logrus.WithFields(logrus.Fields{
		"domain":   domain,
		"certPath": certPath,
		"keyPath":  keyPath,
	}).Info("Requesting certificate for domain")
	if err = os.MkdirAll(domainFolder, 0755); err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"domain":     domain,
			"certPath":   certPath,
			"keyPath":    keyPath,
			"domainPath": domainFolder,
		}).Error("Failed to create folder for domain")
		return
	}

	if !checkCertValid(certPath) {
		logrus.WithError(err).WithFields(logrus.Fields{
			"domain":     domain,
			"certPath":   certPath,
			"keyPath":    keyPath,
			"domainPath": domainFolder,
		}).Info("No valid certificate founf for domain")
		if newCerts, err = m.requestCertificate(domain, certPath, keyPath); err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"domain":     domain,
				"certPath":   certPath,
				"keyPath":    keyPath,
				"domainPath": domainFolder,
			}).Error("Failed to request certificate for domain")
			return "", "", newCerts, err
		}
	} else {
		logrus.WithError(err).WithFields(logrus.Fields{
			"domain":     domain,
			"certPath":   certPath,
			"keyPath":    keyPath,
			"domainPath": domainFolder,
		}).Info("Domain has already valid certificates")
	}
	return certPath, keyPath, newCerts, nil
}

func (m *Manager) putHTTPToken(path, token string) {
	m.httpTokenLock.Lock()
	defer m.httpTokenLock.Unlock()
	m.httpTokens[path] = token
}

func (m *Manager) getHTTPToken(path string) string {
	m.httpTokenLock.Lock()
	defer m.httpTokenLock.Unlock()
	return m.httpTokens[path]
}

func (m *Manager) deleteHTTPToken(path string) {
	m.httpTokenLock.Lock()
	defer m.httpTokenLock.Unlock()
	delete(m.httpTokens, path)
}

func (m *Manager) HTTP01ChallengeHandler(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/") {
		logrus.WithFields(logrus.Fields{
			"urlPath": r.URL.Path,
		}).Error("Received request at invalid path")
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	token := m.getHTTPToken(r.URL.Path)
	if token == "" {
		logrus.WithFields(logrus.Fields{
			"urlPath": r.URL.Path,
		}).Error("Received request for not existing token")
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}
	logrus.WithFields(logrus.Fields{
		"urlPath": r.URL.Path,
	}).Info("Responding to HTTP-01 challenge")
	w.Write([]byte(token))
}

func (m *Manager) requestCertificate(domain, certPath, keyPath string) (newCerts bool, err error) {
	authz, err := m.acmeClient.Authorize(m.ctx, domain)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"domain": domain,
		}).Error("Failed to get authorization for domain")
		return newCerts, err
	}

	if authz.Status != acme.StatusValid && authz.Status != acme.StatusInvalid {
		newCerts = true
		logrus.WithFields(logrus.Fields{
			"domain": domain,
		}).Info("Domain is currently not authorized")
		var acceptedChallenge *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				acceptedChallenge = c
				break
			}
		}

		if acceptedChallenge == nil {
			logrus.WithFields(logrus.Fields{
				"domain": domain,
			}).Error("Can't find acceptable challenge for domain")
			return newCerts, errors.New("No acceptable challenge found")
		}
		path := m.acmeClient.HTTP01ChallengePath(acceptedChallenge.Token)
		m.putHTTPToken(path, acceptedChallenge.Token)
		chal, err := m.acmeClient.Accept(m.ctx, acceptedChallenge)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"domain": domain,
			}).Error("Failed to accept authorization challenge")
			return newCerts, err
		}

		logrus.WithFields(logrus.Fields{
			"domain": domain,
		}).Info("Waiting for Challenge to complete")
		if err := m.waitForChallenge(chal, time.Minute*1); err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"domain": domain,
			}).Error("Challenge failed")
			return false, err
		}
		m.deleteHTTPToken(path)
	} else if authz.Status == acme.StatusInvalid {
		return newCerts, errors.New("Authorization is invalid")
	}
	// Assume that we have a valid authorization now for our domain
	privKeyFile, err := os.Open(keyPath)
	var privKey *ecdsa.PrivateKey
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"domain": domain,
		}).Info("Generating new private key for domain")
		privKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"domain": domain,
			}).Error("Failed to generate private key for domain")
			return newCerts, err
		}
		privKeyFile, err := os.Create(keyPath)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"domain": domain,
			}).Error("Failed to create private key file")
			return newCerts, err
		}
		logrus.WithFields(logrus.Fields{
			"domain":         domain,
			"privateKeyFile": privKey,
		}).Info("Writing private key for domain")
		writeKey(privKeyFile, privKey)
	} else {
		logrus.WithFields(logrus.Fields{
			"domain":  domain,
			"keyPath": keyPath,
		}).Info("Using existing private key")
		privKey, err = readKey(privKeyFile)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"domain":  domain,
				"keyPath": keyPath,
			}).Error("Failed to read existing private key")
			return newCerts, err
		}
	}

	logrus.WithFields(logrus.Fields{
		"domain": domain,
	}).Info("Creating CSR")
	csr, err := certRequest(privKey, domain, nil) // Ignore extensions for now

	logrus.WithFields(logrus.Fields{
		"domain": domain,
	}).Info("Requesting certificate at ACME issuer")
	der, _, err := m.acmeClient.CreateCert(m.ctx, csr, time.Hour*24*90, true)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"domain": domain,
		}).Error("Failed to create cert for domain")
		return newCerts, err
	}
	return newCerts, writeCertBundle(certPath, der)
}

func (m *Manager) waitForChallenge(challenge *acme.Challenge, timeout time.Duration) (err error) {
	logrus.WithFields(logrus.Fields{
		"challengeToken": challenge.Token,
		"timeoutSeconds": timeout.Seconds(),
	}).Info("Waiting for challenge to complete")
	expired := time.Now().Add(timeout)
	for !time.Now().After(expired) {
		aCtx, _ := context.WithTimeout(m.ctx, time.Second*10)
		challenge, err = m.acmeClient.GetChallenge(aCtx, challenge.URI)
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"challengeToken": challenge.Token,
			}).Error("Failed to retrieve updated challenge")
			return err
		}
		/*if challenge.Status != acme.StatusPending {
			break
		}
		if challenge.Status != acme.StatusProcessing {
			break
		}*/
		if challenge.Status == acme.StatusValid {
			break
		}
		time.Sleep(time.Second * 10)
	}

	if challenge.Status != acme.StatusValid {
		logrus.WithFields(logrus.Fields{
			"challengeStatus": challenge.Status,
			"challengeError":  challenge.Error.Error(),
		}).Error("Challange never became valid")
		return errors.New("Challenge did not become valid during timeout")
	}
	return nil
}

func checkCertValid(certPath string) bool {
	certFile, err := os.Open(certPath)
	if err != nil {
		return false
	}
	certBytes, err := ioutil.ReadAll(certFile)
	if err != nil {
		return false
	}
	block, _ := pem.Decode(certBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}
	now := time.Now()
	return cert.NotBefore.After(now) && now.After(cert.NotAfter)
}

func certRequest(key crypto.Signer, cn string, ext []pkix.Extension, san ...string) ([]byte, error) {
	req := &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: cn},
		DNSNames:        san,
		ExtraExtensions: ext,
	}
	return x509.CreateCertificateRequest(rand.Reader, req, key)
}

func loadCertBundle(pemPath string) ([][]byte, error) {
	pemBytes, err := ioutil.ReadFile(pemPath)
	if err != nil {
		return nil, err
	}
	overflow := pemBytes
	var derBytes [][]byte
	var block *pem.Block
	for {
		block, overflow = pem.Decode(overflow)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			derBytes = append(derBytes, block.Bytes)
		}
	}
	return derBytes, nil
}

func writeCertBundle(certFilePath string, bundle [][]byte) error {
	os.Remove(certFilePath)
	certFile, err := os.Create(certFilePath)
	defer certFile.Close()
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"certFilePath": certFilePath,
		}).Error("Failed to create PEM cert bundle")
		return err
	}
	for _, der := range bundle {
		if err := pem.Encode(certFile, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		}); err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"certFilePath": certFilePath,
			}).Error("Failed to encode PEM cert bundle")
			return err
		}
	}
	return nil
}

func writeKey(keyFile *os.File, key *ecdsa.PrivateKey) error {
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	pemBlock := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}
	return pem.Encode(keyFile, &pemBlock)
}

func readKey(keyFile *os.File) (key *ecdsa.PrivateKey, err error) {
	pemBytes, err := ioutil.ReadAll(keyFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if err != nil {
		return nil, err
	}

	return x509.ParseECPrivateKey(block.Bytes)
}
