package certs

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme"
)

var (
	DefaultBasePath = "/var/lib/nginx-controller"
)

type caClient interface {
	SetKey(privateKey crypto.Signer)
	SetDirectoryURL(directoryURL string)

	Register(ctx context.Context, acc *acme.Account, acceptTos func(tos string) bool) (*acme.Account, error)
	Accept(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error)
	Authorize(ctx context.Context, domain string) (*acme.Authorization, error)
	CreateCert(ctx context.Context, csr []byte, exp time.Duration, bundle bool) (der [][]byte, certURL string, err error)
	GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	GetChallenge(ctx context.Context, url string) (*acme.Challenge, error)
	HTTP01ChallengePath(token string) string
	HTTP01ChallengeResponse(token string) (string, error)
	WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error)
	AuthorizeOrder(ctx context.Context, id []acme.AuthzID, opt ...acme.OrderOption) (*acme.Order, error)
	WaitOrder(ctx context.Context, url string) (*acme.Order, error)
	CreateOrderCert(ctx context.Context, url string, csr []byte, bundle bool) (der [][]byte, certURL string, err error)
}

type store interface {
	StoreAccountKey(privateKey crypto.Signer) error
	LoadAccountKey() (crypto.Signer, error)

	StoreAccount(acc *acme.Account) error
	LoadAccount() (acc *acme.Account, err error)

	StoreDomainPrivateKey(domain string, privateKey crypto.Signer) error
	LoadDomainPrivateKey(domain string) (crypto.Signer, error)
	StoreCertDerBundle(domain string, certs [][]byte) error
	LoadCertDerBundle(domain string) (certs [][]byte, err error)
	LoadCertBundle(domain string) (certs []*x509.Certificate, err error)
	LoadCert(domain string) (cert *x509.Certificate, intermediateCerts []*x509.Certificate, err error)
	KeyPath(domain string) (keyPath string, err error)
	CertPath(domain string) (certPath string, err error)
}

type acmeClient struct {
	acme.Client
}

func (a *acmeClient) SetKey(privateKey crypto.Signer) {
	a.Client.Key = privateKey
}

func (a *acmeClient) SetDirectoryURL(directoryURL string) {
	a.Client.DirectoryURL = directoryURL
}

type Manager struct {
	acmeClient  caClient
	acmeAccount *acme.Account
	certStore   store

	ctx context.Context

	httpTokens    map[string]string
	httpTokenLock *sync.Mutex
	email         string
	renewBefore   time.Duration

	httpServer *http.Server

	mockRenewal bool
	useRSA      bool
}

func NewManager(ctx context.Context, email string, acmeUri string) (*Manager, error) {
	crtStore, err := newCertStore(DefaultBasePath)
	if err != nil {
		logrus.WithError(err).Error("Failed to create cert manager store")
		return nil, err
	}
	m := &Manager{
		acmeClient:    &acmeClient{acme.Client{DirectoryURL: acmeUri}},
		ctx:           ctx,
		httpTokens:    make(map[string]string),
		httpTokenLock: &sync.Mutex{},
		email:         email,
		renewBefore:   time.Hour * 24 * 30,
		mockRenewal:   false,
		useRSA:        true,
		certStore:     crtStore,
	}

	rootMux := http.NewServeMux()
	rootMux.Handle("/", http.HandlerFunc(m.HTTP01ChallengeHandler))
	hs := &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", 8402),
		Handler: rootMux,
	}
	m.httpServer = hs
	if err := m.ensureAccount(email); err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"email": email,
		}).Error("Failed to ensure account")
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

func (m *Manager) ensureAccount(email string) (err error) {
	logger := logrus.WithField("email", email)
	needsRegister := false

	acc, err1 := m.certStore.LoadAccount()
	accKey, err2 := m.certStore.LoadAccountKey()
	if err1 != nil || err2 != nil {
		logger.Debug("Couldn't load existing account, registering new account")
		needsRegister = true
	}

	if needsRegister {
		logger.Info("We need to register an new account")

		var privateKey crypto.Signer

		if m.useRSA {
			privateKey, err = rsa.GenerateKey(rand.Reader, 4096)
		} else {
			privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		}
		m.acmeClient.SetKey(privateKey)
		if err := m.certStore.StoreAccountKey(privateKey); err != nil {
			logger.WithError(err).Error("Failed to write private key")
			return err
		}

		m.acmeAccount = &acme.Account{
			Contact: []string{fmt.Sprintf("mailto:%s", email)},
		}

		m.acmeAccount, err = m.acmeClient.Register(m.ctx, m.acmeAccount, acme.AcceptTOS)
		if err != nil {
			logger.WithError(err).Error("Failed to register account")
			return err
		}
		if err := m.certStore.StoreAccount(m.acmeAccount); err != nil {
			logger.WithError(err).Error("Failed to store account data")
			return err
		}
	} else {
		logger.Info("Using existing ACME account")

		m.acmeClient.SetKey(accKey)
		m.acmeAccount = acc
	}

	return nil
}

func (m *Manager) renewCertificate(domain string) (newCerts bool, err error) {

	logger := logrus.WithFields(logrus.Fields{
		"domain": domain,
	})
	logger.Info("Renewing certificate")
	if m.mockRenewal {
		logger.Info("Actual renewing disabled for now")
		return false, err
	}

	/*logrus.Info("Revoking old certificate")
	if err = m.acmeClient.RevokeCert(m.ctx, nil, certBytes, acme.CRLReasonSuperseded); err != nil {
		logger.WithError(err).Error("Failed to revoke certificate")
		return
	}*/
	logrus.Info("Requesting new certificate")
	newCerts, err = m.requestCertificate(domain)
	if err != nil {
		logger.WithError(err).Error("Failed to request certificate")
	} else {
		logger.Info("Successfully renewed certificate")
	}
	return
}

func (m *Manager) RenewalForDomain(domain string) bool {

	logger := logrus.WithFields(logrus.Fields{
		"domain": domain,
	})
	logger.Info("Checking domain for renewal")
	if !m.checkCertValid(domain) {
		logger.Info("Domain needs renewal")
		newCerts, err := m.renewCertificate(domain)
		if err != nil {
			logger.WithError(err).Error("Failed to renew certificate")
			return false
		}
		return newCerts
	}
	logger.Info("Certificate is still valid")
	return false
}

func (m *Manager) CertForDomain(domain string) (certPath string, keyPath string, newCerts bool, err error) {

	logger := logrus.WithFields(logrus.Fields{
		"domain": domain,
	})
	logger.Info("Requesting certificate for domain")

	if !m.checkCertValid(domain) {
		logger.WithError(err).WithFields(logrus.Fields{}).Info("No valid certificate found for domain")
		if newCerts, err = m.requestCertificate(domain); err != nil {
			logger.WithError(err).WithFields(logrus.Fields{}).Error("Failed to request certificate for domain")
			return "", "", newCerts, err
		}
	} else {
		logger.WithError(err).WithFields(logrus.Fields{}).Info("Domain has already valid certificates")
	}
	certPath, err = m.certStore.CertPath(domain)
	if err != nil {
		logger.WithError(err).Error("Failed to get certificate path")
		return
	}
	keyPath, err = m.certStore.KeyPath(domain)
	if err != nil {
		logger.WithError(err).Error("Failed to get domain key path")
		return
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
		"token":   token,
	}).Info("Responding to HTTP-01 challenge")
	w.Write([]byte(token))
}

func (m *Manager) authorizeDomain(domain string) (finalizeURL string, err error) {
	logger := logrus.WithFields(logrus.Fields{
		"domain": domain,
	})
	order, err := m.acmeClient.AuthorizeOrder(m.ctx, []acme.AuthzID{acme.AuthzID{Type: "dns", Value: domain}})
	if err != nil {
		logger.WithError(err).Error("Failed to get authorization for domain")
		return "", err
	}

	if order.Status == acme.StatusReady || order.Status == acme.StatusValid {
		return order.FinalizeURL, nil
	}

	for _, authzURL := range order.AuthzURLs {
		authz, err := m.acmeClient.GetAuthorization(m.ctx, authzURL)
		if err != nil {
			logger.WithError(err).WithField("authzURL", authzURL).Error("Failed to fetch authorization")
			continue
		}
		if authz.Status != acme.StatusPending {
			// We are interested only in pending authorizations.
			continue
		}
		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "http-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return "", fmt.Errorf("acme/autocert: unable to satisfy %q for domain %q: no viable challenge type found", authz.URI, domain)
		}

		path := m.acmeClient.HTTP01ChallengePath(chal.Token)
		responseToken, err := m.acmeClient.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			logger.WithError(err).WithFields(logrus.Fields{
				"challengeToken": chal.Token,
			}).Error("Failed to create HTTP-01 response")
			return "", err
		}
		m.putHTTPToken(path, responseToken)
		defer func() {
			m.deleteHTTPToken(path)
		}()

		if _, err := m.acmeClient.Accept(m.ctx, chal); err != nil {
			logger.WithError(err).Error("Failed to accept authorization")
			return "", fmt.Errorf("Failed to accept authorization: %w", err)
		}

		if _, err := m.acmeClient.WaitAuthorization(m.ctx, authz.URI); err != nil {
			logger.WithError(err).Error("Failed to wait for authorization")
			return "", fmt.Errorf("Failed to wait for authorization: %w", err)
		}
	}

	order, err = m.acmeClient.WaitOrder(m.ctx, order.URI)
	if err != nil {
		logger.WithError(err).Error("Failed to wait for order")
		return "", fmt.Errorf("Failed to wait for order: %w", err)
	}
	return order.FinalizeURL, nil
}

func (m *Manager) requestCertificate(domain string) (newCerts bool, err error) {
	finalizeURL, err := m.authorizeDomain(domain)
	if err != nil {
		return false, err
	}
	// Assume that we have a valid authorization now for our domain
	privKey, err := m.certStore.LoadDomainPrivateKey(domain)
	if err != nil {
		if m.useRSA {
			privKey, err = rsa.GenerateKey(rand.Reader, 4096)
		} else {
			privKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		}
		if err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"domain": domain,
			}).Error("Failed to generate private key for domain")
			return newCerts, err
		}
		if err := m.certStore.StoreDomainPrivateKey(domain, privKey); err != nil {
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
	ctx, cancel := context.WithTimeout(m.ctx, time.Second*60)
	defer cancel()
	der, _, err := m.acmeClient.CreateOrderCert(ctx, finalizeURL, csr, true)
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"domain": domain,
		}).Error("Failed to create cert for domain")
		return newCerts, err
	}
	logrus.WithFields(logrus.Fields{
		"domain": domain,
	}).Info("Writing certificate to disk")
	return newCerts, m.certStore.StoreCertDerBundle(domain, der)
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

func (m *Manager) checkCertValid(domain string) bool {
	logger := logrus.WithField("domain", domain)
	cert, intermediateCerts, err := m.certStore.LoadCert(domain)
	if err != nil {
		logger.WithError(err).Error("Failed to load certificate for validation")
		return false
	}
	logger = logger.WithFields(logrus.Fields{
		"notBefore": cert.NotBefore.String(),
		"notAfter":  cert.NotAfter.String(),
		"now":       time.Now().String(),
	})

	if err = validateCert(domain, cert, intermediateCerts...); err != nil {
		logger.WithError(err).Warn("Certificate validation failed")
		return false
	}
	logger.Info("Certificate is stilll valid")
	return true
}

func certRequest(key crypto.Signer, cn string, ext []pkix.Extension, san ...string) ([]byte, error) {
	req := &x509.CertificateRequest{
		Subject:         pkix.Name{CommonName: cn},
		DNSNames:        san,
		ExtraExtensions: ext,
	}
	return x509.CreateCertificateRequest(rand.Reader, req, key)
}
