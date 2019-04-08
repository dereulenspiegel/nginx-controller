package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme"
)

const (
	domainSubfolder  = "domains"
	accountSubfolder = "account"

	keyFileName     = "key.pem"
	certFileName    = "cert.pem"
	accountFilename = "account.json"
)

var (
	ErrorAccountDoesNotExist = errors.New("Account does not exist")
	ErrorKeyDoesNotExist     = errors.New("The private key does not exist")
)

type certStore struct {
	basePath string
}

func newCertStore(basePath string) (*certStore, error) {
	c := &certStore{
		basePath: basePath,
	}
	accountFolder := filepath.Join(c.basePath, accountSubfolder)
	domainFolder := filepath.Join(c.basePath, domainSubfolder)
	logger := logrus.WithFields(logrus.Fields{
		"basePath":         basePath,
		"domainSubFolder":  domainFolder,
		"accountSubFolder": accountFolder,
	})
	if err := os.MkdirAll(accountFolder, 0755); err != nil {
		logger.WithError(err).Error("Failed to create accounts base path")
		return nil, errors.Wrap(errors.WithStack(err), "Failed to create accounts base path")
	}

	if err := os.MkdirAll(domainFolder, 0755); err != nil {
		logger.WithError(err).Error("Failed to create domain certs base path")
		return nil, errors.Wrap(errors.WithStack(err), "Failed to create domain base path")
	}
	return c, nil
}

func ensureDir(dir string) error {
	dir = filepath.Dir(dir)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return errors.Wrap(errors.WithStack(err), "Failed to create directory")
	}
	return nil
}

func (c *certStore) storeKey(keyPath string, privateKey crypto.Signer) error {
	ensureDir(keyPath)
	keyFile, err := os.Create(keyPath)
	defer keyFile.Close()
	if err != nil {
		return errors.Wrap(errors.WithStack(err), "Failed to open key file")
	}
	var pemBlock *pem.Block
	switch t := privateKey.(type) {
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(t)
		if err != nil {
			return errors.Wrap(errors.WithStack(err), "Failed to marshal ec private key")
		}

		pemBlock = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		}

	case *rsa.PrivateKey:
		keyBytes, err := x509.MarshalPKCS8PrivateKey(t)
		if err != nil {
			return errors.Wrap(errors.WithStack(err), "Failed to marshal rsa private key")
		}

		pemBlock = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyBytes,
		}

	default:
		return errors.WithStack(errors.New("Unknown key format"))
	}
	if err := pem.Encode(keyFile, pemBlock); err != nil {
		errors.Wrap(errors.WithStack(err), "Failed to encode pem file")
	}
	return nil
}

func (c *certStore) loadKey(keyPath string) (key crypto.Signer, err error) {
	keyFile, err := os.Open(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrorKeyDoesNotExist
		}
		return nil, errors.Wrap(errors.WithStack(err), "Failed to open key file")
	}
	pemBytes, err := ioutil.ReadAll(keyFile)
	if err != nil {
		return nil, errors.Wrap(errors.WithStack(err), "Failed to read key file")
	}
	block, _ := pem.Decode(pemBytes)
	if err != nil {
		return nil, errors.Wrap(errors.WithStack(err), "Failed to decode pem key")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		var keyVal interface{}
		keyVal, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		if err == nil && keyVal != nil {
			key = keyVal.(crypto.Signer)
		}
	default:
		err = errors.New("Unknown key type")
	}
	if err != nil {
		return nil, errors.Wrap(errors.WithStack(err), "Failed to parse key")
	}
	return
}

func (c *certStore) LoadAccountKey() (crypto.Signer, error) {
	accountKeyPath := filepath.Join(c.basePath, accountSubfolder, keyFileName)
	return c.loadKey(accountKeyPath)
}

func (c *certStore) LoadDomainPrivateKey(domain string) (crypto.Signer, error) {
	keyPath := filepath.Join(c.basePath, domainSubfolder, domain, keyFileName)
	return c.loadKey(keyPath)
}

func (c *certStore) StoreAccountKey(privateKey crypto.Signer) error {
	accountKeyPath := filepath.Join(c.basePath, accountSubfolder, keyFileName)
	return c.storeKey(accountKeyPath, privateKey)
}

func (c *certStore) StoreAccount(acc *acme.Account) error {
	accountPath := filepath.Join(c.basePath, accountSubfolder, accountFilename)
	accountFile, err := os.Create(accountPath)
	defer accountFile.Close()
	if err != nil {
		return errors.Wrap(errors.WithStack(err), "Failed to create account file")
	}
	if err := json.NewEncoder(accountFile).Encode(acc); err != nil {
		return errors.Wrap(errors.WithStack(err), "Failed to marshal account to file")
	}
	return nil
}

func (c *certStore) LoadAccount() (acc *acme.Account, err error) {
	accountPath := filepath.Join(c.basePath, accountSubfolder, accountFilename)
	accountFile, err := os.Open(accountPath)
	defer accountFile.Close()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrorAccountDoesNotExist
		}
		return nil, errors.Wrap(errors.WithStack(err), "Failed to open account file")
	}

	acc = &acme.Account{}
	if err = json.NewDecoder(accountFile).Decode(acc); err != nil {
		return nil, errors.Wrap(errors.WithStack(err), "Failed to unmarshal account from file")
	}
	return
}

func (c *certStore) StoreDomainPrivateKey(domain string, privateKey crypto.Signer) error {
	keyPath := filepath.Join(c.basePath, domainSubfolder, domain, keyFileName)
	return c.storeKey(keyPath, privateKey)
}

func (c *certStore) StoreCertDerBundle(domain string, certs [][]byte) error {
	certPath := filepath.Join(c.basePath, domainSubfolder, domain, certFileName)
	ensureDir(certPath)
	certFile, err := os.Create(certPath)
	defer certFile.Close()
	if err != nil {
		logrus.WithError(err).WithFields(logrus.Fields{
			"certFilePath": certPath,
		}).Error("Failed to create PEM cert bundle")
		return errors.Wrap(errors.WithStack(err), "Failed to open certificate file")
	}

	for _, der := range certs {
		if err := pem.Encode(certFile, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		}); err != nil {
			logrus.WithError(err).WithFields(logrus.Fields{
				"certFilePath": certPath,
				"domain":       domain,
			}).Error("Failed to encode PEM cert bundle")
			return errors.Wrap(errors.WithStack(err), "Failed to encode certificate pem block")
		}
	}
	return nil
}

func (c *certStore) LoadCertDerBundle(domain string) (certs [][]byte, err error) {
	certPath := filepath.Join(c.basePath, domainSubfolder, domain, certFileName)
	certFile, err := os.Open(certPath)
	defer certFile.Close()
	if err != nil {
		return nil, errors.Wrap(errors.WithStack(err), "Failed to open certificate file")
	}
	data, err := ioutil.ReadAll(certFile)
	if err != nil {
		return nil, errors.Wrap(errors.WithStack(err), "Failed to read certificate file")
	}
	overflow := data
	var block *pem.Block
	for {
		block, overflow = pem.Decode(overflow)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certs = append(certs, block.Bytes)
		}
	}
	return
}

func (c *certStore) CertPath(domain string) (certPath string, err error) {
	certPath = filepath.Join(c.basePath, domainSubfolder, domain, certFileName)
	_, err = c.LoadCertDerBundle(domain)
	return
}

func (c *certStore) KeyPath(domain string) (keyPath string, err error) {
	keyPath = filepath.Join(c.basePath, domainSubfolder, domain, keyFileName)
	_, err = c.LoadDomainPrivateKey(domain)
	return
}

func (c *certStore) LoadCertBundle(domain string) (certs []*x509.Certificate, err error) {
	ders, err := c.LoadCertDerBundle(domain)
	if err != nil {
		return nil, err
	}

	for _, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errors.Wrap(errors.WithStack(err), "Failed to parse certificate")
		}
		certs = append(certs, cert)
	}
	return
}

func (c *certStore) LoadCert(domain string) (cert *x509.Certificate, err error) {
	certs, err := c.LoadCertBundle(domain)
	if err != nil {
		return nil, err
	}
	for _, cert = range certs {
		for _, dnsname := range cert.DNSNames {
			if domain == dnsname {
				return
			}
		}
	}
	cert = nil
	err = errors.New("No certificate for domain in cert bundle")
	return
}
