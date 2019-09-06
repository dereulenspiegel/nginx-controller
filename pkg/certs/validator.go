package certs

import (
	"crypto/x509"
)

func validateCert(dnsname string, cert *x509.Certificate, intermediates ...*x509.Certificate) error {
	systemPool, err := x509.SystemCertPool()
	if err != nil {
		return err
	}

	intermediatePool := x509.NewCertPool()
	for _, intermediate := range intermediates {
		intermediatePool.AddCert(intermediate)
	}

	verifyOpts := x509.VerifyOptions{
		DNSName:       dnsname,
		Roots:         systemPool,
		Intermediates: intermediatePool,
	}
	_, err = cert.Verify(verifyOpts)
	return err
}
