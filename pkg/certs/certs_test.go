package certs

import (
	"context"
	"crypto"
	"crypto/x509"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/acme"
)

type mockAcmeClient struct {
	mock.Mock
}

func (m *mockAcmeClient) SetKey(privateKey crypto.Signer) {
	m.Called(privateKey)
}
func (m *mockAcmeClient) SetDirectoryURL(directoryURL string) {
	m.Called(directoryURL)
}

func (m *mockAcmeClient) Register(ctx context.Context, acc *acme.Account, acceptTos func(tos string) bool) (*acme.Account, error) {
	args := m.Called(ctx, acc, acceptTos)
	return args.Get(0).(*acme.Account), args.Error(1)
}
func (m *mockAcmeClient) Accept(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error) {
	args := m.Called(ctx, chal)
	return args.Get(0).(*acme.Challenge), args.Error(1)
}
func (m *mockAcmeClient) Authorize(ctx context.Context, domain string) (*acme.Authorization, error) {
	args := m.Called(ctx, domain)
	return args.Get(0).(*acme.Authorization), args.Error(1)
}
func (m *mockAcmeClient) CreateCert(ctx context.Context, csr []byte, exp time.Duration, bundle bool) (der [][]byte, certURL string, err error) {
	args := m.Called(ctx, csr, exp, bundle)
	return args.Get(0).([][]byte), args.String(1), args.Error(2)
}
func (m *mockAcmeClient) GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	args := m.Called(ctx, url)
	return args.Get(0).(*acme.Authorization), args.Error(1)
}
func (m *mockAcmeClient) GetChallenge(ctx context.Context, url string) (*acme.Challenge, error) {
	args := m.Called(ctx, url)
	return args.Get(0).(*acme.Challenge), args.Error(1)
}
func (m *mockAcmeClient) HTTP01ChallengePath(token string) string {
	args := m.Called(token)
	return args.String(0)
}
func (m *mockAcmeClient) HTTP01ChallengeResponse(token string) (string, error) {
	args := m.Called(token)
	return args.String(0), args.Error(1)
}
func (m *mockAcmeClient) WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	args := m.Called(ctx, url)
	return args.Get(0).(*acme.Authorization), args.Error(1)
}

func (m *mockAcmeClient) AuthorizeOrder(ctx context.Context, id []acme.AuthzID, opt ...acme.OrderOption) (*acme.Order, error) {
	args := m.Called(ctx, id, opt)
	return args.Get(0).(*acme.Order), args.Error(1)
}

func (m *mockAcmeClient) WaitOrder(ctx context.Context, url string) (*acme.Order, error) {
	args := m.Called(ctx, url)
	return args.Get(0).(*acme.Order), args.Error(1)
}

func (m *mockAcmeClient) CreateOrderCert(ctx context.Context, url string, csr []byte, bundle bool) (der [][]byte, certURL string, err error) {
	args := m.Called(ctx, url, csr, bundle)
	return args.Get(0).([][]byte), args.String(1), args.Error(2)
}

type mockStore struct {
	mock.Mock
}

func (m *mockStore) StoreAccountKey(privateKey crypto.Signer) error {
	return m.Called(privateKey).Error(0)
}
func (m *mockStore) LoadAccountKey() (crypto.Signer, error) {
	args := m.Called()
	var arg1 crypto.Signer
	if args.Get(0) != nil {
		arg1 = args.Get(0).(crypto.Signer)
	}
	return arg1, args.Error(1)
}

func (m *mockStore) StoreAccount(acc *acme.Account) error {
	return m.Called(acc).Error(0)
}
func (m *mockStore) LoadAccount() (acc *acme.Account, err error) {
	args := m.Called()
	var arg1 *acme.Account
	arg1 = nil
	if args.Get(0) != nil {
		arg1 = args.Get(0).(*acme.Account)
	}
	return arg1, args.Error(1)
}

func (m *mockStore) StoreDomainPrivateKey(domain string, privateKey crypto.Signer) error {
	return m.Called(domain, privateKey).Error(0)
}
func (m *mockStore) LoadDomainPrivateKey(domain string) (crypto.Signer, error) {
	args := m.Called(domain)
	return args.Get(0).(crypto.Signer), args.Error(1)
}
func (m *mockStore) StoreCertDerBundle(domain string, certs [][]byte) error {
	return m.Called(domain, certs).Error(0)
}
func (m *mockStore) LoadCertDerBundle(domain string) (certs [][]byte, err error) {
	args := m.Called(domain)
	return args.Get(0).([][]byte), args.Error(1)
}
func (m *mockStore) LoadCertBundle(domain string) (certs []*x509.Certificate, err error) {
	args := m.Called(domain)
	return args.Get(0).([]*x509.Certificate), args.Error(1)
}
func (m *mockStore) LoadCert(domain string) (cert *x509.Certificate, intermediates []*x509.Certificate, err error) {
	args := m.Called(domain)
	return args.Get(0).(*x509.Certificate), args.Get(1).([]*x509.Certificate), args.Error(2)
}
func (m *mockStore) KeyPath(domain string) (keyPath string, err error) {
	args := m.Called(domain)
	return args.String(0), args.Error(1)
}
func (m *mockStore) CertPath(domain string) (certPath string, err error) {
	args := m.Called(domain)
	return args.String(0), args.Error(1)
}

func TestAccountRegistration(t *testing.T) {
	caClient := new(mockAcmeClient)
	caStore := new(mockStore)
	email := "foo@bar.baz"

	manager := &Manager{
		certStore:  caStore,
		acmeClient: caClient,
		ctx:        context.TODO(),
		email:      email,
	}

	caStore.On("LoadAccount").Once().Return(nil, ErrorAccountDoesNotExist)
	caStore.On("LoadAccountKey").Once().Return(nil, ErrorKeyDoesNotExist)
	caStore.On("StoreAccount", mock.Anything).Once().Return(nil)
	caStore.On("StoreAccountKey", mock.Anything).Once().Return(nil)

	caClient.On("SetKey", mock.MatchedBy(func(key crypto.Signer) bool {
		if key != nil {

			return true
		}
		return false
	})).Once()

	caClient.On("Register", mock.Anything, mock.Anything, mock.Anything).
		Once().
		Return(&acme.Account{}, nil)

	err := manager.ensureAccount(email)
	require.NoError(t, err)

	caClient.AssertExpectations(t)
	caStore.AssertExpectations(t)
}
