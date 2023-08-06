package authority

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"github.com/kongweiguo/jubilant-controller/internal/utils"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

const (
	PRIVATE_KEY    = "PrivateKey"
	CERT_CHAIN_PEM = "CertChainPEM"
	BUNDLE_PEM     = "BundlePEM"
)

var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

type Authority struct {
	PrivateKey  crypto.Signer
	Certificate *x509.Certificate
	CertChain   []*x509.Certificate // certiciate chain from
	Bundle      []*x509.Certificate

	PrivateKeyPEM []byte
	CertPEM       []byte
	CertChainPEM  []byte
	BundlePEM     []byte

	Backdate time.Duration
	Now      func() time.Time
}

func AuthorityToSecret(secretName *types.NamespacedName, ca *Authority) *corev1.Secret {
	secret := &corev1.Secret{
		TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName.Name,
			Namespace: secretName.Namespace,
		},
		Data: map[string][]byte{
			PRIVATE_KEY:    ca.PrivateKeyPEM,
			CERT_CHAIN_PEM: ca.CertChainPEM,
			BUNDLE_PEM:     ca.BundlePEM,
		},
		Type: corev1.SecretTypeOpaque,
	}

	return secret
}

func SecretToAuthority(s *corev1.Secret) (*Authority, error) {

	PrivateKeyPEM, ok := s.Data[PRIVATE_KEY]
	if !ok {
		return nil, fmt.Errorf("%s empty", PRIVATE_KEY)
	}
	CertChainPEM, ok := s.Data[CERT_CHAIN_PEM]
	if !ok {
		return nil, fmt.Errorf("%s empty", CERT_CHAIN_PEM)
	}
	BundlePEM, ok := s.Data[BUNDLE_PEM]
	if !ok {
		return nil, fmt.Errorf("%s empty", BUNDLE_PEM)
	}

	PrivateKey, err := utils.ParsePrivateKeyPEM(PrivateKeyPEM)
	if err != nil {
		return nil, err
	}

	CertChain, err := utils.ParseCertsPEM(CertChainPEM)
	if err != nil {
		return nil, err
	}

	Bundle, err := utils.ParseCertsPEM(BundlePEM)
	if err != nil {
		return nil, err
	}

	ca := &Authority{
		PrivateKey:    PrivateKey,
		CertChain:     CertChain,
		Bundle:        Bundle,
		PrivateKeyPEM: PrivateKeyPEM,
		CertChainPEM:  CertChainPEM,
		BundlePEM:     BundlePEM,
	}

	return ca, nil
}

// Sign signs a certificate request, applying a SigningPolicy and returns a DER
// encoded x509 certificate.
func (ca *Authority) Sign(crDER []byte, policy SigningPolicy) ([]byte, error) {
	now := time.Now()
	if ca.Now != nil {
		now = ca.Now()
	}

	nbf := now.Add(-ca.Backdate)
	if !nbf.Before(ca.Certificate.NotAfter) {
		return nil, fmt.Errorf("the signer has expired: NotAfter=%v", ca.Certificate.NotAfter)
	}

	cr, err := x509.ParseCertificateRequest(crDER)
	if err != nil {
		return nil, fmt.Errorf("unable to parse certificate request: %v", err)
	}
	if err := cr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("unable to verify certificate request signature: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("unable to generate a serial number for %s: %v", cr.Subject.CommonName, err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:       serialNumber,
		Subject:            cr.Subject,
		DNSNames:           cr.DNSNames,
		IPAddresses:        cr.IPAddresses,
		EmailAddresses:     cr.EmailAddresses,
		URIs:               cr.URIs,
		PublicKeyAlgorithm: cr.PublicKeyAlgorithm,
		PublicKey:          cr.PublicKey,
		Extensions:         cr.Extensions,
		ExtraExtensions:    cr.ExtraExtensions,
		NotBefore:          nbf,
	}
	if err := policy.apply(tmpl); err != nil {
		return nil, err
	}

	if !tmpl.NotAfter.Before(ca.Certificate.NotAfter) {
		tmpl.NotAfter = ca.Certificate.NotAfter
	}
	if !now.Before(ca.Certificate.NotAfter) {
		return nil, fmt.Errorf("refusing to sign a certificate that expired in the past")
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Certificate, cr.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %v", err)
	}
	return der, nil
}
