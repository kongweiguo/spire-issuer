package signer

import (
	"context"
	"crypto"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/apimachinery/pkg/types"

	cfcsr "github.com/cloudflare/cfssl/csr"
	"github.com/kongweiguo/cryptoutils/encoding"
	"github.com/kongweiguo/jubilant-controller/api/v1alpha1"
	"github.com/kongweiguo/jubilant-controller/internal/constants"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
)

type SignerBuilder func(ctx context.Context, namespacedName types.NamespacedName, spec *v1alpha1.IssuerSpec) ([][]byte, error)

var (
	// map[GetSignerKey]Signer
	gSigners = make(map[string]Signer)
)

type Signer interface {
	Sign(csrBytes []byte, req cmapi.CertificateRequestSpec) ([]byte, error)
	GetCertificateChain() ([][]byte, error)
	Check() error
	Close()
}

// BuildSigner
func BuildSigner(ctx context.Context, namespacedName types.NamespacedName, spec *v1alpha1.IssuerSpec) ([][]byte, error) {
	if spec == nil {
		return nil, errors.New("input spec invalid")
	}

	key := GetSignerKey(namespacedName)

	s, ok := gSigners[key]
	if ok && s != nil {
		err := s.Check()
		if err != nil {
			rawCertChain, err := s.GetCertificateChain()
			if err == nil {
				return rawCertChain, nil
			}
		}
	}
	delete(gSigners, key)

	ss := &SpireSigner{
		cfg: &SpireConfig{
			SpireAgentSocket:   spec.SpireAgentSocket,
			SpireServerAddress: spec.SpireServerAddress,
		},
	}
	err := ss.buildDownstreamX509CAFromSpire(ctx)
	if err != nil {
		return nil, err
	}

	gSigners[key] = ss
	rawCertChain, err := ss.GetCertificateChain()
	if err != nil {
		return nil, err
	}

	return rawCertChain, nil
}

func CloseAll() {
	for _, s := range gSigners {
		if s != nil {
			s.Close()
		}
	}
}

// GetSignerAndCertificateChain return signer and its' certificate in PEM format
func GetSignerAndCertificateChain(namespaceName types.NamespacedName) (Signer, [][]byte, error) {
	key := GetSignerKey(namespaceName)
	s, ok := gSigners[key]
	if !ok {
		return nil, nil, constants.ErrorNotFound
	}

	chain, err := s.GetCertificateChain()
	if err != nil {
		return nil, nil, err
	}

	return s, chain, nil
}

func GetSignerKey(namespaceName types.NamespacedName) string {
	return fmt.Sprintf("%s-%s", namespaceName.Namespace, namespaceName.Name)
}

type SpireSigner struct {
	cfg          *SpireConfig
	RawCertChain [][]byte
	Privatekey   crypto.PrivateKey
}

type SpireConfig struct {
	SpireAgentSocket   string `json:"spire_agent_socket"` // spire agent's unix domain socket path
	SpireServerAddress string `json:"spire_address"`      // spire server listen address, looks like: “address:port”
}

// CA certificate and any intermediates required to form a chain of trust
// back to the X.509 authorities (DER encoded). The CA certificate is the
// first.
func (s *SpireSigner) buildDownstreamX509CAFromSpire(ctx context.Context) error {
	// 1. Build up x509 source
	socketPath := s.cfg.SpireAgentSocket
	if len(socketPath) == 0 {
		//socketPath = defaultSocketPath
		return errors.New("config socketPath invalid")
	}

	x509Source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		return fmt.Errorf("unable to create X509Source: %s", err)
	}

	defer x509Source.Close()

	// 2. Build up connection to spire server
	conn, err := grpc.DialContext(ctx, s.cfg.SpireServerAddress, grpc.WithTransportCredentials(
		grpccredentials.MTLSClientCredentials(x509Source, x509Source, tlsconfig.AuthorizeAny()),
	))
	if err != nil {
		return fmt.Errorf("failed to dial: %s", err)
	}
	defer conn.Close()

	svidClient := svidv1.NewSVIDClient(conn)
	csr, privatekey, err := s.generateKeyAndCSR()
	if err != nil {
		return err
	}

	request := &svidv1.NewDownstreamX509CARequest{
		Csr: csr,
	}

	resp, err := svidClient.NewDownstreamX509CA(ctx, request)
	if err != nil {
		return status.Error(codes.Internal, fmt.Sprintf("failed to New Downstream X509 CA: %s", err))
	}

	s.RawCertChain = resp.CaCertChain
	s.Privatekey = privatekey

	return nil
}

func (s *SpireSigner) generateKeyAndCSR() (csr []byte, key crypto.PrivateKey, err error) {
	keyRequest := cfcsr.NewKeyRequest()
	priv, err := keyRequest.Generate()
	if err != nil {
		return nil, nil, status.Error(codes.Internal, fmt.Sprintf("failed to generate private key: %s", err))
	}

	req := &cfcsr.CertificateRequest{
		CN: "trustauth.net",
		Names: []cfcsr.Name{
			{
				C: "CN",
				O: "TrustAuth",
			},
		},
	}

	csrPEM, err := cfcsr.Generate(priv.(crypto.Signer), req)
	if err != nil {
		return nil, nil, status.Error(codes.Internal, fmt.Sprintf("failed to generate csr: %s", err))
	}

	csr, err = encoding.PEM2ASN1(csrPEM, encoding.PEMTypeCertSignRequest)
	if err != nil {
		return nil, nil, fmt.Errorf("fail to transfer pem to der, err:%s", err)
	}

	return csr, priv, nil
}

func (s *SpireSigner) Close() {
}

func (s *SpireSigner) Check() error {
	cert, err := parseCert(s.RawCertChain[0])
	if err != nil {
		return err
	}

	if cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) / 2).Before(time.Now()) {
		return constants.ErrorCertTTLShorterThanHalf
	}

	return nil
}

func (s *SpireSigner) Update(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	return s.buildDownstreamX509CAFromSpire(ctx)
}

func (s *SpireSigner) Sign(csrBytes []byte, req cmapi.CertificateRequestSpec) ([]byte, error) {
	csr, err := parseCSR(csrBytes)
	if err != nil {
		return nil, err
	}

	cert, err := parseCert(s.RawCertChain[0])
	if err != nil {
		return nil, err
	}

	ca := &CertificateAuthority{
		Certificate: cert,
		PrivateKey:  s.Privatekey.(crypto.Signer),
		Backdate:    5 * time.Minute,
	}

	crtDER, err := ca.Sign(csr.Raw, PermissiveSigningPolicy{
		TTL:    req.Duration.Duration,
		Usages: req.Usages,
	})
	if err != nil {
		return nil, err
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: crtDER,
	}), nil
}

func (s *SpireSigner) GetCertificateChain() ([][]byte, error) {
	if s != nil && s.RawCertChain != nil {
		return s.RawCertChain, nil
	}

	return nil, constants.ErrorNotFound
}
