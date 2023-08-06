package authority

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cfcsr "github.com/cloudflare/cfssl/csr"
	"github.com/kongweiguo/cryptoutils/encoding"
	"github.com/kongweiguo/jubilant-controller/internal/constants"
	"github.com/kongweiguo/jubilant-controller/internal/utils"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
)

// type Cache struct {
// 	client    map[string]*SpireClient
// 	authority map[string]*Authority
// 	mutex     sync.Mutex
// }

// var c Cache

// func Put(nsName types.NamespacedName, client *SpireClient) {
// 	c.mutex.Lock()
// 	defer c.mutex.Unlock()

// 	c.client[nsName.String()] = client
// }

// func Get(nsName types.NamespacedName) (*SpireClient, bool) {
// 	c.mutex.Lock()
// 	defer c.mutex.Unlock()

// 	client, ok := c.client[nsName.String()]

// 	return client, ok
// }

type SpireClient struct {
	x509Source *workloadapi.X509Source
	conn       *grpc.ClientConn
	svidClient svidv1.SVIDClient
}

type SpireConfig struct {
	TrustDomain  string `json:"trustDomain" yaml:"trustDomain"`
	AgentSocket  string `json:"agentSocket" yaml:"agentSocket"`   // spire agent's unix domain socket path
	SpireAddress string `json:"spireAddress" yaml:"spireAddress"` // spire server listen address, looks like: “address:port”
}

func NewSpireClient(ctx context.Context, cfg *SpireConfig) (*SpireClient, error) {

	socketPath := cfg.AgentSocket
	if len(socketPath) == 0 {
		return nil, fmt.Errorf("config socketPath invalid")
	}

	x509Source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		return nil, fmt.Errorf("unable to create X509Source: %s", err)
	}

	// 2. Build up connection to spire server
	conn, err := grpc.DialContext(ctx, cfg.SpireAddress, grpc.WithTransportCredentials(
		grpccredentials.MTLSClientCredentials(x509Source, x509Source, tlsconfig.AuthorizeAny()),
	))
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %s", err)
	}

	client := &SpireClient{
		x509Source: x509Source,
		conn:       conn,
		svidClient: svidv1.NewSVIDClient(conn),
	}

	return client, nil
}

func (s *SpireClient) Close() {
	if s != nil {
		if s.x509Source != nil {
			s.x509Source.Close()
		}

		if s.conn != nil {
			s.conn.Close()
		}
	}
}

func (s *SpireClient) NewDownstreamAuthority(ctx context.Context) (*Authority, error) {
	csr, privatekey, err := s.generateKeyAndCSR()
	if err != nil {
		return nil, err
	}

	request := &svidv1.NewDownstreamX509CARequest{
		Csr: csr,
	}

	resp, err := s.svidClient.NewDownstreamX509CA(ctx, request)
	if err != nil {
		return nil, err
	}

	if len(resp.CaCertChain) == 0 {
		return nil, fmt.Errorf("spire return emtpy ca certchain")
	}

	CertPEM := utils.X509DERToPEM(resp.CaCertChain[0])

	CertChainPEM := utils.X509DERsToPEMs(resp.X509Authorities)

	BundlePEM := utils.X509DERsToPEMs(resp.X509Authorities)

	ca := &Authority{
		PrivateKey:    privatekey,
		Certificate:   &x509.Certificate{},
		CertChain:     []*x509.Certificate{},
		Bundle:        []*x509.Certificate{},
		PrivateKeyPEM: []byte{},
		CertPEM:       CertPEM,
		CertChainPEM:  CertChainPEM,
		BundlePEM:     BundlePEM,
	}

	return &privatekey, nil
}

func (s *SpireClient) generateKeyAndCSR() (csr []byte, privateKey crypto.Signer, err error) {
	keyRequest := cfcsr.NewKeyRequest()

	priv, err = keyRequest.Generate()
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

func (s *SpireClient) Check() error {
	cert, err := parseCert(s.RawCertChain[0])
	if err != nil {
		return err
	}

	if cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) / 2).Before(time.Now()) {
		return constants.ErrorCertTTLShorterThanHalf
	}

	return nil
}

func (s *SpireClient) Update(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	return s.buildSpireDownstreamX509CA(ctx)
}

func (s *SpireClient) Sign(csrBytes []byte, req cmapi.CertificateRequestSpec) ([]byte, error) {
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

func (s *SpireClient) GetCertificateChain() ([][]byte, error) {
	if s != nil && s.RawCertChain != nil {
		return s.RawCertChain, nil
	}

	return nil, constants.ErrorNotFound
}
