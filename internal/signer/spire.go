package signer

import (
	"context"
	"crypto"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/kongweiguo/jubilant-controller/api/v1alpha1"
	"k8s.io/apimachinery/pkg/types"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cfcsr "github.com/cloudflare/cfssl/csr"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"

	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	svidv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/svid/v1"
)

type SpireSigner struct {
	x509Source *workloadapi.X509Source
	svidClient svidv1.SVIDClient

	RawCertChain [][]byte
	Privatekey   crypto.PrivateKey
}

func newSpireSigner(ctx context.Context, issuer *v1alpha1.ClusterIssuer) (Signer, error) {
	if issuer == nil {
		return nil, status.Error(codes.InvalidArgument, "config invalid")
	}

	signer := &SpireSigner{
		NamespacedName: types.NamespacedName{Namespace: issuer.Namespace, Name: issuer.Name},
	}

	// 1. Build up x509 source
	socketPath := issuer.Spec.AgentSocketPath
	if len(socketPath) == 0 {
		//socketPath = defaultSocketPath
		return nil, status.Error(codes.InvalidArgument, "config socketPath invalid")
	}

	x509Source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("unable to create X509Source: %s", err))
	}
	signer.x509Source = x509Source

	// 2. Build up connection to spire server

	conn, err := grpc.DialContext(ctx, issuer.Spec.SpireAddress, grpc.WithTransportCredentials(
		grpccredentials.MTLSClientCredentials(x509Source, x509Source, tlsconfig.AuthorizeAny()),
	))
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to dial: %s", err))
	}

	svidClient := svidv1.NewSVIDClient(conn)
	signer.svidClient = svidClient

	caCertChain, privateKey, err := signer.newDownstreamX509CA(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	signer.caCertChain = caCertChain
	signer.privatekey = privateKey

	return signer, nil
}

// CA certificate and any intermediates required to form a chain of trust
// back to the X.509 authorities (DER encoded). The CA certificate is the
// first.
func (s *SpireSigner) newDownstreamX509CA(ctx context.Context) (CaCertChain [][]byte, privatekey crypto.PrivateKey, err error) {

	csr, privatekey, err := s.generateKeyAndCSR()
	if err != nil {
		return nil, nil, status.Error(codes.Internal, err.Error())
	}

	request := &svidv1.NewDownstreamX509CARequest{
		Csr: csr,
	}

	resp, err := s.svidClient.NewDownstreamX509CA(ctx, request)
	if err != nil {
		return nil, nil, status.Error(codes.Internal, fmt.Sprintf("failed to New Downstream X509 CA: %s", err))
	}

	return resp.CaCertChain, privatekey, nil
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

	csr, err = cfcsr.Generate(priv.(crypto.Signer), req)
	if err != nil {
		return nil, nil, status.Error(codes.Internal, fmt.Sprintf("failed to generate csr: %s", err))
	}

	return csr, priv, nil
}

func (s *SpireSigner) Close() {
	if s != nil && s.x509Source != nil {
		s.x509Source.Close()
	}
}

func (s *SpireSigner) Check() error {
	return nil
}

func (s *SpireSigner) Sign(csrBytes []byte, req cmapi.CertificateRequestSpec) ([]byte, error) {
	csr, err := parseCSR(csrBytes)
	if err != nil {
		return nil, err
	}

	cert, err := parseCert(s.caCertChain[0])
	if err != nil {
		return nil, err
	}

	ca := &CertificateAuthority{
		Certificate: cert,
		PrivateKey:  s.privatekey.(crypto.Signer),
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
