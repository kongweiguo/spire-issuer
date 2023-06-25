package signer

import (
	"context"
	"fmt"

	"github.com/kongweiguo/jubilant-controller/api/v1alpha1"
	"k8s.io/apimachinery/pkg/types"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

type Signer interface {
	Sign(csrBytes []byte, req cmapi.CertificateRequestSpec) ([]byte, error)
	Close()
}

type SignerBuilder func(issuerSpec *v1alpha1.IssuerSpec, data map[string][]byte) (Signer, error)

func NewSigner(ctx context.Context, issuer *v1alpha1.ClusterIssuer) error {
	namespacedName := types.NamespacedName{Namespace: issuer.Namespace, Name: issuer.Name}
	key := GetSignerKey(namespacedName)

	s := GetSigner(namespacedName)
	if s != nil {
		s.Close()
	}

	s, err := newSpireSigner(ctx, issuer)
	if err != nil {
		return err
	}

	gSigners[key] = s
	return nil
}

func CloseAll() {
	for _, s := range gSigners {
		if s != nil {
			s.Close()
		}
	}
}

func GetSigner(namespaceName types.NamespacedName) Signer {
	// for _, s := range gSigners {
	// 	if reflect.DeepEqual(s.NamespacedName, namespaceName) {
	// 		return s
	// 	}
	// }

	key := GetSignerKey(namespaceName)
	s, ok := gSigners[key]
	if !ok {
		return nil
	}

	return s
}

func GetSignerKey(namespaceName types.NamespacedName) string {
	return fmt.Sprintf("%s-%s", namespaceName.Namespace, namespaceName.Name)
}

func Sign(namespacedName types.NamespacedName, csrBytes []byte, req cmapi.CertificateRequestSpec) ([]byte, error) {
	index := GetSignerKey(namespacedName)

	signer, ok := gSigners[index]
	if !ok || signer == nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Not found issuer namespace:%s, name:%s", namespacedName.Namespace, namespacedName.Name))
	}

	return signer.Sign(csrBytes, req)
}
