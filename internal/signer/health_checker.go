package signer

import "github.com/kongweiguo/jubilant-controller/api/v1alpha1"

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(issuerSpec *v1alpha1.IssuerSpec, data map[string][]byte) (HealthChecker, error)

func BuildHealthChecker(issuerSpec *v1alpha1.IssuerSpec, data map[string][]byte) (HealthChecker, error) {

}

type healthchecker struct {
}


