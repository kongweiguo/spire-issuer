/*
Copyright 2020 The cert-manager Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"encoding/pem"
	"fmt"
	"reflect"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/kongweiguo/jubilant-controller/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func GetSpecAndStatus(issuer client.Object) (*v1alpha1.IssuerSpec, *v1alpha1.IssuerStatus, error) {
	switch t := issuer.(type) {
	case *v1alpha1.Issuer:
		return &t.Spec, &t.Status, nil
	case *v1alpha1.ClusterIssuer:
		return &t.Spec, &t.Status, nil
	default:
		return nil, nil, fmt.Errorf("not an issuer type: %t", t)
	}
}

func SetReadyCondition(status *v1alpha1.IssuerStatus, conditionStatus v1alpha1.ConditionStatus, reason, message string) {
	ready := GetReadyCondition(status)
	if ready == nil {
		ready = &v1alpha1.IssuerCondition{
			Type: v1alpha1.IssuerConditionReady,
		}
		status.Conditions = append(status.Conditions, *ready)
	}
	if ready.Status != conditionStatus {
		ready.Status = conditionStatus
		now := metav1.Now()
		ready.LastTransitionTime = &now
	}
	ready.Reason = reason
	ready.Message = message

	for i, c := range status.Conditions {
		if c.Type == v1alpha1.IssuerConditionReady {
			status.Conditions[i] = *ready
			return
		}
	}
}

func GetReadyCondition(status *v1alpha1.IssuerStatus) *v1alpha1.IssuerCondition {
	for _, c := range status.Conditions {
		if c.Type == v1alpha1.IssuerConditionReady {
			return &c
		}
	}
	return nil
}

func IsReady(status *v1alpha1.IssuerStatus) bool {
	if c := GetReadyCondition(status); c != nil {
		return c.Status == v1alpha1.ConditionTrue
	}
	return false
}

func X509DERToPEM(der []byte) []byte {
	x509PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	})

	return x509PEM
}

// DeepEqual ...
func DeepEqual(x, y interface{}, isEquateEmpty bool) bool {
	if isEquateEmpty {
		opts := []cmp.Option{cmpopts.EquateEmpty(), cmpopts.IgnoreUnexported()}
		return cmp.Equal(x, y, opts...)
	}

	return reflect.DeepEqual(x, y)
}
