/*
Copyright 2023 will@trustauth.net.

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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:printcolumn:name="Phase",type="string",JSONPath=".status.phase"
//+kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"
//+kubebuilder:printcolumn:name="NotAfter",type="date",JSONPath=".metadata.notBefore"
//+kubebuilder:printcolumn:name="NotAfter",type="date",JSONPath=".metadata.notAfter"
//+kubebuilder:printcolumn:name="CertChain",type="string",JSONPath=".metadata.certChain"

// Issuer is the Schema for the issuers API
type Issuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec   `json:"spec,omitempty"`
	Status IssuerStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// IssuerList contains a list of Issuer
type IssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Issuer `json:"items"`
}

// IssuerSpec defines the desired state of Issuer
type IssuerSpec struct {
	// INSERT ADDITIONAL SPEC FIELDS - desired state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	TrustDomain   string `json:"trustDomain"`  // trustdomain of the issuer,should be same with spire agent and spire server configuration
	AgentSocket   string `json:"agentSocket"`  // spire agent's unix domain socket path
	ServerAddress string `json:"spireAddress"` // spire server listen address, looks like: “address:port”
	//WorkMode      WorkMode `json:"workMode,omitempty"` // issuer work mode, could be one ["downstream"|"mint"]
}

type WorkMode string

const (
	Downstream WorkMode = "downstream" //
	Mint       WorkMode = "mint"
)

// IssuerStatus defines the observed state of Issuer
type IssuerStatus struct {
	// INSERT ADDITIONAL STATUS FIELD - define observed state of cluster
	// Important: Run "make" to regenerate code after modifying this file

	Phase      Phase              `json:"phase,omitempty"`
	NotBefore  *metav1.Time       `json:"notBefore,omitempty"`
	NotAfter   *metav1.Time       `json:"notAfter,omitempty"`
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	CertChain  string             `json:"certChain,omitempty"`
}

type Phase string

const (
	Processing  Phase = "Processing"
	Running     Phase = "Running"
	Terminating Phase = "Terminating"
)

func init() {
	SchemeBuilder.Register(&Issuer{}, &IssuerList{})
}
