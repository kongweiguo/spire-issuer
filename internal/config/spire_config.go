package config

import "github.com/kongweiguo/jubilant-controller/api/v1alpha1"

type SpireConfig struct {
	IssuerMode      v1alpha1.IssuerMode `json:"issuer_mode"`
	AgentSocketPath string              `json:"agent_socket_path"` // uds
	SpireAddress    string              `json:"spire_address"`     // “address:port”
}
