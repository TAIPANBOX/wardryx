package main

import (
	"path/filepath"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/config"
)

// A verifier that is half configured would verify nothing, or everything, so
// the process refuses to start rather than run with a setting missing.
func TestAPartialAgentTokenConfigurationRefusesToStart(t *testing.T) {
	partial := config.Config{
		AgentTokenAudiences: "https://wardryx.example",
		AgentTokenJWKSFile:  filepath.Join(t.TempDir(), "jwks.json"),
	}
	if v, _, err := buildAgentTokens(partial); err == nil || v != nil {
		t.Fatalf("audiences and a key file without an issuer: err %v, verifier %v; want a refusal naming WARDRYX_AGENT_TOKEN_ISSUER", err, v)
	}
	// Nothing configured is not a partial configuration: no verifier, no error.
	if v, _, err := buildAgentTokens(config.Config{}); err != nil || v != nil {
		t.Fatalf("nothing configured: err %v, verifier %v; want neither", err, v)
	}
}
