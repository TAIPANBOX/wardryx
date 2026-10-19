package config

import "testing"

// The agent-token settings are read here, once, like every other WARDRYX_*
// variable (invariant 23 holds the README table to these names).
func TestAgentTokenSettingsAreReadFromTheEnvironment(t *testing.T) {
	t.Setenv("WARDRYX_AGENT_TOKEN_ISSUER", "https://vouchryx.example")
	t.Setenv("WARDRYX_AGENT_TOKEN_JWKS_URL", "https://vouchryx.example/.well-known/jwks.json")
	t.Setenv("WARDRYX_AGENT_TOKEN_JWKS_FILE", "/etc/wardryx/agent-jwks.json")
	t.Setenv("WARDRYX_AGENT_TOKEN_AUDIENCES", "https://wardryx.example,https://wardryx-b.example")
	t.Setenv("WARDRYX_AGENT_TOKEN_REVOCATION_URL", "https://vouchryx.example/v1/revocations")
	cfg := FromEnv()
	if cfg.AgentTokenIssuer != "https://vouchryx.example" {
		t.Errorf("AgentTokenIssuer = %q", cfg.AgentTokenIssuer)
	}
	if cfg.AgentTokenJWKSURL != "https://vouchryx.example/.well-known/jwks.json" {
		t.Errorf("AgentTokenJWKSURL = %q", cfg.AgentTokenJWKSURL)
	}
	if cfg.AgentTokenJWKSFile != "/etc/wardryx/agent-jwks.json" {
		t.Errorf("AgentTokenJWKSFile = %q", cfg.AgentTokenJWKSFile)
	}
	if cfg.AgentTokenAudiences != "https://wardryx.example,https://wardryx-b.example" {
		t.Errorf("AgentTokenAudiences = %q", cfg.AgentTokenAudiences)
	}
	if cfg.AgentTokenRevocationURL != "https://vouchryx.example/v1/revocations" {
		t.Errorf("AgentTokenRevocationURL = %q", cfg.AgentTokenRevocationURL)
	}
}
