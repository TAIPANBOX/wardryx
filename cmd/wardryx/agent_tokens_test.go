package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
	"github.com/TAIPANBOX/wardryx/internal/config"
)

// writeKeyFile writes a valid key set, so a test that fails on a setting fails
// on that setting and not on an unreadable file.
func writeKeyFile(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(delegation.Set{Keys: []delegation.JWK{delegation.FromPublic(&key.PublicKey, "k1")}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A verifier that is half configured would verify less than the operator asked
// for, or nothing, so the process refuses to start rather than run with a setting
// missing.
func TestAPartialAgentTokenConfigurationRefusesToStart(t *testing.T) {
	partial := config.Config{
		AgentTokenAudiences: "https://wardryx.example",
		AgentTokenJWKSFile:  filepath.Join(t.TempDir(), "jwks.json"),
	}
	if v, _, _, err := buildAgentTokens(partial, nil); err == nil || v != nil {
		t.Fatalf("audiences and a key file without an issuer: err %v, verifier %v; want a refusal naming WARDRYX_AGENT_TOKEN_ISSUER", err, v)
	}
	// Nothing configured is not a partial configuration: no verifier, no error.
	if v, _, _, err := buildAgentTokens(config.Config{}, nil); err != nil || v != nil {
		t.Fatalf("nothing configured: err %v, verifier %v; want neither", err, v)
	}
}

// With an issuer, the door origins are required: a proof is checked against them.
func TestAnIssuerWithoutDoorOriginsRefusesToStart(t *testing.T) {
	cfg := config.Config{
		AgentTokenIssuer:    "https://vouchryx.example",
		AgentTokenAudiences: "https://wardryx.example",
		AgentTokenJWKSFile:  writeKeyFile(t),
	}
	if _, _, _, err := buildAgentTokens(cfg, nil); err == nil || !strings.Contains(err.Error(), "WARDRYX_AGENT_TOKEN_DOOR_ORIGINS") {
		t.Fatalf("an issuer with no door origins: err %v, want a refusal naming WARDRYX_AGENT_TOKEN_DOOR_ORIGINS", err)
	}
}

// Turning the proof requirement off is allowed, and says so at startup.
func TestTurningOffTheProofRequirementWarnsAtStartup(t *testing.T) {
	cfg := config.Config{
		AgentTokenIssuer:       "https://vouchryx.example",
		AgentTokenAudiences:    "https://wardryx.example",
		AgentTokenJWKSFile:     writeKeyFile(t),
		AgentTokenDoorOrigins:  "https://pep.example",
		AgentTokenRequireProof: "0",
	}
	v, _, warnings, err := buildAgentTokens(cfg, nil)
	if err != nil || v == nil {
		t.Fatalf("a configuration with the proof requirement off: err %v, verifier %v; want a verifier", err, v)
	}
	if len(warnings) == 0 || !strings.Contains(strings.Join(warnings, " "), "REQUIRE_PROOF") {
		t.Fatalf("warnings %q, want one naming WARDRYX_AGENT_TOKEN_REQUIRE_PROOF", warnings)
	}
}

// The proof window is a number of seconds from 1 to 300; anything else refuses
// the start, rather than silently taking the default.
func TestAProofWindowOutsideOneToThreeHundredSecondsRefusesToStart(t *testing.T) {
	for _, raw := range []string{"0", "-5", "301", "soon"} {
		cfg := config.Config{
			AgentTokenIssuer:             "https://vouchryx.example",
			AgentTokenAudiences:          "https://wardryx.example",
			AgentTokenJWKSFile:           writeKeyFile(t),
			AgentTokenDoorOrigins:        "https://pep.example",
			AgentTokenProofMaxAgeSeconds: raw,
		}
		if _, _, _, err := buildAgentTokens(cfg, nil); err == nil {
			t.Errorf("WARDRYX_AGENT_TOKEN_PROOF_MAX_AGE_SECONDS=%q was accepted, want a refusal", raw)
		}
	}
}

// With no database the record of accepted proofs lives in this process, and the
// start says what that costs. With a database, or with no tokens to verify,
// there is nothing to say.
func TestThePerProcessProofRecordIsWarnedAtStartup(t *testing.T) {
	warn := proofRecordWarning("https://vouchryx.example", "")
	for _, want := range []string{"WARDRYX_DB", "restart", "instance"} {
		if !strings.Contains(warn, want) {
			t.Fatalf("the warning %q does not name %q", warn, want)
		}
	}
	if got := proofRecordWarning("https://vouchryx.example", "postgres://db/wardryx"); got != "" {
		t.Fatalf("a warning with a database configured: %q", got)
	}
	if got := proofRecordWarning("", ""); got != "" {
		t.Fatalf("a warning with no token verification configured: %q", got)
	}
}

// proofRecordStub counts purges; a purge is how a record given to
// buildAgentTokens shows it reached the verifier.
type proofRecordStub struct{ purged chan struct{} }

func (proofRecordStub) TryRecordProof(context.Context, string, time.Time) (bool, error) {
	return true, nil
}

func (s proofRecordStub) PurgeProofs(context.Context, time.Duration) (int64, error) {
	select {
	case s.purged <- struct{}{}:
	default:
	}
	return 0, nil
}

// What serve hands buildAgentTokens is what the verifier uses, and the run
// function it returns keeps the table purged.
func TestTheRecordGivenToBuildAgentTokensReachesTheVerifierAndIsPurged(t *testing.T) {
	cfg := config.Config{
		AgentTokenIssuer:      "https://vouchryx.example",
		AgentTokenAudiences:   "https://wardryx.example",
		AgentTokenJWKSFile:    writeKeyFile(t),
		AgentTokenDoorOrigins: "https://pep.example",
	}
	record := proofRecordStub{purged: make(chan struct{}, 1)}
	_, run, _, err := buildAgentTokens(cfg, record)
	if err != nil {
		t.Fatalf("buildAgentTokens: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go run(ctx, nil)
	select {
	case <-record.purged:
	case <-time.After(5 * time.Second):
		t.Fatal("the record was never purged: it did not reach the verifier, or the purge loop was not started")
	}
}
