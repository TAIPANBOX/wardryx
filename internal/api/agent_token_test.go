package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/wardryx/internal/agenttoken"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/store"
)

// The enforcement point sends the agent's own access token in the decide body.
// These tests hold wardryx to what invariant 13 says it verifies, and to the
// refusals that follow from it. Tokens are minted per run; no key is written
// down.

const (
	tokIssuer   = "https://vouchryx.example"
	tokAudience = "https://wardryx.example"
	tokKid      = "k-agent-api"
	tokSubject  = "agent://acme.example/support/bot1"
	tokOther    = "agent://acme.example/support/bot2"
	tokDoor     = "https://pep.example"
	tokHTU      = "https://pep.example/v1/tools/call"
)

// tokenKeySet is one signing key and the key set file that publishes it, and
// the holder key an agent's token is bound to and its proofs are signed with.
type tokenKeySet struct {
	key    *ecdsa.PrivateKey
	file   string
	holder *ecdsa.PrivateKey
}

func newTokenKeySet(t *testing.T) tokenKeySet {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(delegation.Set{Keys: []delegation.JWK{delegation.FromPublic(&key.PublicKey, tokKid)}})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return tokenKeySet{key: key, file: file, holder: holder}
}

// mintAgentToken signs a compact at+jwt for sub, valid now, with the overrides
// applied (a nil value removes the claim).
func mintAgentToken(t *testing.T, k tokenKeySet, sub string, over map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding
	now := time.Now().Unix()
	claims := map[string]any{
		"iss": tokIssuer, "sub": sub, "client_id": sub, "aud": tokAudience,
		"iat": now, "exp": now + 300, "jti": "jti-" + sub, "cnf": map[string]any{"jkt": holderThumbprint(t, k)},
	}
	for name, v := range over {
		if v == nil {
			delete(claims, name)
		} else {
			claims[name] = v
		}
	}
	hdr, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": tokKid})
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := enc.EncodeToString(hdr) + "." + enc.EncodeToString(body)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + enc.EncodeToString(sig)
}

// requireAgentToken is a policy that allows only a request whose identity
// source is agent-token.
func requireAgentToken() []policy.Policy {
	return []policy.Policy{{
		Name:                  "needs-a-verified-agent",
		Target:                "agent://acme.example/*",
		RequireIdentitySource: []string{policy.IdentitySourceAgentToken},
	}}
}

// agentTokenServer builds the server the way serve does. With configured, the
// verifier is wired from the key set file; without, the token is ignored.
func agentTokenServer(t *testing.T, pols []policy.Policy, k tokenKeySet, configured bool, eventsPath string) *Server {
	t.Helper()
	set, err := policy.Compile(pols)
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	keys := map[string]Principal{keyDigest(adminKey): {Org: "acme", Role: RoleAdmin, Agents: "agent://*"}}
	var ew *event.ChainedWriter
	if eventsPath != "" {
		if ew, err = event.NewChainedWriter(eventsPath); err != nil {
			t.Fatalf("NewChainedWriter: %v", err)
		}
	}
	srv := New(pdp.New(set, []byte(testHMAC)), store.NewMemory(), ew, nil,
		keys, []byte(testHMAC), false, set.Policies())
	if configured {
		v, err := agenttoken.New(agenttoken.Config{
			Issuer:      tokIssuer,
			Audiences:   []string{tokAudience},
			JWKSFile:    k.file,
			DoorOrigins: []string{tokDoor},
		}, nil)
		if err != nil {
			t.Fatalf("agenttoken.New: %v", err)
		}
		if err := v.Load(t.Context()); err != nil {
			t.Fatalf("agenttoken Load: %v", err)
		}
		srv.WithAgentTokens(v)
	}
	return srv
}

func TestAVerifiedAgentTokenSetsTheIdentitySource(t *testing.T) {
	k := newTokenKeySet(t)
	srv := agentTokenServer(t, requireAgentToken(), k, true, "")
	tok := mintAgentToken(t, k, tokSubject, nil)
	dto := decideRequestDTO{AgentID: tokSubject, RunID: "r1", AgentToken: tok,
		AgentDPoPProof: mintDPoPProof(t, k, tok, tokHTU, time.Now().Unix(), "p-verified")}
	if got := decisionFor(t, srv, dto); got.Decision != "allow" {
		t.Fatalf("a verified agent token did not set the source the policy requires: decision %q, reason %q",
			got.Decision, got.Reason)
	}
}

func TestATokenNamingAnotherAgentIsRefusedAndPutOnTheBus(t *testing.T) {
	k := newTokenKeySet(t)
	events := filepath.Join(t.TempDir(), "events.ndjson")
	srv := agentTokenServer(t, nil, k, true, events)
	// The token is for bot1; the request names bot2, which the key may speak for.
	dto := decideRequestDTO{AgentID: tokOther, RunID: "r1", AgentToken: mintAgentToken(t, k, tokSubject, nil)}
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, dto)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "agent_contradicts_token") {
		t.Fatalf("a token for another agent: status %d, body %s, want 403 agent_contradicts_token", rec.Code, rec.Body)
	}
	var sawMismatch, sawDecision bool
	for _, e := range readEventsFile(t, events) {
		switch e.Type {
		case "identity_mismatch":
			sawMismatch = true
		case "policy_allow", "policy_deny", "approval_requested":
			sawDecision = true
		}
	}
	if !sawMismatch {
		t.Fatal("the refused request wrote no identity_mismatch event")
	}
	if sawDecision {
		t.Fatal("a refused request was decided as well")
	}
}

func TestAnExpiredAgentTokenIsRefusedWith403(t *testing.T) {
	k := newTokenKeySet(t)
	srv := agentTokenServer(t, nil, k, true, "")
	expired := mintAgentToken(t, k, tokSubject, map[string]any{"exp": time.Now().Add(-time.Hour).Unix()})
	dto := decideRequestDTO{AgentID: tokSubject, RunID: "r1", AgentToken: expired}
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, dto)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "agent_token_invalid") {
		t.Fatalf("an expired token: status %d, body %s, want 403 agent_token_invalid", rec.Code, rec.Body)
	}
}

func TestAClaimOfAgentTokenWithNoTokenIsRefused(t *testing.T) {
	k := newTokenKeySet(t)
	srv := agentTokenServer(t, nil, k, true, "")
	claim := decideRequestDTO{AgentID: tokSubject, RunID: "r1", IdentitySource: policy.IdentitySourceAgentToken}
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, claim)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "agent_token_required") {
		t.Fatalf("a claim of agent-token with no token: status %d, body %s, want 403 agent_token_required", rec.Code, rec.Body)
	}
	// A client-key claim with no token is not what this refusal is about.
	honest := decideRequestDTO{AgentID: tokSubject, RunID: "r2", IdentitySource: policy.IdentitySourceClientKey}
	if got := decisionFor(t, srv, honest); got.Decision != "allow" {
		t.Fatalf("a client-key request with no token: decision %q, want allow", got.Decision)
	}
}

func TestWithoutVerificationTheTokenIsIgnoredAndTheRequestDecidesAsBefore(t *testing.T) {
	k := newTokenKeySet(t)
	srv := agentTokenServer(t, requireAgentToken(), k, false, "")
	// The token is ignored: a client-key claim does not meet the requirement.
	ignored := decideRequestDTO{
		AgentID: tokSubject, RunID: "r1", IdentitySource: policy.IdentitySourceClientKey,
		AgentToken: mintAgentToken(t, k, tokSubject, nil),
	}
	if got := decisionFor(t, srv, ignored); got.Decision != "deny" {
		t.Fatalf("with no verifier configured, the token must be ignored: decision %q, want deny", got.Decision)
	}
	// And the claim is trusted as before, with a junk token that is never read.
	claimed := decideRequestDTO{
		AgentID: tokSubject, RunID: "r2", IdentitySource: policy.IdentitySourceAgentToken,
		AgentToken: "not-a-token",
	}
	if got := decisionFor(t, srv, claimed); got.Decision != "allow" {
		t.Fatalf("with no verifier configured, the claim decides as before: decision %q, want allow", got.Decision)
	}
}

func TestTheDecideBodyIgnoresAnUnknownFieldAsBefore(t *testing.T) {
	k := newTokenKeySet(t)
	srv := agentTokenServer(t, nil, k, false, "")
	body := map[string]any{"agent_id": tokSubject, "run_id": "r1", "a_field_not_declared": "x"}
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("a decide body with an unknown field: status %d, body %s, want 200 as before", rec.Code, rec.Body)
	}
}

// holderThumbprint is the RFC 7638 thumbprint of the holder key, the value a
// token's cnf.jkt carries.
func holderThumbprint(t *testing.T, k tokenKeySet) string {
	t.Helper()
	tp, err := delegation.Thumbprint(delegation.FromPublic(&k.holder.PublicKey, ""))
	if err != nil {
		t.Fatal(err)
	}
	return tp
}

// mintDPoPProof signs a proof with the holder key, for token, sent to htu at iat.
func mintDPoPProof(t *testing.T, k tokenKeySet, token, htu string, iat int64, jti string) string {
	t.Helper()
	enc := base64.RawURLEncoding
	raw, err := json.Marshal(delegation.FromPublic(&k.holder.PublicKey, ""))
	if err != nil {
		t.Fatal(err)
	}
	var jwk map[string]any
	if err := json.Unmarshal(raw, &jwk); err != nil {
		t.Fatal(err)
	}
	hdr, _ := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk})
	body, _ := json.Marshal(map[string]any{
		"htm": "POST", "htu": htu, "iat": iat, "jti": jti,
		"ath": delegation.AccessTokenHash(token),
	})
	input := enc.EncodeToString(hdr) + "." + enc.EncodeToString(body)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k.holder, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + enc.EncodeToString(sig)
}

// With proofs required, a token alone is refused. The proof is what makes the
// token the holder's, and without it the token is usable by anyone who has it.
func TestAnAgentTokenWithNoProofIsRefusedWith403(t *testing.T) {
	k := newTokenKeySet(t)
	srv := agentTokenServer(t, nil, k, true, "")
	dto := decideRequestDTO{AgentID: tokSubject, RunID: "r1", AgentToken: mintAgentToken(t, k, tokSubject, nil)}
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, dto)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "agent_token_proof_required") {
		t.Fatalf("a token with no proof: status %d, body %s, want 403 agent_token_proof_required", rec.Code, rec.Body)
	}
}

// A proof made for another token does not verify this one (the ath differs).
func TestAProofThatDoesNotVerifyIsRefusedWith403(t *testing.T) {
	k := newTokenKeySet(t)
	srv := agentTokenServer(t, nil, k, true, "")
	tok := mintAgentToken(t, k, tokSubject, nil)
	other := mintAgentToken(t, k, tokSubject, map[string]any{"jti": "another"})
	dto := decideRequestDTO{AgentID: tokSubject, RunID: "r1", AgentToken: tok,
		AgentDPoPProof: mintDPoPProof(t, k, other, tokHTU, time.Now().Unix(), "p-other")}
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, dto)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "agent_token_proof_invalid") {
		t.Fatalf("a proof for another token: status %d, body %s, want 403 agent_token_proof_invalid", rec.Code, rec.Body)
	}
}

// A proof sent to a door wardryx was not configured to accept is refused.
func TestAProofToAForeignDoorIsRefusedWith403(t *testing.T) {
	k := newTokenKeySet(t)
	srv := agentTokenServer(t, nil, k, true, "")
	tok := mintAgentToken(t, k, tokSubject, nil)
	dto := decideRequestDTO{AgentID: tokSubject, RunID: "r1", AgentToken: tok,
		AgentDPoPProof: mintDPoPProof(t, k, tok, "https://elsewhere.example/v1/tools/call", time.Now().Unix(), "p-foreign")}
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, dto)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "agent_token_proof_invalid") {
		t.Fatalf("a proof to a foreign door: status %d, body %s, want 403 agent_token_proof_invalid", rec.Code, rec.Body)
	}
}
