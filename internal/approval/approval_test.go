package approval

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/store"
)

func TestMintAndVerifyRoundTrip(t *testing.T) {
	secret := []byte("test-secret")
	tools := []string{"send_wire_transfer", "delete_account"}
	token, exp, err := MintApprovalToken(secret, "agent://x/bot", "run-1", tools, 1000, DefaultTTL)
	if err != nil {
		t.Fatalf("MintApprovalToken: %v", err)
	}
	if token == "" {
		t.Fatal("MintApprovalToken returned an empty token")
	}
	if !exp.After(time.Now()) {
		t.Errorf("expiresAt = %v, want a time in the future", exp)
	}

	// Verify with tools presented in a different order: binding compares
	// the tool *set*, not a literal sequence.
	reordered := []string{"delete_account", "send_wire_transfer"}
	if err := VerifyApprovalToken(secret, token, "agent://x/bot", "run-1", reordered, 1000); err != nil {
		t.Errorf("VerifyApprovalToken: %v, want nil (valid)", err)
	}
}

func TestVerifyWrongSecret(t *testing.T) {
	token, _, err := MintApprovalToken([]byte("secret-a"), "agent://x/bot", "run-1", []string{"tool"}, 100, DefaultTTL)
	if err != nil {
		t.Fatalf("MintApprovalToken: %v", err)
	}
	err = VerifyApprovalToken([]byte("secret-b"), token, "agent://x/bot", "run-1", []string{"tool"}, 100)
	if !errors.Is(err, ErrTokenSignature) {
		t.Errorf("VerifyApprovalToken with wrong secret = %v, want ErrTokenSignature", err)
	}
}

func TestVerifyExpiredToken(t *testing.T) {
	secret := []byte("test-secret")
	token, _, err := MintApprovalToken(secret, "agent://x/bot", "run-1", []string{"tool"}, 100, -time.Second)
	if err != nil {
		t.Fatalf("MintApprovalToken: %v", err)
	}
	err = VerifyApprovalToken(secret, token, "agent://x/bot", "run-1", []string{"tool"}, 100)
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("VerifyApprovalToken with a negative TTL = %v, want ErrTokenExpired", err)
	}
}

func TestVerifyWrongBinding(t *testing.T) {
	secret := []byte("test-secret")
	token, _, err := MintApprovalToken(secret, "agent://x/bot", "run-1", []string{"tool_a"}, 100, DefaultTTL)
	if err != nil {
		t.Fatalf("MintApprovalToken: %v", err)
	}

	cases := []struct {
		name    string
		agentID string
		runID   string
		tools   []string
	}{
		{"wrong agent", "agent://y/bot", "run-1", []string{"tool_a"}},
		{"wrong run", "agent://x/bot", "run-2", []string{"tool_a"}},
		{"wrong tools", "agent://x/bot", "run-1", []string{"tool_b"}},
		{"extra tool", "agent://x/bot", "run-1", []string{"tool_a", "tool_b"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := VerifyApprovalToken(secret, token, c.agentID, c.runID, c.tools, 100)
			if !errors.Is(err, ErrTokenBinding) {
				t.Errorf("VerifyApprovalToken(%s) = %v, want ErrTokenBinding", c.name, err)
			}
		})
	}
}

// TestVerifyCostCeiling covers the ceiling comparison directly: a token
// minted with a given MaxCostUSD accepts any estCostUSD up to and
// including it (an exact match and a lower retry both work) and rejects
// anything higher, all the way up to a wildly inflated amount.
func TestVerifyCostCeiling(t *testing.T) {
	secret := []byte("test-secret")
	token, _, err := MintApprovalToken(secret, "agent://x/bot", "run-1", []string{"tool"}, 501, DefaultTTL)
	if err != nil {
		t.Fatalf("MintApprovalToken: %v", err)
	}
	cases := []struct {
		name    string
		cost    float64
		wantErr bool
	}{
		{"exactly at the ceiling", 501, false},
		{"under the ceiling", 100, false},
		{"zero cost", 0, false},
		{"a cent over the ceiling", 501.01, true},
		{"wildly over the ceiling", 5_000_000, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := VerifyApprovalToken(secret, token, "agent://x/bot", "run-1", []string{"tool"}, c.cost)
			if c.wantErr && !errors.Is(err, ErrTokenCostExceeded) {
				t.Errorf("VerifyApprovalToken(estCostUSD=%v) = %v, want ErrTokenCostExceeded", c.cost, err)
			}
			if !c.wantErr && err != nil {
				t.Errorf("VerifyApprovalToken(estCostUSD=%v) = %v, want nil", c.cost, err)
			}
		})
	}
}

// TestVerifyOldFormatTokenFailsClosedOnCost simulates a token minted before
// MaxCostUSD existed: its JSON payload has no max_cost_usd key at all, not
// merely an explicit zero value. Decoding it into today's claims leaves
// MaxCostUSD at Go's zero value, and that must fail closed against any
// positive presented cost rather than being treated as "no ceiling" --
// otherwise a token issued just before this fix shipped would carry on
// authorizing unbounded cost for the rest of its (short) TTL.
func TestVerifyOldFormatTokenFailsClosedOnCost(t *testing.T) {
	secret := []byte("test-secret")
	type oldClaims struct {
		AgentID string   `json:"agent_id"`
		RunID   string   `json:"run_id"`
		Tools   []string `json:"tools"`
		Exp     int64    `json:"exp"`
		Nonce   string   `json:"nonce"`
	}
	old := oldClaims{
		AgentID: "agent://x/bot",
		RunID:   "run-1",
		Tools:   []string{"tool"},
		Exp:     time.Now().Add(time.Minute).Unix(),
		Nonce:   "abcd1234abcd1234",
	}
	body, err := json.Marshal(old)
	if err != nil {
		t.Fatalf("marshal old-format claims: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	token := payload + "." + sign(secret, payload)

	if err := VerifyApprovalToken(secret, token, "agent://x/bot", "run-1", []string{"tool"}, 0.01); !errors.Is(err, ErrTokenCostExceeded) {
		t.Errorf("VerifyApprovalToken(old-format token, estCostUSD=0.01) = %v, want ErrTokenCostExceeded", err)
	}
	// pdp.Decide only ever calls VerifyApprovalToken with a positive
	// EstCostUSD (overThreshold requires cost > a positive threshold), so
	// a zero-cost request against an old-format token is not a case the
	// fail-closed rule needs to guard -- but the comparison is documented
	// as strictly greater-than, not greater-or-equal, so it is worth
	// pinning here too.
	if err := VerifyApprovalToken(secret, token, "agent://x/bot", "run-1", []string{"tool"}, 0); err != nil {
		t.Errorf("VerifyApprovalToken(old-format token, estCostUSD=0) = %v, want nil", err)
	}
}

func TestMintAndVerifyFailClosedWithNoSecret(t *testing.T) {
	if _, _, err := MintApprovalToken(nil, "agent://x/bot", "run-1", []string{"tool"}, 100, DefaultTTL); !errors.Is(err, ErrNoSecret) {
		t.Errorf("MintApprovalToken with no secret = %v, want ErrNoSecret", err)
	}
	// Even a syntactically well-formed token (minted under some other
	// secret) must be refused once the verifying side has no secret
	// configured: empty secret is never "no signature required."
	token, _, err := MintApprovalToken([]byte("some-secret"), "agent://x/bot", "run-1", []string{"tool"}, 100, DefaultTTL)
	if err != nil {
		t.Fatalf("MintApprovalToken: %v", err)
	}
	if err := VerifyApprovalToken(nil, token, "agent://x/bot", "run-1", []string{"tool"}, 100); !errors.Is(err, ErrNoSecret) {
		t.Errorf("VerifyApprovalToken with no secret = %v, want ErrNoSecret", err)
	}
}

func TestVerifyMalformedToken(t *testing.T) {
	secret := []byte("test-secret")
	cases := []string{"", "no-dot-separator", "payload.", ".sig", "not-base64!!!.deadbeef"}
	for _, tok := range cases {
		if err := VerifyApprovalToken(secret, tok, "agent://x/bot", "run-1", nil, 0); err == nil {
			t.Errorf("VerifyApprovalToken(%q) = nil, want an error", tok)
		}
	}
}

func TestRequestAndDecideGrantMintsUsableToken(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	secret := []byte("test-secret")

	held, err := Request(ctx, st, "agent://acme.example/finance/bot1", "run-42",
		[]string{"send_wire_transfer"},
		map[string]any{"org": "acme", "est_cost_usd": 1200.0})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if held.ApprovalID == "" {
		t.Fatal("Request did not assign an ApprovalID")
	}
	if !held.Pending() {
		t.Fatal("a freshly requested approval must be Pending")
	}

	decided, token, err := Decide(ctx, st, secret, held.ApprovalID, "grant", "alice@acme.example", DefaultTTL)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if decided.Decision != "grant" || decided.DecidedBy != "alice@acme.example" {
		t.Errorf("decided = %+v, want grant by alice", decided)
	}
	if token == "" {
		t.Fatal("Decide(grant) returned an empty token")
	}
	if err := VerifyApprovalToken(secret, token, "agent://acme.example/finance/bot1", "run-42", []string{"send_wire_transfer"}, 1200); err != nil {
		t.Errorf("the token minted by Decide(grant) does not verify: %v", err)
	}
	// The token must stay bound to exactly the held tool set: presenting it
	// for a different tool must fail.
	if err := VerifyApprovalToken(secret, token, "agent://acme.example/finance/bot1", "run-42", []string{"a_different_tool"}, 1200); !errors.Is(err, ErrTokenBinding) {
		t.Errorf("token verified against a different tool set: %v, want ErrTokenBinding", err)
	}
	// The token must also stay bound to the est_cost_usd that triggered the
	// hold (1200, stamped in Request's context above): it is a ceiling on
	// what Decide mints, not merely a value that happened to verify once.
	// A wildly higher cost at redemption time must fail even though every
	// other binding (agent/run/tool-set) matches.
	if err := VerifyApprovalToken(secret, token, "agent://acme.example/finance/bot1", "run-42", []string{"send_wire_transfer"}, 5_000_000); !errors.Is(err, ErrTokenCostExceeded) {
		t.Errorf("token verified for $5,000,000 against a $1,200 approval: %v, want ErrTokenCostExceeded", err)
	}
}

func TestDecideDenyReturnsNoToken(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	held, err := Request(ctx, st, "agent://x/bot", "run-1", []string{"tool"}, nil)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	decided, token, err := Decide(ctx, st, []byte("secret"), held.ApprovalID, "deny", "alice", DefaultTTL)
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if decided.Decision != "deny" {
		t.Errorf("Decision = %q, want deny", decided.Decision)
	}
	if token != "" {
		t.Errorf("Decide(deny) returned a non-empty token: %q", token)
	}
}

func TestDecideGrantFailsClosedWithNoSecretAndLeavesApprovalPending(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	held, err := Request(ctx, st, "agent://x/bot", "run-1", []string{"tool"}, nil)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if _, _, err := Decide(ctx, st, nil, held.ApprovalID, "grant", "alice", DefaultTTL); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("Decide(grant) with no secret = %v, want ErrNoSecret", err)
	}
	// The refusal must happen before the store is touched: no
	// half-granted state with an unusable token.
	still, err := st.GetApproval(ctx, held.ApprovalID)
	if err != nil {
		t.Fatalf("GetApproval: %v", err)
	}
	if !still.Pending() {
		t.Errorf("approval = %+v, want still Pending after a failed-closed grant attempt", still)
	}
}

func TestDecideRejectsUnknownDecisionValue(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	held, err := Request(ctx, st, "agent://x/bot", "run-1", []string{"tool"}, nil)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if _, _, err := Decide(ctx, st, []byte("secret"), held.ApprovalID, "maybe", "alice", DefaultTTL); !errors.Is(err, ErrInvalidDecision) {
		t.Errorf("Decide with an unknown decision = %v, want ErrInvalidDecision", err)
	}
}

func TestDecideTwiceFails(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	secret := []byte("test-secret")
	held, err := Request(ctx, st, "agent://x/bot", "run-1", []string{"tool"}, nil)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if _, _, err := Decide(ctx, st, secret, held.ApprovalID, "grant", "alice", DefaultTTL); err != nil {
		t.Fatalf("first Decide: %v", err)
	}
	if _, _, err := Decide(ctx, st, secret, held.ApprovalID, "deny", "bob", DefaultTTL); !errors.Is(err, store.ErrAlreadyDecided) {
		t.Errorf("second Decide = %v, want store.ErrAlreadyDecided", err)
	}
}

func TestDecideUnknownApprovalID(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	if _, _, err := Decide(ctx, st, []byte("secret"), "does-not-exist", "grant", "alice", DefaultTTL); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Decide(unknown id) = %v, want store.ErrNotFound", err)
	}
}

// TestRedemptionKeyStableAndDistinct covers the properties
// WARDRYX_APPROVAL_SINGLE_USE depends on: the same token always produces
// the same key (so a genuine retry is recognized), and two different
// tokens -- even ones minted for the exact same (agent_id, run_id, tools)
// binding -- produce different keys (so a fresh re-grant of the same
// triple is never mistaken for the earlier, already-redeemed one).
func TestRedemptionKeyStableAndDistinct(t *testing.T) {
	secret := []byte("test-secret")
	tokenA, _, err := MintApprovalToken(secret, "agent://x/bot", "run-1", []string{"tool"}, 100, DefaultTTL)
	if err != nil {
		t.Fatalf("mint tokenA: %v", err)
	}
	// tokenB is minted for the identical binding but is a distinct grant
	// (its own expiry baked into the claims), the same way a re-approval
	// after single-use exhaustion would mint a new token for the same
	// triple.
	tokenB, _, err := MintApprovalToken(secret, "agent://x/bot", "run-1", []string{"tool"}, 100, DefaultTTL+time.Second)
	if err != nil {
		t.Fatalf("mint tokenB: %v", err)
	}
	if tokenA == tokenB {
		t.Fatal("tokenA and tokenB are identical; test setup must mint two distinct tokens")
	}

	if first, again := RedemptionKey(tokenA), RedemptionKey(tokenA); first != again {
		t.Errorf("RedemptionKey(tokenA) is not stable across calls: got %q then %q", first, again)
	}
	if RedemptionKey(tokenA) == RedemptionKey(tokenB) {
		t.Error("RedemptionKey(tokenA) == RedemptionKey(tokenB): two different grants for the same triple must not collide")
	}
	if got := RedemptionKey(tokenA); len(got) != 64 {
		t.Errorf("RedemptionKey returned %d hex chars, want 64 (sha256)", len(got))
	}
}
