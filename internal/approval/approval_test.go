package approval

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/store"
)

func TestMintAndVerifyRoundTrip(t *testing.T) {
	secret := []byte("test-secret")
	tools := []string{"send_wire_transfer", "delete_account"}
	token, exp, err := MintApprovalToken(secret, "agent://x/bot", "run-1", tools, DefaultTTL)
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
	if err := VerifyApprovalToken(secret, token, "agent://x/bot", "run-1", reordered); err != nil {
		t.Errorf("VerifyApprovalToken: %v, want nil (valid)", err)
	}
}

func TestVerifyWrongSecret(t *testing.T) {
	token, _, err := MintApprovalToken([]byte("secret-a"), "agent://x/bot", "run-1", []string{"tool"}, DefaultTTL)
	if err != nil {
		t.Fatalf("MintApprovalToken: %v", err)
	}
	err = VerifyApprovalToken([]byte("secret-b"), token, "agent://x/bot", "run-1", []string{"tool"})
	if !errors.Is(err, ErrTokenSignature) {
		t.Errorf("VerifyApprovalToken with wrong secret = %v, want ErrTokenSignature", err)
	}
}

func TestVerifyExpiredToken(t *testing.T) {
	secret := []byte("test-secret")
	token, _, err := MintApprovalToken(secret, "agent://x/bot", "run-1", []string{"tool"}, -time.Second)
	if err != nil {
		t.Fatalf("MintApprovalToken: %v", err)
	}
	err = VerifyApprovalToken(secret, token, "agent://x/bot", "run-1", []string{"tool"})
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("VerifyApprovalToken with a negative TTL = %v, want ErrTokenExpired", err)
	}
}

func TestVerifyWrongBinding(t *testing.T) {
	secret := []byte("test-secret")
	token, _, err := MintApprovalToken(secret, "agent://x/bot", "run-1", []string{"tool_a"}, DefaultTTL)
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
			err := VerifyApprovalToken(secret, token, c.agentID, c.runID, c.tools)
			if !errors.Is(err, ErrTokenBinding) {
				t.Errorf("VerifyApprovalToken(%s) = %v, want ErrTokenBinding", c.name, err)
			}
		})
	}
}

func TestMintAndVerifyFailClosedWithNoSecret(t *testing.T) {
	if _, _, err := MintApprovalToken(nil, "agent://x/bot", "run-1", []string{"tool"}, DefaultTTL); !errors.Is(err, ErrNoSecret) {
		t.Errorf("MintApprovalToken with no secret = %v, want ErrNoSecret", err)
	}
	// Even a syntactically well-formed token (minted under some other
	// secret) must be refused once the verifying side has no secret
	// configured: empty secret is never "no signature required."
	token, _, err := MintApprovalToken([]byte("some-secret"), "agent://x/bot", "run-1", []string{"tool"}, DefaultTTL)
	if err != nil {
		t.Fatalf("MintApprovalToken: %v", err)
	}
	if err := VerifyApprovalToken(nil, token, "agent://x/bot", "run-1", []string{"tool"}); !errors.Is(err, ErrNoSecret) {
		t.Errorf("VerifyApprovalToken with no secret = %v, want ErrNoSecret", err)
	}
}

func TestVerifyMalformedToken(t *testing.T) {
	secret := []byte("test-secret")
	cases := []string{"", "no-dot-separator", "payload.", ".sig", "not-base64!!!.deadbeef"}
	for _, tok := range cases {
		if err := VerifyApprovalToken(secret, tok, "agent://x/bot", "run-1", nil); err == nil {
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
	if err := VerifyApprovalToken(secret, token, "agent://acme.example/finance/bot1", "run-42", []string{"send_wire_transfer"}); err != nil {
		t.Errorf("the token minted by Decide(grant) does not verify: %v", err)
	}
	// The token must stay bound to exactly the held tool set: presenting it
	// for a different tool must fail.
	if err := VerifyApprovalToken(secret, token, "agent://acme.example/finance/bot1", "run-42", []string{"a_different_tool"}); !errors.Is(err, ErrTokenBinding) {
		t.Errorf("token verified against a different tool set: %v, want ErrTokenBinding", err)
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
