package pdp

import (
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/approval"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

const testSecret = "test-approval-secret"

func testEngine(t *testing.T) *Engine {
	t.Helper()
	set, err := policy.Compile([]policy.Policy{
		{
			Name:                 "finance-guardrail",
			Target:               "agent://acme.example/finance/*",
			DenyTool:             []string{"send_wire_transfer", "delete_account"},
			RequireHumanAboveUSD: 500,
			DenyIfUnattested:     true,
		},
		{
			Name:   "support-baseline",
			Target: "agent://acme.example/support/*",
			// No deny_tool/threshold/attestation rule: exists only to
			// prove a second, non-firing matched policy doesn't change
			// the outcome.
		},
	})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	return New(set, []byte(testSecret))
}

// TestDecideTable covers the six required cases: allow; deny (denied
// tool); deny (unattested); hold (over threshold); allow with a valid
// approval token; deny with an expired-or-wrong token.
func TestDecideTable(t *testing.T) {
	engine := testEngine(t)

	validToken, _, err := approval.MintApprovalToken([]byte(testSecret), "agent://acme.example/finance/bot1", "run-1", []string{"generate_report"}, approval.DefaultTTL)
	if err != nil {
		t.Fatalf("mint valid token: %v", err)
	}
	expiredToken, _, err := approval.MintApprovalToken([]byte(testSecret), "agent://acme.example/finance/bot1", "run-1", []string{"generate_report"}, -time.Minute)
	if err != nil {
		t.Fatalf("mint expired token: %v", err)
	}
	wrongBindingToken, _, err := approval.MintApprovalToken([]byte(testSecret), "agent://acme.example/finance/bot1", "a-different-run", []string{"generate_report"}, approval.DefaultTTL)
	if err != nil {
		t.Fatalf("mint wrong-binding token: %v", err)
	}

	cases := []struct {
		name           string
		req            DecideRequest
		wantDecision   string
		wantReasonHas  string
		wantApprovalTR bool
	}{
		{
			name: "allow",
			req: DecideRequest{
				AgentID:           "agent://acme.example/finance/bot1",
				RunID:             "run-1",
				ToolNames:         []string{"generate_report"},
				EstCostUSD:        10,
				AttestationMethod: "spiffe-svid",
			},
			wantDecision:  Allow,
			wantReasonHas: "allowed",
		},
		{
			name: "deny (denied tool)",
			req: DecideRequest{
				AgentID:           "agent://acme.example/finance/bot1",
				RunID:             "run-1",
				ToolNames:         []string{"send_wire_transfer"},
				AttestationMethod: "spiffe-svid",
			},
			wantDecision:  Deny,
			wantReasonHas: `tool "send_wire_transfer" is denied`,
		},
		{
			name: "deny (unattested)",
			req: DecideRequest{
				AgentID:           "agent://acme.example/finance/bot1",
				RunID:             "run-1",
				ToolNames:         []string{"generate_report"},
				AttestationMethod: "",
			},
			wantDecision:  Deny,
			wantReasonHas: "requires a live attestation",
		},
		{
			name: "deny (unattested, explicit none)",
			req: DecideRequest{
				AgentID:           "agent://acme.example/finance/bot1",
				RunID:             "run-1",
				ToolNames:         []string{"generate_report"},
				AttestationMethod: "none",
			},
			wantDecision:  Deny,
			wantReasonHas: "requires a live attestation",
		},
		{
			name: "hold (over threshold)",
			req: DecideRequest{
				AgentID:           "agent://acme.example/finance/bot1",
				RunID:             "run-1",
				ToolNames:         []string{"generate_report"},
				EstCostUSD:        750,
				AttestationMethod: "spiffe-svid",
			},
			wantDecision:   Hold,
			wantReasonHas:  "human approval required",
			wantApprovalTR: true,
		},
		{
			name: "allow with a valid approval token",
			req: DecideRequest{
				AgentID:           "agent://acme.example/finance/bot1",
				RunID:             "run-1",
				ToolNames:         []string{"generate_report"},
				EstCostUSD:        750,
				AttestationMethod: "spiffe-svid",
				ApprovalToken:     validToken,
			},
			wantDecision:   Allow,
			wantReasonHas:  "valid approval_token",
			wantApprovalTR: true,
		},
		{
			name: "deny with an expired token",
			req: DecideRequest{
				AgentID:           "agent://acme.example/finance/bot1",
				RunID:             "run-1",
				ToolNames:         []string{"generate_report"},
				EstCostUSD:        750,
				AttestationMethod: "spiffe-svid",
				ApprovalToken:     expiredToken,
			},
			wantDecision:   Deny,
			wantReasonHas:  "approval_token is invalid",
			wantApprovalTR: true,
		},
		{
			name: "deny with a wrong-binding token",
			req: DecideRequest{
				AgentID:           "agent://acme.example/finance/bot1",
				RunID:             "run-1",
				ToolNames:         []string{"generate_report"},
				EstCostUSD:        750,
				AttestationMethod: "spiffe-svid",
				ApprovalToken:     wrongBindingToken,
			},
			wantDecision:   Deny,
			wantReasonHas:  "approval_token is invalid",
			wantApprovalTR: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := engine.Decide(c.req)
			if resp.Decision != c.wantDecision {
				t.Errorf("Decision = %q, want %q (reason: %s)", resp.Decision, c.wantDecision, resp.Reason)
			}
			if !strings.Contains(resp.Reason, c.wantReasonHas) {
				t.Errorf("Reason = %q, want it to contain %q", resp.Reason, c.wantReasonHas)
			}
			if resp.ApprovalTokenRequired != c.wantApprovalTR {
				t.Errorf("ApprovalTokenRequired = %v, want %v", resp.ApprovalTokenRequired, c.wantApprovalTR)
			}
			if resp.ApprovalID != "" {
				t.Errorf("ApprovalID = %q, want empty: Decide never assigns one (the API layer does)", resp.ApprovalID)
			}
			if resp.PolicyVersion == "" {
				t.Error("PolicyVersion must always be set")
			}
		})
	}
}

func TestDecideNoMatchedPolicyAllows(t *testing.T) {
	engine := testEngine(t)
	resp := engine.Decide(DecideRequest{AgentID: "agent://other.example/anything/bot", ToolNames: []string{"send_wire_transfer"}})
	if resp.Decision != Allow {
		t.Errorf("Decision = %q, want %q: no policy targets this agent", resp.Decision, Allow)
	}
	if !strings.Contains(resp.Reason, "no policy targets") {
		t.Errorf("Reason = %q, want it to explain no policy matched", resp.Reason)
	}
}

func TestDecideEmptyEngineAllowsEverything(t *testing.T) {
	engine := New(nil, nil)
	resp := engine.Decide(DecideRequest{AgentID: "agent://anything/at/all", ToolNames: []string{"send_wire_transfer"}, EstCostUSD: 1_000_000})
	if resp.Decision != Allow {
		t.Errorf("Decision = %q, want %q with no policy loaded at all", resp.Decision, Allow)
	}
}

func TestDecideZeroThresholdNeverHolds(t *testing.T) {
	// require_human_above_usd's zero value means "no threshold configured",
	// not "hold on any positive spend."
	set, err := policy.Compile([]policy.Policy{{Target: "agent://x/*"}})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	engine := New(set, nil)
	resp := engine.Decide(DecideRequest{AgentID: "agent://x/bot", EstCostUSD: 999999})
	if resp.Decision != Allow {
		t.Errorf("Decision = %q, want %q: no policy on this agent sets a positive threshold", resp.Decision, Allow)
	}
}

func TestDecideInvalidOnBehalfOfChainDeniesBeforeAnyPolicyRule(t *testing.T) {
	engine := testEngine(t)
	resp := engine.Decide(DecideRequest{
		AgentID:    "agent://acme.example/finance/bot1",
		RunID:      "run-1",
		OnBehalfOf: []string{"user://acme.example/alice", "user://acme.example/alice"}, // cycle: repeated entry
	})
	if resp.Decision != Deny {
		t.Fatalf("Decision = %q, want %q for a cyclic delegation chain", resp.Decision, Deny)
	}
	if !strings.Contains(resp.Reason, "on_behalf_of") {
		t.Errorf("Reason = %q, want it to mention the delegation chain", resp.Reason)
	}
}

func TestDecidePicksStrictestExceededThreshold(t *testing.T) {
	set, err := policy.Compile([]policy.Policy{
		{Name: "loose", Target: "agent://x/*", RequireHumanAboveUSD: 1000},
		{Name: "strict", Target: "agent://x/*", RequireHumanAboveUSD: 100},
	})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	engine := New(set, nil)
	resp := engine.Decide(DecideRequest{AgentID: "agent://x/bot", EstCostUSD: 500})
	if resp.Decision != Hold {
		t.Fatalf("Decision = %q, want %q", resp.Decision, Hold)
	}
	if !strings.Contains(resp.Reason, `"strict"`) {
		t.Errorf("Reason = %q, want it to cite the strict policy (lowest exceeded threshold)", resp.Reason)
	}
}

func TestPolicyVersionSurfacedOnEveryDecision(t *testing.T) {
	engine := testEngine(t)
	want := engine.PolicyVersion()
	for _, req := range []DecideRequest{
		{AgentID: "agent://acme.example/finance/bot1", ToolNames: []string{"generate_report"}, AttestationMethod: "spiffe-svid"},
		{AgentID: "agent://acme.example/finance/bot1", ToolNames: []string{"send_wire_transfer"}, AttestationMethod: "spiffe-svid"},
	} {
		if got := engine.Decide(req).PolicyVersion; got != want {
			t.Errorf("PolicyVersion = %q, want %q", got, want)
		}
	}
}
