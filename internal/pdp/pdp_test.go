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
			AllowDomains:         []string{"good.example.com", "reports.acme.example"},
			RequireHumanAboveUSD: 500,
			MaxSteps:             5,
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

// TestDecideTable covers the decision table: allow; deny (denied tool);
// deny (unattested); deny (max_steps at/over the cap, allow under it);
// deny (domain outside allow_domains, allow inside it, no-op when the
// request declares no domains); hold (over threshold); allow with a valid
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
			name: "allow (steps under the cap)",
			req: DecideRequest{
				AgentID:           "agent://acme.example/finance/bot1",
				RunID:             "run-1",
				ToolNames:         []string{"generate_report"},
				Steps:             4,
				EstCostUSD:        10,
				AttestationMethod: "spiffe-svid",
			},
			wantDecision:  Allow,
			wantReasonHas: "allowed",
		},
		{
			name: "deny (max_steps at the cap)",
			req: DecideRequest{
				AgentID:           "agent://acme.example/finance/bot1",
				RunID:             "run-1",
				ToolNames:         []string{"generate_report"},
				Steps:             5,
				EstCostUSD:        10,
				AttestationMethod: "spiffe-svid",
			},
			wantDecision:  Deny,
			wantReasonHas: "step budget exhausted: 5 >= max_steps 5",
		},
		{
			name: "deny (max_steps over the cap)",
			req: DecideRequest{
				AgentID:           "agent://acme.example/finance/bot1",
				RunID:             "run-1",
				ToolNames:         []string{"generate_report"},
				Steps:             9,
				EstCostUSD:        10,
				AttestationMethod: "spiffe-svid",
			},
			wantDecision:  Deny,
			wantReasonHas: "step budget exhausted: 9 >= max_steps 5",
		},
		{
			name: "allow (domain present in allow_domains)",
			req: DecideRequest{
				AgentID:           "agent://acme.example/finance/bot1",
				RunID:             "run-1",
				ToolNames:         []string{"generate_report"},
				Domains:           []string{"good.example.com"},
				EstCostUSD:        10,
				AttestationMethod: "spiffe-svid",
			},
			wantDecision:  Allow,
			wantReasonHas: "allowed",
		},
		{
			name: "deny (domain absent from allow_domains)",
			req: DecideRequest{
				AgentID:           "agent://acme.example/finance/bot1",
				RunID:             "run-1",
				ToolNames:         []string{"generate_report"},
				Domains:           []string{"evil.example.com"},
				EstCostUSD:        10,
				AttestationMethod: "spiffe-svid",
			},
			wantDecision:  Deny,
			wantReasonHas: `domain "evil.example.com" is not allowed`,
		},
		{
			name: "allow (empty domains is a no-op even though allow_domains is configured)",
			req: DecideRequest{
				AgentID:           "agent://acme.example/finance/bot1",
				RunID:             "run-1",
				ToolNames:         []string{"generate_report"},
				Domains:           []string{},
				EstCostUSD:        10,
				AttestationMethod: "spiffe-svid",
			},
			wantDecision:  Allow,
			wantReasonHas: "allowed",
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

func TestDecidePicksStrictestExceededMaxSteps(t *testing.T) {
	set, err := policy.Compile([]policy.Policy{
		{Name: "loose", Target: "agent://x/*", MaxSteps: 20},
		{Name: "strict", Target: "agent://x/*", MaxSteps: 10},
	})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	engine := New(set, nil)
	resp := engine.Decide(DecideRequest{AgentID: "agent://x/bot", Steps: 15})
	if resp.Decision != Deny {
		t.Fatalf("Decision = %q, want %q", resp.Decision, Deny)
	}
	if !strings.Contains(resp.Reason, `"strict"`) {
		t.Errorf("Reason = %q, want it to cite the strict policy (lowest exceeded max_steps)", resp.Reason)
	}
}

func TestDecideMaxStepsZeroNeverDenies(t *testing.T) {
	// max_steps's zero value means "no cap configured," not "deny any step
	// count," mirroring require_human_above_usd's zero value.
	set, err := policy.Compile([]policy.Policy{{Target: "agent://x/*"}})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	engine := New(set, nil)
	resp := engine.Decide(DecideRequest{AgentID: "agent://x/bot", Steps: 999999})
	if resp.Decision != Allow {
		t.Errorf("Decision = %q, want %q: no policy on this agent sets a positive max_steps", resp.Decision, Allow)
	}
}

func TestDecideAllowDomainsComposeByIntersectionAcrossMatchedPolicies(t *testing.T) {
	// Two matched policies each declare their own non-empty allow_domains.
	// A domain allowed by one but not the other must still deny: allow-list
	// policies compose by intersection, the most restrictive matched policy
	// governs (see deniedDomain's doc comment).
	set, err := policy.Compile([]policy.Policy{
		{Name: "broad", Target: "agent://x/*", AllowDomains: []string{"a.example", "b.example"}},
		{Name: "narrow", Target: "agent://x/*", AllowDomains: []string{"b.example"}},
	})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	engine := New(set, nil)

	resp := engine.Decide(DecideRequest{AgentID: "agent://x/bot", Domains: []string{"a.example"}})
	if resp.Decision != Deny {
		t.Fatalf("Decision = %q, want %q: a.example is outside the narrow policy's allow_domains", resp.Decision, Deny)
	}
	if !strings.Contains(resp.Reason, `"narrow"`) {
		t.Errorf("Reason = %q, want it to cite the narrow policy", resp.Reason)
	}

	resp = engine.Decide(DecideRequest{AgentID: "agent://x/bot", Domains: []string{"b.example"}})
	if resp.Decision != Allow {
		t.Fatalf("Decision = %q, want %q: b.example satisfies both matched policies' allow_domains", resp.Decision, Allow)
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
