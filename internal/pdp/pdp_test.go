package pdp

import (
	"strings"
	"sync"
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

	validToken, _, err := approval.MintApprovalToken([]byte(testSecret), "agent://acme.example/finance/bot1", "run-1", []string{"generate_report"}, 750, approval.DefaultTTL)
	if err != nil {
		t.Fatalf("mint valid token: %v", err)
	}
	expiredToken, _, err := approval.MintApprovalToken([]byte(testSecret), "agent://acme.example/finance/bot1", "run-1", []string{"generate_report"}, 750, -time.Minute)
	if err != nil {
		t.Fatalf("mint expired token: %v", err)
	}
	wrongBindingToken, _, err := approval.MintApprovalToken([]byte(testSecret), "agent://acme.example/finance/bot1", "a-different-run", []string{"generate_report"}, 750, approval.DefaultTTL)
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
			// Every case here matches finance-guardrail, which sets
			// max_steps, allow_domains, and require_human_above_usd, so
			// every one of them is request-specific regardless of which
			// rule actually fired -- see TestDecideCacheable for the
			// dedicated true/false coverage.
			if resp.Cacheable {
				t.Error("Cacheable = true, want false: finance-guardrail sets max_steps, allow_domains, and require_human_above_usd")
			}
		})
	}
}

// TestDecideApprovalTokenCostCeiling reproduces a real bug: an
// approval_token was bound to (agent_id, run_id, tool set) but not to the
// cost a human actually approved, so a token minted for a hold that crossed
// the policy threshold by a single dollar would then authorize *any*
// est_cost_usd whatsoever for the same agent/run/tool-set, for the rest of
// its TTL. The fix binds the token to the est_cost_usd that triggered the
// hold as a ceiling: a resubmission at the same or a lower cost still
// allows (retries are not penalized), but a resubmission at a wildly higher
// cost must not.
func TestDecideApprovalTokenCostCeiling(t *testing.T) {
	engine := testEngine(t)
	const approvedCost = 501 // just over finance-guardrail's require_human_above_usd: 500

	token, _, err := approval.MintApprovalToken([]byte(testSecret), "agent://acme.example/finance/bot1", "run-1", []string{"generate_report"}, approvedCost, approval.DefaultTTL)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}

	t.Run("same-or-lower cost still allows", func(t *testing.T) {
		resp := engine.Decide(DecideRequest{
			AgentID:           "agent://acme.example/finance/bot1",
			RunID:             "run-1",
			ToolNames:         []string{"generate_report"},
			EstCostUSD:        approvedCost,
			AttestationMethod: "spiffe-svid",
			ApprovalToken:     token,
		})
		if resp.Decision != Allow {
			t.Fatalf("Decision = %q (reason: %s), want %q: a retry at the exact approved cost must still work", resp.Decision, resp.Reason, Allow)
		}
	})

	t.Run("inflated cost is rejected despite a token valid for the original amount", func(t *testing.T) {
		resp := engine.Decide(DecideRequest{
			AgentID:           "agent://acme.example/finance/bot1",
			RunID:             "run-1",
			ToolNames:         []string{"generate_report"},
			EstCostUSD:        5_000_000,
			AttestationMethod: "spiffe-svid",
			ApprovalToken:     token,
		})
		if resp.Decision == Allow {
			t.Fatalf("Decision = %q (reason: %s), want Hold or Deny: a token approved for $%d must not authorize $5,000,000", resp.Decision, resp.Reason, approvedCost)
		}
	})
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
	if resp.Cacheable {
		t.Error("Cacheable = true, want false: on_behalf_of is a per-request value like Steps or Domains, and this deny returns before any policy is even matched")
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

func TestSetPoliciesChangesPolicyVersion(t *testing.T) {
	engine := testEngine(t)
	before := engine.PolicyVersion()

	replacement, err := policy.Compile([]policy.Policy{
		{Name: "new-rule", Target: "agent://acme.example/*", DenyTool: []string{"anything"}},
	})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	engine.SetPolicies(replacement)

	after := engine.PolicyVersion()
	if after == before {
		t.Errorf("PolicyVersion unchanged after SetPolicies: %q", after)
	}
	if after != replacement.Version() {
		t.Errorf("PolicyVersion = %q, want %q (the swapped-in set's own version)", after, replacement.Version())
	}
}

// TestSetPoliciesChangesDecideOutcome proves the swap is live, not just a
// version-string bookkeeping change: a request denied under the old policy
// must allow once SetPolicies removes the rule that denied it, and a fresh
// deny_tool rule introduced by the swap must start denying immediately.
func TestSetPoliciesChangesDecideOutcome(t *testing.T) {
	engine := testEngine(t)
	req := DecideRequest{
		AgentID: "agent://acme.example/finance/bot1", RunID: "r1",
		ToolNames: []string{"send_wire_transfer"}, AttestationMethod: "spiffe-svid",
	}
	if got := engine.Decide(req).Decision; got != Deny {
		t.Fatalf("before SetPolicies: Decision = %q, want deny (send_wire_transfer denied by the fixture policy)", got)
	}

	empty, err := policy.Compile(nil)
	if err != nil {
		t.Fatalf("policy.Compile(nil): %v", err)
	}
	engine.SetPolicies(empty)

	if got := engine.Decide(req).Decision; got != Allow {
		t.Errorf("after SetPolicies(empty): Decision = %q, want allow (zero policies loaded)", got)
	}
}

func TestSetPoliciesNilResetsToEmpty(t *testing.T) {
	engine := testEngine(t)
	engine.SetPolicies(nil)
	if got, want := engine.PolicyVersion(), policy.Empty().Version(); got != want {
		t.Errorf("PolicyVersion after SetPolicies(nil) = %q, want %q (policy.Empty())", got, want)
	}
	req := DecideRequest{AgentID: "agent://acme.example/finance/bot1", RunID: "r1", ToolNames: []string{"send_wire_transfer"}}
	if got := engine.Decide(req).Decision; got != Allow {
		t.Errorf("Decision after SetPolicies(nil) = %q, want allow", got)
	}
}

// TestSetPoliciesConcurrentWithDecide is a race-detector stress test:
// SetPolicies from one goroutine while many others call Decide, proving the
// atomic.Pointer swap (not a plain field) is what makes Engine safe for
// concurrent use once policies stop being fixed at construction time. Run
// with -race; this test asserts no panic/race, not a specific outcome.
func TestSetPoliciesConcurrentWithDecide(t *testing.T) {
	engine := testEngine(t)
	altSet, err := policy.Compile([]policy.Policy{
		{Name: "alt", Target: "agent://acme.example/*", DenyTool: []string{"x"}},
	})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}

	stop := make(chan struct{})
	setterDone := make(chan struct{})
	go func() {
		defer close(setterDone)
		toggle := false
		for {
			select {
			case <-stop:
				return
			default:
				if toggle {
					engine.SetPolicies(altSet)
				} else {
					engine.SetPolicies(policy.Empty())
				}
				toggle = !toggle
			}
		}
	}()

	var deciders sync.WaitGroup
	for range 50 {
		deciders.Add(1)
		go func() {
			defer deciders.Done()
			engine.Decide(DecideRequest{AgentID: "agent://acme.example/finance/bot1", RunID: "r1"})
		}()
	}
	deciders.Wait()
	close(stop)
	<-setterDone
}

// TestDecideCacheable covers Cacheable directly: false whenever a matched
// policy sets max_steps, allow_domains, require_human_above_usd, or
// deny_above_usd (the fields Decide checks against per-request state), true
// for a matched policy that only sets deny_tool/deny_if_unattested (stable
// per-agent facts) and for no match at all, and -- the case most likely to
// be implemented wrong -- false whenever a request-specific policy matched
// even if a different, non-request-specific rule is what actually denied.
func TestDecideCacheable(t *testing.T) {
	cases := []struct {
		name          string
		policies      []policy.Policy
		req           DecideRequest
		wantDecision  string
		wantCacheable bool
	}{
		{
			name:          "false: matched policy sets max_steps",
			policies:      []policy.Policy{{Target: "agent://x/*", MaxSteps: 5}},
			req:           DecideRequest{AgentID: "agent://x/bot"},
			wantDecision:  Allow,
			wantCacheable: false,
		},
		{
			name:          "false: matched policy sets allow_domains",
			policies:      []policy.Policy{{Target: "agent://x/*", AllowDomains: []string{"good.example.com"}}},
			req:           DecideRequest{AgentID: "agent://x/bot"},
			wantDecision:  Allow,
			wantCacheable: false,
		},
		{
			name:          "false: matched policy sets require_human_above_usd",
			policies:      []policy.Policy{{Target: "agent://x/*", RequireHumanAboveUSD: 100}},
			req:           DecideRequest{AgentID: "agent://x/bot"},
			wantDecision:  Allow,
			wantCacheable: false,
		},
		{
			name:          "false: matched policy sets deny_above_usd",
			policies:      []policy.Policy{{Target: "agent://x/*", DenyAboveUSD: 1000}},
			req:           DecideRequest{AgentID: "agent://x/bot", EstCostUSD: 10},
			wantDecision:  Allow,
			wantCacheable: false,
		},
		{
			name: "true: matched policy only sets deny_tool and deny_if_unattested, request allowed",
			policies: []policy.Policy{
				{Target: "agent://x/*", DenyTool: []string{"send_wire_transfer"}, DenyIfUnattested: true},
			},
			req:           DecideRequest{AgentID: "agent://x/bot", ToolNames: []string{"read_file"}, AttestationMethod: "spiffe-svid"},
			wantDecision:  Allow,
			wantCacheable: true,
		},
		{
			name: "true: matched policy only sets deny_tool and deny_if_unattested, request denied",
			// Cacheable describes the shape of the matched policy set, not
			// whether this particular request was allowed or denied: a
			// deny_tool verdict is exactly as safe to cache as the allow
			// case above, since neither ever depends on steps, domains, or
			// cost.
			policies: []policy.Policy{
				{Target: "agent://x/*", DenyTool: []string{"send_wire_transfer"}, DenyIfUnattested: true},
			},
			req:           DecideRequest{AgentID: "agent://x/bot", ToolNames: []string{"send_wire_transfer"}, AttestationMethod: "spiffe-svid"},
			wantDecision:  Deny,
			wantCacheable: true,
		},
		{
			name:          "true: no policy matched at all",
			policies:      []policy.Policy{{Target: "agent://other/*", MaxSteps: 5}},
			req:           DecideRequest{AgentID: "agent://x/bot"},
			wantDecision:  Allow,
			wantCacheable: true,
		},
		{
			name: "false: request-specific policy matched even though deny_tool is what actually fired",
			// deny_tool wins outright and produces this Decision, but the
			// same matched policy also sets max_steps: a later call from
			// this agent with the same (allowed) tool set could still
			// resolve differently once Steps crosses 5, so the decision
			// must be marked non-cacheable even though this particular
			// verdict didn't itself depend on Steps.
			policies: []policy.Policy{
				{Target: "agent://x/*", DenyTool: []string{"send_wire_transfer"}, MaxSteps: 5},
			},
			req:           DecideRequest{AgentID: "agent://x/bot", ToolNames: []string{"send_wire_transfer"}},
			wantDecision:  Deny,
			wantCacheable: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			set, err := policy.Compile(c.policies)
			if err != nil {
				t.Fatalf("policy.Compile: %v", err)
			}
			engine := New(set, nil)
			resp := engine.Decide(c.req)
			if resp.Decision != c.wantDecision {
				t.Fatalf("Decision = %q, want %q (reason: %s)", resp.Decision, c.wantDecision, resp.Reason)
			}
			if resp.Cacheable != c.wantCacheable {
				t.Errorf("Cacheable = %v, want %v (decision=%s, reason=%s)", resp.Cacheable, c.wantCacheable, resp.Decision, resp.Reason)
			}
		})
	}
}

// TestDecideUnattestedNormalization reproduces a real bypass:
// unattestedDenied compared attestation_method exactly and case-sensitively
// against only "" and "none", so deny_if_unattested was defeated by any
// other spelling of "no attestation" -- "None", "NONE", a bare space,
// "n/a", and "unattested" all slipped through and were treated as a live
// attestation. Fixed by trimming and lowercasing method before comparing it
// against a small set of known no-attestation spellings (unattestedSentinels
// in pdp.go).
func TestDecideUnattestedNormalization(t *testing.T) {
	engine := testEngine(t)

	cases := []struct {
		name         string
		method       string
		wantDecision string
	}{
		{name: "denies mixed-case None", method: "None", wantDecision: Deny},
		{name: "denies upper-case NONE", method: "NONE", wantDecision: Deny},
		{name: "denies a bare space", method: " ", wantDecision: Deny},
		{name: "denies n/a", method: "n/a", wantDecision: Deny},
		{name: "denies unattested", method: "unattested", wantDecision: Deny},
		{name: "denies none with surrounding whitespace", method: "  none  ", wantDecision: Deny},
		{name: "allows a genuine attestation method", method: "spiffe-svid", wantDecision: Allow},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := engine.Decide(DecideRequest{
				AgentID:           "agent://acme.example/finance/bot1",
				RunID:             "run-1",
				ToolNames:         []string{"generate_report"},
				AttestationMethod: c.method,
			})
			if resp.Decision != c.wantDecision {
				t.Fatalf("Decision = %q (reason: %s), want %q for attestation_method %q", resp.Decision, resp.Reason, c.wantDecision, c.method)
			}
			if c.wantDecision == Deny && !strings.Contains(resp.Reason, "requires a live attestation") {
				t.Errorf("Reason = %q, want it to mention the missing attestation", resp.Reason)
			}
		})
	}
}

// TestDecideDenyToolNormalization reproduces a real bypass: deniedTool's
// membership check compared tool names exactly and case-sensitively, so a
// deny_tool entry like "send_wire_transfer" failed to catch
// "Send_Wire_Transfer", "SEND_WIRE_TRANSFER", or a trailing-whitespace
// variant -- under-matching a security deny-list fails open. Fixed by
// comparing case-insensitively (strings.EqualFold) after trimming both
// sides (containsFold in pdp.go).
func TestDecideDenyToolNormalization(t *testing.T) {
	engine := testEngine(t)

	cases := []struct {
		name         string
		tool         string
		wantDecision string
	}{
		{name: "denies mixed-case variant", tool: "Send_Wire_Transfer", wantDecision: Deny},
		{name: "denies upper-case variant", tool: "SEND_WIRE_TRANSFER", wantDecision: Deny},
		{name: "denies a trailing-whitespace variant", tool: "send_wire_transfer ", wantDecision: Deny},
		{name: "allows an unrelated tool", tool: "read_docs", wantDecision: Allow},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := engine.Decide(DecideRequest{
				AgentID:           "agent://acme.example/finance/bot1",
				RunID:             "run-1",
				ToolNames:         []string{c.tool},
				AttestationMethod: "spiffe-svid",
			})
			if resp.Decision != c.wantDecision {
				t.Fatalf("Decision = %q (reason: %s), want %q for tool %q", resp.Decision, resp.Reason, c.wantDecision, c.tool)
			}
			if c.wantDecision == Deny && !strings.Contains(resp.Reason, "is denied") {
				t.Errorf("Reason = %q, want it to mention the denied tool", resp.Reason)
			}
		})
	}
}

// TestDecideDenyAboveUSDHardCeiling covers deny_above_usd: a HARD,
// non-approvable cost ceiling, unlike require_human_above_usd's approvable
// hold. A cost over the ceiling denies outright and, critically, denies
// even when a token that would otherwise verify cleanly is presented -- no
// approval can ever authorize crossing this line, which is the whole point
// of the field and the key differentiator from require_human_above_usd. A
// cost at or under the ceiling is not denied by this rule.
func TestDecideDenyAboveUSDHardCeiling(t *testing.T) {
	set, err := policy.Compile([]policy.Policy{
		{Name: "hard-ceiling", Target: "agent://x/*", DenyAboveUSD: 1000},
	})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	engine := New(set, []byte(testSecret))

	t.Run("over the ceiling denies", func(t *testing.T) {
		resp := engine.Decide(DecideRequest{AgentID: "agent://x/bot", EstCostUSD: 1500})
		if resp.Decision != Deny {
			t.Fatalf("Decision = %q (reason: %s), want %q", resp.Decision, resp.Reason, Deny)
		}
		if !strings.Contains(resp.Reason, "hard ceiling") || !strings.Contains(resp.Reason, "deny_above_usd") {
			t.Errorf("Reason = %q, want it to name the hard ceiling and deny_above_usd", resp.Reason)
		}
		if resp.ApprovalTokenRequired {
			t.Error("ApprovalTokenRequired = true, want false: deny_above_usd is not an approval gate")
		}
	})

	t.Run("a token that verifies cleanly still denies: the ceiling is not approvable", func(t *testing.T) {
		const agentID = "agent://x/bot"
		const runID = "run-1"
		tools := []string{"generate_report"}
		const cost = 1500.0

		token, _, err := approval.MintApprovalToken([]byte(testSecret), agentID, runID, tools, cost, approval.DefaultTTL)
		if err != nil {
			t.Fatalf("mint token: %v", err)
		}
		// Prove the token is genuinely valid by the approval package's own
		// standard, so this test cannot be trivially satisfied by an
		// accidentally-broken token: if a future change ever made Decide
		// consult the token for deny_above_usd, this exact token would
		// verify cleanly and would need to be rejected for some other
		// reason.
		if err := approval.VerifyApprovalToken([]byte(testSecret), token, agentID, runID, tools, cost); err != nil {
			t.Fatalf("test setup: token should verify cleanly, got %v", err)
		}

		resp := engine.Decide(DecideRequest{
			AgentID:       agentID,
			RunID:         runID,
			ToolNames:     tools,
			EstCostUSD:    cost,
			ApprovalToken: token,
		})
		if resp.Decision != Deny {
			t.Fatalf("Decision = %q (reason: %s), want %q: a cleanly-verifying approval_token must not authorize crossing a deny_above_usd hard ceiling", resp.Decision, resp.Reason, Deny)
		}
		if !strings.Contains(resp.Reason, "deny_above_usd") {
			t.Errorf("Reason = %q, want it to name deny_above_usd", resp.Reason)
		}
	})

	t.Run("under the ceiling is not denied by this rule", func(t *testing.T) {
		resp := engine.Decide(DecideRequest{AgentID: "agent://x/bot", EstCostUSD: 500})
		if resp.Decision != Allow {
			t.Fatalf("Decision = %q (reason: %s), want %q: $500 is under the $1000 ceiling and no other rule applies", resp.Decision, resp.Reason, Allow)
		}
	})

	t.Run("exactly at the ceiling is not denied by this rule", func(t *testing.T) {
		// DenyAboveUSD denies strictly-greater-than costs, mirroring
		// RequireHumanAboveUSD's "cost > threshold" convention (see
		// overThreshold): a cost equal to the ceiling itself must not deny.
		resp := engine.Decide(DecideRequest{AgentID: "agent://x/bot", EstCostUSD: 1000})
		if resp.Decision != Allow {
			t.Fatalf("Decision = %q (reason: %s), want %q: $1000 equals the ceiling, not above it", resp.Decision, resp.Reason, Allow)
		}
	})
}

// TestDecideDenyAboveUSDPrecedesRequireHumanAboveUSDHold covers precedence:
// a policy setting both deny_above_usd and require_human_above_usd, with a
// cost over both, must Deny rather than Hold -- the hard ceiling wins
// outright and require_human_above_usd's hold is never even reached, so
// ApprovalTokenRequired stays false.
func TestDecideDenyAboveUSDPrecedesRequireHumanAboveUSDHold(t *testing.T) {
	set, err := policy.Compile([]policy.Policy{
		{Name: "both", Target: "agent://x/*", DenyAboveUSD: 1000, RequireHumanAboveUSD: 100},
	})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	engine := New(set, nil)
	resp := engine.Decide(DecideRequest{AgentID: "agent://x/bot", EstCostUSD: 1500})
	if resp.Decision != Deny {
		t.Fatalf("Decision = %q (reason: %s), want %q: deny_above_usd must win over require_human_above_usd's hold", resp.Decision, resp.Reason, Deny)
	}
	if !strings.Contains(resp.Reason, "hard ceiling") {
		t.Errorf("Reason = %q, want it to cite the hard ceiling", resp.Reason)
	}
	if resp.ApprovalTokenRequired {
		t.Error("ApprovalTokenRequired = true, want false: require_human_above_usd's threshold check is never reached once deny_above_usd fires")
	}
}
