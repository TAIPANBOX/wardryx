package pdp

import (
	"strings"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// These tests hold the allow-list rule (features/allow-tool.feature): a policy
// that names the only tools its agents may use. They sit beside signal_test.go
// and approval_call_test.go, and use the same token secret those files use.

const allowAgent = "agent://acme.example/shop/bot1"

func allowEngine(t *testing.T, pols ...policy.Policy) *Engine {
	t.Helper()
	set, err := policy.Compile(pols)
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	return New(set, []byte("signal-test-secret"))
}

func shopPolicy(allow ...string) policy.Policy {
	return policy.Policy{Name: "shop", Target: "agent://acme.example/shop/*", AllowTool: allow}
}

// TestAToolOnTheAllowListIsAllowed is the scenario "A tool on the allow-list is
// allowed".
func TestAToolOnTheAllowListIsAllowed(t *testing.T) {
	e := allowEngine(t, shopPolicy("apply_staff_coupon"))
	resp := e.Decide(DecideRequest{AgentID: allowAgent, RunID: "r1", ToolNames: []string{"apply_staff_coupon"}})
	if resp.Decision != Allow {
		t.Fatalf("Decision = %q (reason %q), want allow: the tool is on the list", resp.Decision, resp.Reason)
	}
}

// TestAToolTheListLeavesOutIsDeniedByName is the scenario "A tool the list
// leaves out is denied, and the reason names the rule and the tool". The exact
// reason is pinned, because replay compares it byte for byte.
func TestAToolTheListLeavesOutIsDeniedByName(t *testing.T) {
	e := allowEngine(t, shopPolicy("search", "lookup"))
	resp := e.Decide(DecideRequest{AgentID: allowAgent, RunID: "r1", ToolNames: []string{"shell"}})
	want := `tool "shell" is not in the allow_tool of policy "shop" (target agent://acme.example/shop/*)`
	if resp.Decision != Deny || resp.Reason != want {
		t.Fatalf("Decision = %q, Reason = %q; want deny with reason %q", resp.Decision, resp.Reason, want)
	}
}

// TestNoAllowListMeansNoRestriction is the scenario "No allow-list means no
// restriction". An absent list and an explicit empty one must both restrict
// nothing: an empty list read as deny-all would break every existing policy
// that never set the field.
func TestNoAllowListMeansNoRestriction(t *testing.T) {
	cases := map[string]*Engine{
		"absent": allowEngine(t, policy.Policy{Name: "shop", Target: "agent://acme.example/shop/*"}),
		"empty":  allowEngine(t, policy.Policy{Name: "shop", Target: "agent://acme.example/shop/*", AllowTool: []string{}}),
	}
	for name, e := range cases {
		resp := e.Decide(DecideRequest{AgentID: allowAgent, RunID: "r1", ToolNames: []string{"shell", "anything"}})
		if resp.Decision != Allow {
			t.Fatalf("%s allow_tool: Decision = %q (reason %q), want allow: no list means no restriction", name, resp.Decision, resp.Reason)
		}
	}
}

// TestTwoAllowListsNarrowEachOther is the scenario "Two policies narrow each
// other". A tool must be listed by every matched allow-list that applies, so
// two lists intersect, and a matched policy with no list adds no restriction.
// A union would allow "search" here, which is the planted mutant this catches.
func TestTwoAllowListsNarrowEachOther(t *testing.T) {
	e := allowEngine(t,
		policy.Policy{Name: "a", Target: "agent://acme.example/*", AllowTool: []string{"search", "lookup"}},
		policy.Policy{Name: "b", Target: "agent://acme.example/shop/*", AllowTool: []string{"lookup", "refund"}},
		policy.Policy{Name: "c", Target: "agent://acme.example/shop/*"},
	)
	cases := []struct {
		tool string
		want string
	}{
		{"lookup", Allow}, // both lists name it
		{"search", Deny},  // only a names it
		{"refund", Deny},  // only b names it
		{"shell", Deny},   // neither names it
	}
	for _, c := range cases {
		resp := e.Decide(DecideRequest{AgentID: allowAgent, RunID: "r1", ToolNames: []string{c.tool}})
		if resp.Decision != c.want {
			t.Fatalf("tool %q: Decision = %q (reason %q), want %q: every matched allow-list must list the tool", c.tool, resp.Decision, resp.Reason, c.want)
		}
	}
}

// TestToolCallNameIsCheckedAgainstTheAllowList is the scenario "The tool named
// in the broker's call is checked too". The MCP broker sends tool_call.name
// beside the tool list, and a call that names an unlisted tool must be denied
// even when the list itself names only listed tools.
func TestToolCallNameIsCheckedAgainstTheAllowList(t *testing.T) {
	e := allowEngine(t, shopPolicy("search"))

	listedList := e.Decide(DecideRequest{
		AgentID: allowAgent, RunID: "r1", ToolNames: []string{"search"},
		ToolCall: &ToolCall{Name: "apply_staff_coupon", Target: "https://shop.example/coupons"},
	})
	if listedList.Decision != Deny || !strings.Contains(listedList.Reason, `"apply_staff_coupon"`) {
		t.Fatalf("Decision = %q (reason %q), want deny naming the tool call: tool_call.name is not checked", listedList.Decision, listedList.Reason)
	}

	unlistedList := e.Decide(DecideRequest{
		AgentID: allowAgent, RunID: "r1", ToolNames: []string{"apply_staff_coupon"},
		ToolCall: &ToolCall{Name: "search", Target: "https://shop.example/search"},
	})
	if unlistedList.Decision != Deny {
		t.Fatalf("Decision = %q (reason %q), want deny: the tool list names a tool the list leaves out", unlistedList.Decision, unlistedList.Reason)
	}

	listed := e.Decide(DecideRequest{
		AgentID: allowAgent, RunID: "r1", ToolNames: []string{"search"},
		ToolCall: &ToolCall{Name: "search", Target: "https://shop.example/search"},
	})
	if listed.Decision != Allow {
		t.Fatalf("Decision = %q (reason %q), want allow: the tool and the call both name a listed tool", listed.Decision, listed.Reason)
	}
}

// TestAllowToolFoldsCaseLikeDenyTool is the scenario "Matching follows the case
// rule the deny-list already uses". The same request must match the same way
// under deny_tool and allow_tool, and a separator variant must not match at all.
func TestAllowToolFoldsCaseLikeDenyTool(t *testing.T) {
	allow := allowEngine(t, shopPolicy("apply_staff_coupon"))
	deny := allowEngine(t, policy.Policy{Name: "shop", Target: "agent://acme.example/shop/*", DenyTool: []string{"apply_staff_coupon"}})

	upper := DecideRequest{AgentID: allowAgent, RunID: "r1", ToolNames: []string{"APPLY_STAFF_COUPON"}}
	if got := allow.Decide(upper); got.Decision != Allow {
		t.Fatalf("allow_tool: Decision = %q (reason %q) for the upper-case name, want allow: the fold matches deny_tool's", got.Decision, got.Reason)
	}
	if got := deny.Decide(upper); got.Decision != Deny {
		t.Fatalf("deny_tool: Decision = %q for the upper-case name, want deny: the fold this rule is held to", got.Decision)
	}

	separator := DecideRequest{AgentID: allowAgent, RunID: "r1", ToolNames: []string{"apply-staff-coupon"}}
	if got := allow.Decide(separator); got.Decision != Deny {
		t.Fatalf("Decision = %q (reason %q) for the hyphenated name, want deny: separators are not folded", got.Decision, got.Reason)
	}
}

// TestDenyToolWinsOverAllowTool is the scenario "A tool that both lists deny is
// denied by the deny-list". Rule 2 runs before rule 3, so the reason names
// deny_tool, not allow_tool.
func TestDenyToolWinsOverAllowTool(t *testing.T) {
	e := allowEngine(t, policy.Policy{
		Name: "shop", Target: "agent://acme.example/shop/*",
		DenyTool: []string{"shell"}, AllowTool: []string{"shell", "search"},
	})
	resp := e.Decide(DecideRequest{AgentID: allowAgent, RunID: "r1", ToolNames: []string{"shell"}})
	want := `tool "shell" is denied by policy "shop" (target agent://acme.example/shop/*)`
	if resp.Decision != Deny || resp.Reason != want {
		t.Fatalf("Decision = %q, Reason = %q; want deny by deny_tool with reason %q", resp.Decision, resp.Reason, want)
	}
}

// TestAnApprovalDoesNotLiftAnAllowListDenial is the scenario "A valid approval
// does not lift an allow-list denial". The allow-list is a floor like deny_tool:
// it runs before the cost gate, so a valid token for the very call is never
// inspected. The control request, with the same token shape on a listed tool,
// shows the token itself is valid.
func TestAnApprovalDoesNotLiftAnAllowListDenial(t *testing.T) {
	e := allowEngine(t, policy.Policy{
		Name: "shop", Target: "agent://acme.example/shop/*",
		RequireHumanAboveUSD: usd(100), AllowTool: []string{"search"},
	})

	refused := DecideRequest{AgentID: allowAgent, RunID: "r1", ToolNames: []string{"shell"}, EstCostUSD: 500}
	refused.ApprovalToken = mintFor(t, refused, 500)
	if got := e.Decide(refused); got.Decision != Deny || !strings.Contains(got.Reason, "allow_tool") {
		t.Fatalf("Decision = %q (reason %q), want deny by allow_tool: an approval must not lift it", got.Decision, got.Reason)
	}

	control := DecideRequest{AgentID: allowAgent, RunID: "r1", ToolNames: []string{"search"}, EstCostUSD: 500}
	control.ApprovalToken = mintFor(t, control, 500)
	if got := e.Decide(control); got.Decision != Allow {
		t.Fatalf("control: Decision = %q (reason %q), want allow: the same token lifts the cost hold for a listed tool", got.Decision, got.Reason)
	}
}

// TestAnAllowToolDecisionIsNeverCacheable: the decision reads tool_call.name,
// which is a per-call value and not part of the agent and tool set an
// enforcement point's cache keys on, so a decision under an allow-list is
// marked not cacheable, the same as a signal-dependent one.
func TestAnAllowToolDecisionIsNeverCacheable(t *testing.T) {
	e := allowEngine(t, shopPolicy("search"))
	resp := e.Decide(DecideRequest{AgentID: allowAgent, RunID: "r1", ToolNames: []string{"search"}})
	if resp.Decision != Allow {
		t.Fatalf("Decision = %q (reason %q), want allow for the listed tool", resp.Decision, resp.Reason)
	}
	if resp.Cacheable {
		t.Fatal("Cacheable = true under an allow-list: a cache keyed on agent and tool set would reuse it for a call naming another tool")
	}
}

// TestFilterReportsAToolOutsideTheAllowList is the pdp half of the scenario "The
// filter reports a tool outside the list". Each denied tool names the rule that
// refused it, and a tool the deny-list refuses still reports deny_tool.
func TestFilterReportsAToolOutsideTheAllowList(t *testing.T) {
	e := allowEngine(t, policy.Policy{
		Name: "shop", Target: "agent://acme.example/shop/*",
		DenyTool: []string{"email_send"}, AllowTool: []string{"search", "email_send"},
	})
	resp := e.Filter(FilterRequest{AgentID: allowAgent, RunID: "r1", ToolNames: []string{"search", "shell", "email_send"}})

	if len(resp.Allowed) != 1 || resp.Allowed[0] != "search" {
		t.Fatalf("Allowed = %v, want [search]", resp.Allowed)
	}
	want := []DeniedTool{
		{Name: "shell", Policy: "shop", Rule: "allow_tool"},
		{Name: "email_send", Policy: "shop", Rule: "deny_tool"},
	}
	if len(resp.Denied) != len(want) {
		t.Fatalf("Denied = %+v, want %+v", resp.Denied, want)
	}
	for i := range want {
		if resp.Denied[i] != want[i] {
			t.Fatalf("Denied[%d] = %+v, want %+v", i, resp.Denied[i], want[i])
		}
	}
}
