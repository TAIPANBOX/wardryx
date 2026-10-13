package pdp

import (
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// These tests hold the deny-list to every tool name a request carries, the tool
// list and the name of its tool call, the same as the allow-list
// (features/deny-tool-call.feature). They use allowEngine and allow_tool_test.go's
// helpers, so they sit beside the allow-list suite.

const denyCallAgent = "agent://acme.example/finance/bot1"

func denyCallEngine(t *testing.T) *Engine {
	t.Helper()
	return allowEngine(t, policy.Policy{
		Name: "finance-deny", Target: "agent://acme.example/finance/*",
		DenyTool: []string{"send_wire_transfer"},
	})
}

// TestADeniedToolNamedOnlyByTheToolCallIsDenied is the scenario "A denied tool
// named only by the tool call is denied". The measured case: the tool list is
// benign and tool_call.name is on the deny-list. Before this change the call was
// allowed. The reason is pinned, because replay compares it byte for byte.
func TestADeniedToolNamedOnlyByTheToolCallIsDenied(t *testing.T) {
	resp := denyCallEngine(t).Decide(DecideRequest{
		AgentID: denyCallAgent, RunID: "r1", ToolNames: []string{"search"},
		ToolCall: &ToolCall{Name: "send_wire_transfer", Target: "https://bank.example"},
	})
	want := `tool "send_wire_transfer" is denied by policy "finance-deny" (target agent://acme.example/finance/*)`
	if resp.Decision != Deny || resp.Reason != want {
		t.Fatalf("Decision = %q, Reason = %q; want deny with reason %q: the tool call names a denied tool", resp.Decision, resp.Reason, want)
	}
}

// TestADenyToolDecisionForACallIsNeverCacheable is the scenario "A decision that
// reads a tool call is never served from a cache". A cached allow for the tool
// list would otherwise be served to a later call whose tool call names a denied
// tool, since the tool call is outside the (agent, tool set) key. Both outcomes
// are checked: the refused call and the allowed call are both per-call.
func TestADenyToolDecisionForACallIsNeverCacheable(t *testing.T) {
	e := denyCallEngine(t)

	refused := e.Decide(DecideRequest{
		AgentID: denyCallAgent, RunID: "r1", ToolNames: []string{"search"},
		ToolCall: &ToolCall{Name: "send_wire_transfer", Target: "https://bank.example"},
	})
	if refused.Decision != Deny {
		t.Fatalf("Decision = %q (reason %q), want deny for a tool call naming a denied tool", refused.Decision, refused.Reason)
	}
	if refused.Cacheable {
		t.Fatal("Cacheable = true for a refused tool call: a cache would reuse it for another call with the same tool list")
	}

	allowed := e.Decide(DecideRequest{
		AgentID: denyCallAgent, RunID: "r1", ToolNames: []string{"search"},
		ToolCall: &ToolCall{Name: "search", Target: "https://search.example"},
	})
	if allowed.Decision != Allow {
		t.Fatalf("Decision = %q (reason %q), want allow for a tool call naming a listed tool", allowed.Decision, allowed.Reason)
	}
	if allowed.Cacheable {
		t.Fatal("Cacheable = true for an allowed tool call under a deny-list: a later call naming a denied tool would be served it")
	}
}

// TestWithoutAToolCallADenyToolDecisionIsStillCacheable is the golden for the
// scenario "A request with no tool call keeps its cacheability": a request that
// carries no tool call decides, and is cached, exactly as it did before the
// deny-list read tool call names. Both an allow and a deny are checked.
func TestWithoutAToolCallADenyToolDecisionIsStillCacheable(t *testing.T) {
	e := denyCallEngine(t)

	allowed := e.Decide(DecideRequest{AgentID: denyCallAgent, RunID: "r1", ToolNames: []string{"search"}})
	if allowed.Decision != Allow || !allowed.Cacheable {
		t.Fatalf("no tool call, allowed: Decision = %q, Cacheable = %v; want allow and cacheable", allowed.Decision, allowed.Cacheable)
	}

	refused := e.Decide(DecideRequest{AgentID: denyCallAgent, RunID: "r1", ToolNames: []string{"send_wire_transfer"}})
	if refused.Decision != Deny || !refused.Cacheable {
		t.Fatalf("no tool call, refused by the tool list: Decision = %q, Cacheable = %v; want deny and cacheable", refused.Decision, refused.Cacheable)
	}
}
