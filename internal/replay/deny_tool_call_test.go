package replay

import (
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// A decision recorded as allowed, whose tool call names a tool the deny-list now
// refuses, was a call the deny-list should have refused. Replay puts the recorded
// tool call back, reaches the deny, and reports it as a divergence rather than
// reproducing the old allow. That is the honest answer: the record is a bypass.

// TestARecordedAllowWhoseToolCallIsNowDeniedDiverges is the scenario "A recorded
// allow whose tool call is now denied replays as a divergence".
func TestARecordedAllowWhoseToolCallIsNowDeniedDiverges(t *testing.T) {
	set, err := policy.Compile([]policy.Policy{{
		Name: "finance-deny", Target: "agent://acme.example/finance/*",
		DenyTool: []string{"send_wire_transfer"},
	}})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	ev := decisionEvent("policy_allow", set.Version(), "allowed: request satisfies all matched policy rules", map[string]any{
		"tool_names": []any{"search"},
		"tool_call": map[string]any{
			"name": "send_wire_transfer", "target": "https://bank.example",
			"arguments_sha256": "00", "arguments_truncated": false, "digest": "00",
		},
	})
	ev.AgentID = "agent://acme.example/finance/bot1"

	report := Run([]event.Event{ev}, archiveOf(t, set), nil)
	if report.Diverged != 1 || report.Reproduced != 0 {
		t.Fatalf("a recorded allow whose tool call the deny-list refuses must diverge, not reproduce:\n%s", Format(report, "x", ""))
	}
}
