package replay

import (
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// A denial by an allow-list names, in the tool call the event records beside the
// tool list, the tool the list leaves out. Replay has to put that name back to
// the PDP, or the same denial would replay as an allow and be reported as a
// divergence.

const allowShopAgent = "agent://acme.example/shop/bot1"

const allowShopReason = `tool "apply_staff_coupon" is not in the allow_tool of policy "shop" (target agent://acme.example/shop/*)`

func allowShopSet(t *testing.T) *policy.Set {
	t.Helper()
	set, err := policy.Compile([]policy.Policy{{
		Name: "shop", Target: "agent://acme.example/shop/*", AllowTool: []string{"search"},
	}})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	return set
}

func allowShopDenial(version string, toolCall any) event.Event {
	data := map[string]any{"tool_names": []any{"search"}}
	if toolCall != nil {
		data["tool_call"] = toolCall
	}
	ev := decisionEvent("policy_deny", version, allowShopReason, data)
	ev.AgentID = allowShopAgent
	return ev
}

func recordedCall(name string) map[string]any {
	return map[string]any{
		"name": name, "target": "https://shop.example/coupons",
		"arguments_sha256": "00", "arguments_truncated": false, "digest": "00",
	}
}

// TestAnAllowToolDenialReplaysFromTheRecord is the scenario "A recorded
// allow-list denial replays to the same verdict".
func TestAnAllowToolDenialReplaysFromTheRecord(t *testing.T) {
	set := allowShopSet(t)
	report := Run([]event.Event{allowShopDenial(set.Version(), recordedCall("apply_staff_coupon"))}, archiveOf(t, set), nil)
	if report.Reproduced != 1 || report.Diverged != 0 || report.Unreadable != 0 {
		t.Fatalf("the recorded allow-list denial did not reproduce:\n%s", Format(report, "x", ""))
	}
}

// Without the recorded tool call the same record replays as an allow: the
// divergence the record exists to prevent, and the test that goes red when
// replay stops feeding the tool call back.
func TestAnAllowToolDenialWithoutItsRecordedCallIsADivergence(t *testing.T) {
	set := allowShopSet(t)
	report := Run([]event.Event{allowShopDenial(set.Version(), nil)}, archiveOf(t, set), nil)
	if report.Diverged != 1 {
		t.Fatalf("a denial whose tool call was not recorded must diverge, not reproduce:\n%s", Format(report, "x", ""))
	}
}

// A tool call that is not the shape the emitter writes is not a question that
// can be put again, and replay says so by name rather than guessing a name.
func TestAMalformedRecordedToolCallIsUnreadableNotGuessed(t *testing.T) {
	set := allowShopSet(t)
	cases := map[string]any{
		"not an object":   "apply_staff_coupon",
		"no name":         map[string]any{"target": "https://shop.example/coupons"},
		"blank name":      map[string]any{"name": "   "},
		"target not text": map[string]any{"name": "apply_staff_coupon", "target": 7},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			report := Run([]event.Event{allowShopDenial(set.Version(), call)}, archiveOf(t, set), nil)
			if report.Unreadable != 1 {
				t.Fatalf("a malformed tool_call must be unreadable, not replayed:\n%s", Format(report, "x", ""))
			}
		})
	}
}
