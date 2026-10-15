package replay

import (
	"encoding/json"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// A hold on an absent signal was caused by what did NOT arrive, so the record
// of it carries no signals at all. What it carries is the tool call, and replay
// puts that back: the same set holds again, and without the recorded call the
// same record replays as an allow, which is a divergence and is reported as one.

func absentSet(t *testing.T) *policy.Set {
	t.Helper()
	var r policy.SignalRule
	if err := json.Unmarshal([]byte(`{"name":"action.risk_class","values":["destructive"],"min_probability":0.8,"when_absent":"hold"}`), &r); err != nil {
		t.Fatalf("the rule with when_absent did not decode: %v", err)
	}
	set, err := policy.Compile([]policy.Policy{{Name: "risk", Target: "agent://acme.example/finance/*", HoldIfSignal: &r}})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	return set
}

func absentHoldEvent(version string, toolCall any) event.Event {
	reason := `policy "risk" hold_if_signal: no "action.risk_class" signal came with tool call "ask", whose arguments were not sent (arguments_truncated), and the rule holds when the signal is absent (when_absent: hold); human approval required`
	data := map[string]any{"approval_token_required": true, "tool_names": []any{"ask"}}
	if toolCall != nil {
		data["tool_call"] = toolCall
	}
	return decisionEvent("approval_requested", version, reason, data)
}

func recordedTruncatedCall() map[string]any {
	return map[string]any{"name": "ask", "target": "ask-upstream", "arguments_sha256": "00", "arguments_truncated": true, "digest": "00"}
}

func TestARecordedAbsentSignalHoldReproducesFromTheRecordedToolCall(t *testing.T) {
	set := absentSet(t)
	report := Run([]event.Event{absentHoldEvent(set.Version(), recordedTruncatedCall())}, archiveOf(t, set), nil)
	if report.Reproduced != 1 || report.Diverged != 0 || report.Unreadable != 0 {
		t.Fatalf("the recorded absent-signal hold did not reproduce:\n%s", Format(report, "x", ""))
	}
	// Without the recorded call the question is a model call, which absence
	// never holds: the record and the replay disagree, and replay says so.
	report = Run([]event.Event{absentHoldEvent(set.Version(), nil)}, archiveOf(t, set), nil)
	if report.Diverged != 1 {
		t.Fatalf("an absent-signal hold with no recorded tool call must diverge, not reproduce:\n%s", Format(report, "x", ""))
	}
}
