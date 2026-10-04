package replay

import (
	"strings"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// A decision that read a typed signal records it, and replay puts the recorded
// signal back to the PDP. The service that first produced it is not asked
// again: this package cannot reach it (scripts/decision-path-purity.sh), and
// these tests hold the other half, that what was recorded is enough.

func riskSet(t *testing.T) *policy.Set {
	t.Helper()
	min := 0.8
	set, err := policy.Compile([]policy.Policy{{
		Name: "risk", Target: "agent://acme.example/finance/*",
		HoldIfSignal: &policy.SignalRule{Name: "action.risk_class", Values: []string{"destructive"}, MinProbability: &min},
	}})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	return set
}

func signalHoldEvent(version string, signals any) event.Event {
	reason := `policy "risk" hold_if_signal: signal "action.risk_class" is "destructive" at probability 0.95 (the rule holds from 0.8); human approval required`
	data := map[string]any{"approval_token_required": true}
	if signals != nil {
		data["signals"] = signals
	}
	return decisionEvent("approval_requested", version, reason, data)
}

func destructiveSignal() []any {
	return []any{map[string]any{"name": "action.risk_class", "value": "destructive", "probability": 0.95, "source": "classifier", "answer_id": "ans-1"}}
}

func TestARecordedSignalIsFedBackAndTheHoldReproduces(t *testing.T) {
	set := riskSet(t)
	report := Run([]event.Event{signalHoldEvent(set.Version(), destructiveSignal())}, archiveOf(t, set), nil)
	if report.Reproduced != 1 || report.Diverged != 0 || report.Unreadable != 0 {
		t.Fatalf("the recorded signal hold did not reproduce:\n%s", Format(report, "x", ""))
	}
}

// Without the recorded signal the same record replays as an allow, which is
// the divergence the record exists to prevent. This is the test that goes red
// when replay stops feeding the signal back.
func TestAHoldWhoseSignalWasNotRecordedIsADivergenceNotAReproduction(t *testing.T) {
	set := riskSet(t)
	report := Run([]event.Event{signalHoldEvent(set.Version(), nil)}, archiveOf(t, set), nil)
	if report.Diverged != 1 {
		t.Fatalf("a signal hold with no recorded signal must diverge, not reproduce:\n%s", Format(report, "x", ""))
	}
}

func TestACandidateWithoutTheRuleChangesTheRecordedHold(t *testing.T) {
	set := riskSet(t)
	plain, err := policy.Compile([]policy.Policy{{Name: "plain", Target: "agent://acme.example/finance/*", DenyTool: []string{"x"}}})
	if err != nil {
		t.Fatal(err)
	}
	report := Run([]event.Event{signalHoldEvent(set.Version(), destructiveSignal())}, archiveOf(t, set), plain)
	if report.Changed != 1 || report.Rows[0].Candidate.Decision != pdp.Allow {
		t.Fatalf("the recorded signal did not reach the candidate:\n%s", Format(report, "x", "plain"))
	}
}

func TestADecisionThatRecordedNoSignalsReplaysAsBefore(t *testing.T) {
	inForce := compile(t, []string{"good.example.com"}, 500)
	report := Run([]event.Event{
		decisionEvent("policy_deny", inForce.Version(),
			`domain "payouts.evil.example" is not allowed by policy "finance-guardrail" (target agent://acme.example/finance/*)`, nil),
	}, archiveOf(t, inForce), nil)
	if report.Reproduced != 1 {
		t.Fatalf("a record with no signals key stopped reproducing:\n%s", Format(report, "x", ""))
	}
}

// A record whose signals are not what the emitter writes is not a question
// that can be put again, and replay says so by name instead of guessing.
func TestMalformedRecordedSignalsAreUnreadableNotGuessed(t *testing.T) {
	set := riskSet(t)
	cases := map[string]any{
		"not a list":              "destructive",
		"an item that is text":    []any{"destructive"},
		"no probability":          []any{map[string]any{"name": "action.risk_class", "value": "destructive", "source": "classifier"}},
		"a string probability":    []any{map[string]any{"name": "action.risk_class", "value": "destructive", "probability": "0.95", "source": "classifier"}},
		"a probability above one": []any{map[string]any{"name": "action.risk_class", "value": "destructive", "probability": 1.5, "source": "classifier"}},
		"no name":                 []any{map[string]any{"value": "destructive", "probability": 0.95, "source": "classifier"}},
	}
	for name, signals := range cases {
		t.Run(name, func(t *testing.T) {
			report := Run([]event.Event{signalHoldEvent(set.Version(), signals)}, archiveOf(t, set), nil)
			if report.Unreadable != 1 {
				t.Fatalf("malformed recorded signals should be unreadable:\n%s", Format(report, "x", ""))
			}
			if !strings.Contains(report.Rows[0].Note, "signals") {
				t.Errorf("the note does not name the signals: %q", report.Rows[0].Note)
			}
		})
	}
}
