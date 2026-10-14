package pdp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/approval"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// A hold_if_signal rule reads a signal that somebody else produces. When that
// signal does not arrive, the rule has nothing to read, and by default the call
// goes on as if it had been harmless. It does not arrive when the enforcement
// point left the arguments out for their size (arguments_truncated), when the
// producer's own budget is spent, when it timed out, or when it is down: each is
// a way for a caller to make a call that no signal rule can hold.
//
// when_absent: hold closes that. A tool call that carries no signal of the
// rule's name holds, for a person to approve, and only an approval of that call
// lifts it. A request with no tool call (a model call) is never held for it, and
// nothing about it can deny.

// absentPolicy is riskPolicy with its rule decoded from the text an operator
// writes, carrying when_absent.
func absentPolicy(t *testing.T, whenAbsent string) policy.Policy {
	t.Helper()
	doc := `{"name":"action.risk_class","values":["destructive","external_send","financial"],"min_probability":0.8,"when_absent":"` + whenAbsent + `"}`
	var r policy.SignalRule
	if err := json.Unmarshal([]byte(doc), &r); err != nil {
		t.Fatalf("the rule with when_absent: %s did not decode: %v", whenAbsent, err)
	}
	p := riskPolicy()
	p.HoldIfSignal = &r
	return p
}

// brokerCall is the tool call TokenFuse's MCP broker sends for a tools/call
// whose arguments are over its cap: the name, the upstream target, the flag,
// and no arguments.
func brokerCall(sigs ...Signal) DecideRequest {
	return DecideRequest{
		AgentID:   signalAgent,
		RunID:     "mcp:" + signalAgent,
		ToolNames: []string{"ask"},
		Signals:   sigs,
		ToolCall:  &ToolCall{Name: "ask", Target: "typryx", ArgumentsTruncated: true},
	}
}

func TestAToolCallWithNoSignalHoldsWhenTheRuleHoldsOnAbsence(t *testing.T) {
	// The bypass as it stands without the option: the call is allowed.
	if got := signalEngine(t, riskPolicy()).Decide(brokerCall()); got.Decision != Allow {
		t.Fatalf("control: with when_absent left out a truncated call with no signal is %s (%s), want allow, the default", got.Decision, got.Reason)
	}
	if got := signalEngine(t, absentPolicy(t, "allow")).Decide(brokerCall()); got.Decision != Allow {
		t.Fatalf("when_absent: allow is the default and must allow: %s (%s)", got.Decision, got.Reason)
	}

	e := signalEngine(t, absentPolicy(t, "hold"))
	got := e.Decide(brokerCall())
	if got.Decision != Hold || !got.ApprovalTokenRequired {
		t.Fatalf("a truncated tool call with no signal under when_absent: hold is %s (%s) tokenRequired=%v, want a hold a person can approve", got.Decision, got.Reason, got.ApprovalTokenRequired)
	}
	for _, want := range []string{`policy "risk"`, "hold_if_signal", `"action.risk_class"`, `tool call "ask"`, "arguments_truncated", "when_absent: hold", "human approval required"} {
		if !strings.Contains(got.Reason, want) {
			t.Errorf("reason %q does not say %q", got.Reason, want)
		}
	}

	// The other ways a signal goes missing look the same here: a call whose
	// arguments were sent, and a call with only signals the rule does not read.
	whole := toolCallRequest()
	if got := e.Decide(whole); got.Decision != Hold || strings.Contains(got.Reason, "arguments_truncated") {
		t.Fatalf("a whole call with no signal: %s (%s), want a hold that does not claim truncation", got.Decision, got.Reason)
	}
	other := Signal{Name: "request.complexity", Value: "high", Probability: 0.99, Source: "classifier"}
	if got := e.Decide(toolCallRequest(other)); got.Decision != Hold {
		t.Fatalf("a call carrying only a signal the rule does not read: %s (%s), want hold", got.Decision, got.Reason)
	}
}

// The model path carries no tool call: no call has been chosen, so no signal
// about one could exist, and holding there would hold every model call.
func TestAModelCallWithNoToolCallIsNeverHeldForAMissingSignal(t *testing.T) {
	e := signalEngine(t, absentPolicy(t, "hold"))
	for name, req := range map[string]DecideRequest{
		"a model call with offered tools": {AgentID: signalAgent, RunID: "run-1", ToolNames: []string{"s3.delete_object", "ask"}, Model: "m"},
		"a request with nothing in it":    {AgentID: signalAgent, RunID: "run-1"},
	} {
		got := e.Decide(req)
		if got.Decision != Allow || got.ApprovalTokenRequired {
			t.Errorf("%s under when_absent: hold: %s (%s) tokenRequired=%v, want a plain allow", name, got.Decision, got.Reason, got.ApprovalTokenRequired)
		}
	}
}

// Absence adds a hold and nothing else: a deny stays the same deny, another
// rule's hold keeps its reason, and a token that does not verify holds again.
func TestAnAbsentSignalOnlyEverHolds(t *testing.T) {
	deny := absentPolicy(t, "hold")
	deny.DenyTool = []string{"ask"}
	plainDeny := riskPolicy()
	plainDeny.DenyTool = []string{"ask"}
	want := signalEngine(t, plainDeny).Decide(brokerCall())
	if got := signalEngine(t, deny).Decide(brokerCall()); got.Decision != Deny || got.Reason != want.Reason || want.Decision != Deny {
		t.Fatalf("a deny under when_absent: hold became %s (%s), want the same deny %q", got.Decision, got.Reason, want.Reason)
	}

	cost := absentPolicy(t, "hold")
	cost.RequireHumanAboveUSD = f64(10)
	plainCost := riskPolicy()
	plainCost.RequireHumanAboveUSD = f64(10)
	req := brokerCall()
	req.EstCostUSD = 50
	want = signalEngine(t, plainCost).Decide(req)
	if got := signalEngine(t, cost).Decide(req); got.Decision != Hold || got.Reason != want.Reason {
		t.Fatalf("a cost hold under when_absent: hold became %s (%s), want %q", got.Decision, got.Reason, want.Reason)
	}

	e := signalEngine(t, absentPolicy(t, "hold"))
	for name, tok := range map[string]string{
		"garbage":            "not-a-token",
		"another run's":      mustToken(t, approval.MintApprovalTokenForCall, "another-run", brokerCall().ToolCall.Digest()),
		"another call's":     mustToken(t, approval.MintApprovalTokenForCall, brokerCall().RunID, (&ToolCall{Name: "ask", Target: "elsewhere", ArgumentsTruncated: true}).Digest()),
		"signed by somebody": forgedToken(t),
	} {
		r := brokerCall()
		r.ApprovalToken = tok
		if got := e.Decide(r); got.Decision != Hold {
			t.Errorf("%s token on an absent-signal hold: %s (%s), want hold, never deny", name, got.Decision, got.Reason)
		}
	}
}

// A signal of the rule's name that arrived is present, whatever it says: a
// value the rule does not list, or one under the threshold, is an answer, and
// an answer that does not hold the call lets it through as it always did.
func TestASignalWithAnUnlistedValueIsPresentNotAbsent(t *testing.T) {
	e := signalEngine(t, absentPolicy(t, "hold"))
	for name, s := range map[string]Signal{
		"an unlisted value":                    riskSignal("read_only", 0.99),
		"a listed value under the threshold":   riskSignal("destructive", 0.5),
		"an unlisted value, spelled otherwise": {Name: " Action.Risk_Class ", Value: "read_only", Probability: 0.99, Source: "classifier"},
	} {
		if got := e.Decide(brokerCall(s)); got.Decision != Allow {
			t.Errorf("%s: %s (%s), want allow: the signal arrived", name, got.Decision, got.Reason)
		}
	}
	got := e.Decide(brokerCall(riskSignal("destructive", 0.95)))
	if got.Decision != Hold || strings.Contains(got.Reason, "when_absent") || !strings.Contains(got.Reason, "0.95") {
		t.Fatalf("a destructive signal: %s (%s), want the hold that names the signal, not its absence", got.Decision, got.Reason)
	}
}

func TestAnAbsentSignalHoldIsLiftedByATokenBoundToTheCall(t *testing.T) {
	e := signalEngine(t, absentPolicy(t, "hold"))
	req := brokerCall()
	req.ApprovalToken = mustToken(t, approval.MintApprovalTokenForCall, req.RunID, req.ToolCall.Digest())
	got := e.Decide(req)
	if got.Decision != Allow || !got.ApprovalTokenRequired || !strings.Contains(got.Reason, "allowed via a valid approval_token") {
		t.Fatalf("the approved call with its token: %s (%s) tokenRequired=%v, want an allow through the token", got.Decision, got.Reason, got.ApprovalTokenRequired)
	}
	if got.Cacheable {
		t.Error("an allow through a token on an absent-signal hold was marked cacheable")
	}
}

// A token minted for a hold that carried no tool call binds no call (invariant
// 28's named limit). It must not lift a hold whose whole point is that nobody
// could say what the call does: that hold is lifted only by an approval of the
// call itself.
func TestAnUnboundTokenDoesNotLiftAnAbsentSignalHold(t *testing.T) {
	req := brokerCall()
	unbound, _, err := approval.MintApprovalToken([]byte("signal-test-secret"), req.AgentID, req.RunID, req.ToolNames, 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req.ApprovalToken = unbound
	if got := signalEngine(t, absentPolicy(t, "hold")).Decide(req); got.Decision != Hold {
		t.Fatalf("an unbound token on an absent-signal hold: %s (%s), want hold", got.Decision, got.Reason)
	}
	// The control: the same token is valid, and lifts a hold that a signal
	// that did arrive caused, as it always has.
	present := brokerCall(riskSignal("destructive", 0.95))
	present.ApprovalToken = unbound
	if got := signalEngine(t, riskPolicy()).Decide(present); got.Decision != Allow {
		t.Fatalf("control: the unbound token no longer verifies at all: %s (%s)", got.Decision, got.Reason)
	}
	// Two rules matched, one held on a present signal and one on an absent
	// one: the call is still one nobody could fully describe, so the binding
	// is required.
	second := policy.Policy{Name: "zz-other", Target: "agent://acme.example/support/*", HoldIfSignal: absentPolicy(t, "hold").HoldIfSignal}
	second.HoldIfSignal.Name = "action.data_class"
	if got := signalEngine(t, riskPolicy(), second).Decide(present); got.Decision != Hold {
		t.Fatalf("an unbound token where one matched rule held on absence: %s (%s), want hold", got.Decision, got.Reason)
	}
}

// Nothing decided under a rule that can hold on absence is offered for reuse:
// whether a signal arrived is a fact about one call, outside the agent and tool
// set an enforcement point's cache keys on.
func TestAnAbsentSignalHoldIsNeverCacheable(t *testing.T) {
	e := signalEngine(t, absentPolicy(t, "hold"))
	cases := map[string]DecideRequest{
		"the absent-signal hold":                 brokerCall(),
		"an allow with the signal present":       brokerCall(riskSignal("read_only", 0.99)),
		"a model call the rule does not hold":    {AgentID: signalAgent, RunID: "run-1", ToolNames: []string{"ask"}},
		"a hold for a signal that did arrive":    brokerCall(riskSignal("destructive", 0.99)),
		"a whole call with no signal, held also": toolCallRequest(),
	}
	for name, req := range cases {
		if got := e.Decide(req); got.Cacheable {
			t.Errorf("%s (%s): marked cacheable", name, got.Decision)
		}
	}
}

func mustToken(t *testing.T, mint func([]byte, string, string, []string, float64, string, time.Duration) (string, time.Time, error), runID, digest string) string {
	t.Helper()
	tok, _, err := mint([]byte("signal-test-secret"), signalAgent, runID, []string{"ask"}, 0, digest, time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return tok
}

func forgedToken(t *testing.T) string {
	t.Helper()
	tok, _, err := approval.MintApprovalTokenForCall([]byte("somebody-elses-secret"), signalAgent, brokerCall().RunID, []string{"ask"}, 0, brokerCall().ToolCall.Digest(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}
