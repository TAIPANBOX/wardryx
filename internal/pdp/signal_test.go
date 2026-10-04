package pdp

import (
	"encoding/json"
	"math"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/approval"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// A typed risk signal may turn a call into a hold and into nothing else. These
// tests hold that sentence from every side: the rule that holds, the
// thresholds it respects, the rules it must never override, and the shapes a
// hostile or careless caller can hand it.

const signalAgent = "agent://acme.example/support/bot1"

func f64(v float64) *float64 { return &v }

// riskRule is the rule the design names: hold on a destructive, external or
// financial call the classifier is at least 80% sure of.
func riskRule() *policy.SignalRule {
	return &policy.SignalRule{
		Name:           "action.risk_class",
		Values:         []string{"destructive", "external_send", "financial"},
		MinProbability: f64(0.8),
	}
}

func signalEngine(t *testing.T, pols ...policy.Policy) *Engine {
	t.Helper()
	set, err := policy.Compile(pols)
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	return New(set, []byte("signal-test-secret"))
}

func riskPolicy() policy.Policy {
	return policy.Policy{Name: "risk", Target: "agent://acme.example/support/*", HoldIfSignal: riskRule()}
}

func riskSignal(value string, p float64) Signal {
	return Signal{Name: "action.risk_class", Value: value, Probability: p, Source: "classifier", AnswerID: "ans-1"}
}

func toolCallRequest(sigs ...Signal) DecideRequest {
	return DecideRequest{
		AgentID:   signalAgent,
		RunID:     "run-1",
		ToolNames: []string{"s3.delete_object"},
		Signals:   sigs,
		ToolCall: &ToolCall{
			Name:      "s3.delete_object",
			Arguments: json.RawMessage(`{"bucket":"prod-backups","key":"2026/db.dump"}`),
			Target:    "s3://prod-backups",
		},
	}
}

// TestADestructiveSignalHoldsACallThatWasAllowed is the case the feature
// exists for: the same call, allowed with no signal and held with one.
func TestADestructiveSignalHoldsACallThatWasAllowed(t *testing.T) {
	e := signalEngine(t, riskPolicy())

	before := e.Decide(toolCallRequest())
	if before.Decision != Allow {
		t.Fatalf("with no signal the call is %s (%s), want allow", before.Decision, before.Reason)
	}
	after := e.Decide(toolCallRequest(riskSignal("destructive", 0.95)))
	if after.Decision != Hold {
		t.Fatalf("with a destructive signal at 0.95 the call is %s (%s), want hold", after.Decision, after.Reason)
	}
	if !after.ApprovalTokenRequired {
		t.Error("a signal hold is an approval gate: ApprovalTokenRequired must be set so a granted token can lift it and single-use applies")
	}
	for _, want := range []string{"hold_if_signal", "action.risk_class", "destructive", "0.95"} {
		if !strings.Contains(after.Reason, want) {
			t.Errorf("reason %q does not name %q", after.Reason, want)
		}
	}
}

func TestASignalAtTheThresholdHoldsAndBelowItDoesNot(t *testing.T) {
	e := signalEngine(t, riskPolicy())
	cases := []struct {
		p    float64
		want string
	}{
		{0.79, Allow},
		{0.7999999, Allow},
		{0.8, Hold}, // min_probability is a minimum: equal fires
		{0.8000001, Hold},
		{1, Hold},
		{0, Allow},
	}
	for _, c := range cases {
		got := e.Decide(toolCallRequest(riskSignal("destructive", c.p)))
		if got.Decision != c.want {
			t.Errorf("p=%v: %s (%s), want %s", c.p, got.Decision, got.Reason, c.want)
		}
	}
}

func TestAValueTheRuleDoesNotListChangesNothing(t *testing.T) {
	e := signalEngine(t, riskPolicy())
	for _, v := range []string{"read_only", "reversible_change", "", "unheard_of"} {
		got := e.Decide(toolCallRequest(riskSignal(v, 0.99)))
		if got.Decision != Allow {
			t.Errorf("value %q at 0.99: %s (%s), want allow", v, got.Decision, got.Reason)
		}
	}
}

func TestASignalWithAnotherNameChangesNothing(t *testing.T) {
	e := signalEngine(t, riskPolicy())
	s := riskSignal("destructive", 0.99)
	s.Name = "request.complexity"
	if got := e.Decide(toolCallRequest(s)); got.Decision != Allow {
		t.Fatalf("a signal the rule does not read held the call: %s (%s)", got.Decision, got.Reason)
	}
}

// A rule over-matching is the safe direction (only more holds), and a signal
// source that spells a label with a capital or a trailing space must not slip
// under the rule.
func TestSignalMatchingFoldsCaseAndSpaceBecauseOnlyMoreHoldsCanFollow(t *testing.T) {
	e := signalEngine(t, riskPolicy())
	s := riskSignal(" Destructive ", 0.95)
	s.Name = "Action.Risk_Class"
	if got := e.Decide(toolCallRequest(s)); got.Decision != Hold {
		t.Fatalf("a differently spelled destructive signal: %s (%s), want hold", got.Decision, got.Reason)
	}
}

func TestASignalNeverChangesADeny(t *testing.T) {
	deny := policy.Policy{Name: "no-delete", Target: "agent://acme.example/support/*", DenyTool: []string{"s3.delete_object"}, HoldIfSignal: riskRule()}
	e := signalEngine(t, deny)
	plain := e.Decide(toolCallRequest())
	withSignal := e.Decide(toolCallRequest(riskSignal("destructive", 0.99)))
	if plain.Decision != Deny {
		t.Fatalf("setup: the call should be denied by deny_tool, got %s", plain.Decision)
	}
	if withSignal.Decision != Deny || withSignal.Reason != plain.Reason {
		t.Fatalf("a signal changed a deny: %s (%s), want the same deny %q", withSignal.Decision, withSignal.Reason, plain.Reason)
	}
}

func TestASignalNeverRemovesACostHold(t *testing.T) {
	cost := riskPolicy()
	cost.RequireHumanAboveUSD = f64(10)
	e := signalEngine(t, cost)

	req := toolCallRequest()
	req.EstCostUSD = 50
	plain := e.Decide(req)
	if plain.Decision != Hold {
		t.Fatalf("setup: expected the cost hold, got %s", plain.Decision)
	}
	// A harmless signal beside it must not lift anything.
	withSignal := e
	req.Signals = []Signal{riskSignal("read_only", 0.99)}
	got := withSignal.Decide(req)
	if got.Decision != Hold || got.Reason != plain.Reason {
		t.Fatalf("a signal changed a cost hold: %s (%s), want %q", got.Decision, got.Reason, plain.Reason)
	}
	// And a firing one leaves the cost reason in charge.
	req.Signals = []Signal{riskSignal("destructive", 0.99)}
	got = e.Decide(req)
	if got.Decision != Hold || got.Reason != plain.Reason {
		t.Fatalf("a firing signal beside a cost hold changed it: %s (%s), want %q", got.Decision, got.Reason, plain.Reason)
	}
}

func TestASignalHoldIsLiftedByAValidApprovalTokenAndNeverTurnsIntoADeny(t *testing.T) {
	e := signalEngine(t, riskPolicy())
	req := toolCallRequest(riskSignal("destructive", 0.95))

	tok, _, err := approval.MintApprovalToken([]byte("signal-test-secret"), req.AgentID, req.RunID, req.ToolNames, 0, time.Minute)
	if err != nil {
		t.Fatalf("MintApprovalToken: %v", err)
	}
	req.ApprovalToken = tok
	got := e.Decide(req)
	if got.Decision != Allow || !got.ApprovalTokenRequired {
		t.Fatalf("a valid token on a signal hold: %s (%s) tokenRequired=%v, want allow with the gate flagged", got.Decision, got.Reason, got.ApprovalTokenRequired)
	}

	// A token for another run does not verify. Without the signal this call
	// is allowed, so the signal may hold it and must not deny it.
	other := toolCallRequest(riskSignal("destructive", 0.95))
	other.RunID = "some-other-run"
	other.ApprovalToken = tok
	got = e.Decide(other)
	if got.Decision != Hold {
		t.Fatalf("an invalid token on a signal hold: %s (%s), want hold: a signal can add a hold and nothing else", got.Decision, got.Reason)
	}
	garbage := toolCallRequest(riskSignal("destructive", 0.95))
	garbage.ApprovalToken = "not-a-token"
	if got = e.Decide(garbage); got.Decision != Hold {
		t.Fatalf("a garbage token on a signal hold: %s (%s), want hold", got.Decision, got.Reason)
	}
}

// The property under every test above, swept: over random policy sets and
// requests, adding signals may turn an allow into a hold and may change
// nothing else. 200 seeds, so a counterexample is a number somebody can rerun.
func TestSignalsNeverChangeADenyOrRemoveAHoldOverRandomPolicies(t *testing.T) {
	values := []string{"destructive", "external_send", "financial", "read_only", "reversible_change"}
	for seed := int64(1); seed <= 200; seed++ {
		r := rand.New(rand.NewSource(seed))
		pol := policy.Policy{Name: "p", Target: "agent://acme.example/support/*"}
		if r.Intn(2) == 0 {
			pol.DenyTool = []string{"s3.delete_object"}
		}
		if r.Intn(2) == 0 {
			pol.RequireHumanAboveUSD = f64(float64(r.Intn(20)))
		}
		if r.Intn(3) == 0 {
			pol.MaxSteps = 1 + r.Intn(5)
		}
		if r.Intn(3) == 0 {
			pol.AllowDomains = []string{"ok.example.com"}
		}
		if r.Intn(3) == 0 {
			pol.DenyIfUnattested = true
		}
		if r.Intn(4) != 0 {
			pol.HoldIfSignal = &policy.SignalRule{
				Name:           "action.risk_class",
				Values:         values[:1+r.Intn(3)],
				MinProbability: f64(float64(r.Intn(11)) / 10),
			}
		}
		set, err := policy.Compile([]policy.Policy{pol})
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		e := New(set, []byte("signal-test-secret"))

		req := toolCallRequest()
		req.EstCostUSD = float64(r.Intn(30))
		req.Steps = r.Intn(7)
		if r.Intn(2) == 0 {
			req.Domains = []string{"ok.example.com"}
		} else {
			req.Domains = []string{"bad.example.com"}
		}
		if r.Intn(2) == 0 {
			req.AttestationMethod = "tpm"
		}
		base := e.Decide(req)

		for n := 1 + r.Intn(3); n > 0; n-- {
			req.Signals = append(req.Signals, riskSignal(values[r.Intn(len(values))], float64(r.Intn(101))/100))
		}
		with := e.Decide(req)

		switch {
		case base.Decision == Deny:
			if with.Decision != Deny || with.Reason != base.Reason {
				t.Fatalf("seed %d: a signal changed a deny: %s (%s) -> %s (%s)", seed, base.Decision, base.Reason, with.Decision, with.Reason)
			}
		case base.Decision == Hold:
			if with.Decision != Hold || with.Reason != base.Reason {
				t.Fatalf("seed %d: a signal changed a hold: %s (%s) -> %s (%s)", seed, base.Decision, base.Reason, with.Decision, with.Reason)
			}
		case base.Decision == Allow:
			if with.Decision != Allow && with.Decision != Hold {
				t.Fatalf("seed %d: a signal turned an allow into %s (%s)", seed, with.Decision, with.Reason)
			}
		}
	}
}

// Signals vary per call (the arguments differ) so a decision that read one is
// never the same for the same agent and tool set. Cacheable must say so, or an
// enforcement point's cache serves the allow of a harmless call to a
// destructive one.
func TestADecisionThatCanReadASignalIsNeverCacheable(t *testing.T) {
	with := signalEngine(t, riskPolicy())
	if got := with.Decide(toolCallRequest()); got.Cacheable {
		t.Error("a decision under a hold_if_signal policy is Cacheable: the next call's arguments may carry a signal")
	}
	without := signalEngine(t, policy.Policy{Name: "plain", Target: "agent://acme.example/support/*", DenyTool: []string{"x"}})
	if got := without.Decide(toolCallRequest()); !got.Cacheable {
		t.Error("control: a policy with no per-request rule stopped being Cacheable")
	}
}

// --- validation: what a hostile or careless caller can hand in ---

func TestSignalValidationRefusesTheMalformed(t *testing.T) {
	ok := riskSignal("destructive", 0.9)
	if err := ValidateSignals([]Signal{ok}); err != nil {
		t.Fatalf("a well-formed signal was refused: %v", err)
	}
	if err := ValidateSignals(nil); err != nil {
		t.Fatalf("no signals is not malformed: %v", err)
	}

	mut := func(f func(s *Signal)) Signal { s := ok; f(&s); return s }
	long := strings.Repeat("a", MaxSignalFieldBytes+1)
	bad := map[string]Signal{
		"NaN":               mut(func(s *Signal) { s.Probability = math.NaN() }),
		"+Inf":              mut(func(s *Signal) { s.Probability = math.Inf(1) }),
		"-Inf":              mut(func(s *Signal) { s.Probability = math.Inf(-1) }),
		"above one":         mut(func(s *Signal) { s.Probability = 1.0000001 }),
		"below zero":        mut(func(s *Signal) { s.Probability = -0.0000001 }),
		"empty name":        mut(func(s *Signal) { s.Name = "" }),
		"blank name":        mut(func(s *Signal) { s.Name = "  " }),
		"long name":         mut(func(s *Signal) { s.Name = long }),
		"control in name":   mut(func(s *Signal) { s.Name = "a\nb" }),
		"empty value":       mut(func(s *Signal) { s.Value = "" }),
		"long value":        mut(func(s *Signal) { s.Value = long }),
		"control in value":  mut(func(s *Signal) { s.Value = "des\x00tructive" }),
		"empty source":      mut(func(s *Signal) { s.Source = "" }),
		"long source":       mut(func(s *Signal) { s.Source = long }),
		"long answer id":    mut(func(s *Signal) { s.AnswerID = long }),
		"control answer id": mut(func(s *Signal) { s.AnswerID = "a\r\nb" }),
	}
	for name, s := range bad {
		if err := ValidateSignals([]Signal{s}); err == nil {
			t.Errorf("%s: a malformed signal was accepted", name)
		}
	}

	many := make([]Signal, MaxSignals+1)
	for i := range many {
		many[i] = ok
	}
	if err := ValidateSignals(many); err == nil {
		t.Errorf("%d signals accepted, the cap is %d", len(many), MaxSignals)
	}
	if err := ValidateSignals(many[:MaxSignals]); err != nil {
		t.Errorf("exactly %d signals refused: %v", MaxSignals, err)
	}
}

func TestToolCallValidationCapsWhatCanBeSent(t *testing.T) {
	good := ToolCall{Name: "s3.delete_object", Arguments: json.RawMessage(`{"a":1}`), Target: "s3://x"}
	if err := ValidateToolCall(good); err != nil {
		t.Fatalf("a well-formed call refused: %v", err)
	}
	if err := ValidateToolCall(ToolCall{Name: "list_files"}); err != nil {
		t.Fatalf("a call with no arguments and no target refused: %v", err)
	}
	atCap := ToolCall{Name: "t", Arguments: json.RawMessage(`"` + strings.Repeat("x", MaxToolArgumentsBytes-2) + `"`)}
	if err := ValidateToolCall(atCap); err != nil {
		t.Fatalf("arguments of exactly %d bytes refused: %v", MaxToolArgumentsBytes, err)
	}
	over := ToolCall{Name: "t", Arguments: json.RawMessage(`"` + strings.Repeat("x", MaxToolArgumentsBytes) + `"`)}
	bad := map[string]ToolCall{
		"no name":            {Arguments: good.Arguments},
		"long name":          {Name: strings.Repeat("n", MaxToolNameBytes+1)},
		"control in name":    {Name: "a\nb"},
		"long target":        {Name: "t", Target: strings.Repeat("t", MaxToolTargetBytes+1)},
		"control in target":  {Name: "t", Target: "a\x00b"},
		"arguments too big":  over,
		"arguments not JSON": {Name: "t", Arguments: json.RawMessage(`{"a":`)},
	}
	for name, tc := range bad {
		if err := ValidateToolCall(tc); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// An enforcement point caches decisions keyed on the agent and tool set, with
// no arguments in the key. A decision that depended on a signal, which is a
// fact about ONE call's arguments, must therefore never be marked cacheable:
// the hold for a destructive call must not be served to the next, harmless,
// call under the same agent and tool set, and an allow reached while a signal
// rule could have fired must not be served to a destructive one.
func TestEverySignalDependentDecisionIsMarkedNotCacheable(t *testing.T) {
	e := signalEngine(t, riskPolicy())
	cases := map[string]DecideRequest{
		"a hold caused by a signal":                          toolCallRequest(riskSignal("destructive", 0.95)),
		"an allow after a signal that did not fire":          toolCallRequest(riskSignal("read_only", 0.99)),
		"an allow after a signal under the threshold":        toolCallRequest(riskSignal("destructive", 0.5)),
		"an allow with no signal, the rule could have fired": toolCallRequest(),
	}
	for name, req := range cases {
		if got := e.Decide(req); got.Cacheable {
			t.Errorf("%s (%s, %s): marked cacheable", name, got.Decision, got.Reason)
		}
	}
	// Granted by a person: still a decision that read a signal.
	req := toolCallRequest(riskSignal("destructive", 0.95))
	tok, _, _ := approval.MintApprovalToken([]byte("signal-test-secret"), req.AgentID, req.RunID, req.ToolNames, 0, time.Minute)
	req.ApprovalToken = tok
	if got := e.Decide(req); got.Decision != Allow || got.Cacheable {
		t.Errorf("an allow via an approval on a signal hold: %s cacheable=%v", got.Decision, got.Cacheable)
	}
	// A deny under such a policy is request-specific for the same reason.
	deny := riskPolicy()
	deny.DenyTool = []string{"s3.delete_object"}
	if got := signalEngine(t, deny).Decide(toolCallRequest(riskSignal("destructive", 0.95))); got.Decision != Deny || got.Cacheable {
		t.Errorf("a deny under a signal policy: %s cacheable=%v", got.Decision, got.Cacheable)
	}
	// The control: signals nobody reads change nothing about cacheability.
	plain := signalEngine(t, policy.Policy{Name: "plain", Target: "agent://acme.example/support/*", DenyTool: []string{"x"}})
	if got := plain.Decide(toolCallRequest(riskSignal("destructive", 0.95))); !got.Cacheable {
		t.Error("control: a signal no policy reads made a decision uncacheable")
	}
}

func TestATruncatedToolCallIsConsistentOrRefused(t *testing.T) {
	if err := ValidateToolCall(ToolCall{Name: "t", ArgumentsTruncated: true}); err != nil {
		t.Fatalf("truncated with no arguments refused: %v", err)
	}
	if err := ValidateToolCall(ToolCall{Name: "t", ArgumentsTruncated: true, Arguments: json.RawMessage(`null`)}); err != nil {
		t.Fatalf("truncated with a null arguments refused: %v", err)
	}
	if err := ValidateToolCall(ToolCall{Name: "t", ArgumentsTruncated: true, Arguments: json.RawMessage(`{"a":1}`)}); err == nil {
		t.Fatal("truncated arguments that are also present were accepted: one of the two is false")
	}
}
