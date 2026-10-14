package pdp

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/TAIPANBOX/wardryx/internal/approval"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// Caps on what a caller may hand the decision path. Signals and tool calls
// arrive from outside the process, so each is bounded before anything reads it.
const (
	// MaxSignals is how many signals one request may carry.
	MaxSignals = 16
	// MaxSignalFieldBytes bounds each text field of a signal.
	MaxSignalFieldBytes = 128
	// MaxToolNameBytes and MaxToolTargetBytes bound a tool call's text fields.
	MaxToolNameBytes   = 256
	MaxToolTargetBytes = 1024
	// MaxToolArgumentsBytes bounds a tool call's raw JSON arguments. An
	// enforcement point that has more marks the call arguments_truncated and
	// sends none, so a bound here costs it nothing it could not already say.
	MaxToolArgumentsBytes = 12 << 10
)

// Signal is one typed fact about a request that somebody else established
// before Decide ran: "this tool call is destructive, at probability 0.95".
//
// Decide only READS signals. It never fetches one, and nothing in this package
// can: a signal is an input exactly like EstCostUSD, so the same request
// against the same policy set yields the same decision, which is what lets a
// recorded decision be replayed with whatever produced the signal unreachable.
//
// The trust boundary is the one ChainProven and AttestationMethod already
// have: a caller that lies is believed. That costs
// little here, because a signal can only ever ADD a hold (see
// policy.Policy.HoldIfSignal): a false signal is a delay for a person, never a
// refusal and never an allow.
type Signal struct {
	// Name says which question was asked, e.g. "action.risk_class".
	Name string
	// Value is the answer, e.g. "destructive".
	Value string
	// Probability is how sure the source was of Value, in [0, 1].
	Probability float64
	// Source says who established it. Recorded, never branched on.
	Source string
	// AnswerID identifies the source's own record of the answer, so an auditor
	// can find it. Optional.
	AnswerID string
}

// ToolCall is the concrete tool call a request is about to make, when the
// enforcement point knows it. It exists so the layer outside the decision path
// can ask a classifier about it and turn the answer into a Signal. Decide reads
// its name (deny_tool, allow_tool) and whether it is there at all (a
// hold_if_signal rule with when_absent: hold), never its arguments. Arguments
// are raw JSON and are never recorded, since they can carry customer data.
type ToolCall struct {
	Name      string
	Arguments json.RawMessage
	Target    string
	// ArgumentsTruncated says the enforcement point cut the arguments off
	// (they were too large to send), so Arguments is empty and means nothing.
	ArgumentsTruncated bool
}

// Digest is the digest an approval for this call is bound to
// (approval.ToolCallDigest): name, target, a sha-256 of the arguments exactly as
// received, and the truncated flag. It is the same value the decision event
// records as tool_call.digest and the same one a granted token carries, so the
// record, the hold a person saw and the token agree. A nil call has no digest
// and returns "", which is how a request that carries no tool call presents
// itself to approval.VerifyApprovalTokenForCall.
func (tc *ToolCall) Digest() string {
	if tc == nil {
		return ""
	}
	return approval.ToolCallDigest(tc.Name, tc.Target, tc.Arguments, tc.ArgumentsTruncated)
}

// ValidateSignals refuses a malformed list of signals. It names the index and
// the field and never echoes the value it refused.
func ValidateSignals(ss []Signal) error {
	if len(ss) > MaxSignals {
		return fmt.Errorf("at most %d signals per request, got %d", MaxSignals, len(ss))
	}
	for i, s := range ss {
		if err := validText(s.Name, MaxSignalFieldBytes, true); err != nil {
			return fmt.Errorf("signals[%d].name: %v", i, err)
		}
		if err := validText(s.Value, MaxSignalFieldBytes, true); err != nil {
			return fmt.Errorf("signals[%d].value: %v", i, err)
		}
		if math.IsNaN(s.Probability) || math.IsInf(s.Probability, 0) || s.Probability < 0 || s.Probability > 1 {
			return fmt.Errorf("signals[%d].probability must be a number between 0 and 1", i)
		}
		if err := validText(s.Source, MaxSignalFieldBytes, true); err != nil {
			return fmt.Errorf("signals[%d].source: %v", i, err)
		}
		if err := validText(s.AnswerID, MaxSignalFieldBytes, false); err != nil {
			return fmt.Errorf("signals[%d].answer_id: %v", i, err)
		}
	}
	return nil
}

// ValidateToolCall refuses a malformed or oversized tool call.
func ValidateToolCall(tc ToolCall) error {
	if err := validText(tc.Name, MaxToolNameBytes, true); err != nil {
		return fmt.Errorf("tool_call.name: %v", err)
	}
	if err := validText(tc.Target, MaxToolTargetBytes, false); err != nil {
		return fmt.Errorf("tool_call.target: %v", err)
	}
	if tc.ArgumentsTruncated && len(tc.Arguments) > 0 && string(tc.Arguments) != "null" {
		return fmt.Errorf("tool_call.arguments_truncated is true and arguments are present: one of the two is false")
	}
	if len(tc.Arguments) > MaxToolArgumentsBytes {
		return fmt.Errorf("tool_call.arguments is over the %d-byte cap", MaxToolArgumentsBytes)
	}
	if len(tc.Arguments) > 0 && !json.Valid(tc.Arguments) {
		return fmt.Errorf("tool_call.arguments is not valid JSON")
	}
	return nil
}

// validText accepts valid UTF-8 with no control character, at most max bytes,
// and, when required, something other than whitespace.
func validText(s string, max int, required bool) error {
	if len(s) > max {
		return fmt.Errorf("is over %d bytes", max)
	}
	if !utf8.ValidString(s) {
		return fmt.Errorf("is not valid UTF-8")
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return fmt.Errorf("holds a control character")
		}
	}
	if required && strings.TrimSpace(s) == "" {
		return fmt.Errorf("is required")
	}
	return nil
}

// signalHold is what rule 12 found: the policy whose hold_if_signal rule holds
// the request, and why.
type signalHold struct {
	// pol is the first matched policy, in compiled order, whose rule holds.
	pol policy.Policy
	// sig is the signal that satisfied pol's rule. Zero when absent is set.
	sig Signal
	// absent says pol's rule holds because the request carries a tool call and
	// no signal of the rule's name (when_absent: hold).
	absent bool
	// callMustBeBound says some matched rule, pol's or a later one, holds on an
	// absent signal, so only an approval token bound to the call lifts the
	// hold. A token that binds no call was granted with no call in view, and the
	// hold exists because nobody could say what this call does.
	callMustBeBound bool
}

// reason is the hold's sentence, before what became of it.
func (h signalHold) reason(call *ToolCall) string {
	rule := h.pol.HoldIfSignal
	if !h.absent {
		return fmt.Sprintf("policy %q hold_if_signal: signal %q is %q at probability %s (the rule holds from %s)",
			h.pol.Name, h.sig.Name, h.sig.Value, formatProbability(h.sig.Probability), formatProbability(*rule.MinProbability))
	}
	// ruleHolds never sets absent without a call; reading a nil one would
	// panic in the decision path, so the sentence is built defensively.
	name, truncated := "", ""
	if call != nil {
		name = call.Name
		if call.ArgumentsTruncated {
			truncated = ", whose arguments were not sent (arguments_truncated)"
		}
	}
	return fmt.Sprintf("policy %q hold_if_signal: no %q signal came with tool call %q%s, and the rule holds when the signal is absent (when_absent: %s)",
		h.pol.Name, rule.Name, name, truncated, policy.WhenAbsentHold)
}

// heldBySignal returns the first matched policy whose hold_if_signal rule holds
// the request. Policies are walked in the compiled order and signals in the
// order the request carries them, so the reported rule is deterministic for a
// given request.
//
// A rule holds when one of the request's signals has its name, a listed value,
// and a probability at least the rule's minimum. Names and values are compared
// with case and surrounding space folded, the direction in which a mismatch can
// only cause MORE holds. A NaN probability satisfies nothing, and a rule with no
// minimum satisfies nothing: both are unvalidated shapes, and doing nothing is
// the only safe answer to them.
//
// A rule with when_absent: hold also holds a request that carries a tool call
// and no signal of its name at all. A signal of that name with any other value,
// or under the threshold, is present: it is an answer, and it holds nothing. A
// request with no tool call is never held for a missing signal.
func heldBySignal(policies []policy.Policy, signals []Signal, call *ToolCall) (signalHold, bool) {
	var first signalHold
	found, mustBind := false, false
	for _, p := range policies {
		h, ok := ruleHolds(p, signals, call)
		if !ok {
			continue
		}
		mustBind = mustBind || h.absent
		if !found {
			first, found = h, true
		}
	}
	first.callMustBeBound = mustBind
	return first, found
}

// ruleHolds reports whether p's hold_if_signal rule holds this request.
func ruleHolds(p policy.Policy, signals []Signal, call *ToolCall) (signalHold, bool) {
	r := p.HoldIfSignal
	if r == nil || r.MinProbability == nil {
		return signalHold{}, false
	}
	named := false
	for _, s := range signals {
		if !foldEqual(r.Name, s.Name) {
			continue
		}
		named = true
		if containsFold(r.Values, s.Value) && s.Probability >= *r.MinProbability {
			return signalHold{pol: p, sig: s}, true
		}
	}
	if !named && call != nil && r.WhenAbsent == policy.WhenAbsentHold {
		return signalHold{pol: p, absent: true}, true
	}
	return signalHold{}, false
}

func foldEqual(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// formatProbability prints a probability as the exact shortest decimal, so a
// reason says 0.8 for 0.8 and never rounds 0.795 up to a figure that reads as
// meeting a threshold it does not.
func formatProbability(p float64) string {
	return strconv.FormatFloat(p, 'g', -1, 64)
}
