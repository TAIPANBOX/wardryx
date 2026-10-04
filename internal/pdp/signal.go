package pdp

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

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
	// MaxToolArgumentsBytes bounds a tool call's raw JSON arguments. Smaller
	// than the 16384-byte state a typryx template accepts, so that any call
	// wardryx accepts also fits what enrichment sends for it.
	MaxToolArgumentsBytes = 12 << 10
)

// Signal is one typed fact about a request that somebody else established
// before Decide ran: "this tool call is destructive, at probability 0.95".
//
// Decide only READS signals. It never fetches one, and nothing in this package
// can: a signal is an input exactly like EstCostUSD, so the same request
// against the same policy set yields the same decision, which is what lets a
// recorded decision be replayed with typryx, or whatever produced the signal,
// unreachable. The trust boundary is the one ChainProven and
// AttestationMethod already have: a caller that lies is believed. That costs
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
// enforcement point knows it. Decide does not branch on it: it exists so the
// layer outside the decision path can ask a classifier about it and turn the
// answer into a Signal. Arguments are raw JSON and are never recorded, since
// they can carry customer data.
type ToolCall struct {
	Name      string
	Arguments json.RawMessage
	Target    string
	// ArgumentsTruncated says the enforcement point cut the arguments off
	// (they were too large to send), so Arguments is empty and means nothing.
	ArgumentsTruncated bool
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

// ReadsSignal reports whether any policy matching agentID holds on a signal of
// this name. It is how the layer outside the decision path learns whether
// asking a classifier could change anything: a signal no policy reads is spend
// for nothing.
func (e *Engine) ReadsSignal(agentID, name string) bool {
	for _, p := range e.policies.Load().Match(agentID) {
		if p.HoldIfSignal != nil && foldEqual(p.HoldIfSignal.Name, name) {
			return true
		}
	}
	return false
}

// heldBySignal returns the first matched policy whose hold_if_signal rule one
// of the request's signals satisfies, with that signal. Policies are walked in
// the compiled order and signals in the order the request carries them, so the
// reported rule is deterministic for a given request.
//
// A rule matches when the signal's name and value are listed (case and
// surrounding space folded, the direction in which a mismatch can only cause
// MORE holds) and its probability is at least the rule's minimum. A NaN
// probability satisfies nothing, and a rule with no minimum satisfies nothing:
// both are unvalidated shapes, and doing nothing is the only safe answer to
// them.
func heldBySignal(policies []policy.Policy, signals []Signal) (policy.Policy, Signal, bool) {
	for _, p := range policies {
		r := p.HoldIfSignal
		if r == nil || r.MinProbability == nil {
			continue
		}
		for _, s := range signals {
			if !foldEqual(r.Name, s.Name) || !containsFold(r.Values, s.Value) {
				continue
			}
			if s.Probability >= *r.MinProbability {
				return p, s, true
			}
		}
	}
	return policy.Policy{}, Signal{}, false
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
