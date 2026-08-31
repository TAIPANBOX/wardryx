// Package replay answers what a different policy would have done to decisions
// that already happened, by putting each recorded question back to the PDP.
//
// # Why it can be trusted, and where it stops
//
// Decide is a deterministic function of the loaded policy set and the
// request, with no LLM, no clock and no network on the decision path. So a
// recorded question put to the same set must come back with the same answer,
// and this package checks that FIRST on every row. A counterfactual is only
// offered for decisions that reproduced; anything else is counted and named,
// never quietly folded in.
//
// # The four ways a row can fail to be replayable, all reported
//
//   - Unreadable: the event predates the emitter carrying the decision input,
//     so the question was never written down.
//   - NotArchived: the policy version the event names was never kept, so
//     there are no rules to put the question to.
//   - Diverged: replaying against the version the event itself names
//     disagrees with what was recorded. The record and the code no longer
//     agree about the past, and every counterfactual built on that row would
//     be worthless.
//   - ApprovalDecided: not a failure. The approval token is deliberately not
//     recorded (it is a live credential and this record outlives it), so
//     replay cannot redeem one. What it can do is reach the exact hold a
//     human then answered, which is faithful up to that answer.
//
// # What it does NOT do
//
// It replays one DECISION, not the agent. If a candidate policy turns a
// refusal into an allowance, everything the agent would have done afterwards
// is a world nothing recorded, and this package does not pretend otherwise.
// The honest question it answers is aggregate: over this history, which
// decisions would the candidate have taken differently.
package replay

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/wardryx/internal/archive"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// Fidelity is what happened when a recorded decision was put back to the
// policy set it names.
type Fidelity string

const (
	// Reproduced: same verdict, same reason. The counterfactual is offered.
	Reproduced Fidelity = "reproduced"
	// ApprovalDecided: replay reached the hold a human then answered. The
	// counterfactual is offered against that hold, not against the human's
	// answer.
	ApprovalDecided Fidelity = "approval-decided"
	// NotArchived: the version this decision names was never kept.
	NotArchived Fidelity = "not-archived"
	// Unreadable: the event does not carry the question that was asked.
	Unreadable Fidelity = "unreadable"
	// Diverged: replaying its own version disagrees with the record.
	Diverged Fidelity = "diverged"
)

// decisionVerdict maps the three decision events onto the verdict each one
// records. Every other event type in the stream is not a decision and is not
// counted: an events file also carries policy_updated, approval_granted and
// the rest, and counting those would inflate every figure in the report.
var decisionVerdict = map[string]string{
	"policy_allow":       pdp.Allow,
	"policy_deny":        pdp.Deny,
	"approval_requested": pdp.Hold,
}

// Row is one recorded decision and what became of it.
type Row struct {
	AgentID string
	RunID   string
	Type    string
	// Recorded is the verdict the event records. For an allow a human
	// granted, this is allow while Baseline is the hold the PDP produced.
	Recorded string
	// Baseline is the verdict the PDP itself reached at the time, which is
	// what a candidate is compared against.
	Baseline string
	Reason   string
	Version  string
	Fidelity Fidelity
	// Note says what went wrong, for every Fidelity except Reproduced.
	Note string
	// Candidate is nil unless the row reproduced.
	Candidate *pdp.DecideResponse
}

// Changed reports whether the candidate set would have decided differently.
func (r Row) Changed() bool {
	return r.Candidate != nil && r.Candidate.Decision != r.Baseline
}

// Report is the whole run. Every count is over decisions actually found:
// Total is the sum of the five fidelities, and Changed is a subset of
// Reproduced plus ApprovalDecided.
type Report struct {
	Rows            []Row
	Total           int
	Reproduced      int
	ApprovalDecided int
	NotArchived     int
	Unreadable      int
	Diverged        int
	Changed         int
}

// Replayable is how many rows carried a counterfactual at all.
func (r Report) Replayable() int { return r.Reproduced + r.ApprovalDecided }

// Run replays every decision in events against the version it names, then
// against candidate. A nil candidate runs the fidelity pass alone, which is a
// useful question on its own: can this history be replayed at all.
func Run(events []event.Event, arch *archive.Archive, candidate *policy.Set) Report {
	var report Report
	for _, ev := range events {
		verdict, isDecision := decisionVerdict[ev.Type]
		if !isDecision {
			continue
		}
		report.Total++
		report.Rows = append(report.Rows, replayOne(ev, verdict, arch, candidate))
	}
	for _, row := range report.Rows {
		switch row.Fidelity {
		case Reproduced:
			report.Reproduced++
		case ApprovalDecided:
			report.ApprovalDecided++
		case NotArchived:
			report.NotArchived++
		case Unreadable:
			report.Unreadable++
		case Diverged:
			report.Diverged++
		}
		if row.Changed() {
			report.Changed++
		}
	}
	return report
}

func replayOne(ev event.Event, verdict string, arch *archive.Archive, candidate *policy.Set) Row {
	row := Row{
		AgentID:  ev.AgentID,
		RunID:    ev.RunID,
		Type:     ev.Type,
		Recorded: verdict,
		Baseline: verdict,
	}

	req, version, tokenRequired, err := question(ev)
	if err != nil {
		row.Fidelity = Unreadable
		row.Note = err.Error()
		return row
	}
	row.Version = version
	row.Reason, _ = ev.Data["reason"].(string)

	policies, err := arch.Get(version)
	if err != nil {
		row.Fidelity = NotArchived
		row.Note = err.Error()
		return row
	}
	inForce, err := policy.Compile(policies)
	if err != nil {
		row.Fidelity = NotArchived
		row.Note = fmt.Sprintf("the archived set for %s does not compile: %v", version, err)
		return row
	}

	// A nil secret is correct and not a shortcut: Decide only reaches
	// VerifyApprovalToken when the request carries a token, and a replayed
	// request never does, because the token is deliberately not recorded.
	again := pdp.New(inForce, nil).Decide(req)

	switch {
	case again.Decision == row.Recorded && again.Reason == row.Reason:
		row.Fidelity = Reproduced
	case row.Recorded == pdp.Allow && tokenRequired &&
		again.Decision == pdp.Hold && again.ApprovalTokenRequired:
		// The one faithful disagreement. Decide's own doc comment says
		// Allow with ApprovalTokenRequired uniquely identifies an allow
		// produced by redeeming a valid token, and replay holds no token.
		row.Fidelity = ApprovalDecided
		row.Baseline = pdp.Hold
		row.Note = "the PDP held this and a human granted it; replay reaches the hold, not the answer"
	default:
		row.Fidelity = Diverged
		row.Note = fmt.Sprintf("recorded %s (%q) but %s answers %s (%q)",
			row.Recorded, row.Reason, version, again.Decision, again.Reason)
		return row
	}

	if candidate != nil {
		answer := pdp.New(candidate, nil).Decide(req)
		row.Candidate = &answer
	}
	return row
}

// question rebuilds the DecideRequest one event recorded, or names what the
// event lacks. Nothing is defaulted: a missing member means the question was
// not written down, and a request filled in with zero values would replay as
// something nobody ever asked, permissively (see internal/archive on why the
// permissive reading is always the harmful one here).
func question(ev event.Event) (pdp.DecideRequest, string, bool, error) {
	var missing []string
	need := func(key string) any {
		v, ok := ev.Data[key]
		if !ok {
			missing = append(missing, key)
			return nil
		}
		return v
	}

	toolNames := need("tool_names")
	domains := need("domains")
	steps := need("steps")
	model := need("model")
	cost := need("est_cost_usd")
	attestation := need("attestation_method")
	chainProven := need("chain_proven")
	version := need("policy_version")
	tokenRequired := need("approval_token_required")
	need("reason")

	if len(missing) > 0 {
		sort.Strings(missing)
		return pdp.DecideRequest{}, "", false, fmt.Errorf(
			"the event does not carry the question: no %s. Decisions recorded before the emitter carried the decision input cannot be replayed",
			strings.Join(missing, ", "))
	}

	v, ok := version.(string)
	if !ok || v == "" {
		return pdp.DecideRequest{}, "", false, fmt.Errorf("policy_version is not a version: %#v", version)
	}

	return pdp.DecideRequest{
		AgentID:           ev.AgentID,
		RunID:             ev.RunID,
		OnBehalfOf:        ev.OnBehalfOf,
		ToolNames:         textList(toolNames),
		Domains:           textList(domains),
		Steps:             int(number(steps)),
		Model:             text(model),
		EstCostUSD:        number(cost),
		AttestationMethod: text(attestation),
		ChainProven:       chainProven == true,
	}, v, tokenRequired == true, nil
}

// JSON gives back float64 for every number, []any for every list, and null
// for a Go nil slice the emitter wrote. Null is a value the emitter really
// recorded (no domains were declared), not a missing member, so it decodes to
// an empty slice rather than to an error.
func textList(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func number(v any) float64 {
	f, _ := v.(float64)
	return f
}

func text(v any) string {
	s, _ := v.(string)
	return s
}

// Format renders a report the way an operator reads it: what could be
// replayed, what could not, and only then what would change. The order is
// deliberate. A count of changes is meaningless without the count of
// decisions the run could not examine, so the two never appear apart.
func Format(r Report, source, candidateName string) string {
	var b strings.Builder

	fmt.Fprintf(&b, "Replayed %d decision(s) from %s\n\n", r.Total, source)
	if r.Total == 0 {
		b.WriteString("  no decisions in this file. policy_allow, policy_deny and\n")
		b.WriteString("  approval_requested are the three events that record one.\n")
		return b.String()
	}

	line := func(label string, n int, note string) {
		fmt.Fprintf(&b, "  %-18s %5d", label, n)
		if note != "" && n > 0 {
			fmt.Fprintf(&b, "   %s", note)
		}
		b.WriteString("\n")
	}
	line("reproduced", r.Reproduced, "")
	line("approval-decided", r.ApprovalDecided, "the PDP held these and a human answered")
	line("not archived", r.NotArchived, "the version they name was never kept")
	line("unreadable", r.Unreadable, "recorded before the emitter carried the question")
	line("diverged", r.Diverged, "replaying their OWN version disagrees with the record")

	if r.Diverged > 0 {
		b.WriteString("\nDIVERGED rows mean the record and this build no longer agree about the\n")
		b.WriteString("past. Nothing below is trustworthy until that is explained:\n")
		for _, row := range r.Rows {
			if row.Fidelity == Diverged {
				fmt.Fprintf(&b, "  %s run %s: %s\n", row.AgentID, row.RunID, row.Note)
			}
		}
	}

	unexamined := r.NotArchived + r.Unreadable + r.Diverged
	if candidateName == "" {
		fmt.Fprintf(&b, "\nNo candidate policy given, so this run only asked whether the history\n")
		fmt.Fprintf(&b, "can be replayed at all: %d of %d can.\n", r.Replayable(), r.Total)
		return b.String()
	}

	fmt.Fprintf(&b, "\nAgainst %s, %d of %d replayable decision(s) change:\n",
		candidateName, r.Changed, r.Replayable())
	if r.Changed == 0 {
		b.WriteString("  none.\n")
	}
	for _, row := range r.Rows {
		if !row.Changed() {
			continue
		}
		fmt.Fprintf(&b, "\n  %s -> %s   %s  run %s\n", row.Baseline, row.Candidate.Decision, row.AgentID, row.RunID)
		fmt.Fprintf(&b, "        was: %s\n", row.Reason)
		fmt.Fprintf(&b, "        now: %s\n", row.Candidate.Reason)
	}

	if unexamined > 0 {
		fmt.Fprintf(&b, "\n%d decision(s) could not be replayed and are NOT in the figures above.\n", unexamined)
		b.WriteString("A change count that silently omits them would read as coverage it does not have.\n")
	}
	return b.String()
}
