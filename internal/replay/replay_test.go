package replay

import (
	"strings"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/wardryx/internal/archive"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// Replay answers one question: what would a different policy have done to
// decisions that already happened. It is only worth anything if it first
// proves it can reproduce what DID happen, so these tests are mostly about
// the honesty of that first pass, and about refusing to guess when it cannot.

func compile(t *testing.T, allowDomains []string, threshold float64) *policy.Set {
	t.Helper()
	set, err := policy.Compile([]policy.Policy{{
		Name:                 "finance-guardrail",
		Target:               "agent://acme.example/finance/*",
		DenyTool:             []string{"send_wire_transfer"},
		AllowDomains:         allowDomains,
		RequireHumanAboveUSD: threshold,
		MaxSteps:             5,
	}})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	return set
}

func archiveOf(t *testing.T, sets ...*policy.Set) *archive.Archive {
	t.Helper()
	a, err := archive.New(t.TempDir())
	if err != nil {
		t.Fatalf("archive.New: %v", err)
	}
	for _, s := range sets {
		if err := a.Keep(s); err != nil {
			t.Fatalf("Keep: %v", err)
		}
	}
	return a
}

// decisionEvent builds an event of the shape internal/api emits.
func decisionEvent(evType, version, reason string, data map[string]any) event.Event {
	base := map[string]any{
		"tool_names": []any{"http_get"}, "domains": []any{"payouts.evil.example"},
		"steps": float64(3), "model": "claude-sonnet-5", "est_cost_usd": float64(12.40),
		"attestation_method": "tpm", "chain_proven": false,
		"policy_version": version, "reason": reason,
		"approval_token_required": false,
	}
	for k, v := range data {
		base[k] = v
	}
	return event.Event{
		Schema: "taipanbox.dev/agent-event/v0.2", TS: "2026-08-31T00:00:00Z",
		Source: "wardryx", Type: evType, AgentID: "agent://acme.example/finance/bot1",
		RunID: "r1", Data: base,
	}
}

// TestADecisionThatReproducesCarriesTheCounterfactual is the happy path and
// the shape of the whole exercise: reproduce first, then ask the new question.
func TestADecisionThatReproducesCarriesTheCounterfactual(t *testing.T) {
	inForce := compile(t, []string{"good.example.com"}, 500)
	candidate := compile(t, []string{"good.example.com", "payouts.evil.example"}, 500)

	report := Run([]event.Event{
		decisionEvent("policy_deny", inForce.Version(),
			`domain "payouts.evil.example" is not allowed by policy "finance-guardrail" (target agent://acme.example/finance/*)`, nil),
	}, archiveOf(t, inForce), candidate)

	if len(report.Rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(report.Rows))
	}
	row := report.Rows[0]
	if row.Fidelity != Reproduced {
		t.Fatalf("fidelity = %s (%s), want %s", row.Fidelity, row.Note, Reproduced)
	}
	if row.Candidate == nil {
		t.Fatal("a reproduced decision must carry a counterfactual")
	}
	if row.Candidate.Decision != pdp.Allow {
		t.Fatalf("candidate verdict = %s, want %s", row.Candidate.Decision, pdp.Allow)
	}
	if !row.Changed() {
		t.Fatal("deny -> allow must count as a change")
	}
	if report.Changed != 1 || report.Reproduced != 1 {
		t.Fatalf("counts: changed=%d reproduced=%d, want 1 and 1", report.Changed, report.Reproduced)
	}
}

// TestAnUnarchivedVersionIsCountedNotSkipped. Silence is the failure this
// whole line of work is against: a decision whose rules are gone must appear
// in the report as unexaminable, never be quietly dropped from the total.
func TestAnUnarchivedVersionIsCountedNotSkipped(t *testing.T) {
	inForce := compile(t, []string{"good.example.com"}, 500)
	report := Run([]event.Event{
		decisionEvent("policy_deny", "ffffffffffff", "whatever", nil),
	}, archiveOf(t), compile(t, nil, 500))

	if report.Total != 1 {
		t.Fatalf("total = %d, want 1: an unreplayable decision still happened", report.Total)
	}
	if report.NotArchived != 1 {
		t.Fatalf("notArchived = %d, want 1", report.NotArchived)
	}
	if report.Rows[0].Candidate != nil {
		t.Fatal("a decision whose own rules are gone must carry no counterfactual")
	}
	_ = inForce
}

// TestADivergentReplayIsReportedLoudly. If replaying a decision against the
// very version it names disagrees with what was recorded, the record and the
// code no longer agree about the past, and every counterfactual built on that
// row is worthless. It must never be silently folded into the reproduced pile.
func TestADivergentReplayIsReportedLoudly(t *testing.T) {
	inForce := compile(t, []string{"good.example.com"}, 500)
	// The event claims an allow the rules could not have produced.
	report := Run([]event.Event{
		decisionEvent("policy_allow", inForce.Version(), "allowed: request satisfies all matched policy rules", nil),
	}, archiveOf(t, inForce), compile(t, nil, 500))

	if report.Diverged != 1 {
		t.Fatalf("diverged = %d, want 1. rows: %+v", report.Diverged, report.Rows)
	}
	if report.Reproduced != 0 {
		t.Fatalf("a divergent row must not count as reproduced")
	}
	if report.Rows[0].Candidate != nil {
		t.Fatal("a divergent row must carry no counterfactual")
	}
	if report.Rows[0].Note == "" {
		t.Error("a divergence must say what disagreed")
	}
}

// TestAnAllowGrantedByAHumanIsNotADivergence. The approval token is
// deliberately never recorded, so replay cannot redeem one. What it CAN do is
// reach the exact hold a human then answered, and that is faithful up to the
// human's answer, not a disagreement about the past.
func TestAnAllowGrantedByAHumanIsNotADivergence(t *testing.T) {
	inForce := compile(t, []string{"good.example.com"}, 5)
	ev := decisionEvent("policy_allow", inForce.Version(),
		`estimated cost $12.40 exceeds policy "finance-guardrail" threshold $5.00; allowed via a valid approval_token`,
		map[string]any{"domains": []any{"good.example.com"}, "approval_token_required": true})

	// Raising the threshold above the cost: the action no longer needs anybody.
	report := Run([]event.Event{ev}, archiveOf(t, inForce), compile(t, []string{"good.example.com"}, 500))

	if report.Diverged != 0 {
		t.Fatalf("an approval-granted allow must not be a divergence: %+v", report.Rows[0])
	}
	if report.ApprovalDecided != 1 {
		t.Fatalf("approvalDecided = %d, want 1 (%s: %s)", report.ApprovalDecided, report.Rows[0].Fidelity, report.Rows[0].Note)
	}
	if report.Rows[0].Candidate == nil {
		t.Fatal("the counterfactual is well defined here: under the candidate nobody is asked at all")
	}
	if report.Rows[0].Candidate.Decision != pdp.Allow || report.Rows[0].Candidate.ApprovalTokenRequired {
		t.Fatalf("candidate = %s (approval required: %v), want a plain allow",
			report.Rows[0].Candidate.Decision, report.Rows[0].Candidate.ApprovalTokenRequired)
	}
}

// TestAnEventWithoutTheQuestionIsUnreadable covers the records written before
// the emitter carried the decision input. They are not replayable and the
// report says so by name rather than counting them as unchanged.
func TestAnEventWithoutTheQuestionIsUnreadable(t *testing.T) {
	old := event.Event{
		Schema: "taipanbox.dev/agent-event/v0.2", TS: "2026-08-30T00:00:00Z",
		Source: "wardryx", Type: "policy_deny", AgentID: "agent://acme.example/finance/bot1",
		RunID: "r0",
		Data:  map[string]any{"reason": "domain is not allowed", "tool_names": []any{"http_get"}},
	}
	report := Run([]event.Event{old}, archiveOf(t), compile(t, nil, 500))

	if report.Unreadable != 1 {
		t.Fatalf("unreadable = %d, want 1", report.Unreadable)
	}
	if report.Total != 1 {
		t.Fatalf("total = %d, want 1", report.Total)
	}
	if report.Rows[0].Note == "" {
		t.Error("an unreadable row must say what it lacked")
	}
}

// TestNonDecisionEventsAreNotCounted. An events file carries policy_updated,
// approval_granted and the rest; only the three verdicts are decisions, and
// counting the others would inflate every number in the report.
func TestNonDecisionEventsAreNotCounted(t *testing.T) {
	inForce := compile(t, []string{"good.example.com"}, 500)
	report := Run([]event.Event{
		{Schema: "s", TS: "t", Source: "wardryx", Type: "policy_updated", AgentID: "agent://acme.example/system",
			Data: map[string]any{"action": "put", "policy_version": inForce.Version()}},
		{Schema: "s", TS: "t", Source: "wardryx", Type: "approval_granted", AgentID: "agent://acme.example/finance/bot1",
			Data: map[string]any{"approval_id": "a1"}},
	}, archiveOf(t, inForce), compile(t, nil, 500))

	if report.Total != 0 {
		t.Fatalf("total = %d, want 0: no decision was replayed", report.Total)
	}
	if len(report.Rows) != 0 {
		t.Fatalf("rows = %d, want 0", len(report.Rows))
	}
}

// TestAHoldThatStaysAHoldIsNotAChange guards the counting: a candidate that
// leaves a decision alone must not appear in the changed tally.
func TestAHoldThatStaysAHoldIsNotAChange(t *testing.T) {
	inForce := compile(t, []string{"good.example.com"}, 5)
	ev := decisionEvent("approval_requested", inForce.Version(),
		`estimated cost $12.40 exceeds policy "finance-guardrail" threshold $5.00; human approval required`,
		map[string]any{"domains": []any{"good.example.com"}})

	report := Run([]event.Event{ev}, archiveOf(t, inForce), compile(t, []string{"good.example.com"}, 10))

	if report.Reproduced != 1 {
		t.Fatalf("reproduced = %d, want 1 (%s)", report.Reproduced, report.Rows[0].Note)
	}
	if report.Changed != 0 {
		t.Fatalf("changed = %d, want 0: still over the new threshold, still a hold", report.Changed)
	}
}

// TestTheReportNamesWhatItCouldNotExamine. A change count that silently omits
// the decisions a run could not replay reads as coverage it does not have,
// which is the same silent failure the whole line of work is against.
func TestTheReportNamesWhatItCouldNotExamine(t *testing.T) {
	inForce := compile(t, []string{"good.example.com"}, 500)
	candidate := compile(t, []string{"good.example.com", "payouts.evil.example"}, 500)
	reason := `domain "payouts.evil.example" is not allowed by policy "finance-guardrail" (target agent://acme.example/finance/*)`

	report := Run([]event.Event{
		decisionEvent("policy_deny", inForce.Version(), reason, nil),
		decisionEvent("policy_deny", "ffffffffffff", reason, nil),
		{Schema: "s", TS: "t", Source: "wardryx", Type: "policy_deny",
			AgentID: "agent://acme.example/finance/bot1", RunID: "old",
			Data: map[string]any{"reason": reason}},
	}, archiveOf(t, inForce), candidate)

	out := Format(report, "events.ndjson", "candidate.yaml")

	for _, want := range []string{
		"Replayed 3 decision(s)",
		"not archived",
		"unreadable",
		"1 of 1 replayable decision(s) change",
		"2 decision(s) could not be replayed and are NOT in the figures above",
		"deny -> allow",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report never says %q:\n%s", want, out)
		}
	}
}

// TestWithNoCandidateTheReportIsAFidelityCheck. Asking only "can this history
// be replayed at all" is a useful question on its own, and the report must
// not imply a comparison nobody asked for.
func TestWithNoCandidateTheReportIsAFidelityCheck(t *testing.T) {
	inForce := compile(t, []string{"good.example.com"}, 500)
	reason := `domain "payouts.evil.example" is not allowed by policy "finance-guardrail" (target agent://acme.example/finance/*)`
	report := Run([]event.Event{decisionEvent("policy_deny", inForce.Version(), reason, nil)},
		archiveOf(t, inForce), nil)

	out := Format(report, "events.ndjson", "")
	if !strings.Contains(out, "1 of 1 can") {
		t.Errorf("the fidelity-only report does not say what it found:\n%s", out)
	}
	if strings.Contains(out, "change") {
		t.Errorf("with no candidate the report must not talk about changes:\n%s", out)
	}
	if report.Rows[0].Candidate != nil {
		t.Error("with no candidate a row must carry no counterfactual")
	}
}

// TestAnEmptyFileSaysSoRatherThanReportingZeroChanges. "0 of 0 change" reads
// like a clean bill of health for a file that held no decisions at all.
func TestAnEmptyFileSaysSoRatherThanReportingZeroChanges(t *testing.T) {
	out := Format(Run(nil, archiveOf(t), compile(t, nil, 500)), "empty.ndjson", "candidate.yaml")
	if !strings.Contains(out, "no decisions in this file") {
		t.Errorf("an empty run must say it measured nothing:\n%s", out)
	}
}
