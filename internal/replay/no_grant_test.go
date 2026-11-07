package replay

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// Candidate replay is the check to make before a floor is enabled: it reads what
// agents actually did and says which of those calls would wait for a person. A
// report that missed a caller would be the installer turning the floor on over an
// agent nobody knew was there, so these tests hold what it counts.

const (
	workerAgent   = "agent://acme.example/agents/worker"
	operatorAgent = "agent://acme.example/agents/operator"
	noPolicySays  = "allowed: no policy targets agent "
)

func compileSet(t *testing.T, pols ...policy.Policy) *policy.Set {
	t.Helper()
	set, err := policy.Compile(pols)
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	return set
}

func floorSet(t *testing.T, more ...policy.Policy) *policy.Set {
	t.Helper()
	return compileSet(t, append([]policy.Policy{{Name: "tool-hold", Target: "*", WhenNoGrant: policy.WhenNoGrantHold}}, more...)...)
}

func toolAllow(agent, tool, version, ts string) event.Event {
	ev := decisionEvent("policy_allow", version, noPolicySays+agent, map[string]any{
		"tool_names": []any{tool},
		"tool_call":  map[string]any{"name": tool, "target": "t", "arguments_sha256": "00", "arguments_truncated": false, "digest": "00"},
	})
	ev.AgentID = agent
	ev.TS = ts
	return ev
}

func modelAllow(agent, version string) event.Event {
	ev := decisionEvent("policy_allow", version, noPolicySays+agent, map[string]any{"model": "claude-sonnet-5", "tool_names": []any{"fetch_url"}})
	ev.AgentID = agent
	return ev
}

func TestACandidateFloorReportsWhatItWouldHold(t *testing.T) {
	old := policy.Empty()
	arch := archiveOf(t, old)
	evs := []event.Event{
		toolAllow(workerAgent, "fetch_url", old.Version(), "2026-11-01T10:00:00Z"),
		toolAllow(workerAgent, "fetch_url", old.Version(), "2026-11-03T10:00:00Z"),
		toolAllow(workerAgent, "fetch_url", old.Version(), "2026-11-02T10:00:00Z"),
		toolAllow(workerAgent, "browse", old.Version(), "2026-11-01T11:00:00Z"),
		toolAllow(operatorAgent, "ask", old.Version(), "2026-11-04T10:00:00Z"),
		modelAllow(workerAgent, old.Version()),
	}
	report := Run(evs, arch, floorSet(t))
	if report.Total != 6 || report.Reproduced != 6 {
		t.Fatalf("%+v", report)
	}
	if report.Changed != 5 {
		t.Fatalf("Changed = %d, want the five tool calls and not the model call", report.Changed)
	}
	want := []HeldTool{
		{AgentID: operatorAgent, Tool: "ask", Calls: 1, Last: "2026-11-04T10:00:00Z"},
		{AgentID: workerAgent, Tool: "browse", Calls: 1, Last: "2026-11-01T11:00:00Z"},
		{AgentID: workerAgent, Tool: "fetch_url", Calls: 3, Last: "2026-11-03T10:00:00Z"},
	}
	if len(report.WouldHold) != len(want) {
		t.Fatalf("WouldHold = %+v", report.WouldHold)
	}
	for i := range want {
		if report.WouldHold[i] != want[i] {
			t.Errorf("WouldHold[%d] = %+v, want %+v", i, report.WouldHold[i], want[i])
		}
	}
}

func TestACandidateGrantTakesACallOutOfTheReport(t *testing.T) {
	old := policy.Empty()
	arch := archiveOf(t, old)
	evs := []event.Event{
		toolAllow(workerAgent, "fetch_url", old.Version(), "2026-11-01T10:00:00Z"),
		toolAllow(workerAgent, "browse", old.Version(), "2026-11-01T10:00:00Z"),
	}
	report := Run(evs, arch, floorSet(t, policy.Policy{Name: "g", Target: workerAgent, GrantTool: []string{"fetch_url"}}))
	if len(report.WouldHold) != 1 || report.WouldHold[0].Tool != "browse" {
		t.Fatalf("WouldHold = %+v, want browse alone", report.WouldHold)
	}
}

func TestEveryUngrantedToolOfACallIsReported(t *testing.T) {
	old := policy.Empty()
	arch := archiveOf(t, old)
	ev := toolAllow(workerAgent, "fetch_url", old.Version(), "2026-11-01T10:00:00Z")
	ev.Data["tool_names"] = []any{"fetch_url", "browse"}
	report := Run([]event.Event{ev}, arch, floorSet(t))
	if len(report.WouldHold) != 2 {
		t.Fatalf("WouldHold = %+v: a run that names one tool at a time makes an operator enable it twice", report.WouldHold)
	}
}

func TestACandidateWithNoFloorReportsNothingHeld(t *testing.T) {
	old := policy.Empty()
	arch := archiveOf(t, old)
	cost := compileSet(t, policy.Policy{Name: "p", Target: "agent://*", RequireHumanAboveUSD: usd(0)})
	ev := toolAllow(workerAgent, "fetch_url", old.Version(), "2026-11-01T10:00:00Z")
	ev.Data["est_cost_usd"] = 5.0
	report := Run([]event.Event{ev}, arch, cost)
	if len(report.WouldHold) != 0 {
		t.Fatalf("a cost hold is reported as a hold of the floor: %+v", report.WouldHold)
	}
}

func TestAHoldAnEarlierRuleWouldTakeIsNotReportedAsTheFloors(t *testing.T) {
	old := policy.Empty()
	arch := archiveOf(t, old)
	cand := floorSet(t, policy.Policy{Name: "no", Target: "agent://*", DenyTool: []string{"fetch_url"}})
	report := Run([]event.Event{toolAllow(workerAgent, "fetch_url", old.Version(), "2026-11-01T10:00:00Z")}, arch, cand)
	if len(report.WouldHold) != 0 || report.Rows[0].Candidate.Decision != pdp.Deny {
		t.Fatalf("%+v %+v", report.WouldHold, report.Rows[0].Candidate)
	}
}

func TestAHoldAnotherRuleTakesIsNotCountedAsTheFloors(t *testing.T) {
	old := policy.Empty()
	arch := archiveOf(t, old)
	cand := floorSet(t, policy.Policy{Name: "pricey", Target: "agent://*", RequireHumanAboveUSD: usd(0)})
	ev := toolAllow(workerAgent, "fetch_url", old.Version(), "2026-11-01T10:00:00Z")
	ev.Data["est_cost_usd"] = 5.0
	report := Run([]event.Event{ev}, arch, cand)
	if report.Rows[0].Candidate.Decision != pdp.Hold || len(report.WouldHold) != 0 {
		t.Fatalf("a cost hold is listed under the floor: %+v %+v", report.Rows[0].Candidate, report.WouldHold)
	}
}

func TestFormatNamesEveryAgentAndToolWithItsCountAndLastTime(t *testing.T) {
	old := policy.Empty()
	arch := archiveOf(t, old)
	hostile := "agent://x/y\n  was: nothing to see here"
	report := Run([]event.Event{
		toolAllow(workerAgent, "fetch_url", old.Version(), "2026-11-01T10:00:00Z"),
		toolAllow(workerAgent, "fetch_url", old.Version(), "2026-11-02T10:00:00Z"),
		toolAllow(hostile, "ask", old.Version(), "2026-11-02T10:00:00Z"),
	}, arch, floorSet(t))
	out := Format(report, "events.ndjson", "candidate.yaml")
	for _, want := range []string{"would wait for a person", "when_no_grant", `"fetch_url"`, `"` + workerAgent + `"`, "2026-11-02T10:00:00Z", "  2   "} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(strings.SplitN(out, "would wait for a person", 2)[1], "y\n  was:") {
		t.Errorf("a hostile id reached the table raw:\n%s", out)
	}
}

func TestFormatSaysNothingOfTheFloorWhenNothingWouldBeHeld(t *testing.T) {
	old := policy.Empty()
	arch := archiveOf(t, old)
	report := Run([]event.Event{modelAllow(workerAgent, old.Version())}, arch, floorSet(t))
	if out := Format(report, "e", "c"); strings.Contains(out, "would wait for a person") {
		t.Fatalf("the report names a hold nothing would take:\n%s", out)
	}
}

func TestTheJSONFormCarriesWhatCouldNotBeExamined(t *testing.T) {
	old := policy.Empty()
	arch := archiveOf(t, old)
	gone := toolAllow(workerAgent, "fetch_url", "version-nobody-kept", "2026-11-01T10:00:00Z")
	report := Run([]event.Event{toolAllow(workerAgent, "ask", old.Version(), "2026-11-01T10:00:00Z"), gone}, arch, floorSet(t))
	got := AsJSON(report, "e", "c")
	if got.NotArchived != 1 || got.Unexamined != 1 || got.Total != 2 || got.Reproduced != 1 || got.Changed != 1 || len(got.WouldHold) != 1 {
		t.Fatalf("%+v", got)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if _, ok := back["would_hold"]; !ok {
		t.Fatalf("no would_hold: %s", raw)
	}
	empty := AsJSON(Run(nil, arch, nil), "e", "")
	raw, _ = json.Marshal(empty)
	if !strings.Contains(string(raw), `"would_hold":[]`) {
		t.Fatalf("an empty report must carry an empty list, so a reader never has to tell null from none: %s", raw)
	}
}

func TestARecordedNoGrantHoldReproducesFromTheRecordedToolCall(t *testing.T) {
	set := floorSet(t)
	reason := `policy "tool-hold" when_no_grant: no policy grants tool "fetch_url" to agent "` + workerAgent + `"; human approval required`
	ev := decisionEvent("approval_requested", set.Version(), reason, map[string]any{
		"tool_names":              []any{"fetch_url"},
		"approval_token_required": true,
		"tool_call":               recordedCall("fetch_url"),
	})
	ev.AgentID = workerAgent
	report := Run([]event.Event{ev}, archiveOf(t, set), nil)
	if report.Reproduced != 1 {
		t.Fatalf("%+v %+v", report, report.Rows)
	}
	// Without the tool call in the record, the same question is a model call and
	// passes: replay must read the call back, or a hold reads as a divergence.
	delete(ev.Data, "tool_call")
	if got := Run([]event.Event{ev}, archiveOf(t, set), nil); got.Diverged != 1 {
		t.Fatalf("a hold with no recorded call must diverge: %+v", got)
	}
}

func TestAGrantedNoGrantHoldIsApprovalDecided(t *testing.T) {
	set := floorSet(t)
	reason := `policy "tool-hold" when_no_grant: no policy grants tool "fetch_url" to agent "` + workerAgent + `"; allowed via a valid approval_token`
	ev := decisionEvent("policy_allow", set.Version(), reason, map[string]any{
		"tool_names":              []any{"fetch_url"},
		"approval_token_required": true,
		"tool_call":               recordedCall("fetch_url"),
	})
	ev.AgentID = workerAgent
	report := Run([]event.Event{ev}, archiveOf(t, set), nil)
	if report.ApprovalDecided != 1 || report.Rows[0].Baseline != pdp.Hold {
		t.Fatalf("%+v %+v", report, report.Rows)
	}
}

func TestAnOldAllowStaysReproducedUnderItsOwnVersion(t *testing.T) {
	old := policy.Empty()
	floored := floorSet(t)
	arch := archiveOf(t, old, floored)
	ev := toolAllow(workerAgent, "fetch_url", old.Version(), "2026-11-01T10:00:00Z")
	report := Run([]event.Event{ev}, arch, nil)
	if report.Reproduced != 1 || report.Diverged != 0 {
		t.Fatalf("an allow from before the floor no longer replays: %+v %+v", report, report.Rows)
	}
}

func TestAnAllowTheFloorWouldHaveHeldUnderItsOwnVersionDiverges(t *testing.T) {
	set := floorSet(t)
	ev := toolAllow(workerAgent, "fetch_url", set.Version(), "2026-11-01T10:00:00Z")
	ev.Data["reason"] = "allowed: request satisfies all matched policy rules"
	report := Run([]event.Event{ev}, archiveOf(t, set), nil)
	if report.Diverged != 1 {
		t.Fatalf("a plain allow under a floor that nothing lifted must diverge: %+v", report)
	}
}
