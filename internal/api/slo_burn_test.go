package api

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/replay"
	"github.com/TAIPANBOX/wardryx/internal/sloburn"
)

// An agent whose error budget is spent has its actions put to a person. The
// quality plane writes an slo_burn event when a budget is exhausted or burning
// fast; wardryx reads that file, adds one standing signal to a decision, and the
// policy, not the file, says whether the signal holds anything. These tests
// drive that through the real handler, with the file written the way the plane
// writes it.

const (
	budgetAgent  = "agent://acme.example/support/bot1"
	budgetAgent2 = "agent://acme.example/support/bot2"
)

var budgetT0 = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

// budgetPol holds the support agents' tool calls on the slo_burn signal.
func budgetPol(whenAbsent string, values ...string) policy.Policy {
	return policy.Policy{
		Name: "budget", Target: "agent://acme.example/support/*",
		HoldIfSignal: &policy.SignalRule{Name: "slo_burn", Values: values, MinProbability: usd(1), WhenAbsent: whenAbsent},
	}
}

var spent = []string{sloburn.ValueExhausted, sloburn.ValueFastBurn}

type budgetHarness struct {
	*sigHarness
	bus    string
	w      *event.ChainedWriter
	reader *sloburn.Reader
	now    time.Time
}

func newBudgetHarness(t *testing.T, singleUse bool, maxAge time.Duration, pols ...policy.Policy) *budgetHarness {
	t.Helper()
	h := &budgetHarness{sigHarness: newSigHarness(t, singleUse, pols...), now: budgetT0}
	h.bus = filepath.Join(t.TempDir(), "verdryx-events.ndjson")
	w, err := event.NewChainedWriter(h.bus)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	h.w = w
	h.reader = sloburn.New(h.bus, maxAge).WithClock(func() time.Time { return h.now })
	h.srv.WithSLOBurn(h.reader)
	return h
}

// burn writes an slo_burn event the way verdryx shapes it, then lets wardryx
// poll the file.
func (h *budgetHarness) burn(t *testing.T, agent, trigger string, seen any, age time.Duration) {
	t.Helper()
	data := map[string]any{
		"sli": "task_success", "target": 0.95, "observed": 0.8, "events": 100, "window": "28d",
		"budget_remaining": -3.0, "burn_rate": 14.4, "trigger": trigger, "identity_field": "agent_id",
	}
	if seen != nil {
		data["burn_events_seen"] = seen
	}
	if err := h.w.Write(event.Event{
		Schema: "taipanbox.dev/agent-event/v0.2", TS: h.now.Add(-age).UTC().Format(time.RFC3339Nano),
		Source: "verdryx", Type: "slo_burn", Severity: "high", AgentID: agent, Data: data,
	}); err != nil {
		t.Fatal(err)
	}
	h.reader.Refresh()
}

// removeBus takes the file away, as a missing mount or a deleted file would.
func (h *budgetHarness) removeBus(t *testing.T) {
	t.Helper()
	_ = h.w.Close()
	if err := os.Remove(h.bus); err != nil {
		t.Fatal(err)
	}
	h.reader.Refresh()
}

// reopenBus brings a file back, with a fresh chain, as the plane would write it.
func (h *budgetHarness) reopenBus(t *testing.T) {
	t.Helper()
	w, err := event.NewChainedWriter(h.bus)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	h.w = w
}

func (h *budgetHarness) askAs(agent string) decideRequestDTO {
	a := plainAsk()
	a.AgentID = agent
	return a
}

func (h *budgetHarness) decision(t *testing.T, a decideRequestDTO) decideResponseDTO {
	t.Helper()
	rec := h.decide(t, a)
	if rec.Code != http.StatusOK {
		t.Fatalf("decide answered %d: %s", rec.Code, rec.Body.String())
	}
	return decodeBody[decideResponseDTO](t, rec)
}

func TestAnExhaustedAgentsToolCallIsHeldWhenThePolicyHoldsOnTheSignal(t *testing.T) {
	// Control: the same policy and the same call with the option off is allowed.
	off := newSigHarness(t, false, budgetPol("", spent...))
	if got := decodeBody[decideResponseDTO](t, off.decide(t, plainAsk())); got.Decision != pdp.Allow {
		t.Fatalf("control: with the option off the call is %s (%s), want allow", got.Decision, got.Reason)
	}

	h := newBudgetHarness(t, false, sloburn.DefaultMaxAge, budgetPol("", spent...))
	h.burn(t, budgetAgent, "exhausted", 40, time.Hour)
	held := h.decision(t, h.askAs(budgetAgent))
	if held.Decision != pdp.Hold || held.ApprovalID == "" || !held.ApprovalTokenRequired {
		t.Fatalf("an exhausted agent's call is %s (%s) approval %q, want a hold a person can decide", held.Decision, held.Reason, held.ApprovalID)
	}
	if held.Cacheable {
		t.Error("a decision under a rule on the budget signal was marked cacheable")
	}
	for _, want := range []string{`"slo_burn"`, `"exhausted"`} {
		if !strings.Contains(held.Reason, want) {
			t.Errorf("the reason %q does not name %s", held.Reason, want)
		}
	}

	// The record carries the signal, its source and the line it stands on.
	var hold *event.Event
	events := h.read(t)
	for i := range events {
		if events[i].Type == "approval_requested" {
			hold = &events[i]
		}
	}
	if hold == nil {
		t.Fatalf("no approval_requested among %d events", len(events))
	}
	list, _ := hold.Data["signals"].([]any)
	if len(list) != 1 {
		t.Fatalf("recorded signals = %#v, want exactly the standing one", hold.Data["signals"])
	}
	got, _ := list[0].(map[string]any)
	if got["name"] != "slo_burn" || got["value"] != "exhausted" || got["probability"] != float64(1) ||
		got["source"] != sloburn.SignalSource || got["answer_id"] == "" || got["answer_id"] == nil {
		t.Errorf("recorded signal = %#v", got)
	}
}

func TestTheExamplePolicyHoldsAnAgentWhoseBudgetIsSpent(t *testing.T) {
	// The policy the README points at, as an operator would copy it.
	set, err := policy.Load(filepath.Join("..", "..", "docs", "examples", "hold-while-the-budget-is-spent.yaml"))
	if err != nil {
		t.Fatalf("the example policy does not load: %v", err)
	}
	h := newBudgetHarness(t, false, sloburn.DefaultMaxAge, set.Policies()...)
	h.burn(t, budgetAgent, "exhausted", 40, time.Hour)
	if got := h.decision(t, h.askAs(budgetAgent)); got.Decision != pdp.Hold {
		t.Fatalf("the example policy and a spent budget: %s (%s), want hold", got.Decision, got.Reason)
	}
	if got := h.decision(t, h.askAs(budgetAgent2)); got.Decision != pdp.Allow {
		t.Fatalf("the example policy and an agent with no event: %s (%s), want allow", got.Decision, got.Reason)
	}
}

func TestAGrantedApprovalLiftsTheBudgetHoldForThatCall(t *testing.T) {
	h := newBudgetHarness(t, true, sloburn.DefaultMaxAge, budgetPol("", spent...))
	h.burn(t, budgetAgent, "exhausted", 40, time.Hour)
	ask := h.askAs(budgetAgent)
	held := h.decision(t, ask)
	if held.Decision != pdp.Hold {
		t.Fatalf("setup: %s (%s)", held.Decision, held.Reason)
	}
	granted := decodeBody[approvalDecideResponseDTO](t, doRequest(t, h.srv.Handler(), http.MethodPost,
		"/v1/approvals/"+held.ApprovalID+"/decide", adminKey, approvalDecideRequestDTO{Decision: "grant", DecidedBy: "alice@acme.example"}))
	ask.ApprovalToken = granted.ApprovalToken
	if got := h.decision(t, ask); got.Decision != pdp.Allow {
		t.Fatalf("the granted call is %s (%s), want allow", got.Decision, got.Reason)
	}
	// Single use: the same token does not carry a second call, and the agent is
	// still held.
	if got := h.decision(t, ask); got.Decision != pdp.Hold {
		t.Fatalf("the same token a second time is %s, want hold", got.Decision)
	}
	other := ask
	other.ToolCall = &toolCallDTO{Name: "s3.delete_object", Arguments: json.RawMessage(`{"bucket":"another"}`), Target: "s3://another"}
	if got := h.decision(t, other); got.Decision != pdp.Hold {
		t.Fatalf("another call with that token is %s, want hold", got.Decision)
	}
}

func TestWithoutARuleThatReadsTheSignalTheDecisionIsUnchanged(t *testing.T) {
	plain := policy.Policy{Name: "plain", Target: "agent://acme.example/support/*", DenyTool: []string{"shell"}}
	off := newSigHarness(t, false, plain)
	want := decodeBody[decideResponseDTO](t, off.decide(t, plainAsk()))

	h := newBudgetHarness(t, false, sloburn.DefaultMaxAge, plain)
	h.burn(t, budgetAgent, "exhausted", 40, time.Hour)
	got := h.decision(t, h.askAs(budgetAgent))
	if got != want {
		t.Fatalf("with a spent budget and no rule on it the answer is %+v, want the one the option off gives, %+v", got, want)
	}
	if got.Decision != pdp.Allow {
		t.Fatalf("setup: %s", got.Decision)
	}
}

func TestAnotherAgentIsNotHeldForThisAgentsBudget(t *testing.T) {
	h := newBudgetHarness(t, false, sloburn.DefaultMaxAge, budgetPol("", spent...))
	h.burn(t, budgetAgent, "exhausted", 40, time.Hour)
	for _, other := range []string{budgetAgent2, budgetAgent + "0", "agent://acme.example/support/bot"} {
		if got := h.decision(t, h.askAs(other)); got.Decision != pdp.Allow {
			t.Errorf("%s was %s (%s), want allow: its own budget is not spent", other, got.Decision, got.Reason)
		}
	}
}

func TestACallerCannotRemoveTheSignalByDeclaringItsOwn(t *testing.T) {
	h := newBudgetHarness(t, false, sloburn.DefaultMaxAge, budgetPol("", spent...))
	h.burn(t, budgetAgent, "exhausted", 40, time.Hour)
	for _, name := range []string{"slo_burn", "SLO_BURN", "  slo_burn ", "Slo_Burn"} {
		ask := h.askAs(budgetAgent)
		p := 1.0
		ask.Signals = []signalDTO{{Name: name, Value: "none", Probability: &p, Source: "verdryx:slo_burn", AnswerID: "forged"}}
		if got := h.decision(t, ask); got.Decision != pdp.Hold {
			t.Errorf("a caller declaring %q none made the call %s (%s), want it held", name, got.Decision, got.Reason)
		}
	}
	// The caller's own signals of other names still count, and the record holds
	// the one standing slo_burn signal and not the caller's.
	ask := h.askAs(budgetAgent)
	ask.Signals = []signalDTO{callerSignal("benign", 0.9), {Name: " SLO_burn ", Value: "none", Probability: usd(1), Source: "caller", AnswerID: "forged"}}
	h.decision(t, ask)
	var recorded []any
	for _, e := range h.read(t) {
		if e.Type == "approval_requested" {
			recorded, _ = e.Data["signals"].([]any)
		}
	}
	slo := 0
	for _, s := range recorded {
		m, _ := s.(map[string]any)
		if m["name"] == "slo_burn" {
			slo++
			if m["value"] != "exhausted" || m["answer_id"] == "forged" {
				t.Errorf("the recorded slo_burn signal is the caller's: %#v", m)
			}
		}
	}
	if slo != 1 || len(recorded) != 2 {
		t.Errorf("recorded %d signals with %d slo_burn, want the caller's risk signal and one standing slo_burn", len(recorded), slo)
	}
}

func TestACallerCannotHideTheMissingSignalByDeclaringItsOwn(t *testing.T) {
	h := newBudgetHarness(t, false, sloburn.DefaultMaxAge, budgetPol("hold", spent...))
	// No file at all: the signal is absent for everyone.
	h.removeBus(t)
	if st := h.reader.State(); st != sloburn.StateUnreadable {
		t.Fatalf("setup: state %q", st)
	}
	bare := h.decision(t, h.askAs(budgetAgent))
	if bare.Decision != pdp.Hold || !strings.Contains(bare.Reason, "when_absent") {
		t.Fatalf("with the file missing the call is %s (%s), want the absent-signal hold", bare.Decision, bare.Reason)
	}
	// A rule reads a signal's name with case and surrounding space folded, so any
	// such spelling of the name is "a signal of its name" to it, and would end the
	// absence if it were kept.
	for _, name := range []string{"slo_burn", "SLO_BURN", "  slo_burn ", "Slo_Burn", " SLO_burn"} {
		ask := h.askAs(budgetAgent)
		p := 1.0
		ask.Signals = []signalDTO{{Name: name, Value: "none", Probability: &p, Source: "caller"}}
		if got := h.decision(t, ask); got.Decision != pdp.Hold || !strings.Contains(got.Reason, "when_absent") {
			t.Errorf("a caller's own %q none made the call %s (%s), want the absent-signal hold to stand", name, got.Decision, got.Reason)
		}
	}
}

func TestWithTheOptionOnARequestMayCarryFifteenSignalsOfItsOwn(t *testing.T) {
	many := func(n int) []signalDTO {
		out := make([]signalDTO, n)
		for i := range out {
			p := 0.1
			out[i] = signalDTO{Name: fmt.Sprintf("s%d", i), Value: "x", Probability: &p, Source: "classifier"}
		}
		return out
	}
	off := newSigHarness(t, false, budgetPol("", spent...))
	a := plainAsk()
	a.Signals = many(pdp.MaxSignals)
	if rec := off.decide(t, a); rec.Code != http.StatusOK {
		t.Fatalf("control: sixteen signals with the option off answered %d: %s", rec.Code, rec.Body.String())
	}

	h := newBudgetHarness(t, false, sloburn.DefaultMaxAge, budgetPol("", spent...))
	h.burn(t, budgetAgent, "exhausted", 40, time.Hour)
	a = h.askAs(budgetAgent)
	a.Signals = many(pdp.MaxSignals - 1)
	if got := h.decision(t, a); got.Decision != pdp.Hold {
		t.Fatalf("fifteen signals and the standing one: %s (%s), want hold", got.Decision, got.Reason)
	}
	a.Signals = many(pdp.MaxSignals)
	rec := h.decide(t, a)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "15") {
		t.Fatalf("sixteen signals with the option on answered %d %s, want a 400 naming fifteen", rec.Code, rec.Body.String())
	}
	// The recorded decision with all fifteen and the standing one still replays:
	// the record never exceeds the cap the replay reads.
	a.Signals = many(pdp.MaxSignals - 1)
	h.decision(t, a)
	report := replay.Run(h.read(t), h.arch, nil)
	if report.Unreadable != 0 || report.Diverged != 0 {
		t.Fatalf("a request at the cap did not replay:\n%s", replay.Format(report, "events", ""))
	}
}

func TestAReadableFileGivesAnAgentWithNoEventTheValueNoneSoHoldOnAbsenceHoldsNobodyHealthy(t *testing.T) {
	h := newBudgetHarness(t, false, sloburn.DefaultMaxAge, budgetPol("hold", spent...))
	h.burn(t, budgetAgent, "exhausted", 40, time.Hour)

	healthy := h.decision(t, h.askAs(budgetAgent2))
	if healthy.Decision != pdp.Allow {
		t.Fatalf("an agent with no event is %s (%s) under a rule that holds on absence, want allow", healthy.Decision, healthy.Reason)
	}
	if held := h.decision(t, h.askAs(budgetAgent)); held.Decision != pdp.Hold {
		t.Fatalf("the exhausted agent is %s, want hold", held.Decision)
	}
	var recorded []any
	for _, e := range h.read(t) {
		if e.Type == "policy_allow" {
			recorded, _ = e.Data["signals"].([]any)
		}
	}
	if len(recorded) != 1 {
		t.Fatalf("the allow recorded %#v, want the standing none", recorded)
	}
	m, _ := recorded[0].(map[string]any)
	if m["name"] != "slo_burn" || m["value"] != "none" || m["answer_id"] == "" || m["answer_id"] == nil {
		t.Errorf("recorded %#v, want slo_burn none naming the head of the file", m)
	}
}

func TestAnUnreadableFileLeavesTheSignalAbsentAndWhenAbsentDecides(t *testing.T) {
	modelCall := func(agent string) decideRequestDTO {
		m := "claude-sonnet-5-5"
		return decideRequestDTO{AgentID: agent, RunID: "run-model", Model: &m}
	}
	for name, breakIt := range map[string]func(t *testing.T, h *budgetHarness){
		"the file is missing": func(t *testing.T, h *budgetHarness) {
			if err := os.Remove(h.bus); err != nil {
				t.Fatal(err)
			}
		},
		"the chain is broken": func(t *testing.T, h *budgetHarness) {
			raw, err := os.ReadFile(h.bus)
			if err != nil {
				t.Fatal(err)
			}
			raw = []byte(strings.Replace(string(raw), `"observed":0.8`, `"observed":0.1`, 1))
			if err := os.WriteFile(h.bus, raw, 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			// The default: the missing signal changes nothing, as it never did.
			def := newBudgetHarness(t, false, sloburn.DefaultMaxAge, budgetPol("", spent...))
			def.burn(t, budgetAgent, "exhausted", 40, time.Hour)
			def.burn(t, budgetAgent, "fast_burn", 3, 30*time.Minute)
			breakIt(t, def)
			def.reader.Refresh()
			if got := def.decision(t, def.askAs(budgetAgent)); got.Decision != pdp.Allow {
				t.Fatalf("with the default when_absent the call is %s (%s), want allow", got.Decision, got.Reason)
			}

			h := newBudgetHarness(t, false, sloburn.DefaultMaxAge, budgetPol("hold", spent...))
			h.burn(t, budgetAgent, "exhausted", 40, time.Hour)
			h.burn(t, budgetAgent, "fast_burn", 3, 30*time.Minute)
			breakIt(t, h)
			h.reader.Refresh()
			got := h.decision(t, h.askAs(budgetAgent))
			if got.Decision != pdp.Hold || !strings.Contains(got.Reason, "when_absent: hold") {
				t.Fatalf("with when_absent: hold the call is %s (%s), want the absent-signal hold", got.Decision, got.Reason)
			}
			if got := h.decision(t, modelCall(budgetAgent)); got.Decision != pdp.Allow {
				t.Fatalf("a model call is %s, want allow: it is never held for a missing signal", got.Decision)
			}
		})
	}

	// And the file coming back ends the absence.
	h := newBudgetHarness(t, false, sloburn.DefaultMaxAge, budgetPol("hold", spent...))
	h.removeBus(t)
	if st := h.reader.State(); st != sloburn.StateUnreadable {
		t.Fatalf("setup: %q", st)
	}
	if got := h.decision(t, h.askAs(budgetAgent)); got.Decision != pdp.Hold {
		t.Fatalf("with no file: %s, want hold", got.Decision)
	}
	h.reopenBus(t)
	h.burn(t, budgetAgent2, "exhausted", 40, time.Hour)
	if got := h.decision(t, h.askAs(budgetAgent)); got.Decision != pdp.Allow {
		t.Fatalf("with the file back and no event for the agent: %s (%s), want allow", got.Decision, got.Reason)
	}
}

func TestAnUnmeasuredRateHoldsOnlyWhereThePolicyListsIt(t *testing.T) {
	h := newBudgetHarness(t, false, sloburn.DefaultMaxAge, budgetPol("", spent...))
	h.burn(t, budgetAgent, "fast_burn", 0, time.Hour)
	if got := h.decision(t, h.askAs(budgetAgent)); got.Decision != pdp.Allow {
		t.Fatalf("a fast burn nobody measured is %s (%s) under a rule on exhausted and fast_burn, want allow", got.Decision, got.Reason)
	}
	h2 := newBudgetHarness(t, false, sloburn.DefaultMaxAge, budgetPol("", append([]string{sloburn.ValueUnmeasured}, spent...)...))
	h2.burn(t, budgetAgent, "fast_burn", 0, time.Hour)
	got := h2.decision(t, h2.askAs(budgetAgent))
	if got.Decision != pdp.Hold || !strings.Contains(got.Reason, `"unmeasured"`) {
		t.Fatalf("with unmeasured listed the call is %s (%s), want a hold naming unmeasured", got.Decision, got.Reason)
	}
}

func TestAnExpiredEventReleasesTheAgent(t *testing.T) {
	h := newBudgetHarness(t, false, time.Hour, budgetPol("", spent...))
	h.burn(t, budgetAgent, "exhausted", 40, 0)
	h.now = budgetT0.Add(30 * time.Minute)
	if got := h.decision(t, h.askAs(budgetAgent)); got.Decision != pdp.Hold {
		t.Fatalf("inside the age: %s, want hold", got.Decision)
	}
	h.now = budgetT0.Add(61 * time.Minute) // no poll in between: expiry is read per decision
	if got := h.decision(t, h.askAs(budgetAgent)); got.Decision != pdp.Allow {
		t.Fatalf("past the age: %s (%s), want allow", got.Decision, got.Reason)
	}
}

func TestTheBudgetSignalOnlyEverTurnsAnAllowIntoAHoldOverRandomPolicies(t *testing.T) {
	tools := []string{"s3.delete_object", "search", "shell"}
	models := []string{"claude-sonnet-5-5", "gpt-x"}
	for seed := int64(0); seed < 200; seed++ {
		rng := rand.New(rand.NewSource(seed))
		var pols []policy.Policy
		for i := 0; i < 1+rng.Intn(3); i++ {
			p := policy.Policy{Name: fmt.Sprintf("p%d", i), Target: "agent://acme.example/support/*"}
			if rng.Intn(3) == 0 {
				p.DenyTool = []string{tools[rng.Intn(len(tools))]}
			}
			if rng.Intn(4) == 0 {
				p.AllowTool = []string{tools[rng.Intn(len(tools))], tools[rng.Intn(len(tools))]}
			}
			if rng.Intn(4) == 0 {
				p.AllowModels = []string{models[rng.Intn(len(models))]}
			}
			if rng.Intn(4) == 0 {
				p.RequireHumanAboveUSD = usd(float64(rng.Intn(10)))
			}
			if rng.Intn(5) == 0 {
				p.DenyAboveUSD = usd(float64(5 + rng.Intn(10)))
			}
			if rng.Intn(2) == 0 {
				vals := [][]string{spent, {sloburn.ValueUnmeasured}, {sloburn.ValueNone}, {"exhausted"}}[rng.Intn(4)]
				wa := []string{"", "allow", "hold"}[rng.Intn(3)]
				p.HoldIfSignal = &policy.SignalRule{Name: "slo_burn", Values: vals, MinProbability: usd(float64(rng.Intn(2))), WhenAbsent: wa}
			}
			pols = append(pols, p)
		}
		on := newBudgetHarness(t, false, sloburn.DefaultMaxAge, pols...)
		off := newSigHarness(t, false, pols...)
		switch rng.Intn(5) {
		case 0:
			on.burn(t, budgetAgent, "exhausted", 40, time.Hour)
		case 1:
			on.burn(t, budgetAgent, "fast_burn", 5, time.Hour)
		case 2:
			on.burn(t, budgetAgent, "fast_burn", 0, time.Hour)
		case 3: // the file is not there
			on.removeBus(t)
		default: // a file with other agents only
			on.burn(t, budgetAgent2, "exhausted", 40, time.Hour)
		}
		a := plainAsk()
		a.ToolNames = []string{tools[rng.Intn(len(tools))]}
		a.EstCostUSD = float64(rng.Intn(12))
		if rng.Intn(3) == 0 {
			a.ToolCall = nil
			m := models[rng.Intn(len(models))]
			a.Model = &m
		} else {
			a.ToolCall = &toolCallDTO{Name: a.ToolNames[0], Target: "t"}
		}
		got := on.decision(t, a)
		want := decodeBody[decideResponseDTO](t, off.decide(t, a))
		// The signal may turn an allow into a hold. A hold for a signal that never
		// arrived is the one thing it may also lift: with the option on the signal
		// has arrived and says what it says. Nothing else moves, and nothing ever
		// becomes a deny.
		absenceHold := want.Decision == pdp.Hold && strings.Contains(want.Reason, "when_absent: hold")
		switch {
		case got.Decision == want.Decision && got.Reason == want.Reason:
		case want.Decision == pdp.Allow && got.Decision == pdp.Hold:
		case absenceHold && (got.Decision == pdp.Allow || got.Decision == pdp.Hold):
		default:
			t.Fatalf("seed %d: with the option on the call is %s (%s), off it is %s (%s): the signal may only turn an allow into a hold", seed, got.Decision, got.Reason, want.Decision, want.Reason)
		}
		if got.Decision == pdp.Deny && want.Decision != pdp.Deny {
			t.Fatalf("seed %d: the signal produced a deny", seed)
		}
		if want.Decision == pdp.Deny && (got.Decision != pdp.Deny || got.Reason != want.Reason) {
			t.Fatalf("seed %d: the signal changed a deny: off %s, on %s (%s)", seed, want.Reason, got.Decision, got.Reason)
		}
	}
}

func TestAHoldForAnExhaustedBudgetReplaysFromTheRecordAlone(t *testing.T) {
	h := newBudgetHarness(t, false, sloburn.DefaultMaxAge, budgetPol("", spent...))
	h.burn(t, budgetAgent, "exhausted", 40, time.Hour)
	if held := h.decision(t, h.askAs(budgetAgent)); held.Decision != pdp.Hold {
		t.Fatalf("setup: %s (%s)", held.Decision, held.Reason)
	}
	events := h.read(t)
	// The file is gone, and nothing in the replay can ask for it.
	if err := os.Remove(h.bus); err != nil {
		t.Fatal(err)
	}
	report := replay.Run(events, h.arch, nil)
	if report.Total != 1 || report.Reproduced != 1 || report.Diverged != 0 || report.Unreadable != 0 {
		t.Fatalf("the hold did not reproduce from the record:\n%s", replay.Format(report, "events", ""))
	}
	plain, err := policy.Compile([]policy.Policy{{Name: "plain", Target: "agent://acme.example/support/*", DenyTool: []string{"other"}}})
	if err != nil {
		t.Fatal(err)
	}
	cf := replay.Run(events, h.arch, plain)
	if cf.Changed != 1 || cf.Rows[0].Baseline != pdp.Hold || cf.Rows[0].Candidate.Decision != pdp.Allow {
		t.Fatalf("a policy without the rule did not turn the recorded hold into an allow:\n%s", replay.Format(cf, "events", "plain"))
	}
}

func TestReadyzSaysWhatTheBudgetFileIsDoingAndNeverWhy(t *testing.T) {
	h := newBudgetHarness(t, false, sloburn.DefaultMaxAge, budgetPol("", spent...))
	ready := func() (int, map[string]string, string) {
		rec := doRaw(t, h.srv.Handler(), http.MethodGet, "/readyz", "", "")
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("readyz body %q: %v", rec.Body.String(), err)
		}
		return rec.Code, body, rec.Body.String()
	}

	h.removeBus(t) // no file
	code, body, raw := ready()
	if code != http.StatusOK || body["signal_events"] != "unreadable" || body["store"] != "ok" {
		t.Fatalf("missing file: %d %s, want 200 with signal_events unreadable", code, raw)
	}
	h.reopenBus(t)
	h.burn(t, budgetAgent, "exhausted", 40, time.Hour)
	h.burn(t, budgetAgent2, "exhausted", 40, time.Hour)
	if code, body, raw = ready(); code != http.StatusOK || body["signal_events"] != "ok" {
		t.Fatalf("good file: %d %s, want 200 with signal_events ok", code, raw)
	}
	raw0, _ := os.ReadFile(h.bus)
	if err := os.WriteFile(h.bus, []byte(strings.Replace(string(raw0), `"observed":0.8`, `"observed":0.1`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	h.reader.Refresh()
	code, body, raw = ready()
	if code != http.StatusOK || body["signal_events"] != "broken" {
		t.Fatalf("broken chain: %d %s, want 200 with signal_events broken", code, raw)
	}
	// Never why: no path, no line number, no library text (invariant 10).
	for _, leak := range []string{h.bus, filepath.Base(h.bus), "no such file", "line ", "prev_hash", "chain"} {
		if strings.Contains(raw, leak) {
			t.Errorf("readyz leaks %q: %s", leak, raw)
		}
	}
}

func TestReadyzLeavesTheBodyAloneWhenTheOptionIsOff(t *testing.T) {
	h := newSigHarness(t, false)
	rec := doRaw(t, h.srv.Handler(), http.MethodGet, "/readyz", "", "")
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("readyz body %q: %v", rec.Body.String(), err)
	}
	if rec.Code != http.StatusOK || len(body) != 1 || body["store"] != "ok" {
		t.Fatalf("readyz with the option off: %d %s, want the body it always had", rec.Code, rec.Body.String())
	}
}

func TestTheDecisionPathKnowsNothingOfTheBudgetFile(t *testing.T) {
	const module = "github.com/TAIPANBOX/wardryx/"
	reader := module + "internal/sloburn"
	for _, pkg := range []string{"internal/pdp", "internal/policy", "internal/replay", "internal/approval", "internal/archive"} {
		out, err := exec.Command("go", "list", "-deps", module+pkg).Output()
		if err != nil {
			t.Fatalf("go list -deps %s: %v", pkg, err)
		}
		for _, dep := range strings.Fields(string(out)) {
			if dep == reader {
				t.Errorf("%s depends on the budget file reader", pkg)
			}
		}
	}
	out, err := exec.Command("go", "list", "-deps", reader).Output()
	if err != nil {
		t.Fatalf("go list -deps sloburn: %v", err)
	}
	deps := strings.Fields(string(out))
	if len(deps) < 10 {
		t.Fatalf("go list measured nothing: %d dependencies", len(deps))
	}
	for _, dep := range deps {
		switch {
		case dep == "net" || dep == "net/http" || dep == "os/exec" || dep == "database/sql" || strings.Contains(dep, "pgx"):
			t.Errorf("the reader reaches %s: it reads one local file and must reach no network, process or database", dep)
		}
	}
}
