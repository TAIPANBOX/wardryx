package sloburn

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
)

// The reader answers for one agent what the quality plane's event file says
// about its error budget. These tests write that file the way the plane does
// (a hash-chained NDJSON stream of agent-event lines, source verdryx, type
// slo_burn) and ask the reader what it makes of it.

const (
	botA = "agent://lab.example/support/bot-a"
	botB = "agent://lab.example/support/bot-b"
)

var t0 = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

// absent marks a data member that is left out of the event altogether.
type absent struct{}

type bus struct {
	t    *testing.T
	path string
	w    *event.ChainedWriter
}

func newBus(t *testing.T) *bus {
	t.Helper()
	path := filepath.Join(t.TempDir(), "verdryx-events.ndjson")
	w, err := event.NewChainedWriter(path)
	if err != nil {
		t.Fatalf("NewChainedWriter: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	return &bus{t: t, path: path, w: w}
}

func (b *bus) write(e event.Event) {
	b.t.Helper()
	if err := b.w.Write(e); err != nil {
		b.t.Fatalf("write: %v", err)
	}
}

// burn writes an slo_burn event the way verdryx's burn_events payload shapes it.
func (b *bus) burn(agent, sli, trigger string, seen any, ts time.Time) {
	b.t.Helper()
	data := map[string]any{
		"sli": sli, "target": 0.95, "observed": 0.8, "events": 100,
		"window": "28d", "budget_remaining": -3.0, "burn_rate": 14.4,
		"trigger": trigger, "identity_field": "agent_id",
	}
	if _, omit := seen.(absent); !omit {
		data["burn_events_seen"] = seen
	}
	b.write(event.Event{
		Schema: "taipanbox.dev/agent-event/v0.2", TS: ts.UTC().Format(time.RFC3339Nano),
		Source: "verdryx", Type: "slo_burn", Severity: "high", AgentID: agent, Data: data,
	})
}

func (b *bus) other(source, typ, agent string, ts time.Time) {
	b.t.Helper()
	b.write(event.Event{
		Schema: "taipanbox.dev/agent-event/v0.2", TS: ts.UTC().Format(time.RFC3339Nano),
		Source: source, Type: typ, AgentID: agent, Data: map[string]any{"trigger": "exhausted", "sli": "task_success"},
	})
}

func (b *bus) bytes() []byte {
	b.t.Helper()
	raw, err := os.ReadFile(b.path)
	if err != nil {
		b.t.Fatal(err)
	}
	return raw
}

func (b *bus) replace(raw []byte) {
	b.t.Helper()
	if err := os.WriteFile(b.path, raw, 0o600); err != nil {
		b.t.Fatal(err)
	}
}

// clock is a hand-set clock the reader reads.
type clock struct{ now time.Time }

func (c *clock) at() time.Time { return c.now }

func reader(t *testing.T, b *bus, maxAge time.Duration) (*Reader, *clock) {
	t.Helper()
	c := &clock{now: t0}
	r := New(b.path, maxAge).WithClock(c.at)
	if st := r.Refresh(); st != StateOK {
		t.Fatalf("the reader's first state is %q, want ok", st)
	}
	return r, c
}

func mustSignal(t *testing.T, r *Reader, agent string) Signal {
	t.Helper()
	sig, ok := r.For(agent)
	if !ok {
		t.Fatalf("no signal for %s while the state is %q", agent, r.State())
	}
	return sig
}

func TestAnExhaustedEventGivesTheAgentTheValueExhausted(t *testing.T) {
	b := newBus(t)
	b.burn(botA, "task_success", "exhausted", 40, t0.Add(-time.Hour))
	r, _ := reader(t, b, DefaultMaxAge)
	sig := mustSignal(t, r, botA)
	if sig.Name != SignalName || sig.Value != ValueExhausted || sig.Probability != 1 || sig.Source != SignalSource {
		t.Fatalf("signal = %+v, want slo_burn exhausted at probability 1 from %s", sig, SignalSource)
	}
}

func TestOnlyTheExactAgentIsSignalled(t *testing.T) {
	b := newBus(t)
	b.burn(botA, "task_success", "exhausted", 40, t0.Add(-time.Hour))
	r, _ := reader(t, b, DefaultMaxAge)
	for _, other := range []string{botB, botA + "-2", strings.ToUpper(botA), botA + "/", " " + botA, "agent://lab.example/support/bot-"} {
		if sig := mustSignal(t, r, other); sig.Value != ValueNone {
			t.Errorf("%q got %q from an event about %q, want none", other, sig.Value, botA)
		}
	}
}

func TestAnAgentWithNoEventGetsTheValueNoneAndTheHeadOfTheFile(t *testing.T) {
	b := newBus(t)
	b.burn(botA, "task_success", "exhausted", 40, t0.Add(-time.Hour))
	r, _ := reader(t, b, DefaultMaxAge)
	sig := mustSignal(t, r, botB)
	if sig.Value != ValueNone || sig.Probability != 1 || sig.Name != SignalName {
		t.Fatalf("an agent with no event got %+v, want slo_burn none", sig)
	}
	lines := bytes.Split(bytes.TrimSpace(b.bytes()), []byte("\n"))
	want, err := event.ChainHashRaw(lines[len(lines)-1])
	if err != nil {
		t.Fatal(err)
	}
	if sig.AnswerID != want {
		t.Errorf("none names %q, want the chain hash of the last line, %q", sig.AnswerID, want)
	}

	empty := newBus(t)
	empty.replace(nil)
	r2, _ := reader(t, empty, DefaultMaxAge)
	if sig := mustSignal(t, r2, botA); sig.Value != ValueNone || sig.AnswerID != "" {
		t.Errorf("an empty file gave %+v, want none naming nothing", sig)
	}
}

func TestAFastBurnWithoutAMeasuredRateIsUnmeasuredAndNeverNone(t *testing.T) {
	// burn_events_seen is the n behind burn_rate. A rate of 0.0 over no events is
	// "never measured", not "burning nothing", and the float cannot tell them apart.
	for name, seen := range map[string]any{
		"absent": absent{}, "null": nil, "zero": 0, "negative": -1, "fractional": 1.5,
		"text": "3", "boolean": true, "list": []any{3},
	} {
		t.Run(name, func(t *testing.T) {
			b := newBus(t)
			b.burn(botA, "task_success", "fast_burn", seen, t0.Add(-time.Hour))
			r, _ := reader(t, b, DefaultMaxAge)
			if sig := mustSignal(t, r, botA); sig.Value != ValueUnmeasured {
				t.Fatalf("a fast burn with burn_events_seen %s is %q, want unmeasured", name, sig.Value)
			}
		})
	}
	b := newBus(t)
	b.burn(botA, "task_success", "fast_burn", 1, t0.Add(-time.Hour))
	r, _ := reader(t, b, DefaultMaxAge)
	if sig := mustSignal(t, r, botA); sig.Value != ValueFastBurn {
		t.Fatalf("a fast burn over one measured event is %q, want fast_burn", sig.Value)
	}
}

func TestAnExhaustedEventStandsOnTheBudgetWhateverItsRateSays(t *testing.T) {
	for name, seen := range map[string]any{"absent": absent{}, "zero": 0, "text": "n"} {
		t.Run(name, func(t *testing.T) {
			b := newBus(t)
			b.burn(botA, "task_success", "exhausted", seen, t0.Add(-time.Hour))
			r, _ := reader(t, b, DefaultMaxAge)
			if sig := mustSignal(t, r, botA); sig.Value != ValueExhausted {
				t.Fatalf("an exhausted budget with burn_events_seen %s is %q, want exhausted", name, sig.Value)
			}
		})
	}
}

func TestAnEventThePlaneCannotReadIsUnmeasured(t *testing.T) {
	// A trigger this build does not know, a missing one, and a payload that is not
	// an object are events about the agent that cannot be read. They are not
	// evidence of health either, so the agent is unmeasured, never none.
	for name, data := range map[string]map[string]any{
		"slow burn":      {"sli": "task_success", "trigger": "slow_burn", "burn_events_seen": 9},
		"no trigger":     {"sli": "task_success"},
		"trigger casing": {"sli": "task_success", "trigger": "EXHAUSTED"},
		"no payload":     nil,
	} {
		t.Run(name, func(t *testing.T) {
			b := newBus(t)
			b.write(event.Event{
				Schema: "taipanbox.dev/agent-event/v0.2", TS: t0.Add(-time.Hour).Format(time.RFC3339Nano),
				Source: "verdryx", Type: "slo_burn", AgentID: botA, Data: data,
			})
			r, _ := reader(t, b, DefaultMaxAge)
			if sig := mustSignal(t, r, botA); sig.Value != ValueUnmeasured {
				t.Fatalf("%s gave %q, want unmeasured", name, sig.Value)
			}
		})
	}
}

func TestAnEventPastItsMaxAgeNoLongerSignals(t *testing.T) {
	b := newBus(t)
	b.burn(botA, "task_success", "exhausted", 40, t0)
	r, c := reader(t, b, 2*time.Hour)

	c.now = t0.Add(2 * time.Hour) // exactly at its age: still live
	if sig := mustSignal(t, r, botA); sig.Value != ValueExhausted {
		t.Fatalf("at its max age the signal is %q, want exhausted", sig.Value)
	}
	c.now = t0.Add(2*time.Hour + time.Second)
	if sig := mustSignal(t, r, botA); sig.Value != ValueNone {
		t.Fatalf("a second past its max age the signal is %q, want none", sig.Value)
	}
	// Expiry is read when the question is asked, not when the file was last
	// polled, so a poll that has not run since changes nothing.
	c.now = t0.Add(time.Minute)
	if sig := mustSignal(t, r, botA); sig.Value != ValueExhausted {
		t.Fatalf("with the clock back inside the age the signal is %q, want exhausted", sig.Value)
	}
}

func TestTheNewestEventOfAnIndicatorReplacesTheOlderOne(t *testing.T) {
	b := newBus(t)
	b.burn(botA, "task_success", "exhausted", 40, t0.Add(-3*time.Hour))
	b.burn(botA, "task_success", "fast_burn", 12, t0.Add(-time.Hour))
	r, _ := reader(t, b, DefaultMaxAge)
	if sig := mustSignal(t, r, botA); sig.Value != ValueFastBurn {
		t.Fatalf("exhausted then a later fast burn is %q, want fast_burn: the budget came back", sig.Value)
	}

	b2 := newBus(t)
	b2.burn(botA, "task_success", "fast_burn", 12, t0.Add(-3*time.Hour))
	b2.burn(botA, "task_success", "exhausted", 40, t0.Add(-time.Hour))
	r2, _ := reader(t, b2, DefaultMaxAge)
	if sig := mustSignal(t, r2, botA); sig.Value != ValueExhausted {
		t.Fatalf("a fast burn then exhausted is %q, want exhausted", sig.Value)
	}
}

func TestTheMostSevereLiveIndicatorIsReported(t *testing.T) {
	b := newBus(t)
	b.burn(botA, "cost_discipline", "fast_burn", 12, t0.Add(-time.Hour))
	b.burn(botA, "task_success", "exhausted", 40, t0.Add(-2*time.Hour))
	b.burn(botA, "containment", "fast_burn", 0, t0.Add(-time.Hour)) // unmeasured
	r, c := reader(t, b, 90*time.Minute)
	if sig := mustSignal(t, r, botA); sig.Value != ValueFastBurn {
		// the exhausted one is 2h old and past the 90 minute age
		t.Fatalf("with exhausted expired the signal is %q, want fast_burn over unmeasured", sig.Value)
	}
	c.now = t0.Add(-90 * time.Minute) // all three inside their age
	if sig := mustSignal(t, r, botA); sig.Value != ValueExhausted {
		t.Fatalf("with all three live the signal is %q, want exhausted", sig.Value)
	}
	c.now = t0.Add(10 * time.Hour)
	if sig := mustSignal(t, r, botA); sig.Value != ValueNone {
		t.Fatalf("with all three expired the signal is %q, want none", sig.Value)
	}
}

func TestOnlyVerdryxSloBurnEventsCount(t *testing.T) {
	b := newBus(t)
	b.other("verdryx", "quality_drift", botA, t0.Add(-time.Hour))
	b.other("tokenfuse", "slo_burn", botA, t0.Add(-time.Hour))
	b.other("wardryx", "policy_deny", botA, t0.Add(-time.Hour))
	r, _ := reader(t, b, DefaultMaxAge)
	if sig := mustSignal(t, r, botA); sig.Value != ValueNone {
		t.Fatalf("other lines gave %q, want none", sig.Value)
	}
	b.burn(botA, "task_success", "exhausted", 40, t0.Add(-time.Minute))
	b.other("verdryx", "eval_run", botA, t0.Add(-time.Second))
	if st := r.Refresh(); st != StateOK {
		t.Fatalf("state %q after more lines, want ok: the chain runs across the lines that are not ours", st)
	}
	if sig := mustSignal(t, r, botA); sig.Value != ValueExhausted {
		t.Fatalf("got %q, want exhausted from the one slo_burn line among the others", sig.Value)
	}
}

func TestTheSignalNamesTheLineItStandsOn(t *testing.T) {
	b := newBus(t)
	b.burn(botA, "task_success", "exhausted", 40, t0.Add(-time.Hour))
	b.other("verdryx", "eval_run", botB, t0.Add(-time.Minute))
	r, _ := reader(t, b, DefaultMaxAge)
	lines := bytes.Split(bytes.TrimSpace(b.bytes()), []byte("\n"))
	want, err := event.ChainHashRaw(lines[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := mustSignal(t, r, botA).AnswerID; got != want {
		t.Fatalf("answer id = %q, want the chain hash of the exhausted line, %q", got, want)
	}
	// And it is the hash the next line carries, so an auditor can walk from the
	// decision to the line by the chain itself.
	next, err := event.Unmarshal(lines[1])
	if err != nil {
		t.Fatal(err)
	}
	if next.PrevHash != want {
		t.Fatalf("the next line's prev_hash is %q, not the answer id %q", next.PrevHash, want)
	}
}

func TestAFileWhoseChainDoesNotHoldIsBroken(t *testing.T) {
	build := func(t *testing.T) *bus {
		b := newBus(t)
		b.burn(botA, "task_success", "exhausted", 40, t0.Add(-3*time.Hour))
		b.burn(botB, "task_success", "exhausted", 40, t0.Add(-2*time.Hour))
		b.burn(botA, "containment", "fast_burn", 9, t0.Add(-time.Hour))
		return b
	}
	cases := map[string]func(raw []byte) []byte{
		"a line edited in place": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"observed":0.8`), []byte(`"observed":0.1`), 1)
		},
		"a line removed from the middle": func(raw []byte) []byte {
			lines := bytes.SplitAfter(raw, []byte("\n"))
			return bytes.Join([][]byte{lines[0], lines[2]}, nil)
		},
		"a malformed line": func(raw []byte) []byte {
			lines := bytes.SplitAfter(raw, []byte("\n"))
			return bytes.Join([][]byte{lines[0], []byte("{not json\n"), lines[1], lines[2]}, nil)
		},
		"a malformed last line": func(raw []byte) []byte {
			// Nothing follows it to be left unverifiable, so only the count of
			// malformed lines can see it.
			return append(append([]byte{}, raw...), []byte("{not json\n")...)
		},
		"a chain restart": func(raw []byte) []byte {
			// A complete event with no prev_hash after the first line: legal in the
			// spec, and the history before it is no longer bound to what follows.
			line := `{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-11-04T11:59:00Z","source":"verdryx","type":"slo_burn","agent_id":"` + botB + `","data":{"sli":"task_success","trigger":"exhausted"}}` + "\n"
			return append(append([]byte{}, raw...), line...)
		},
		"a file that opens mid-chain": func(raw []byte) []byte {
			lines := bytes.SplitAfter(raw, []byte("\n"))
			return bytes.Join(lines[1:], nil)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			b := build(t)
			r, _ := reader(t, b, DefaultMaxAge)
			if sig := mustSignal(t, r, botA); sig.Value != ValueExhausted {
				t.Fatalf("control: the intact file gave %q", sig.Value)
			}
			b.replace(mutate(b.bytes()))
			if st := r.Refresh(); st != StateBroken {
				t.Fatalf("state = %q, want broken", st)
			}
			for _, agent := range []string{botA, botB} {
				if sig, ok := r.For(agent); ok {
					t.Errorf("a broken file still signalled %s: %+v", agent, sig)
				}
			}
		})
	}
}

func TestAnEventDatedInTheFutureMakesTheFileBroken(t *testing.T) {
	b := newBus(t)
	b.burn(botA, "task_success", "exhausted", 40, t0.Add(ClockLeeway)) // inside the leeway
	r, c := reader(t, b, DefaultMaxAge)
	if st := r.State(); st != StateOK {
		t.Fatalf("an event %s ahead is %q, want ok: that much clock skew is allowed", ClockLeeway, st)
	}
	b.burn(botA, "task_success", "exhausted", 40, t0.Add(ClockLeeway+time.Second))
	if st := r.Refresh(); st != StateBroken {
		t.Fatalf("an event past the leeway is %q, want broken", st)
	}
	c.now = t0.Add(ClockLeeway + 2*time.Second) // the clock catches up with the file
	if st := r.Refresh(); st != StateOK {
		t.Fatalf("once the clock reaches the event the state is %q, want ok: it was only early", st)
	}
}

func TestAnEventWithNoUsableTimeMakesTheFileBroken(t *testing.T) {
	for _, ts := range []string{"yesterday", "2026-11-04", "2026-11-04 12:00:00", "1793793600"} {
		t.Run(ts, func(t *testing.T) {
			b := newBus(t)
			b.write(event.Event{
				Schema: "taipanbox.dev/agent-event/v0.2", TS: ts, Source: "verdryx", Type: "slo_burn", AgentID: botA,
				Data: map[string]any{"sli": "task_success", "trigger": "exhausted"},
			})
			r := New(b.path, DefaultMaxAge).WithClock((&clock{now: t0}).at)
			if st := r.Refresh(); st != StateBroken {
				t.Fatalf("ts %q gave %q, want broken: an event that cannot be aged cannot be expired", ts, st)
			}
		})
	}
}

func TestAFileOverTheSizeCapIsBroken(t *testing.T) {
	b := newBus(t)
	b.burn(botA, "task_success", "exhausted", 40, t0.Add(-time.Hour))
	size := int64(len(b.bytes()))
	r := New(b.path, DefaultMaxAge).WithClock((&clock{now: t0}).at).WithMaxBytes(size)
	if st := r.Refresh(); st != StateOK {
		t.Fatalf("a file exactly at the cap is %q, want ok", st)
	}
	r = New(b.path, DefaultMaxAge).WithClock((&clock{now: t0}).at).WithMaxBytes(size - 1)
	if st := r.Refresh(); st != StateBroken {
		t.Fatalf("a file one byte over the cap is %q, want broken", st)
	}
}

func TestATornLastLineIsAnAppendInProgressNotAnError(t *testing.T) {
	b := newBus(t)
	b.burn(botA, "task_success", "exhausted", 40, t0.Add(-time.Hour))
	r, _ := reader(t, b, DefaultMaxAge)
	f, err := os.OpenFile(b.path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(`{"schema":"taipanbox.dev/agent-event/v0.2","ts":"2026-11-04T11:`); err != nil {
		t.Fatal(err)
	}
	if st := r.Refresh(); st != StateOK {
		t.Fatalf("a half-written last line makes the state %q, want ok: a writer is mid-append", st)
	}
	if sig := mustSignal(t, r, botA); sig.Value != ValueExhausted {
		t.Fatalf("the complete lines before it gave %q, want exhausted", sig.Value)
	}
}

func TestAMissingFileIsUnreadableAndRecoversWhenItAppears(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "later.ndjson")
	c := &clock{now: t0}
	r := New(path, DefaultMaxAge).WithClock(c.at)
	if st := r.Refresh(); st != StateUnreadable {
		t.Fatalf("a missing file is %q, want unreadable", st)
	}
	if sig, ok := r.For(botA); ok {
		t.Fatalf("an unreadable file signalled %+v", sig)
	}
	w, err := event.NewChainedWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.Write(event.Event{
		Schema: "taipanbox.dev/agent-event/v0.2", TS: t0.Add(-time.Hour).Format(time.RFC3339Nano),
		Source: "verdryx", Type: "slo_burn", AgentID: botA,
		Data: map[string]any{"sli": "task_success", "trigger": "exhausted"},
	}); err != nil {
		t.Fatal(err)
	}
	if st := r.Refresh(); st != StateOK {
		t.Fatalf("once the file is there the state is %q, want ok", st)
	}
	if sig := mustSignal(t, r, botA); sig.Value != ValueExhausted {
		t.Fatalf("got %q, want exhausted", sig.Value)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if st := r.Refresh(); st != StateUnreadable {
		t.Fatalf("a file that went away is %q, want unreadable", st)
	}
}

func TestSomethingThatIsNotAPlainFileIsUnreadableAndNeverBlocks(t *testing.T) {
	r := New(t.TempDir(), DefaultMaxAge).WithClock((&clock{now: t0}).at)
	if st := r.Refresh(); st != StateUnreadable {
		t.Fatalf("a directory is %q, want unreadable", st)
	}
	if fifo := filepath.Join(t.TempDir(), "pipe"); makeFIFO(fifo) == nil {
		done := make(chan State, 1)
		go func() { done <- New(fifo, DefaultMaxAge).WithClock((&clock{now: t0}).at).Refresh() }()
		select {
		case st := <-done:
			if st != StateUnreadable {
				t.Fatalf("a named pipe is %q, want unreadable", st)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("reading a named pipe blocked")
		}
	}
}

func TestAnUnchangedFileIsNotParsedAgainAndAChangedOneIs(t *testing.T) {
	b := newBus(t)
	b.burn(botA, "task_success", "exhausted", 40, t0.Add(-time.Hour))
	r, _ := reader(t, b, DefaultMaxAge)
	if n := r.Parses(); n != 1 {
		t.Fatalf("parses after the first read = %d, want 1", n)
	}
	for i := 0; i < 3; i++ {
		r.Refresh()
	}
	if n := r.Parses(); n != 1 {
		t.Fatalf("parses after three polls of an untouched file = %d, want 1", n)
	}
	b.burn(botB, "task_success", "exhausted", 40, t0.Add(-time.Minute))
	r.Refresh()
	if n := r.Parses(); n != 2 {
		t.Fatalf("parses after a line was appended = %d, want 2", n)
	}
	if sig := mustSignal(t, r, botB); sig.Value != ValueExhausted {
		t.Fatalf("the appended line was not seen: %+v", sig)
	}
}

func TestAFileWrittenByVerdryxItselfVerifiesAndIsRead(t *testing.T) {
	// testdata/verdryx-events.ndjson is what `verdryx slo --events` wrote on a real
	// run (see testdata/README.md): Python's json and Python's chain hash, read by
	// Go's. The chain holds across the two languages or this fails.
	raw, err := os.ReadFile(filepath.Join("testdata", "verdryx-events.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	rep, err := event.VerifyChain(bytes.NewReader(raw))
	if err != nil || !rep.Ok() || rep.Malformed != 0 || len(rep.Unverifiable) != 0 || len(rep.HeadLines) != 1 {
		t.Fatalf("the shared library does not accept the fixture: %+v, %v", rep, err)
	}
	var newest time.Time
	var exhausted, fast string
	if _, err := event.Scan(bytes.NewReader(raw), func(e event.Event) error {
		ts, err := time.Parse(time.RFC3339Nano, e.TS)
		if err != nil {
			return err
		}
		if ts.After(newest) {
			newest = ts
		}
		switch e.Data["trigger"] {
		case "exhausted":
			exhausted = e.AgentID
		case "fast_burn":
			fast = e.AgentID
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if exhausted == "" {
		t.Fatal("the fixture holds no exhausted event")
	}
	r := New(filepath.Join("testdata", "verdryx-events.ndjson"), DefaultMaxAge).WithClock((&clock{now: newest.Add(time.Minute)}).at)
	if st := r.Refresh(); st != StateOK {
		t.Fatalf("the state of a file verdryx wrote is %q, want ok", st)
	}
	if sig := mustSignal(t, r, exhausted); sig.Value != ValueExhausted {
		t.Fatalf("%s is %q, want exhausted", exhausted, sig.Value)
	}
	if fast != "" {
		if sig := mustSignal(t, r, fast); sig.Value != ValueFastBurn && sig.Value != ValueExhausted {
			t.Fatalf("%s is %q, want fast_burn or worse", fast, sig.Value)
		}
	}
}

func TestParseMaxAgeAcceptsOnlyAUsableAge(t *testing.T) {
	if d, err := ParseMaxAge(""); err != nil || d != DefaultMaxAge {
		t.Fatalf("empty = %v, %v, want the default %v", d, err, DefaultMaxAge)
	}
	if d, err := ParseMaxAge("36h"); err != nil || d != 36*time.Hour {
		t.Fatalf("36h = %v, %v", d, err)
	}
	for _, bad := range []string{"0", "0s", "-1h", "30", "soon", "59s", "721h", "1h30", " 1h "} {
		if d, err := ParseMaxAge(bad); err == nil {
			t.Errorf("%q was accepted as %v", bad, d)
		}
	}
	for _, edge := range []string{"1m", "720h"} {
		if _, err := ParseMaxAge(edge); err != nil {
			t.Errorf("%q is a limit and was refused: %v", edge, err)
		}
	}
}

func TestRunPollsTheFileUntilTheContextEnds(t *testing.T) {
	b := newBus(t)
	r := New(b.path, DefaultMaxAge).WithClock((&clock{now: t0}).at).WithPoll(5 * time.Millisecond)
	r.Refresh()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	b.burn(botA, "task_success", "exhausted", 40, t0.Add(-time.Hour))
	deadline := time.Now().Add(5 * time.Second)
	for {
		if sig, ok := r.For(botA); ok && sig.Value == ValueExhausted {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a line appended to the file was never seen: Run does not poll")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return when its context ended")
	}
}

func TestAChangeOfStateIsLoggedOnceAndTheDetailNamesTheLine(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	lines := func(substr string) int { return strings.Count(logged.String(), substr) }

	b := newBus(t)
	b.burn(botA, "task_success", "exhausted", 40, t0.Add(-3*time.Hour))
	b.burn(botB, "task_success", "exhausted", 40, t0.Add(-2*time.Hour))
	r, _ := reader(t, b, DefaultMaxAge)
	if logged.Len() != 0 {
		t.Fatalf("a good file logged: %q", logged.String())
	}

	good := b.bytes()
	b.replace(bytes.Replace(good, []byte(`"observed":0.8`), []byte(`"observed":0.1`), 1))
	for i := 0; i < 4; i++ {
		r.Refresh()
	}
	if n := lines("are broken"); n != 1 {
		t.Fatalf("four polls of one broken file logged %d broken lines, want 1:\n%s", n, logged.String())
	}
	if d := r.Detail(); !strings.Contains(d, "line 2") {
		t.Errorf("the detail %q does not name the line the chain broke at", d)
	}
	if !strings.Contains(logged.String(), b.path) {
		t.Errorf("the log does not name the file: %s", logged.String())
	}

	b.replace(good)
	r.Refresh()
	r.Refresh()
	if n := lines("readable again"); n != 1 || r.State() != StateOK {
		t.Fatalf("the file came back: state %q, %d recovery lines, want ok and 1", r.State(), n)
	}
	if r.Detail() != "" {
		t.Errorf("a good file has the detail %q", r.Detail())
	}
}
