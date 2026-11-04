// Package sloburn reads the quality plane's event file and answers, for one
// agent, the standing signal a decision carries: whether the agent's error
// budget is spent.
//
// The quality plane (verdryx) writes an slo_burn event when an agent's budget is
// exhausted or burning fast. Wardryx reads that file here, outside the decision
// path, and the API layer adds one signal to a request before it reaches the
// engine. The engine only reads signals (pdp.Signal), so everything it does with
// this one is what it does with any other: a hold_if_signal rule can add a hold
// and can do nothing else (invariant 25), and a decision records the signal so a
// replay needs no file (invariant 27). Nothing in internal/pdp, internal/policy,
// internal/replay, internal/approval or internal/archive imports this package,
// and this package imports no network, process or database package
// (invariant 45; scripts/slo-signal-stays-outside-the-decision.sh).
//
// What the file is believed for. The file is a hash-chained NDJSON stream. The
// chain is checked with the shared library (event.VerifyChain) and is strict: a
// break, a malformed line, a chain restart, a file that opens mid-chain, a time
// that cannot be read, an event dated ahead of the clock and a file over the size
// cap each make the whole file broken, and a broken file signals nobody. The
// chain shows that a line was not edited or removed from the middle. It does not
// say who wrote the file, and it cannot see lines cut from the end: whoever can
// append to the file can write a line that verifies, so the file is only as
// trustworthy as its permissions.
//
// What the signal says. Probability is always 1: a line on the file is a fact the
// quality plane established, not an estimate. The value says which fact:
//
//	exhausted   the newest live event of some indicator says the budget is spent
//	fast_burn   the budget is burning fast, over a rate that was measured
//	unmeasured  an event about the agent that does not establish a burn: a fast
//	            burn whose burn_events_seen is missing, zero, negative, fractional
//	            or not a number (the rate is then "never measured", which a float
//	            of 0.0 cannot tell from "burning nothing"), or an event this build
//	            cannot read. It is never none, since an unmeasured zero is not
//	            evidence of health
//	none        the file is sound and holds no live event for the agent. This says
//	            there is no live event, not that the agent is healthy
//
// An exhausted event stands on the budget and not on the rate, so its
// burn_events_seen does not matter. The quality plane writes no event when a
// budget recovers, so recovery is the next event of the same indicator being a
// weaker one, or the signal ending MaxAge after the last event.
package sloburn

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
)

const (
	// SignalName is the name of the signal a decision carries, and the name a
	// hold_if_signal rule reads. It is reserved while the file is read: a signal
	// of this name from a caller is dropped.
	SignalName = "slo_burn"
	// SignalSource is the source recorded on the signal. Recorded, never
	// branched on.
	SignalSource = "verdryx:slo_burn"

	ValueExhausted  = "exhausted"
	ValueFastBurn   = "fast_burn"
	ValueUnmeasured = "unmeasured"
	ValueNone       = "none"

	// DefaultMaxAge is how long after its time an event keeps signalling. It is
	// longer than a daily `verdryx slo` run on purpose: a signal that ends early
	// lets an agent off, and one that ends late holds it a little longer.
	DefaultMaxAge = 48 * time.Hour
	// MinMaxAge and MaxMaxAge bound WARDRYX_SIGNAL_EVENTS_MAX_AGE.
	MinMaxAge = time.Minute
	MaxMaxAge = 30 * 24 * time.Hour
	// PollEvery is how often the file is looked at. Parsing happens only when it
	// changed.
	PollEvery = 15 * time.Second
	// MaxFileBytes is the largest file that is read. A bigger one is broken: it
	// is read whole, and a bus that has outgrown this wants rotating.
	MaxFileBytes = 32 << 20
	// ClockLeeway is how far ahead of this clock an event's time may sit before
	// the file is not believed.
	ClockLeeway = 5 * time.Minute

	eventType   = "slo_burn"
	eventSource = "verdryx"
)

// State is what the file is doing, in a word that carries no path and no error
// text: it is what /readyz says.
type State string

const (
	// StateOK means the file was read and its chain holds.
	StateOK State = "ok"
	// StateUnreadable means it could not be opened or is not a plain file.
	StateUnreadable State = "unreadable"
	// StateBroken means it was read and cannot be believed.
	StateBroken State = "broken"
)

// Signal is the standing signal for one agent. It carries the five fields of a
// pdp.Signal and is converted by the caller: this package imports nothing the
// decision path stands on, and nothing that reaches a network.
type Signal struct {
	Name        string
	Value       string
	Probability float64
	Source      string
	AnswerID    string
}

// Reader holds the last reading of the file. It is safe for concurrent use.
type Reader struct {
	path     string
	maxAge   time.Duration
	maxBytes int64
	now      func() time.Time
	poll     time.Duration

	mu     sync.Mutex // serialises Refresh and guards the fields below
	last   *parsed
	parses int
	logged State

	cur atomic.Pointer[view]
}

// view is what For consults: the state, and the reading behind it when it is ok.
type view struct {
	state  State
	detail string
	p      *parsed
}

type entry struct {
	sli   string
	ts    time.Time
	value string
	hash  string
}

// parsed is one reading of one version of the file. It does not depend on the
// clock, so it can be kept while the file is unchanged.
type parsed struct {
	sum     [sha256.Size]byte
	broken  string
	byAgent map[string][]entry // each agent's newest event per indicator, by indicator
	head    string             // the chain hash of the last line
	maxTS   time.Time          // the latest time of any slo_burn event
}

// New returns a Reader for the file at path whose signals live for maxAge after
// their event. It reads nothing until Refresh.
func New(path string, maxAge time.Duration) *Reader {
	return &Reader{path: path, maxAge: maxAge, maxBytes: MaxFileBytes, now: time.Now, poll: PollEvery}
}

// ParseMaxAge reads WARDRYX_SIGNAL_EVENTS_MAX_AGE: empty is DefaultMaxAge, else a
// Go duration from MinMaxAge to MaxMaxAge.
func ParseMaxAge(s string) (time.Duration, error) {
	if s == "" {
		return DefaultMaxAge, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("WARDRYX_SIGNAL_EVENTS_MAX_AGE is not a duration such as 48h or 90m")
	}
	if d < MinMaxAge || d > MaxMaxAge {
		return 0, fmt.Errorf("WARDRYX_SIGNAL_EVENTS_MAX_AGE must be from %s to %s", MinMaxAge, MaxMaxAge)
	}
	return d, nil
}

// WithClock replaces the clock. It is for tests.
func (r *Reader) WithClock(now func() time.Time) *Reader {
	r.now = now
	return r
}

// WithMaxBytes replaces the size cap. It is for tests.
func (r *Reader) WithMaxBytes(n int64) *Reader {
	r.maxBytes = n
	return r
}

// WithPoll replaces the interval Run polls at. It is for tests.
func (r *Reader) WithPoll(d time.Duration) *Reader {
	r.poll = d
	return r
}

// Parses says how many times the file has been parsed. It is for tests.
func (r *Reader) Parses() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.parses
}

// State is the state of the last Refresh. Before the first, it is unreadable.
func (r *Reader) State() State {
	if v := r.cur.Load(); v != nil {
		return v.state
	}
	return StateUnreadable
}

// Detail says why the state is not ok, for a log line. It names the path and the
// line, so it never goes into an HTTP response.
func (r *Reader) Detail() string {
	if v := r.cur.Load(); v != nil {
		return v.detail
	}
	return "not read yet"
}

// Path is the file being read.
func (r *Reader) Path() string { return r.path }

// MaxAge is how long after its time an event keeps signalling.
func (r *Reader) MaxAge() time.Duration { return r.maxAge }

// Refresh looks at the file, parses it if it changed since the last parse, and
// returns the state. A change of state is logged once.
func (r *Reader) Refresh() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	v := &view{}
	p, err := r.load()
	switch {
	case err != nil:
		v.state, v.detail = StateUnreadable, err.Error()
	case p.broken != "":
		v.state, v.detail = StateBroken, p.broken
	case p.maxTS.After(now.Add(ClockLeeway)):
		v.state, v.detail = StateBroken, fmt.Sprintf("an slo_burn event is dated %s, more than %s ahead of this clock", p.maxTS.UTC().Format(time.RFC3339), ClockLeeway)
	default:
		v.state, v.p = StateOK, p
	}
	r.cur.Store(v)
	r.note(v)
	return v.state
}

// note logs a change of state, once.
func (r *Reader) note(v *view) {
	if v.state == r.logged {
		return
	}
	prev := r.logged
	r.logged = v.state
	switch {
	case v.state == StateOK && prev == "":
		// The first good reading is for the start-up line to report.
	case v.state == StateOK:
		log.Printf("wardryx: signal events %s are readable again, so the slo_burn signal is back for every agent", r.path)
	default:
		log.Printf("wardryx: signal events %s are %s: %s; the slo_burn signal is absent for every agent until that is fixed, and a policy's when_absent decides what that means", r.path, v.state, v.detail)
	}
}

// load returns the parse of the file as it is now, from the last parse if its
// bytes are the same. An error means the file could not be read at all.
//
// The file is read on every poll and told apart by a digest of its bytes, not
// by its size and modification time: an edit of the same length inside one clock
// tick changes neither, and the file is capped small enough that reading it is
// cheap.
func (r *Reader) load() (*parsed, error) {
	// Looked at before it is opened: opening a named pipe waits for a writer.
	fi, err := os.Stat(r.path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("not a plain file")
	}
	f, err := os.Open(r.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err = f.Stat(); err != nil {
		return nil, err
	} else if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("not a plain file")
	}
	data, err := io.ReadAll(io.LimitReader(f, r.maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > r.maxBytes {
		return &parsed{broken: fmt.Sprintf("the file is over the %d byte cap; rotate it", r.maxBytes)}, nil
	}
	sum := sha256.Sum256(data)
	if r.last != nil && r.last.sum == sum {
		return r.last, nil
	}
	p := parse(data)
	p.sum = sum
	r.last = p
	r.parses++
	return p, nil
}

// parse checks the chain and reads the slo_burn lines of one version of the file.
func parse(data []byte) *parsed {
	// A last line with no newline is an append in progress: the writer ends every
	// line with one. It is read on the poll after it is complete.
	if len(data) > 0 && data[len(data)-1] != '\n' {
		if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
			data = data[:i+1]
		} else {
			data = nil
		}
	}
	rep, err := event.VerifyChain(bytes.NewReader(data))
	switch {
	case err != nil:
		return &parsed{broken: fmt.Sprintf("the chain could not be read: %v", err)}
	case len(rep.Breaks) > 0:
		b := rep.Breaks[0]
		return &parsed{broken: fmt.Sprintf("the chain is broken at line %d (%d breaks in all)", b.Line, len(rep.Breaks))}
	case rep.Malformed > 0:
		return &parsed{broken: fmt.Sprintf("%d line(s) are not events", rep.Malformed)}
	case len(rep.Unverifiable) > 0:
		return &parsed{broken: fmt.Sprintf("the file opens mid-chain, at line %d", rep.Unverifiable[0])}
	case len(rep.HeadLines) > 1:
		return &parsed{broken: fmt.Sprintf("the chain restarts at line %d, so what came before is not bound to what follows", rep.HeadLines[1])}
	}

	p := &parsed{}
	newest := map[string]map[string]entry{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var last []byte
	for lineNo := 1; sc.Scan(); lineNo++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		last = append(last[:0], line...)
		e, err := event.Unmarshal(line)
		if err != nil || e.Type != eventType || e.Source != eventSource {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, e.TS)
		if err != nil {
			return &parsed{broken: fmt.Sprintf("the time of the slo_burn event at line %d is not RFC 3339", lineNo)}
		}
		h, err := event.ChainHashRaw(line)
		if err != nil {
			return &parsed{broken: fmt.Sprintf("the slo_burn event at line %d cannot be hashed", lineNo)}
		}
		sli, _ := e.Data["sli"].(string)
		if newest[e.AgentID] == nil {
			newest[e.AgentID] = map[string]entry{}
		}
		// The file is in write order, so a later line of an indicator is the newer
		// reading of it, whatever either says about its time.
		newest[e.AgentID][sli] = entry{sli: sli, ts: ts, value: interpret(e.Data), hash: h}
		if ts.After(p.maxTS) {
			p.maxTS = ts
		}
	}
	if err := sc.Err(); err != nil {
		return &parsed{broken: fmt.Sprintf("the file could not be scanned: %v", err)}
	}
	if last != nil {
		p.head, _ = event.ChainHashRaw(last)
	}
	p.byAgent = make(map[string][]entry, len(newest))
	for agent, bySLI := range newest {
		list := make([]entry, 0, len(bySLI))
		for _, en := range bySLI {
			list = append(list, en)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].sli < list[j].sli })
		p.byAgent[agent] = list
	}
	return p
}

// interpret says what one slo_burn payload establishes. Anything it does not
// establish is unmeasured, never none.
func interpret(data map[string]any) string {
	trigger, _ := data["trigger"].(string)
	switch trigger {
	case "exhausted":
		return ValueExhausted
	case "fast_burn":
		if n, ok := data["burn_events_seen"].(float64); ok && n >= 1 && n == math.Trunc(n) {
			return ValueFastBurn
		}
	}
	return ValueUnmeasured
}

func rank(value string) int {
	switch value {
	case ValueExhausted:
		return 3
	case ValueFastBurn:
		return 2
	case ValueUnmeasured:
		return 1
	}
	return 0
}

// For returns the standing signal for an agent, or false when the file cannot be
// believed and so the signal is absent. The agent is matched exactly. An event
// ends signalling once it is older than MaxAge, read at this call and not at the
// last poll. The most severe live indicator is the one reported; with none live
// the value is none, and the answer id is the chain hash of the file's last line.
func (r *Reader) For(agentID string) (Signal, bool) {
	v := r.cur.Load()
	if v == nil || v.state != StateOK {
		return Signal{}, false
	}
	now := r.now()
	best := entry{}
	bestRank := 0
	for _, en := range v.p.byAgent[agentID] {
		if now.Sub(en.ts) > r.maxAge {
			continue
		}
		if rk := rank(en.value); rk > bestRank {
			best, bestRank = en, rk
		}
	}
	sig := Signal{Name: SignalName, Probability: 1, Source: SignalSource}
	if bestRank == 0 {
		sig.Value, sig.AnswerID = ValueNone, v.p.head
		return sig, true
	}
	sig.Value, sig.AnswerID = best.value, best.hash
	return sig, true
}

// Run refreshes every PollEvery until ctx ends.
func (r *Reader) Run(ctx context.Context) {
	t := time.NewTicker(r.poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.Refresh()
		}
	}
}
