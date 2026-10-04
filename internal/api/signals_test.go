package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/wardryx/internal/archive"
	"github.com/TAIPANBOX/wardryx/internal/enrich"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/replay"
	"github.com/TAIPANBOX/wardryx/internal/store"
)

// A typed risk signal reaches a decision two ways: a caller supplies it, or
// wardryx asks typryx for it. These tests drive both through the real handler,
// with a fake typryx that can misbehave, and hold the record and the replay to
// what was actually used.

const (
	sigAgent = "agent://acme.example/support/bot1"
	riskOK   = `{"answer_id":"ans-7","template":"action.risk_class","type":"choice","answer":"destructive","probabilities":{"read_only":0.02,"reversible_change":0.02,"destructive":0.94,"external_send":0.01,"financial":0.01}}`
	argMark  = "SECRET-ARG-MARKER-9f3"
)

func riskPol() policy.Policy {
	return policy.Policy{
		Name: "risk", Target: "agent://acme.example/support/*",
		HoldIfSignal: &policy.SignalRule{
			Name:           "action.risk_class",
			Values:         []string{"destructive", "external_send", "financial"},
			MinProbability: usd(0.8),
		},
	}
}

type sigHarness struct {
	srv    *Server
	events string
	ew     *event.ChainedWriter
	arch   *archive.Archive
	set    *policy.Set
}

func newSigHarness(t *testing.T, singleUse bool, pols ...policy.Policy) *sigHarness {
	t.Helper()
	if len(pols) == 0 {
		pols = []policy.Policy{riskPol()}
	}
	set, err := policy.Compile(pols)
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	path := filepath.Join(t.TempDir(), "events.ndjson")
	ew, err := event.NewChainedWriter(path)
	if err != nil {
		t.Fatalf("NewChainedWriter: %v", err)
	}
	keys := map[string]Principal{adminKey: {Org: "acme", Role: RoleAdmin}}
	srv := New(pdp.New(set, []byte(testHMAC)), store.NewMemory(), ew, nil, keys, []byte(testHMAC), singleUse, set.Policies())
	a, err := archive.New(t.TempDir())
	if err != nil {
		t.Fatalf("archive.New: %v", err)
	}
	if err := srv.SetPolicyArchive(a); err != nil {
		t.Fatalf("SetPolicyArchive: %v", err)
	}
	return &sigHarness{srv: srv, events: path, ew: ew, arch: a, set: set}
}

func (h *sigHarness) decide(t *testing.T, body any) *httptest.ResponseRecorder {
	t.Helper()
	return doRequest(t, h.srv.Handler(), http.MethodPost, "/v1/decide", adminKey, body)
}

func (h *sigHarness) read(t *testing.T) []event.Event {
	t.Helper()
	if err := h.ew.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	evs, err := event.ReadFile(h.events)
	if err != nil {
		t.Fatalf("event.ReadFile: %v", err)
	}
	return evs
}

func deleteCall() *toolCallDTO {
	return &toolCallDTO{
		Name:      "s3.delete_object",
		Arguments: json.RawMessage(`{"bucket":"prod-backups","key":"` + argMark + `"}`),
		Target:    "s3://prod-backups",
	}
}

func callerSignal(value string, p float64) signalDTO {
	return signalDTO{Name: "action.risk_class", Value: value, Probability: &p, Source: "classifier", AnswerID: "c-1"}
}

func plainAsk() decideRequestDTO {
	return decideRequestDTO{AgentID: sigAgent, RunID: "run-sig", ToolNames: []string{"s3.delete_object"}, ToolCall: deleteCall()}
}

// fakeTyprx counts and records what wardryx asks, and answers as told.
type fakeTyprx struct {
	srv   *httptest.Server
	asks  atomic.Int64
	last  atomic.Value // []byte
	keyIn atomic.Value // string
}

func newFakeTyprx(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *fakeTyprx {
	t.Helper()
	f := &fakeTyprx{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.asks.Add(1)
		b, _ := io.ReadAll(r.Body)
		f.last.Store(b)
		f.keyIn.Store(r.Header.Get("X-Typryx-Key"))
		handler(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func answerWith(body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }
}

func (h *sigHarness) withTyprx(t *testing.T, f *fakeTyprx, timeout time.Duration) *enrich.Typryx {
	t.Helper()
	c, err := enrich.NewTypryx(f.srv.URL, "test-typryx-key", timeout)
	if err != nil {
		t.Fatalf("NewTypryx: %v", err)
	}
	h.srv.SetSignalEnricher(c)
	return c
}

func quiet(t *testing.T) {
	t.Helper()
	prev := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(prev) })
}

// --- a caller supplies the signal ---

func TestACallerSuppliedDestructiveSignalHoldsACallThatWasAllowed(t *testing.T) {
	h := newSigHarness(t, false)

	plain := decodeBody[decideResponseDTO](t, h.decide(t, plainAsk()))
	if plain.Decision != pdp.Allow {
		t.Fatalf("with no signal the call is %s (%s), want allow", plain.Decision, plain.Reason)
	}
	ask := plainAsk()
	ask.Signals = []signalDTO{callerSignal("destructive", 0.95)}
	held := decodeBody[decideResponseDTO](t, h.decide(t, ask))
	if held.Decision != pdp.Hold || held.ApprovalID == "" {
		t.Fatalf("with a destructive signal at 0.95 the call is %s (%s) approval %q, want a hold with an approval", held.Decision, held.Reason, held.ApprovalID)
	}
	if held.Cacheable {
		t.Error("a decision under a hold_if_signal policy was marked cacheable")
	}
}

func TestEverySignalUsedIsRecordedInTheEventAndTheApprovalContext(t *testing.T) {
	h := newSigHarness(t, false)
	ask := plainAsk()
	ask.Signals = []signalDTO{callerSignal("destructive", 0.95)}
	held := decodeBody[decideResponseDTO](t, h.decide(t, ask))

	events := h.read(t)
	var hold *event.Event
	for i := range events {
		if events[i].Type == "approval_requested" {
			hold = &events[i]
		}
	}
	if hold == nil {
		t.Fatalf("no approval_requested among %d events", len(events))
	}
	want := map[string]any{"name": "action.risk_class", "value": "destructive", "probability": 0.95, "source": "classifier", "answer_id": "c-1"}
	assertSignals := func(where string, v any) {
		t.Helper()
		list, ok := v.([]any)
		if !ok || len(list) != 1 {
			t.Fatalf("%s signals = %#v, want one recorded signal", where, v)
		}
		got, _ := list[0].(map[string]any)
		for k, w := range want {
			if got[k] != w {
				t.Errorf("%s signals[0][%q] = %#v, want %#v", where, k, got[k], w)
			}
		}
		if len(got) != len(want) {
			t.Errorf("%s signals[0] has %d keys, want exactly %d: %#v", where, len(got), len(want), got)
		}
	}
	assertSignals("event", hold.Data["signals"])

	ctxApproval, err := h.srv.store.GetApproval(context.Background(), held.ApprovalID)
	if err != nil {
		t.Fatalf("GetApproval: %v", err)
	}
	assertSignals("approval context", ctxApproval.Context["signals"])
}

func TestADecisionWithNoSignalsCarriesNoSignalsKey(t *testing.T) {
	h := newSigHarness(t, false)
	h.decide(t, plainAsk())
	for _, ev := range h.read(t) {
		if _, present := ev.Data["signals"]; present {
			t.Fatalf("a decision that used no signal recorded a signals key: %#v", ev.Data["signals"])
		}
	}
}

// --- hostile input at the boundary ---

func TestHostileSignalAndToolCallInputIsRefusedAtTheAPI(t *testing.T) {
	h := newSigHarness(t, false)
	const mark = "ECHO-MARKER-31337"

	sig := func(fields string) string {
		return `{"agent_id":"` + sigAgent + `","run_id":"r","signals":[` + fields + `]}`
	}
	tc := func(fields string) string {
		return `{"agent_id":"` + sigAgent + `","run_id":"r","tool_call":` + fields + `}`
	}
	okSig := `{"name":"action.risk_class","value":"destructive","probability":0.9,"source":"classifier"}`
	many := func(n int) string { return strings.TrimSuffix(strings.Repeat(okSig+",", n), ",") }
	longArgs := `{"x":"` + strings.Repeat("a", pdp.MaxToolArgumentsBytes) + `"}`

	cases := map[string]string{
		"a signal with no probability":      sig(`{"name":"n","value":"v","source":"s"}`),
		"a null probability":                sig(`{"name":"n","value":"v","probability":null,"source":"s"}`),
		"a probability above one":           sig(`{"name":"n","value":"v","probability":1.5,"source":"s"}`),
		"a negative probability":            sig(`{"name":"n","value":"v","probability":-0.1,"source":"s"}`),
		"a probability that is a string":    sig(`{"name":"n","value":"v","probability":"0.9","source":"s"}`),
		"a probability too big for a float": sig(`{"name":"n","value":"v","probability":1e999,"source":"s"}`),
		"a NaN literal":                     sig(`{"name":"n","value":"v","probability":NaN,"source":"s"}`),
		"an empty name":                     sig(`{"name":"","value":"v","probability":0.5,"source":"s"}`),
		"a name over the cap":               sig(`{"name":"` + strings.Repeat("n", 129) + `","value":"v","probability":0.5,"source":"s"}`),
		"a control character in a value":    sig(`{"name":"n","value":"a\u0000b` + mark + `","probability":0.5,"source":"s"}`),
		"no source":                         sig(`{"name":"n","value":"v","probability":0.5}`),
		"a caller claiming to be typryx":    sig(`{"name":"n","value":"v","probability":0.5,"source":"typryx"}`),
		"typryx in another case":            sig(`{"name":"n","value":"v","probability":0.5,"source":" Typryx "}`),
		"seventeen signals":                 sig(many(pdp.MaxSignals + 1)),
		"five thousand signals":             sig(many(5000)),
		"signals as an object":              `{"agent_id":"` + sigAgent + `","run_id":"r","signals":{"a":1}}`,
		"signals as a string":               `{"agent_id":"` + sigAgent + `","run_id":"r","signals":"destructive"}`,
		"a tool call with no name":          tc(`{"arguments":{"a":1}}`),
		"a tool call that is a string":      tc(`"s3.delete_object"`),
		"arguments over the cap":            tc(`{"name":"t","arguments":` + longArgs + `}`),
		"a tool name over the cap":          tc(`{"name":"` + strings.Repeat("t", pdp.MaxToolNameBytes+1) + `"}`),
		"a target over the cap":             tc(`{"name":"t","target":"` + strings.Repeat("t", pdp.MaxToolTargetBytes+1) + `"}`),
		"a control character in a target":   tc(`{"name":"t","target":"a\u0001b` + mark + `"}`),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			rec := doRaw(t, h.srv.Handler(), http.MethodPost, "/v1/decide", adminKey, body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body = %.200s", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), mark) {
				t.Fatalf("the refusal echoes the input it refused: %s", rec.Body.String())
			}
		})
	}

	t.Run("a body over the cap is a 413 and never a 500", func(t *testing.T) {
		huge := tc(`{"name":"t","arguments":{"x":"` + strings.Repeat("a", 2<<20) + `"}}`)
		rec := doRaw(t, h.srv.Handler(), http.MethodPost, "/v1/decide", adminKey, huge)
		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", rec.Code)
		}
	})
	t.Run("what is exactly at the caps is accepted", func(t *testing.T) {
		atCap := `{"x":"` + strings.Repeat("a", pdp.MaxToolArgumentsBytes-len(`{"x":""}`)) + `"}`
		for _, body := range []string{
			tc(`{"name":"t","arguments":` + atCap + `}`),
			sig(many(pdp.MaxSignals)),
			tc(`{"name":"` + strings.Repeat("t", pdp.MaxToolNameBytes) + `","target":"` + strings.Repeat("t", pdp.MaxToolTargetBytes) + `"}`),
		} {
			rec := doRaw(t, h.srv.Handler(), http.MethodPost, "/v1/decide", adminKey, body)
			if rec.Code != http.StatusOK {
				t.Errorf("a request exactly at a cap: status = %d, body = %.200s", rec.Code, rec.Body.String())
			}
		}
	})
}

// --- wardryx asks typryx ---

func TestTyprxSayingDestructiveHoldsTheCallAndTheSignalIsRecorded(t *testing.T) {
	quiet(t)
	h := newSigHarness(t, false)
	f := newFakeTyprx(t, answerWith(riskOK))
	h.withTyprx(t, f, time.Second)

	got := decodeBody[decideResponseDTO](t, h.decide(t, plainAsk()))
	if got.Decision != pdp.Hold {
		t.Fatalf("typryx says destructive at 0.94 and the call is %s (%s), want hold", got.Decision, got.Reason)
	}
	if f.asks.Load() != 1 {
		t.Fatalf("typryx asked %d times, want 1", f.asks.Load())
	}
	if k, _ := f.keyIn.Load().(string); k != "test-typryx-key" {
		t.Errorf("typryx saw key %q", k)
	}
	var sent struct {
		Template string
		State    map[string]json.RawMessage
	}
	b, _ := f.last.Load().([]byte)
	if err := json.Unmarshal(b, &sent); err != nil {
		t.Fatalf("what typryx was sent is not JSON: %v", err)
	}
	if sent.Template != "action.risk_class" || len(sent.State) != 3 {
		t.Fatalf("typryx was sent %s, want the template and exactly tool, arguments, target", b)
	}

	var hold *event.Event
	evs := h.read(t)
	for i := range evs {
		if evs[i].Type == "approval_requested" {
			hold = &evs[i]
		}
	}
	if hold == nil {
		t.Fatal("no approval_requested event")
	}
	list, _ := hold.Data["signals"].([]any)
	if len(list) != 1 {
		t.Fatalf("recorded signals = %#v", hold.Data["signals"])
	}
	s, _ := list[0].(map[string]any)
	if s["source"] != "typryx" || s["value"] != "destructive" || s["answer_id"] != "ans-7" || s["probability"] != 0.94 || s["name"] != "action.risk_class" {
		t.Fatalf("recorded signal = %#v", s)
	}
}

func TestTyprxSayingSomethingBelowOrOutsideTheRuleLeavesTheCallAllowed(t *testing.T) {
	quiet(t)
	cases := map[string]string{
		"read_only at 0.99":        strings.NewReplacer(`"answer":"destructive"`, `"answer":"read_only"`, `"read_only":0.02`, `"read_only":0.99`, `"destructive":0.94`, `"destructive":0.003`).Replace(riskOK),
		"destructive at 0.5":       strings.Replace(riskOK, `"destructive":0.94`, `"destructive":0.5`, 1),
		"destructive just under":   strings.Replace(riskOK, `"destructive":0.94`, `"destructive":0.7999`, 1),
		"reversible_change at 0.9": strings.NewReplacer(`"answer":"destructive"`, `"answer":"reversible_change"`, `"reversible_change":0.02`, `"reversible_change":0.9`).Replace(riskOK),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			h := newSigHarness(t, false)
			h.withTyprx(t, newFakeTyprx(t, answerWith(body)), time.Second)
			got := decodeBody[decideResponseDTO](t, h.decide(t, plainAsk()))
			if got.Decision != pdp.Allow {
				t.Fatalf("%s: the call is %s (%s), want allow", name, got.Decision, got.Reason)
			}
		})
	}
}

// Every way typryx can fail: the call is decided exactly as it would have been
// with no enrichment at all, nothing is recorded as a signal, and the failure
// is counted where an operator can read it.
func TestATyprxThatFailsLeavesTheOriginalDecisionAndNoSignal(t *testing.T) {
	quiet(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	cases := []struct {
		name    string
		timeout time.Duration
		handler func(http.ResponseWriter, *http.Request)
		class   string
	}{
		{"times out", 60 * time.Millisecond, func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
			_, _ = io.WriteString(w, riskOK)
		}, "timeout"},
		{"answers 500", time.Second, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }, "http_5xx"},
		{"answers unanswered", time.Second, answerWith(`{"answer_id":"a","template":"action.risk_class","type":"choice","unanswered":true,"reason":"backend_error"}`), "unanswered"},
		{"answers garbage", time.Second, answerWith(`<html>not what was asked</html>`), "malformed"},
		{"answers an answer that is not one of its probabilities", time.Second, answerWith(strings.Replace(riskOK, `"answer":"destructive"`, `"answer":"explode"`, 1)), "malformed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// What the call is with no enrichment, as the control.
			control := newSigHarness(t, false)
			want := decodeBody[decideResponseDTO](t, control.decide(t, plainAsk()))

			h := newSigHarness(t, false)
			c := h.withTyprx(t, newFakeTyprx(t, tc.handler), tc.timeout)
			got := decodeBody[decideResponseDTO](t, h.decide(t, plainAsk()))
			if got.Decision != want.Decision || got.Reason != want.Reason {
				t.Fatalf("typryx %s: the call is %s (%s), want the original %s (%s)", tc.name, got.Decision, got.Reason, want.Decision, want.Reason)
			}
			for _, ev := range h.read(t) {
				if _, present := ev.Data["signals"]; present {
					t.Fatalf("typryx %s but a signal was recorded: %#v", tc.name, ev.Data["signals"])
				}
			}
			if n := c.Stats().NoSignal[tc.class]; n != 1 {
				t.Fatalf("typryx %s: %q counted %d times, stats %+v", tc.name, tc.class, n, c.Stats())
			}
		})
	}
}

func TestAnUnreachableTyprxLeavesTheOriginalDecision(t *testing.T) {
	quiet(t)
	h := newSigHarness(t, false)
	f := newFakeTyprx(t, answerWith(riskOK))
	c := h.withTyprx(t, f, time.Second)
	f.srv.Close()
	got := decodeBody[decideResponseDTO](t, h.decide(t, plainAsk()))
	if got.Decision != pdp.Allow {
		t.Fatalf("with typryx down the call is %s (%s), want allow", got.Decision, got.Reason)
	}
	if c.Stats().NoSignal["unreachable"] != 1 {
		t.Fatalf("stats = %+v", c.Stats())
	}
}

// Asking costs time and, with a hosted model behind typryx, money. It is asked
// only when the answer could change the verdict.
func TestTyprxIsAskedOnlyWhenTheAnswerCouldChangeTheVerdict(t *testing.T) {
	quiet(t)
	deny := policy.Policy{Name: "no-delete", Target: "agent://acme.example/support/*", DenyTool: []string{"s3.delete_object"}, HoldIfSignal: riskPol().HoldIfSignal}
	cost := riskPol()
	cost.RequireHumanAboveUSD = usd(10)
	noRule := policy.Policy{Name: "plain", Target: "agent://acme.example/support/*", DenyTool: []string{"other"}}
	elsewhere := riskPol()
	elsewhere.Target = "agent://acme.example/finance/*"

	cases := []struct {
		name string
		pols []policy.Policy
		ask  func() decideRequestDTO
		asks int64
	}{
		{"a policy reads the signal and the call is allowed so far", []policy.Policy{riskPol()}, plainAsk, 1},
		{"no policy reads any signal", []policy.Policy{noRule}, plainAsk, 0},
		{"the signal policy targets another agent", []policy.Policy{elsewhere}, plainAsk, 0},
		{"a deny rule already refuses the call", []policy.Policy{deny}, plainAsk, 0},
		{"a cost hold already holds the call", []policy.Policy{cost}, func() decideRequestDTO { a := plainAsk(); a.EstCostUSD = 50; return a }, 0},
		{"the caller's own signal already holds the call", []policy.Policy{riskPol()}, func() decideRequestDTO {
			a := plainAsk()
			a.Signals = []signalDTO{callerSignal("destructive", 0.99)}
			return a
		}, 0},
		{"the request carries no tool call", []policy.Policy{riskPol()}, func() decideRequestDTO { a := plainAsk(); a.ToolCall = nil; return a }, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newSigHarness(t, false, tc.pols...)
			f := newFakeTyprx(t, answerWith(riskOK))
			h.withTyprx(t, f, time.Second)
			rec := h.decide(t, tc.ask())
			if rec.Code != http.StatusOK {
				t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
			}
			if f.asks.Load() != tc.asks {
				t.Fatalf("typryx asked %d times, want %d", f.asks.Load(), tc.asks)
			}
		})
	}
}

func TestWithNoEnrichmentConfiguredATyprxIsNeverAsked(t *testing.T) {
	h := newSigHarness(t, false)
	got := decodeBody[decideResponseDTO](t, h.decide(t, plainAsk()))
	if got.Decision != pdp.Allow {
		t.Fatalf("a tool call with no enricher configured: %s (%s), want allow", got.Decision, got.Reason)
	}
	status := decodeBody[map[string]any](t, doRequest(t, h.srv.Handler(), http.MethodGet, "/v1/status", adminKey, nil))
	if _, present := status["signals"]; present {
		t.Fatalf("/v1/status mentions signal enrichment while it is off: %#v", status["signals"])
	}
}

func TestCallerSignalsAreKeptAndEnrichmentAppendsItsOwn(t *testing.T) {
	quiet(t)
	h := newSigHarness(t, false)
	h.withTyprx(t, newFakeTyprx(t, answerWith(riskOK)), time.Second)
	ask := plainAsk()
	ask.Signals = []signalDTO{callerSignal("read_only", 0.9)} // harmless, so the call is still allowed and typryx is asked
	got := decodeBody[decideResponseDTO](t, h.decide(t, ask))
	if got.Decision != pdp.Hold {
		t.Fatalf("the call is %s (%s), want hold from the appended typryx signal", got.Decision, got.Reason)
	}
	var hold event.Event
	for _, ev := range h.read(t) {
		if ev.Type == "approval_requested" {
			hold = ev
		}
	}
	list, _ := hold.Data["signals"].([]any)
	if len(list) != 2 {
		t.Fatalf("recorded signals = %#v, want the caller's then typryx's", hold.Data["signals"])
	}
	first, _ := list[0].(map[string]any)
	second, _ := list[1].(map[string]any)
	if first["source"] != "classifier" || second["source"] != "typryx" {
		t.Fatalf("order/provenance wrong: %#v then %#v", first, second)
	}
}

func TestToolArgumentsNeverReachTheRecord(t *testing.T) {
	quiet(t)
	h := newSigHarness(t, false)
	h.withTyprx(t, newFakeTyprx(t, answerWith(riskOK)), time.Second)
	held := decodeBody[decideResponseDTO](t, h.decide(t, plainAsk()))
	if held.Decision != pdp.Hold {
		t.Fatalf("setup: %s", held.Decision)
	}
	h.read(t)
	raw, err := os.ReadFile(h.events)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(argMark)) {
		t.Fatal("the tool call's arguments reached the event file")
	}
	approvals, _ := h.srv.store.ListApprovals(context.Background())
	enc, _ := json.Marshal(approvals)
	if bytes.Contains(enc, []byte(argMark)) {
		t.Fatal("the tool call's arguments reached the approval context")
	}
}

// A granted approval lifts a signal hold, once under single-use, and a token
// that does not verify holds again and never denies.
func TestAGrantedApprovalLiftsASignalHoldOnceAndABadTokenNeverDenies(t *testing.T) {
	h := newSigHarness(t, true)
	ask := plainAsk()
	ask.Signals = []signalDTO{callerSignal("destructive", 0.95)}
	held := decodeBody[decideResponseDTO](t, h.decide(t, ask))
	if held.Decision != pdp.Hold {
		t.Fatalf("setup: %s", held.Decision)
	}
	granted := decodeBody[approvalDecideResponseDTO](t, doRequest(t, h.srv.Handler(), http.MethodPost,
		"/v1/approvals/"+held.ApprovalID+"/decide", adminKey, approvalDecideRequestDTO{Decision: "grant", DecidedBy: "alice@acme.example"}))

	ask.ApprovalToken = granted.ApprovalToken
	first := decodeBody[decideResponseDTO](t, h.decide(t, ask))
	second := decodeBody[decideResponseDTO](t, h.decide(t, ask))
	if first.Decision != pdp.Allow {
		t.Fatalf("the granted call is %s (%s), want allow", first.Decision, first.Reason)
	}
	if second.Decision != pdp.Hold || second.Reason != pdp.ReasonApprovalSpent {
		t.Fatalf("the second presentation is %s (%s), want the spent-token hold", second.Decision, second.Reason)
	}
	bad := ask
	bad.ApprovalToken = "garbage"
	if got := decodeBody[decideResponseDTO](t, h.decide(t, bad)); got.Decision != pdp.Hold {
		t.Fatalf("a garbage token on a signal hold is %s (%s), want hold", got.Decision, got.Reason)
	}
}

func TestStatusCountsWhatEnrichmentDid(t *testing.T) {
	quiet(t)
	h := newSigHarness(t, false)
	h.withTyprx(t, newFakeTyprx(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }), time.Second)
	h.decide(t, plainAsk())
	h.decide(t, plainAsk())
	status := decodeBody[struct {
		Signals *struct {
			Source    string           `json:"source"`
			TimeoutMS int64            `json:"timeout_ms"`
			Asked     int64            `json:"asked"`
			Signalled int64            `json:"signalled"`
			NoSignal  map[string]int64 `json:"no_signal"`
		} `json:"signals"`
	}](t, doRequest(t, h.srv.Handler(), http.MethodGet, "/v1/status", adminKey, nil))
	s := status.Signals
	if s == nil || s.Source != "typryx" || s.TimeoutMS != 1000 || s.Asked != 2 || s.Signalled != 0 || s.NoSignal["http_5xx"] != 2 {
		t.Fatalf("status signals = %+v", s)
	}
}

// --- replay: the recorded signal, not a new ask ---

// The decision that was held because typryx said destructive must reproduce
// with typryx gone: replay feeds the recorded signal back and asks nobody. A
// candidate policy without the rule must then change it, which proves the
// recorded signal is what drove the replayed hold.
func TestAReplayReproducesASignalHoldWithTyprxUnreachable(t *testing.T) {
	quiet(t)
	h := newSigHarness(t, false)
	f := newFakeTyprx(t, answerWith(riskOK))
	h.withTyprx(t, f, time.Second)

	held := decodeBody[decideResponseDTO](t, h.decide(t, plainAsk()))
	if held.Decision != pdp.Hold {
		t.Fatalf("setup: %s (%s)", held.Decision, held.Reason)
	}
	events := h.read(t)

	f.srv.Close() // typryx is gone from here on
	asksBefore := f.asks.Load()

	report := replay.Run(events, h.arch, nil)
	if report.Total != 1 || report.Reproduced != 1 || report.Diverged != 0 || report.Unreadable != 0 {
		t.Fatalf("with typryx down the signal hold did not reproduce:\n%s", replay.Format(report, "events", ""))
	}
	if f.asks.Load() != asksBefore {
		t.Fatal("replay asked typryx")
	}

	// The same history against a policy that no longer holds on signals.
	plain, err := policy.Compile([]policy.Policy{{Name: "plain", Target: "agent://acme.example/support/*", DenyTool: []string{"other"}}})
	if err != nil {
		t.Fatal(err)
	}
	cf := replay.Run(events, h.arch, plain)
	if cf.Changed != 1 || cf.Rows[0].Baseline != pdp.Hold || cf.Rows[0].Candidate.Decision != pdp.Allow {
		t.Fatalf("the candidate without the rule did not turn the recorded hold into an allow:\n%s", replay.Format(cf, "events", "plain"))
	}
}

func TestAReplayOfACallerSuppliedSignalHoldAlsoReproduces(t *testing.T) {
	h := newSigHarness(t, false)
	ask := plainAsk()
	ask.Signals = []signalDTO{callerSignal("destructive", 0.95)}
	h.decide(t, ask)
	report := replay.Run(h.read(t), h.arch, nil)
	if report.Total != 1 || report.Reproduced != 1 {
		t.Fatalf("a caller-signal hold did not reproduce:\n%s", replay.Format(report, "events", ""))
	}
}

func TestAGrantedSignalHoldReplaysAsApprovalDecided(t *testing.T) {
	h := newSigHarness(t, false)
	ask := plainAsk()
	ask.Signals = []signalDTO{callerSignal("destructive", 0.95)}
	held := decodeBody[decideResponseDTO](t, h.decide(t, ask))
	granted := decodeBody[approvalDecideResponseDTO](t, doRequest(t, h.srv.Handler(), http.MethodPost,
		"/v1/approvals/"+held.ApprovalID+"/decide", adminKey, approvalDecideRequestDTO{Decision: "grant", DecidedBy: "alice@acme.example"}))
	ask.ApprovalToken = granted.ApprovalToken
	if got := decodeBody[decideResponseDTO](t, h.decide(t, ask)); got.Decision != pdp.Allow {
		t.Fatalf("setup: %s", got.Decision)
	}
	report := replay.Run(h.read(t), h.arch, nil)
	if report.Total != 2 || report.Diverged != 0 || report.Reproduced != 1 || report.ApprovalDecided != 1 {
		t.Fatalf("hold then granted allow:\n%s", replay.Format(report, "events", ""))
	}
}

// --- the gate on the whole feature ---

// The decision path and replay must not be able to reach the enrichment, by
// any chain of imports. scripts/decision-path-purity.sh holds the same thing
// as a gate; this is the test form, so the binding exists in Go too.
func TestTheDecisionPathAndReplayCannotReachTheEnrichment(t *testing.T) {
	for _, pkg := range []string{"internal/pdp", "internal/policy", "internal/replay", "internal/approval", "internal/archive"} {
		deps := goListDeps(t, "github.com/TAIPANBOX/wardryx/"+pkg)
		for _, d := range deps {
			if strings.HasSuffix(d, "/internal/enrich") {
				t.Errorf("%s depends on %s", pkg, d)
			}
		}
	}
	// The control: the enrichment itself does depend on the pdp, so a list
	// that came back empty would look exactly like a clean answer.
	if deps := goListDeps(t, "github.com/TAIPANBOX/wardryx/internal/enrich"); !contains(deps, "github.com/TAIPANBOX/wardryx/internal/pdp") {
		t.Fatalf("go list -deps measured nothing: internal/enrich does not list internal/pdp (%d deps)", len(deps))
	}
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func goListDeps(t *testing.T, pkg string) []string {
	t.Helper()
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", pkg).Output()
	if err != nil {
		t.Fatalf("go list -deps %s: %v", pkg, err)
	}
	return strings.Fields(string(out))
}

// --- the cacheable hint, over the wire ---

func TestTheCacheableHintIsFalseForEverySignalDependentDecisionOverTheWire(t *testing.T) {
	quiet(t)
	build := func(t *testing.T, typryx string) *sigHarness {
		h := newSigHarness(t, false)
		if typryx != "" {
			h.withTyprx(t, newFakeTyprx(t, answerWith(typryx)), time.Second)
		}
		return h
	}
	cases := map[string]func(t *testing.T) decideResponseDTO{
		"a hold from a caller's signal": func(t *testing.T) decideResponseDTO {
			a := plainAsk()
			a.Signals = []signalDTO{callerSignal("destructive", 0.95)}
			return decodeBody[decideResponseDTO](t, build(t, "").decide(t, a))
		},
		"a hold from typryx": func(t *testing.T) decideResponseDTO {
			return decodeBody[decideResponseDTO](t, build(t, riskOK).decide(t, plainAsk()))
		},
		"an allow after typryx said read_only": func(t *testing.T) decideResponseDTO {
			body := strings.NewReplacer(`"answer":"destructive"`, `"answer":"read_only"`, `"read_only":0.02`, `"read_only":0.97`, `"destructive":0.94`, `"destructive":0.01`).Replace(riskOK)
			return decodeBody[decideResponseDTO](t, build(t, body).decide(t, plainAsk()))
		},
		"an allow after typryx failed": func(t *testing.T) decideResponseDTO {
			return decodeBody[decideResponseDTO](t, build(t, `not json`).decide(t, plainAsk()))
		},
		"an allow with typryx not configured": func(t *testing.T) decideResponseDTO {
			return decodeBody[decideResponseDTO](t, build(t, "").decide(t, plainAsk()))
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			got := run(t)
			if got.Cacheable {
				t.Fatalf("%s came back cacheable (%s: %s): an enforcement point would serve it to a call with other arguments", name, got.Decision, got.Reason)
			}
		})
	}
}

// --- what is recorded about the tool call ---

func TestTheToolCallIsRecordedAsNameTargetAndAHashOfItsArguments(t *testing.T) {
	quiet(t)
	h := newSigHarness(t, false)
	h.withTyprx(t, newFakeTyprx(t, answerWith(riskOK)), time.Second)
	ask := plainAsk()
	if got := decodeBody[decideResponseDTO](t, h.decide(t, ask)); got.Decision != pdp.Hold {
		t.Fatalf("setup: %s", got.Decision)
	}
	sum := sha256.Sum256(ask.ToolCall.Arguments)
	var hold event.Event
	for _, ev := range h.read(t) {
		if ev.Type == "approval_requested" {
			hold = ev
		}
	}
	tc, _ := hold.Data["tool_call"].(map[string]any)
	if tc == nil {
		t.Fatalf("a decision that used a signal derived from a tool call records no tool_call: %#v", hold.Data)
	}
	want := map[string]any{"name": "s3.delete_object", "target": "s3://prod-backups", "arguments_sha256": hex.EncodeToString(sum[:]), "arguments_truncated": false}
	for k, w := range want {
		if tc[k] != w {
			t.Errorf("tool_call[%q] = %#v, want %#v", k, tc[k], w)
		}
	}
	if len(tc) != len(want) {
		t.Errorf("tool_call holds %d keys, want exactly %d (no raw arguments): %#v", len(tc), len(want), tc)
	}
	raw, _ := os.ReadFile(h.events)
	if bytes.Contains(raw, []byte(argMark)) {
		t.Fatal("the raw arguments reached the event file")
	}
}

func TestADecisionWithNoToolCallRecordsNoToolCallKey(t *testing.T) {
	h := newSigHarness(t, false)
	a := plainAsk()
	a.ToolCall = nil
	h.decide(t, a)
	for _, ev := range h.read(t) {
		if _, present := ev.Data["tool_call"]; present {
			t.Fatalf("a decision with no tool call recorded one: %#v", ev.Data["tool_call"])
		}
	}
}

// --- tokenfuse sends arguments_truncated when the arguments were too large ---

func TestTruncatedArgumentsAreNeverAskedAboutAndAreRecordedAsTruncated(t *testing.T) {
	quiet(t)
	h := newSigHarness(t, false)
	f := newFakeTyprx(t, answerWith(riskOK))
	h.withTyprx(t, f, time.Second)

	for name, body := range map[string]string{
		"arguments absent": `{"agent_id":"` + sigAgent + `","run_id":"r1","tool_names":["s3.delete_object"],"tool_call":{"name":"s3.delete_object","target":"s3://b","arguments_truncated":true}}`,
		"arguments null":   `{"agent_id":"` + sigAgent + `","run_id":"r2","tool_names":["s3.delete_object"],"tool_call":{"name":"s3.delete_object","arguments":null,"target":"s3://b","arguments_truncated":true}}`,
	} {
		rec := doRaw(t, h.srv.Handler(), http.MethodPost, "/v1/decide", adminKey, body)
		got := decodeBody[decideResponseDTO](t, rec)
		if rec.Code != http.StatusOK || got.Decision != pdp.Allow {
			t.Fatalf("%s: %d %s (%s), want allow: with no arguments there is nothing to classify", name, rec.Code, got.Decision, got.Reason)
		}
	}
	if f.asks.Load() != 0 {
		t.Fatalf("typryx was asked %d time(s) about a call whose arguments were never sent", f.asks.Load())
	}
	for _, ev := range h.read(t) {
		tc, _ := ev.Data["tool_call"].(map[string]any)
		if tc == nil || tc["arguments_truncated"] != true {
			t.Fatalf("the record does not say the arguments were truncated: %#v", ev.Data["tool_call"])
		}
	}
}

func TestTruncatedArgumentsBesideArgumentsAreRefused(t *testing.T) {
	h := newSigHarness(t, false)
	body := `{"agent_id":"` + sigAgent + `","run_id":"r","tool_call":{"name":"t","arguments":{"a":1},"arguments_truncated":true}}`
	if rec := doRaw(t, h.srv.Handler(), http.MethodPost, "/v1/decide", adminKey, body); rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}
