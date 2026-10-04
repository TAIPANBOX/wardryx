package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/wardryx/internal/archive"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/replay"
	"github.com/TAIPANBOX/wardryx/internal/store"
)

// A typed risk signal reaches a decision as a field of the request: whoever
// calls /v1/decide, an enforcement point or a proxy in front of wardryx,
// supplies it. These tests drive that through the real handler and hold the
// record and the replay to what was actually used.

const (
	sigAgent = "agent://acme.example/support/bot1"
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
		"a source over the cap":             sig(`{"name":"n","value":"v","probability":0.5,"source":"` + strings.Repeat("s", 129) + `"}`),
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

func TestAnySourceTheCallerNamesIsRecordedAsClaimed(t *testing.T) {
	h := newSigHarness(t, false)
	ask := plainAsk()
	ask.Signals = []signalDTO{callerSignal("destructive", 0.95)}
	ask.Signals[0].Source = "some-other-classifier"
	h.decide(t, ask)
	for _, ev := range h.read(t) {
		if ev.Type != "approval_requested" {
			continue
		}
		list, _ := ev.Data["signals"].([]any)
		first, _ := list[0].(map[string]any)
		if first["source"] != "some-other-classifier" {
			t.Fatalf("recorded source = %#v", first["source"])
		}
		return
	}
	t.Fatal("no hold recorded")
}

func TestToolArgumentsNeverReachTheRecord(t *testing.T) {
	h := newSigHarness(t, false)
	ask := plainAsk()
	ask.Signals = []signalDTO{callerSignal("destructive", 0.95)}
	held := decodeBody[decideResponseDTO](t, h.decide(t, ask))
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

// --- replay: the recorded signal, nothing fetched ---

// A decision held because of a signal reproduces from the record alone, and a
// candidate policy without the rule changes it, which proves the recorded
// signal is what drove the replayed hold. Replay here has no client of any
// kind to ask with: nothing it stands on can make an outbound call
// (scripts/decision-path-purity.sh).
func TestAReplayReproducesASignalHoldFromTheRecordAlone(t *testing.T) {
	h := newSigHarness(t, false)
	ask := plainAsk()
	ask.Signals = []signalDTO{callerSignal("destructive", 0.95)}
	held := decodeBody[decideResponseDTO](t, h.decide(t, ask))
	if held.Decision != pdp.Hold {
		t.Fatalf("setup: %s (%s)", held.Decision, held.Reason)
	}
	events := h.read(t)

	report := replay.Run(events, h.arch, nil)
	if report.Total != 1 || report.Reproduced != 1 || report.Diverged != 0 || report.Unreadable != 0 {
		t.Fatalf("the signal hold did not reproduce:\n%s", replay.Format(report, "events", ""))
	}
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

// Nothing the decision or its replay stands on, in this module, may make an
// outbound call: no package of this module in their import closure imports
// net/http or os/exec. scripts/decision-path-purity.sh holds the same thing
// as a gate; this is the test form, so the binding exists in Go too.
func TestTheDecisionPathAndReplayCannotMakeAnOutboundCall(t *testing.T) {
	const module = "github.com/TAIPANBOX/wardryx/"
	checked := 0
	for _, pkg := range []string{"internal/pdp", "internal/policy", "internal/replay", "internal/approval", "internal/archive"} {
		out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}} {{join .Imports \" \"}}", module+pkg).Output()
		if err != nil {
			t.Fatalf("go list -deps %s: %v", pkg, err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 0 || !strings.HasPrefix(fields[0], module) {
				continue
			}
			checked++
			for _, imp := range fields[1:] {
				if imp == "net/http" || imp == "os/exec" {
					t.Errorf("%s depends on %s, which imports %s", pkg, fields[0], imp)
				}
			}
		}
	}
	// The control: a list that came back empty would look exactly like a
	// clean answer, and internal/api (not in the closure) really does import
	// net/http.
	if checked < 5 {
		t.Fatalf("go list -deps measured nothing: only %d module package(s) read", checked)
	}
	out, err := exec.Command("go", "list", "-f", "{{join .Imports \" \"}}", module+"internal/otel").Output()
	if err != nil || !strings.Contains(string(out), "net/http") {
		t.Fatalf("the control failed: internal/otel should import net/http (%v)", err)
	}
}

// --- the cacheable hint, over the wire ---

// An enforcement point caches decisions keyed on the agent and tool set with no
// arguments in the key. Nothing a signal touched may be offered for reuse.
func TestTheCacheableHintIsFalseForEverySignalDependentDecisionOverTheWire(t *testing.T) {
	cases := map[string]func(t *testing.T) decideResponseDTO{
		"a hold from a caller's signal": func(t *testing.T) decideResponseDTO {
			a := plainAsk()
			a.Signals = []signalDTO{callerSignal("destructive", 0.95)}
			return decodeBody[decideResponseDTO](t, newSigHarness(t, false).decide(t, a))
		},
		"an allow after a signal that did not fire": func(t *testing.T) decideResponseDTO {
			a := plainAsk()
			a.Signals = []signalDTO{callerSignal("read_only", 0.97)}
			return decodeBody[decideResponseDTO](t, newSigHarness(t, false).decide(t, a))
		},
		"an allow with no signal at all, under a policy that could have fired": func(t *testing.T) decideResponseDTO {
			return decodeBody[decideResponseDTO](t, newSigHarness(t, false).decide(t, plainAsk()))
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
	// The control: a policy with no signal rule is still cacheable, so the
	// hint has not simply been switched off.
	plain := newSigHarness(t, false, policy.Policy{Name: "plain", Target: "agent://acme.example/support/*", DenyTool: []string{"other"}})
	if got := decodeBody[decideResponseDTO](t, plain.decide(t, plainAsk())); !got.Cacheable {
		t.Fatal("control: a policy with no signal rule stopped being cacheable")
	}
}

// --- what is recorded about the tool call ---

func TestTheToolCallIsRecordedAsNameTargetAndAHashOfItsArguments(t *testing.T) {
	h := newSigHarness(t, false)
	ask := plainAsk()
	ask.Signals = []signalDTO{callerSignal("destructive", 0.95)}
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
		t.Fatalf("a decision that carried a tool call records no tool_call: %#v", hold.Data)
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

// --- an enforcement point sends arguments_truncated when the arguments were too large ---

func TestTruncatedArgumentsAreAcceptedWithNoArgumentsAndRecordedAsTruncated(t *testing.T) {
	h := newSigHarness(t, false)
	for name, body := range map[string]string{
		"arguments absent": `{"agent_id":"` + sigAgent + `","run_id":"r1","tool_names":["s3.delete_object"],"tool_call":{"name":"s3.delete_object","target":"s3://b","arguments_truncated":true}}`,
		"arguments null":   `{"agent_id":"` + sigAgent + `","run_id":"r2","tool_names":["s3.delete_object"],"tool_call":{"name":"s3.delete_object","arguments":null,"target":"s3://b","arguments_truncated":true}}`,
	} {
		rec := doRaw(t, h.srv.Handler(), http.MethodPost, "/v1/decide", adminKey, body)
		got := decodeBody[decideResponseDTO](t, rec)
		if rec.Code != http.StatusOK || got.Decision != pdp.Allow {
			t.Fatalf("%s: %d %s (%s), want allow", name, rec.Code, got.Decision, got.Reason)
		}
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
