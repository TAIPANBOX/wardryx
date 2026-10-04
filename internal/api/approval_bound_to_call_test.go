package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/wardryx/internal/approval"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/store"
)

// An approval is for the call a person read. These tests drive the whole path
// through the real handler: a hold is created for a request that carries a
// tool call, a person grants it, and the token is presented again, with the
// same call and with others.

func (h *sigHarness) hold(t *testing.T, ask decideRequestDTO) string {
	t.Helper()
	ask.ApprovalToken = ""
	got := decodeBody[decideResponseDTO](t, h.decide(t, ask))
	if got.Decision != pdp.Hold || got.ApprovalID == "" {
		t.Fatalf("setup: wanted a hold with an approval id, got %s (%s)", got.Decision, got.Reason)
	}
	return got.ApprovalID
}

func (h *sigHarness) grant(t *testing.T, approvalID string) string {
	t.Helper()
	granted := decodeBody[approvalDecideResponseDTO](t, doRequest(t, h.srv.Handler(), http.MethodPost,
		"/v1/approvals/"+approvalID+"/decide", adminKey, approvalDecideRequestDTO{Decision: "grant", DecidedBy: "alice@acme.example"}))
	if granted.ApprovalToken == "" {
		t.Fatal("setup: the grant minted no token")
	}
	return granted.ApprovalToken
}

func (h *sigHarness) present(t *testing.T, ask decideRequestDTO, token string) decideResponseDTO {
	t.Helper()
	ask.ApprovalToken = token
	return decodeBody[decideResponseDTO](t, h.decide(t, ask))
}

func tokenClaims(t *testing.T, token string) map[string]any {
	t.Helper()
	payload, _, _ := strings.Cut(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("token payload: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("token claims: %v", err)
	}
	return m
}

// signalAsk is plainAsk carrying the destructive signal that holds it.
func signalAsk() decideRequestDTO {
	a := plainAsk()
	a.Signals = []signalDTO{callerSignal("destructive", 0.95)}
	return a
}

func withCall(mut func(*toolCallDTO)) decideRequestDTO {
	a := signalAsk()
	tc := *a.ToolCall
	mut(&tc)
	a.ToolCall = &tc
	return a
}

// costHarness holds on cost, not on a signal, so the same property is held on
// the path where a refused token DENIES.
func costHarness(t *testing.T, singleUse bool) *sigHarness {
	t.Helper()
	return newSigHarness(t, singleUse, policy.Policy{
		Name: "cost", Target: "agent://acme.example/support/*", RequireHumanAboveUSD: usd(5),
	})
}

func costAsk() decideRequestDTO {
	a := plainAsk()
	a.EstCostUSD = 10
	return a
}

// A call that differs from the one approved in exactly one respect.
var otherCalls = []struct {
	name string
	mut  func(*toolCallDTO)
}{
	{"same tool, other arguments", func(tc *toolCallDTO) {
		tc.Arguments = json.RawMessage(`{"bucket":"prod-customers","key":"` + argMark + `"}`)
	}},
	{"same tool, same arguments, other target", func(tc *toolCallDTO) { tc.Target = "s3://prod-customers" }},
	{"same arguments, other tool name", func(tc *toolCallDTO) { tc.Name = "s3.delete_bucket" }},
	{"arguments the enforcement point could not send", func(tc *toolCallDTO) {
		tc.Arguments = nil
		tc.ArgumentsTruncated = true
	}},
	{"arguments dropped, not marked truncated", func(tc *toolCallDTO) { tc.Arguments = nil }},
}

func TestAnApprovalForOneCallIsRefusedForAnotherCallOfTheSameTool(t *testing.T) {
	for _, c := range otherCalls {
		t.Run(c.name, func(t *testing.T) {
			h := newSigHarness(t, false)
			id := h.hold(t, signalAsk())
			token := h.grant(t, id)

			got := h.present(t, withCall(c.mut), token)
			if got.Decision == pdp.Allow {
				t.Fatalf("a token granted for one call allowed another (%s)", got.Reason)
			}
			if got.Decision != pdp.Hold || got.ApprovalID == "" || got.ApprovalID == id {
				t.Fatalf("the other call is %s (%s) approval %q, want a fresh hold of its own", got.Decision, got.Reason, got.ApprovalID)
			}
		})
	}
}

func TestTheSameCallPresentedWithItsTokenIsAllowed(t *testing.T) {
	h := newSigHarness(t, false)
	token := h.grant(t, h.hold(t, signalAsk()))
	for i := 0; i < 2; i++ { // reuse switched off: the whole TTL
		if got := h.present(t, signalAsk(), token); got.Decision != pdp.Allow {
			t.Fatalf("presentation %d of the approved call is %s (%s), want allow", i+1, got.Decision, got.Reason)
		}
	}
}

func TestSingleUseStillHoldsForABoundTokenAndARefusedCallDoesNotSpendIt(t *testing.T) {
	h := newSigHarness(t, true)
	token := h.grant(t, h.hold(t, signalAsk()))

	other := withCall(otherCalls[0].mut)
	for i := 0; i < 3; i++ {
		if got := h.present(t, other, token); got.Decision == pdp.Allow {
			t.Fatal("the other call was allowed")
		}
	}
	first := h.present(t, signalAsk(), token)
	second := h.present(t, signalAsk(), token)
	if first.Decision != pdp.Allow {
		t.Fatalf("refused attempts spent the token: the approved call is %s (%s)", first.Decision, first.Reason)
	}
	if second.Decision != pdp.Hold || second.Reason != pdp.ReasonApprovalSpent {
		t.Fatalf("the second presentation is %s (%s), want the spent-token hold", second.Decision, second.Reason)
	}
}

func TestACostHoldIsBoundToTheCallAndARefusedCallDenies(t *testing.T) {
	for _, c := range otherCalls {
		t.Run(c.name, func(t *testing.T) {
			h := costHarness(t, false)
			token := h.grant(t, h.hold(t, costAsk()))

			ask := costAsk()
			tc := *ask.ToolCall
			c.mut(&tc)
			ask.ToolCall = &tc
			got := h.present(t, ask, token)
			if got.Decision != pdp.Deny || !strings.Contains(got.Reason, pdp.ReasonApprovalRefused) {
				t.Fatalf("a cost-gate token for another call is %s (%s), want the refused-token deny", got.Decision, got.Reason)
			}
		})
	}
	h := costHarness(t, false)
	token := h.grant(t, h.hold(t, costAsk()))
	if got := h.present(t, costAsk(), token); got.Decision != pdp.Allow {
		t.Fatalf("the approved call under the cost gate is %s (%s), want allow", got.Decision, got.Reason)
	}
}

func TestATokenBoundToACallIsRefusedOnARequestThatCarriesNone(t *testing.T) {
	h := newSigHarness(t, false)
	token := h.grant(t, h.hold(t, signalAsk()))

	noCall := signalAsk()
	noCall.ToolCall = nil
	if got := h.present(t, noCall, token); got.Decision == pdp.Allow {
		t.Fatalf("a token bound to a call allowed a request with no call (%s)", got.Reason)
	}

	c := costHarness(t, false)
	ctoken := c.grant(t, c.hold(t, costAsk()))
	costNoCall := costAsk()
	costNoCall.ToolCall = nil
	if got := c.present(t, costNoCall, ctoken); got.Decision != pdp.Deny {
		t.Fatalf("a cost token bound to a call on a request with none is %s (%s), want deny", got.Decision, got.Reason)
	}
}

// The path every existing deployment is on: nothing in the request names a
// call, so nothing is bound, and the token is the token it always was.
func TestATokenGrantedForARequestWithNoCallIsTheTokenItAlwaysWas(t *testing.T) {
	h := costHarness(t, false)
	noCall := costAsk()
	noCall.ToolCall = nil
	id := h.hold(t, noCall)
	token := h.grant(t, id)

	claims := tokenClaims(t, token)
	for _, k := range []string{"v", "tcd"} {
		if _, bound := claims[k]; bound {
			t.Errorf("a token granted for a request with no tool call carries %q: %#v", k, claims)
		}
	}
	if got := h.present(t, noCall, token); got.Decision != pdp.Allow {
		t.Fatalf("the no-call request with its legacy token is %s (%s), want allow", got.Decision, got.Reason)
	}
	// It was granted with no call in view, so it binds what it always did and
	// no more: agent, run, tools and cost. A call that appears later is not
	// refused by a digest nobody computed.
	if got := h.present(t, costAsk(), token); got.Decision != pdp.Allow {
		t.Fatalf("an unbound token on a request that now carries a call is %s (%s), want allow as before", got.Decision, got.Reason)
	}
}

// What the person sees, what the token binds and what the record says are one
// value, and none of them is the arguments.
func TestTheApprovalShowsTheCallAndTheTokenEventAndContextAgree(t *testing.T) {
	h := newSigHarness(t, false)
	ask := signalAsk()
	id := h.hold(t, ask)
	token := h.grant(t, id)
	want := approval.ToolCallDigest(ask.ToolCall.Name, ask.ToolCall.Target, ask.ToolCall.Arguments, false)

	rec := doRequest(t, h.srv.Handler(), http.MethodGet, "/v1/approvals", adminKey, nil)
	if bytes.Contains(rec.Body.Bytes(), []byte(argMark)) {
		t.Fatalf("the approval list carries the raw arguments: %s", rec.Body.String())
	}
	var list []approvalDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("approval list: %v", err)
	}
	var shown map[string]any
	for _, a := range list {
		if a.ApprovalID == id {
			shown, _ = a.Context["tool_call"].(map[string]any)
		}
	}
	if shown == nil {
		t.Fatalf("the approval a person decides does not show the call: %s", rec.Body.String())
	}
	if shown["name"] != "s3.delete_object" || shown["target"] != "s3://prod-backups" {
		t.Errorf("the approval shows name %q target %q, want the tool and target being approved", shown["name"], shown["target"])
	}
	for k := range shown {
		switch k {
		case "name", "target", "arguments_truncated", "digest":
		default:
			t.Errorf("the approval's tool_call carries %q, which is neither shown nor bound", k)
		}
	}
	if shown["digest"] != want {
		t.Errorf("approval digest %v, want %s", shown["digest"], want)
	}
	if got := tokenClaims(t, token)["tcd"]; got != want {
		t.Errorf("token digest %v, want %s", got, want)
	}
	if got := tokenClaims(t, token)["v"]; got != float64(2) {
		t.Errorf("token version %v, want 2", got)
	}
	var fromEvent any
	for _, ev := range h.read(t) {
		if ev.Type == "approval_requested" {
			fromEvent = ev.Data["tool_call"].(map[string]any)["digest"]
		}
	}
	if fromEvent != want {
		t.Errorf("event digest %v, want %s", fromEvent, want)
	}
	assertNoArgs(t, h)
}

func assertNoArgs(t *testing.T, h *sigHarness) {
	t.Helper()
	evs, err := event.ReadFile(h.events)
	if err != nil {
		t.Fatalf("event.ReadFile: %v", err)
	}
	raw, _ := json.Marshal(evs)
	if bytes.Contains(raw, []byte(argMark)) {
		t.Fatal("the raw arguments reached the events")
	}
}

// A damaged hold is never turned into an approval that binds nothing.
func TestAHoldWhoseCallDigestIsDamagedCannotBeGrantedUnbound(t *testing.T) {
	h := newSigHarness(t, false)
	damaged := store.Approval{
		ApprovalID: "ap_damaged", AgentID: sigAgent, RunID: "run-sig", RequestedAt: time.Now().UTC(),
		Context: map[string]any{
			"org": "acme", "tool_names": []string{"s3.delete_object"},
			"tool_call": map[string]any{"name": "s3.delete_object"}, // digest gone
		},
	}
	if err := h.srv.store.CreateApproval(t.Context(), damaged); err != nil {
		t.Fatal(err)
	}
	rec := doRequest(t, h.srv.Handler(), http.MethodPost, "/v1/approvals/ap_damaged/decide", adminKey,
		approvalDecideRequestDTO{Decision: "grant", DecidedBy: "alice@acme.example"})
	if rec.Code == http.StatusOK {
		t.Fatalf("a hold with a damaged digest was granted: %s", rec.Body.String())
	}
	got, err := h.srv.store.GetApproval(t.Context(), "ap_damaged")
	if err != nil || !got.Pending() {
		t.Fatalf("the refused grant left the approval decided: %+v %v", got, err)
	}
}

// The digest is over the arguments exactly as received, which is what the
// event's arguments_sha256 has always been, so a re-spaced rendering of the same
// JSON is another call and a refused approval, never a wrongly granted one. The
// test sends raw bytes: doRequest marshals through encoding/json, which would
// compact the difference away.
func TestArgumentsWrittenWithOtherWhitespaceAreAnotherCall(t *testing.T) {
	h := newSigHarness(t, false)
	token := h.grant(t, h.hold(t, signalAsk()))

	raw := func(args string) decideResponseDTO {
		body := `{"agent_id":"` + sigAgent + `","run_id":"run-sig","tool_names":["s3.delete_object"],` +
			`"approval_token":"` + token + `",` +
			`"signals":[{"name":"action.risk_class","value":"destructive","probability":0.95,"source":"classifier"}],` +
			`"tool_call":{"name":"s3.delete_object","target":"s3://prod-backups","arguments":` + args + `}}`
		req := httptest.NewRequest(http.MethodPost, "/v1/decide", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminKey)
		rec := httptest.NewRecorder()
		h.srv.Handler().ServeHTTP(rec, req)
		return decodeBody[decideResponseDTO](t, rec)
	}
	compact := `{"bucket":"prod-backups","key":"` + argMark + `"}`
	spaced := `{ "bucket": "prod-backups", "key": "` + argMark + `" }`
	if got := raw(spaced); got.Decision == pdp.Allow {
		t.Fatalf("re-spaced arguments were allowed on a token for the compact form (%s)", got.Reason)
	}
	if got := raw(compact); got.Decision != pdp.Allow {
		t.Fatalf("the byte-identical arguments are %s (%s), want allow", got.Decision, got.Reason)
	}
}
