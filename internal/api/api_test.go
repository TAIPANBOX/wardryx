package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	wotel "github.com/TAIPANBOX/wardryx/internal/otel"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/store"
)

const (
	adminKey  = "admin-key"
	viewerKey = "viewer-key"
	otherOrg  = "other-org-key"
	testHMAC  = "test-approval-secret"
)

// newTestServer returns a Server with WARDRYX_APPROVAL_SINGLE_USE off (the
// default): a granted approval_token stays reusable for its full TTL.
func newTestServer(t *testing.T) *Server {
	t.Helper()
	return newTestServerOpts(t, false, nil)
}

// newTestServerSingleUse returns a Server with WARDRYX_APPROVAL_SINGLE_USE
// on: a granted approval_token allows exactly one /v1/decide call.
func newTestServerSingleUse(t *testing.T) *Server {
	t.Helper()
	return newTestServerOpts(t, true, nil)
}

// newTestServerWithOtel returns a Server wired to otel (WARDRYX_OTLP_ENDPOINT
// configured), for tests that verify handleDecide's span export.
func newTestServerWithOtel(t *testing.T, otel *wotel.Exporter) *Server {
	t.Helper()
	return newTestServerOpts(t, false, otel)
}

func newTestServerOpts(t *testing.T, singleUse bool, otel *wotel.Exporter) *Server {
	t.Helper()
	set, err := policy.Compile([]policy.Policy{
		{
			Name:                 "finance-guardrail",
			Target:               "agent://acme.example/finance/*",
			DenyTool:             []string{"send_wire_transfer"},
			AllowDomains:         []string{"good.example.com"},
			RequireHumanAboveUSD: 500,
			MaxSteps:             5,
		},
	})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	engine := pdp.New(set, []byte(testHMAC))
	st := store.NewMemory()
	keys := map[string]Principal{
		adminKey:  {Org: "acme", Role: RoleAdmin},
		viewerKey: {Org: "acme", Role: RoleViewer},
		otherOrg:  {Org: "globex", Role: RoleAdmin},
	}
	return New(engine, st, nil, otel, keys, []byte(testHMAC), singleUse, set.Policies())
}

func doRequest(t *testing.T, h http.Handler, method, path, bearer string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decodeBody[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode response body %q: %v", rec.Body.String(), err)
	}
	return v
}

func TestHealthzNoAuthRequired(t *testing.T) {
	srv := newTestServer(t)
	rec := doRequest(t, srv.Handler(), http.MethodGet, "/healthz", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestDecideRequiresAuth(t *testing.T) {
	srv := newTestServer(t)
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", "", decideRequestDTO{AgentID: "agent://x/bot", RunID: "r1"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestDecideRejectsUnknownKey(t *testing.T) {
	srv := newTestServer(t)
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", "not-a-real-key", decideRequestDTO{AgentID: "agent://x/bot", RunID: "r1"})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestDecideAllow(t *testing.T) {
	srv := newTestServer(t)
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "r1", ToolNames: []string{"generate_report"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	got := decodeBody[decideResponseDTO](t, rec)
	if got.Decision != pdp.Allow {
		t.Errorf("Decision = %q, want %q", got.Decision, pdp.Allow)
	}
}

func TestDecideMissingRequiredFields(t *testing.T) {
	srv := newTestServer(t)
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{AgentID: "agent://x/bot"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (missing run_id)", rec.Code)
	}
}

func TestDecideHoldCreatesApprovalListedForOwningOrg(t *testing.T) {
	srv := newTestServer(t)
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "r1", ToolNames: []string{"generate_report"}, EstCostUSD: 999,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	got := decodeBody[decideResponseDTO](t, rec)
	if got.Decision != pdp.Hold {
		t.Fatalf("Decision = %q, want %q", got.Decision, pdp.Hold)
	}
	if got.ApprovalID == "" {
		t.Fatal("ApprovalID is empty on a hold")
	}
	if !got.ApprovalTokenRequired {
		t.Error("ApprovalTokenRequired = false, want true on a hold")
	}

	// Listed for the org that created it.
	listRec := doRequest(t, srv.Handler(), http.MethodGet, "/v1/approvals", adminKey, nil)
	list := decodeBody[[]approvalDTO](t, listRec)
	found := false
	for _, a := range list {
		if a.ApprovalID == got.ApprovalID {
			found = true
			if !a.Pending {
				t.Error("newly held approval should be Pending in the list")
			}
		}
	}
	if !found {
		t.Fatalf("approval %s not present in GET /v1/approvals: %+v", got.ApprovalID, list)
	}

	// NOT listed for a different org.
	otherListRec := doRequest(t, srv.Handler(), http.MethodGet, "/v1/approvals", otherOrg, nil)
	otherList := decodeBody[[]approvalDTO](t, otherListRec)
	for _, a := range otherList {
		if a.ApprovalID == got.ApprovalID {
			t.Fatalf("approval %s leaked into a different org's list", got.ApprovalID)
		}
	}
}

func TestApprovalDecideRequiresAdminRole(t *testing.T) {
	srv := newTestServer(t)
	holdRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "r1", EstCostUSD: 999,
	})
	held := decodeBody[decideResponseDTO](t, holdRec)

	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/approvals/"+held.ApprovalID+"/decide", viewerKey,
		approvalDecideRequestDTO{Decision: "grant", DecidedBy: "bob@acme.example"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a viewer key", rec.Code)
	}
}

func TestFullHoldGrantThenDecideAllowsWithToken(t *testing.T) {
	srv := newTestServer(t)

	holdRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "run-1", ToolNames: []string{"generate_report"}, EstCostUSD: 999,
	})
	held := decodeBody[decideResponseDTO](t, holdRec)
	if held.Decision != pdp.Hold {
		t.Fatalf("initial Decision = %q, want hold", held.Decision)
	}

	grantRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/approvals/"+held.ApprovalID+"/decide", adminKey,
		approvalDecideRequestDTO{Decision: "grant", DecidedBy: "alice@acme.example"})
	if grantRec.Code != http.StatusOK {
		t.Fatalf("grant status = %d, body = %s", grantRec.Code, grantRec.Body.String())
	}
	granted := decodeBody[approvalDecideResponseDTO](t, grantRec)
	if granted.ApprovalToken == "" {
		t.Fatal("grant did not return an approval_token")
	}

	retryRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "run-1", ToolNames: []string{"generate_report"}, EstCostUSD: 999,
		ApprovalToken: granted.ApprovalToken,
	})
	retry := decodeBody[decideResponseDTO](t, retryRec)
	if retry.Decision != pdp.Allow {
		t.Fatalf("Decision after presenting the granted token = %q (%s), want allow", retry.Decision, retry.Reason)
	}
}

// TestSingleUseOffTokenStaysReusableForFullTTL locks in today's default
// behavior (WARDRYX_APPROVAL_SINGLE_USE unset/false, via newTestServer):
// a granted approval_token allows *every* /v1/decide call presenting it
// within its TTL, not just the first. This must keep passing unchanged
// after WARDRYX_APPROVAL_SINGLE_USE is introduced.
func TestSingleUseOffTokenStaysReusableForFullTTL(t *testing.T) {
	srv := newTestServer(t)

	holdRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "run-1", ToolNames: []string{"generate_report"}, EstCostUSD: 999,
	})
	held := decodeBody[decideResponseDTO](t, holdRec)

	grantRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/approvals/"+held.ApprovalID+"/decide", adminKey,
		approvalDecideRequestDTO{Decision: "grant", DecidedBy: "alice@acme.example"})
	granted := decodeBody[approvalDecideResponseDTO](t, grantRec)
	if granted.ApprovalToken == "" {
		t.Fatal("grant did not return an approval_token")
	}

	for i := 0; i < 3; i++ {
		rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
			AgentID: "agent://acme.example/finance/bot1", RunID: "run-1", ToolNames: []string{"generate_report"}, EstCostUSD: 999,
			ApprovalToken: granted.ApprovalToken,
		})
		got := decodeBody[decideResponseDTO](t, rec)
		if got.Decision != pdp.Allow {
			t.Fatalf("presentation #%d: Decision = %q (%s), want allow: single-use is off, the token must stay reusable", i+1, got.Decision, got.Reason)
		}
	}
}

// TestSingleUseOnSecondDecideWithSameTokenHolds is the ON counterpart:
// with WARDRYX_APPROVAL_SINGLE_USE true, the first /v1/decide to redeem a
// granted token allows; a second /v1/decide presenting that same token for
// the same triple must not allow via the token again -- it falls back to a
// fresh hold (a new ApprovalID), not a silent allow.
func TestSingleUseOnSecondDecideWithSameTokenHolds(t *testing.T) {
	srv := newTestServerSingleUse(t)

	holdRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "run-1", ToolNames: []string{"generate_report"}, EstCostUSD: 999,
	})
	held := decodeBody[decideResponseDTO](t, holdRec)
	if held.Decision != pdp.Hold {
		t.Fatalf("initial Decision = %q, want hold", held.Decision)
	}

	grantRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/approvals/"+held.ApprovalID+"/decide", adminKey,
		approvalDecideRequestDTO{Decision: "grant", DecidedBy: "alice@acme.example"})
	granted := decodeBody[approvalDecideResponseDTO](t, grantRec)
	if granted.ApprovalToken == "" {
		t.Fatal("grant did not return an approval_token")
	}

	decideReq := decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "run-1", ToolNames: []string{"generate_report"}, EstCostUSD: 999,
		ApprovalToken: granted.ApprovalToken,
	}

	firstRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideReq)
	first := decodeBody[decideResponseDTO](t, firstRec)
	if first.Decision != pdp.Allow {
		t.Fatalf("first presentation: Decision = %q (%s), want allow", first.Decision, first.Reason)
	}

	secondRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideReq)
	second := decodeBody[decideResponseDTO](t, secondRec)
	if second.Decision != pdp.Hold {
		t.Fatalf("second presentation of the same token: Decision = %q (%s), want hold (single-use mode)", second.Decision, second.Reason)
	}
	if second.ApprovalID == "" {
		t.Fatal("second presentation: ApprovalID is empty on the fresh hold")
	}
	if second.ApprovalID == held.ApprovalID {
		t.Error("second presentation minted the same ApprovalID as the original hold, want a fresh one")
	}
	if !second.ApprovalTokenRequired {
		t.Error("ApprovalTokenRequired = false on the fresh hold, want true")
	}
}

// TestSingleUseOnReapprovalAfterExhaustionAllowsAgain proves single-use
// scopes to one grant, not to the (agent_id, run_id, tool set) triple
// forever: once a token is exhausted and /v1/decide falls back to a fresh
// hold, granting *that* hold mints a new token which itself redeems
// successfully. Single-use must never permanently lock a triple out of
// approval after its first grant is spent.
func TestSingleUseOnReapprovalAfterExhaustionAllowsAgain(t *testing.T) {
	srv := newTestServerSingleUse(t)

	holdRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "run-1", ToolNames: []string{"generate_report"}, EstCostUSD: 999,
	})
	held := decodeBody[decideResponseDTO](t, holdRec)

	grantRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/approvals/"+held.ApprovalID+"/decide", adminKey,
		approvalDecideRequestDTO{Decision: "grant", DecidedBy: "alice@acme.example"})
	granted := decodeBody[approvalDecideResponseDTO](t, grantRec)

	decideReq := decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "run-1", ToolNames: []string{"generate_report"}, EstCostUSD: 999,
		ApprovalToken: granted.ApprovalToken,
	}
	firstRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideReq)
	if decodeBody[decideResponseDTO](t, firstRec).Decision != pdp.Allow {
		t.Fatal("first presentation did not allow")
	}

	// Second presentation of the exhausted token: falls back to a fresh hold.
	secondRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideReq)
	second := decodeBody[decideResponseDTO](t, secondRec)
	if second.Decision != pdp.Hold {
		t.Fatalf("second presentation: Decision = %q, want hold", second.Decision)
	}

	// Re-approve the fresh hold out of band: a new token is minted.
	regrantRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/approvals/"+second.ApprovalID+"/decide", adminKey,
		approvalDecideRequestDTO{Decision: "grant", DecidedBy: "bob@acme.example"})
	regranted := decodeBody[approvalDecideResponseDTO](t, regrantRec)
	if regranted.ApprovalToken == "" {
		t.Fatal("re-grant did not return an approval_token")
	}
	if regranted.ApprovalToken == granted.ApprovalToken {
		t.Fatal("re-grant minted the exact same token string as the first grant")
	}

	// The newly granted token must redeem successfully: single-use is
	// per-grant, not a permanent lock on the triple.
	thirdRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "run-1", ToolNames: []string{"generate_report"}, EstCostUSD: 999,
		ApprovalToken: regranted.ApprovalToken,
	})
	third := decodeBody[decideResponseDTO](t, thirdRec)
	if third.Decision != pdp.Allow {
		t.Fatalf("presenting the freshly re-granted token: Decision = %q (%s), want allow", third.Decision, third.Reason)
	}
}

func TestApprovalDecideDenyReturnsNoToken(t *testing.T) {
	srv := newTestServer(t)
	holdRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "r1", EstCostUSD: 999,
	})
	held := decodeBody[decideResponseDTO](t, holdRec)

	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/approvals/"+held.ApprovalID+"/decide", adminKey,
		approvalDecideRequestDTO{Decision: "deny", DecidedBy: "alice@acme.example"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	got := decodeBody[approvalDecideResponseDTO](t, rec)
	if got.Decision != "deny" || got.ApprovalToken != "" {
		t.Errorf("got = %+v, want decision=deny with no token", got)
	}
}

func TestApprovalDecideUnknownIDReturns404(t *testing.T) {
	srv := newTestServer(t)
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/approvals/does-not-exist/decide", adminKey,
		approvalDecideRequestDTO{Decision: "grant", DecidedBy: "alice"})
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestApprovalDecideTwiceReturns409(t *testing.T) {
	srv := newTestServer(t)
	holdRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "r1", EstCostUSD: 999,
	})
	held := decodeBody[decideResponseDTO](t, holdRec)

	first := doRequest(t, srv.Handler(), http.MethodPost, "/v1/approvals/"+held.ApprovalID+"/decide", adminKey,
		approvalDecideRequestDTO{Decision: "grant", DecidedBy: "alice"})
	if first.Code != http.StatusOK {
		t.Fatalf("first decide status = %d", first.Code)
	}
	second := doRequest(t, srv.Handler(), http.MethodPost, "/v1/approvals/"+held.ApprovalID+"/decide", adminKey,
		approvalDecideRequestDTO{Decision: "deny", DecidedBy: "bob"})
	if second.Code != http.StatusConflict {
		t.Fatalf("second decide status = %d, want 409", second.Code)
	}
}

func TestApprovalDecideRejectsInvalidDecisionValue(t *testing.T) {
	srv := newTestServer(t)
	holdRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "r1", EstCostUSD: 999,
	})
	held := decodeBody[decideResponseDTO](t, holdRec)

	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/approvals/"+held.ApprovalID+"/decide", adminKey,
		approvalDecideRequestDTO{Decision: "maybe", DecidedBy: "alice"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestListApprovalsRequiresAuth(t *testing.T) {
	srv := newTestServer(t)
	rec := doRequest(t, srv.Handler(), http.MethodGet, "/v1/approvals", "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestDecideDenyDeniedTool(t *testing.T) {
	srv := newTestServer(t)
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "r1", ToolNames: []string{"send_wire_transfer"},
	})
	got := decodeBody[decideResponseDTO](t, rec)
	if got.Decision != pdp.Deny {
		t.Fatalf("Decision = %q, want deny", got.Decision)
	}
}

// ------------------------------------------------------------------
// OTLP span export (WARDRYX_OTLP_ENDPOINT / exportSpan). These prove the
// actual wiring from handleDecide into internal/otel, not just internal/otel
// in isolation: a real httptest OTLP receiver, a Server built with a real
// Exporter pointed at it, and one assertion per decision branch.
// ------------------------------------------------------------------

// otlpSpanReceiver is a fake OTLP/HTTP-JSON collector: each POST decodes to
// one span (buildPayload's fixed shape), pushed onto a channel the test
// reads with a timeout, since Exporter.Export posts from a background
// goroutine.
func otlpSpanReceiver(t *testing.T) (url string, spans chan map[string]any) {
	t.Helper()
	spans = make(chan map[string]any, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("otlp receiver: decode body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		resourceSpans, _ := payload["resourceSpans"].([]any)
		scopeSpans, _ := resourceSpans[0].(map[string]any)["scopeSpans"].([]any)
		spanList, _ := scopeSpans[0].(map[string]any)["spans"].([]any)
		span, _ := spanList[0].(map[string]any)
		spans <- span
	}))
	t.Cleanup(srv.Close)
	return srv.URL, spans
}

func recvSpan(t *testing.T, spans chan map[string]any) map[string]any {
	t.Helper()
	select {
	case span := <-spans:
		return span
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the exported OTLP span")
		return nil
	}
}

func spanAttr(span map[string]any, key string) (string, bool) {
	attrs, _ := span["attributes"].([]any)
	for _, a := range attrs {
		m, _ := a.(map[string]any)
		if m["key"] != key {
			continue
		}
		v, _ := m["value"].(map[string]any)
		s, _ := v["stringValue"].(string)
		return s, true
	}
	return "", false
}

func TestDecideAllowExportsOtlpSpan(t *testing.T) {
	url, spans := otlpSpanReceiver(t)
	srv := newTestServerWithOtel(t, wotel.New(url))

	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "r-allow", ToolNames: []string{"generate_report"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	span := recvSpan(t, spans)
	if decision, _ := spanAttr(span, "wardryx.decision"); decision != pdp.Allow {
		t.Errorf("wardryx.decision = %q, want %q", decision, pdp.Allow)
	}
	if runID, _ := spanAttr(span, "wardryx.run_id"); runID != "r-allow" {
		t.Errorf("wardryx.run_id = %q, want r-allow", runID)
	}
}

func TestDecideDenyExportsOtlpSpan(t *testing.T) {
	url, spans := otlpSpanReceiver(t)
	srv := newTestServerWithOtel(t, wotel.New(url))

	doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "r-deny", ToolNames: []string{"send_wire_transfer"},
	})

	span := recvSpan(t, spans)
	if decision, _ := spanAttr(span, "wardryx.decision"); decision != pdp.Deny {
		t.Errorf("wardryx.decision = %q, want %q", decision, pdp.Deny)
	}
}

func TestDecideHoldExportsOtlpSpan(t *testing.T) {
	url, spans := otlpSpanReceiver(t)
	srv := newTestServerWithOtel(t, wotel.New(url))

	doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "r-hold", EstCostUSD: 999,
	})

	span := recvSpan(t, spans)
	if decision, _ := spanAttr(span, "wardryx.decision"); decision != pdp.Hold {
		t.Errorf("wardryx.decision = %q, want %q", decision, pdp.Hold)
	}
}

// TestDecideWithoutOtlpConfiguredNeverExports proves exportSpan's nil-otel
// no-op path: a Server built the normal way (newTestServer, no
// WARDRYX_OTLP_ENDPOINT) must not attempt any export at all -- there is no
// receiver listening here, so an accidental attempt would either error
// (harmlessly swallowed) or, if this test is flaky, hang. The real
// assertion is simpler: /v1/decide must still succeed and respond exactly
// as it does without OTLP in the picture.
func TestDecideWithoutOtlpConfiguredNeverExports(t *testing.T) {
	srv := newTestServer(t)
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "r1", ToolNames: []string{"generate_report"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	got := decodeBody[decideResponseDTO](t, rec)
	if got.Decision != pdp.Allow {
		t.Errorf("Decision = %q, want %q", got.Decision, pdp.Allow)
	}
}

// TestDecideDenyMaxStepsOverWire proves the "steps" JSON field actually
// reaches pdp.Decide over the full HTTP path, not just in-process: this is
// the wire contract the TokenFuse gateway's PEP hook posts against.
func TestDecideDenyMaxStepsOverWire(t *testing.T) {
	srv := newTestServer(t)
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "r1", ToolNames: []string{"generate_report"}, Steps: 5,
	})
	got := decodeBody[decideResponseDTO](t, rec)
	if got.Decision != pdp.Deny {
		t.Fatalf("Decision = %q (%s), want deny: steps=5 reached the fixture policy's max_steps=5", got.Decision, got.Reason)
	}
	if !strings.Contains(got.Reason, "max_steps") {
		t.Errorf("Reason = %q, want it to mention max_steps", got.Reason)
	}

	// One step under the cap still allows.
	underRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "r1", ToolNames: []string{"generate_report"}, Steps: 4,
	})
	under := decodeBody[decideResponseDTO](t, underRec)
	if under.Decision != pdp.Allow {
		t.Fatalf("Decision = %q (%s), want allow: steps=4 is under the fixture policy's max_steps=5", under.Decision, under.Reason)
	}
}

// TestDecideDenyDisallowedDomainOverWire proves the "domains" JSON field
// actually reaches pdp.Decide over the full HTTP path. An empty domains
// list is a no-op even though the fixture policy sets allow_domains.
func TestDecideDenyDisallowedDomainOverWire(t *testing.T) {
	srv := newTestServer(t)
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "r1", ToolNames: []string{"generate_report"}, Domains: []string{"evil.example.com"},
	})
	got := decodeBody[decideResponseDTO](t, rec)
	if got.Decision != pdp.Deny {
		t.Fatalf("Decision = %q (%s), want deny: evil.example.com is outside the fixture policy's allow_domains", got.Decision, got.Reason)
	}
	if !strings.Contains(got.Reason, "evil.example.com") {
		t.Errorf("Reason = %q, want it to name the offending domain", got.Reason)
	}

	// A declared, allowed domain still allows.
	allowedRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "r1", ToolNames: []string{"generate_report"}, Domains: []string{"good.example.com"},
	})
	allowed := decodeBody[decideResponseDTO](t, allowedRec)
	if allowed.Decision != pdp.Allow {
		t.Fatalf("Decision = %q (%s), want allow: good.example.com is in the fixture policy's allow_domains", allowed.Decision, allowed.Reason)
	}

	// No declared domains at all is a no-op, even though the policy sets
	// allow_domains.
	noneRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "r1", ToolNames: []string{"generate_report"},
	})
	none := decodeBody[decideResponseDTO](t, noneRec)
	if none.Decision != pdp.Allow {
		t.Fatalf("Decision = %q (%s), want allow: no domains declared means nothing to restrict", none.Decision, none.Reason)
	}
}

// TestDecideCacheableOverWire proves the "cacheable" JSON field actually
// reaches the wire from pdp.Decide over the full HTTP path, mirroring
// TestDecideDenyMaxStepsOverWire and TestDecideDenyDisallowedDomainOverWire's
// proof for "steps"/"domains". This is the field an enforcement point's own
// decision cache (TokenFuse's gateway) gates storage on, so it has to
// actually arrive on the wire, not just live on pdp.DecideResponse.
func TestDecideCacheableOverWire(t *testing.T) {
	srv := newTestServer(t)

	// The fixture policy (finance-guardrail) sets max_steps, allow_domains,
	// and require_human_above_usd, so any request matching it is
	// request-specific and must report cacheable=false on the wire.
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "r1", ToolNames: []string{"generate_report"},
	})
	got := decodeBody[decideResponseDTO](t, rec)
	if got.Decision != pdp.Allow {
		t.Fatalf("Decision = %q (%s), want allow", got.Decision, got.Reason)
	}
	if got.Cacheable {
		t.Error("Cacheable = true, want false: the fixture policy is request-specific")
	}

	// An agent no policy targets at all is a stable allow: cacheable=true.
	noneRec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://nobody.example/anything/bot", RunID: "r1", ToolNames: []string{"anything"},
	})
	none := decodeBody[decideResponseDTO](t, noneRec)
	if none.Decision != pdp.Allow {
		t.Fatalf("Decision = %q (%s), want allow", none.Decision, none.Reason)
	}
	if !none.Cacheable {
		t.Error("Cacheable = false, want true: no policy targets this agent")
	}
}

// ------------------------------------------------------------------
// Policy-as-code API (/v1/policies). newTestServer's fixture Set (see
// newTestServerOpts) becomes each of these tests' basePolicies -- the fixed
// file-loaded floor -- so these tests also prove that floor survives
// alongside, and after, API-managed policies.
// ------------------------------------------------------------------

func TestListPoliciesRequiresAdmin(t *testing.T) {
	srv := newTestServer(t)
	if rec := doRequest(t, srv.Handler(), http.MethodGet, "/v1/policies", "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no key: status = %d, want 401", rec.Code)
	}
	if rec := doRequest(t, srv.Handler(), http.MethodGet, "/v1/policies", viewerKey, nil); rec.Code != http.StatusForbidden {
		t.Errorf("viewer key: status = %d, want 403", rec.Code)
	}
}

func TestListPoliciesEmptyByDefault(t *testing.T) {
	// The fixture's finance-guardrail policy is file-loaded (basePolicies),
	// not stored -- GET /v1/policies lists only store-managed policies, so
	// a fresh server (nothing written through the API yet) reports empty.
	srv := newTestServer(t)
	rec := doRequest(t, srv.Handler(), http.MethodGet, "/v1/policies", adminKey, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	got := decodeBody[[]policyDTO](t, rec)
	if len(got) != 0 {
		t.Errorf("ListPolicies on a fresh server = %+v, want empty", got)
	}
}

func TestPutPolicyRequiresAdmin(t *testing.T) {
	srv := newTestServer(t)
	body := policy.Policy{Target: "agent://x/*"}
	if rec := doRequest(t, srv.Handler(), http.MethodPut, "/v1/policies/p1", viewerKey, body); rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a viewer key", rec.Code)
	}
}

func TestPutPolicyCreatesThenGetReturnsIt(t *testing.T) {
	srv := newTestServer(t)
	body := policy.Policy{Name: "block-scraping", Target: "agent://acme.example/scraper/*", DenyTool: []string{"scrape"}}

	putRec := doRequest(t, srv.Handler(), http.MethodPut, "/v1/policies/scraper-guard", adminKey, body)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body = %s", putRec.Code, putRec.Body.String())
	}
	put := decodeBody[policyDTO](t, putRec)
	if put.ID != "scraper-guard" || put.Target != body.Target {
		t.Errorf("PUT response = %+v, want id=scraper-guard target=%s", put, body.Target)
	}
	if put.UpdatedAt == "" {
		t.Error("PUT response UpdatedAt is empty")
	}

	getRec := doRequest(t, srv.Handler(), http.MethodGet, "/v1/policies/scraper-guard", adminKey, nil)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body = %s", getRec.Code, getRec.Body.String())
	}
	got := decodeBody[policyDTO](t, getRec)
	if got.ID != "scraper-guard" || len(got.DenyTool) != 1 || got.DenyTool[0] != "scrape" {
		t.Errorf("GET = %+v, want id=scraper-guard deny_tool=[scrape]", got)
	}

	listRec := doRequest(t, srv.Handler(), http.MethodGet, "/v1/policies", adminKey, nil)
	list := decodeBody[[]policyDTO](t, listRec)
	if len(list) != 1 || list[0].ID != "scraper-guard" {
		t.Errorf("ListPolicies = %+v, want exactly [scraper-guard]", list)
	}
}

func TestGetPolicyNotFound(t *testing.T) {
	srv := newTestServer(t)
	rec := doRequest(t, srv.Handler(), http.MethodGet, "/v1/policies/does-not-exist", adminKey, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestPutPolicyTakesEffectImmediately proves the write is live, not just
// stored: a tool /v1/decide would otherwise allow starts denying the
// moment the policy is PUT, with no restart and no cache to invalidate.
func TestPutPolicyTakesEffectImmediately(t *testing.T) {
	srv := newTestServer(t)
	req := decideRequestDTO{AgentID: "agent://acme.example/ops/bot1", RunID: "r1", ToolNames: []string{"shell_exec"}}

	before := decodeBody[decideResponseDTO](t, doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, req))
	if before.Decision != pdp.Allow {
		t.Fatalf("before PUT: Decision = %q, want allow (no policy targets agent://acme.example/ops/* yet)", before.Decision)
	}

	putRec := doRequest(t, srv.Handler(), http.MethodPut, "/v1/policies/ops-guard", adminKey,
		policy.Policy{Target: "agent://acme.example/ops/*", DenyTool: []string{"shell_exec"}})
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body = %s", putRec.Code, putRec.Body.String())
	}

	after := decodeBody[decideResponseDTO](t, doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, req))
	if after.Decision != pdp.Deny {
		t.Fatalf("after PUT: Decision = %q, want deny (shell_exec now denied by ops-guard)", after.Decision)
	}
}

// TestPutPolicyInvalidBodyRejectedWithoutSideEffects is the "never
// partially apply" guarantee: an invalid write must change neither the
// store nor the live Engine.
func TestPutPolicyInvalidBodyRejectedWithoutSideEffects(t *testing.T) {
	srv := newTestServer(t)
	versionBefore := srv.engine.PolicyVersion()

	// Target is required; an empty one must fail policy.Compile.
	rec := doRequest(t, srv.Handler(), http.MethodPut, "/v1/policies/bad", adminKey, policy.Policy{Name: "no-target"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s, want 400", rec.Code, rec.Body.String())
	}

	if srv.engine.PolicyVersion() != versionBefore {
		t.Error("PolicyVersion changed after a rejected PUT: Engine must be untouched on validation failure")
	}
	if _, err := srv.store.GetPolicy(context.Background(), "bad"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetPolicy(bad) after rejected PUT = %v, want ErrNotFound: the store must be untouched too", err)
	}
}

// TestPutPolicyReplacesExisting proves PUT is upsert: a second PUT under
// the same id replaces the first rule's effect rather than adding a second
// one alongside it.
func TestPutPolicyReplacesExisting(t *testing.T) {
	srv := newTestServer(t)
	if rec := doRequest(t, srv.Handler(), http.MethodPut, "/v1/policies/p1", adminKey,
		policy.Policy{Target: "agent://acme.example/x/*", MaxSteps: 3}); rec.Code != http.StatusOK {
		t.Fatalf("first PUT status = %d", rec.Code)
	}
	if rec := doRequest(t, srv.Handler(), http.MethodPut, "/v1/policies/p1", adminKey,
		policy.Policy{Target: "agent://acme.example/x/*", MaxSteps: 30}); rec.Code != http.StatusOK {
		t.Fatalf("second PUT status = %d", rec.Code)
	}

	got := decodeBody[policyDTO](t, doRequest(t, srv.Handler(), http.MethodGet, "/v1/policies/p1", adminKey, nil))
	if got.MaxSteps != 30 {
		t.Errorf("MaxSteps = %d, want 30 (the second PUT's value)", got.MaxSteps)
	}

	// Exactly one stored policy, not two.
	list := decodeBody[[]policyDTO](t, doRequest(t, srv.Handler(), http.MethodGet, "/v1/policies", adminKey, nil))
	if len(list) != 1 {
		t.Errorf("ListPolicies = %+v, want exactly one entry for p1", list)
	}
}

func TestDeletePolicyRequiresAdmin(t *testing.T) {
	srv := newTestServer(t)
	doRequest(t, srv.Handler(), http.MethodPut, "/v1/policies/p1", adminKey, policy.Policy{Target: "agent://x/*"})
	if rec := doRequest(t, srv.Handler(), http.MethodDelete, "/v1/policies/p1", viewerKey, nil); rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for a viewer key", rec.Code)
	}
}

func TestDeletePolicyNotFound(t *testing.T) {
	srv := newTestServer(t)
	rec := doRequest(t, srv.Handler(), http.MethodDelete, "/v1/policies/does-not-exist", adminKey, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

// TestDeletePolicyStopsEnforcingItImmediately mirrors
// TestPutPolicyTakesEffectImmediately for the removal path: once deleted, a
// call the policy used to deny must allow again, live, no restart.
func TestDeletePolicyStopsEnforcingItImmediately(t *testing.T) {
	srv := newTestServer(t)
	doRequest(t, srv.Handler(), http.MethodPut, "/v1/policies/ops-guard", adminKey,
		policy.Policy{Target: "agent://acme.example/ops/*", DenyTool: []string{"shell_exec"}})
	req := decideRequestDTO{AgentID: "agent://acme.example/ops/bot1", RunID: "r1", ToolNames: []string{"shell_exec"}}

	before := decodeBody[decideResponseDTO](t, doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, req))
	if before.Decision != pdp.Deny {
		t.Fatalf("before DELETE: Decision = %q, want deny", before.Decision)
	}

	delRec := doRequest(t, srv.Handler(), http.MethodDelete, "/v1/policies/ops-guard", adminKey, nil)
	if delRec.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want 204", delRec.Code)
	}

	after := decodeBody[decideResponseDTO](t, doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, req))
	if after.Decision != pdp.Allow {
		t.Fatalf("after DELETE: Decision = %q, want allow (ops-guard no longer in force)", after.Decision)
	}

	if _, err := srv.store.GetPolicy(context.Background(), "ops-guard"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("GetPolicy after DELETE = %v, want ErrNotFound", err)
	}
}

// TestFileLoadedPolicyNeverDisappearsFromApiWrites is the core
// policy-as-code safety property: newTestServer's fixture finance-guardrail
// (file-loaded, basePolicies) keeps denying send_wire_transfer through
// several unrelated API writes and deletes, proving the file floor is never
// touched by store-side churn.
func TestFileLoadedPolicyNeverDisappearsFromApiWrites(t *testing.T) {
	srv := newTestServer(t)
	fileFloorReq := decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "r1", ToolNames: []string{"send_wire_transfer"},
	}
	assertStillDenied := func(t *testing.T, when string) {
		t.Helper()
		got := decodeBody[decideResponseDTO](t, doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, fileFloorReq))
		if got.Decision != pdp.Deny {
			t.Errorf("%s: finance-guardrail Decision = %q, want deny (file-loaded floor must survive API writes)", when, got.Decision)
		}
	}
	assertStillDenied(t, "at start")

	doRequest(t, srv.Handler(), http.MethodPut, "/v1/policies/extra-1", adminKey, policy.Policy{Target: "agent://acme.example/ops/*", MaxSteps: 1})
	assertStillDenied(t, "after PUT extra-1")

	doRequest(t, srv.Handler(), http.MethodPut, "/v1/policies/extra-1", adminKey, policy.Policy{Target: "agent://acme.example/ops/*", MaxSteps: 2})
	assertStillDenied(t, "after replacing extra-1")

	doRequest(t, srv.Handler(), http.MethodDelete, "/v1/policies/extra-1", adminKey, nil)
	assertStillDenied(t, "after deleting extra-1")

	// The file-loaded policy itself is not a store id: not listed, not
	// gettable, not deletable through the admin API.
	if rec := doRequest(t, srv.Handler(), http.MethodGet, "/v1/policies/finance-guardrail", adminKey, nil); rec.Code != http.StatusNotFound {
		t.Errorf("GET finance-guardrail by name = %d, want 404 (it is file-loaded, not store-addressable)", rec.Code)
	}
	if rec := doRequest(t, srv.Handler(), http.MethodDelete, "/v1/policies/finance-guardrail", adminKey, nil); rec.Code != http.StatusNotFound {
		t.Errorf("DELETE finance-guardrail = %d, want 404", rec.Code)
	}
	assertStillDenied(t, "after attempting to delete the file-loaded policy by name")
}

// TestPutPolicyMissingIDSegmentRejected covers the PathValue("id") ==""
// defensive check: PUT /v1/policies/ (trailing slash, no id) must not
// silently write an empty-string-keyed policy.
func TestPutPolicyMissingIDSegmentRejected(t *testing.T) {
	srv := newTestServer(t)
	rec := doRequest(t, srv.Handler(), http.MethodPut, "/v1/policies/", adminKey, policy.Policy{Target: "agent://x/*"})
	if rec.Code == http.StatusOK {
		t.Fatalf("PUT /v1/policies/ (no id) succeeded, want a client error")
	}
}
