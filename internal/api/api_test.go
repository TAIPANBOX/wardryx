package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func newTestServer(t *testing.T) *Server {
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
	return New(engine, st, nil, keys, []byte(testHMAC))
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
