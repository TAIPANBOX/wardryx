package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/pdp"
)

// Measured 2026-09-27: PUT /v1/policies/n4-deny-beta with body
// {"name":"n4-deny-beta","target":"agent://taipanbox.dev/hermes/beta","deny_above_usd":0}
// answered 200, the stored policy echoed back WITHOUT a deny_above_usd
// field, and the agent's next call through the enforcement point was
// allowed. These two tests reproduce that exact request end to end; both
// were run against the pre-fix code first (deny_above_usd a plain float64
// with `omitempty`, so an explicit zero and an absent field serialize
// identically) and failed there.

// usd returns a pointer to v, for constructing a policy.Policy's
// RequireHumanAboveUSD/DenyAboveUSD fields (*float64, so a caller can say
// zero and be believed).
func usd(v float64) *float64 { return &v }

func TestPutPolicyWithExplicitZeroDenyAboveUSDIsNotSilentlyDropped(t *testing.T) {
	srv := newTestServer(t)
	rec := doRaw(t, srv.Handler(), http.MethodPut, "/v1/policies/n4-deny-beta", adminKey,
		`{"name":"n4-deny-beta","target":"agent://taipanbox.dev/hermes/beta","deny_above_usd":0}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"deny_above_usd": 0`) {
		t.Errorf("PUT response body = %s, want it to echo back deny_above_usd:0 rather than dropping the field", rec.Body.String())
	}

	getRec := doRequest(t, srv.Handler(), http.MethodGet, "/v1/policies/n4-deny-beta", adminKey, nil)
	if !strings.Contains(getRec.Body.String(), `"deny_above_usd": 0`) {
		t.Errorf("GET response body = %s, want the stored policy to still carry deny_above_usd:0", getRec.Body.String())
	}
}

func TestPutPolicyWithExplicitZeroDenyAboveUSDActuallyDeniesTheNextCall(t *testing.T) {
	srv := newTestServer(t)
	putRec := doRaw(t, srv.Handler(), http.MethodPut, "/v1/policies/n4-deny-beta", adminKey,
		`{"name":"n4-deny-beta","target":"agent://taipanbox.dev/hermes/beta","deny_above_usd":0}`)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body = %s", putRec.Code, putRec.Body.String())
	}

	req := decideRequestDTO{AgentID: "agent://taipanbox.dev/hermes/beta", RunID: "r1", EstCostUSD: 0.000033}
	resp := decodeBody[decideResponseDTO](t, doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, req))
	if resp.Decision != pdp.Deny {
		t.Fatalf("Decision = %q (reason: %s), want %q: a deny_above_usd of 0 must deny any priced call, matching the policy just written", resp.Decision, resp.Reason, pdp.Deny)
	}
}
