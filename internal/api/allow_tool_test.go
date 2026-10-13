package api

import (
	"net/http"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/pdp"
)

// TestARenamedToolIsDeniedByAnAllowList is the scenario "A renamed tool is
// denied" (features/allow-tool.feature). It goes through the policy API, the
// way an operator writes a rule, so the test reads the same field a PUT body
// carries: the allow-list names one spelling, the call uses the other.
func TestARenamedToolIsDeniedByAnAllowList(t *testing.T) {
	srv := newTestServer(t)
	put := doRaw(t, srv.Handler(), http.MethodPut, "/v1/policies/coupon-allow", adminKey,
		`{"target":"agent://acme.example/shop/*","allow_tool":["apply_staff_coupon"]}`)
	if put.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body = %s", put.Code, put.Body.String())
	}

	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/shop/bot1", RunID: "r1", ToolNames: []string{"apply-staff-coupon"},
	})
	got := decodeBody[decideResponseDTO](t, rec)
	if got.Decision != pdp.Deny {
		t.Fatalf("Decision = %q (reason %q), want deny: the renamed tool is not the one the allow-list names", got.Decision, got.Reason)
	}
}

// TestFilterToolsReportsAToolOutsideTheAllowList is the scenario "The filter
// reports a tool outside the list", over the wire: the route names the
// allow_tool rule and the policy that refused the tool, and keeps the listed one.
func TestFilterToolsReportsAToolOutsideTheAllowList(t *testing.T) {
	srv := newTestServer(t)
	put := doRaw(t, srv.Handler(), http.MethodPut, "/v1/policies/shop-allow", adminKey,
		`{"name":"shop-allow","target":"agent://acme.example/shop/*","allow_tool":["search"]}`)
	if put.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body = %s", put.Code, put.Body.String())
	}

	rec := doRaw(t, srv.Handler(), http.MethodPost, "/v1/filter-tools", adminKey,
		`{"agent_id":"agent://acme.example/shop/bot1","run_id":"r1","tool_names":["search","shell"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	out := decodeBody[filterToolsResponseWire](t, rec)
	if len(out.Allowed) != 1 || out.Allowed[0] != "search" {
		t.Fatalf("allowed = %v, want [search]", out.Allowed)
	}
	if len(out.Denied) != 1 || out.Denied[0].Name != "shell" || out.Denied[0].Policy != "shop-allow" || out.Denied[0].Rule != "allow_tool" {
		t.Fatalf("denied = %+v, want one entry naming shell, shop-allow, allow_tool", out.Denied)
	}
}
