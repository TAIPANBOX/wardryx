package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// ------------------------------------------------------------------
// POST /v1/filter-tools: pdp.Filter (rule 2, deny_tool, applied to each
// offered tool alone) exposed over the same auth and body-cap discipline as
// /v1/decide. See features/filter-tools.feature and CLAUDE.md's Filter
// invariant.
// ------------------------------------------------------------------

type filterToolsResponseWire struct {
	Allowed []string `json:"allowed"`
	Denied  []struct {
		Name   string `json:"name"`
		Policy string `json:"policy"`
		Rule   string `json:"rule"`
	} `json:"denied"`
	PolicyVersion string `json:"policy_version"`
}

// TestFilterToolsRequiresAuth is the scenario "The route answers only a
// caller holding a key" (features/filter-tools.feature).
func TestFilterToolsRequiresAuth(t *testing.T) {
	srv := newTestServer(t)
	rec := doRaw(t, srv.Handler(), http.MethodPost, "/v1/filter-tools", "",
		`{"agent_id":"agent://acme.example/finance/bot1","run_id":"r1","tool_names":["search"]}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 with no bearer token", rec.Code)
	}
}

// TestFilterToolsAnswersThePartition drives a real round trip through the
// handler and checks the response shape: empty lists serialize as [] not
// null, and the partition matches the loaded policy's deny_tool.
func TestFilterToolsAnswersThePartition(t *testing.T) {
	srv := newTestServer(t)
	rec := doRaw(t, srv.Handler(), http.MethodPost, "/v1/filter-tools", adminKey,
		`{"agent_id":"agent://acme.example/finance/bot1","run_id":"r1","tool_names":["send_wire_transfer","generate_report"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// Raw-string checks first: the never-null contract is about the bytes on
	// the wire, and json.Unmarshal into a []string field would silently turn
	// a `null` back into a nil slice, hiding exactly the defect this guards.
	body := rec.Body.String()
	if strings.Contains(body, "null") {
		t.Fatalf("response body contains a null list: %s", body)
	}

	var out filterToolsResponseWire
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response body %q: %v", body, err)
	}
	if len(out.Allowed) != 1 || out.Allowed[0] != "generate_report" {
		t.Fatalf("allowed = %v, want [generate_report]", out.Allowed)
	}
	if len(out.Denied) != 1 || out.Denied[0].Name != "send_wire_transfer" ||
		out.Denied[0].Policy != "finance-guardrail" || out.Denied[0].Rule != "deny_tool" {
		t.Fatalf("denied = %+v, want one entry naming send_wire_transfer, finance-guardrail, deny_tool", out.Denied)
	}
	if out.PolicyVersion == "" {
		t.Fatalf("policy_version is empty, want the loaded set's version")
	}
}

// TestFilterToolsRefusesABodyOverTheCap gets the same refusal the decide
// handler gives for a body over maxRequestBodyBytes: both go through
// decodeJSONBody, and a route that bypassed it would let a caller spend
// unbounded memory on this process for free.
func TestFilterToolsRefusesABodyOverTheCap(t *testing.T) {
	srv := newTestServer(t)
	pad := strings.Repeat("a", maxRequestBodyBytes+1)
	body := `{"agent_id":"agent://acme.example/finance/bot1","run_id":"r1","tool_names":["` + pad + `"]}`
	rec := doRaw(t, srv.Handler(), http.MethodPost, "/v1/filter-tools", adminKey, body)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 for a body over the 1 MiB cap", rec.Code)
	}
}

// TestFilterToolsRefusesAMissingAgentID is a 400 through the handler's
// existing error helper: invariant 10 says no raw error text reaches the
// response.
func TestFilterToolsRefusesAMissingAgentID(t *testing.T) {
	srv := newTestServer(t)
	cases := []string{
		`{"run_id":"r1","tool_names":["search"]}`,
		`{"agent_id":"","run_id":"r1","tool_names":["search"]}`,
	}
	for _, body := range cases {
		rec := doRaw(t, srv.Handler(), http.MethodPost, "/v1/filter-tools", adminKey, body)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body %q: status = %d, want 400 for a missing or empty agent_id", body, rec.Code)
		}
	}
}

// TestFilterToolsSurvivesHostileInput never returns 500 and never panics on
// malformed JSON, a tool_names that is not an array, non-string entries, or
// a large-but-within-cap tool list.
func TestFilterToolsSurvivesHostileInput(t *testing.T) {
	srv := newTestServer(t)

	manyNames := make([]string, 10000)
	for i := range manyNames {
		manyNames[i] = fmt.Sprintf("tool_%d", i)
	}
	manyNamesJSON, err := json.Marshal(manyNames)
	if err != nil {
		t.Fatalf("marshal manyNames: %v", err)
	}

	cases := []struct {
		name string
		body string
	}{
		{"truncated JSON", `{"agent_id":`},
		{"not JSON at all", `<?xml version="1.0"?><filter/>`},
		{"a JSON array where an object belongs", `[]`},
		{"empty body", ``},
		{"tool_names is a string, not an array", `{"agent_id":"agent://acme.example/finance/bot1","run_id":"r1","tool_names":"search"}`},
		{"tool_names is an object, not an array", `{"agent_id":"agent://acme.example/finance/bot1","run_id":"r1","tool_names":{"a":1}}`},
		{"tool_names holds non-string entries", `{"agent_id":"agent://acme.example/finance/bot1","run_id":"r1","tool_names":[1,2,3]}`},
		{"tool_names mixes strings and numbers", `{"agent_id":"agent://acme.example/finance/bot1","run_id":"r1","tool_names":["shell",42,null]}`},
		{"10,000 names within the cap", `{"agent_id":"agent://acme.example/finance/bot1","run_id":"r1","tool_names":` + string(manyNamesJSON) + `}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %q: %v", c.name, r)
				}
			}()
			rec := doRaw(t, srv.Handler(), http.MethodPost, "/v1/filter-tools", adminKey, c.body)
			if rec.Code >= 500 {
				t.Fatalf("%q returned %d, want never 500", c.name, rec.Code)
			}
		})
	}
}
