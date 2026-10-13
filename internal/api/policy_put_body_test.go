package api

import (
	"net/http"
	"strings"
	"testing"
)

// These tests hold features/policy-put-body.feature: a PUT /v1/policies/{id}
// body is one policy. json.Decoder stops at the first JSON value, so before this
// change a body with data after the policy read the policy and dropped the rest
// with a 200, and the dropped part was never in force.

// The scenario "Data after the policy in a PUT body is refused, and nothing is
// stored". The second object is refused with a 400 that does not echo it, and
// the policy named by the URL is not stored, so the store and the live rules
// both stay as they were.
func TestAPutBodyWithDataAfterThePolicyIsRefused(t *testing.T) {
	const policy1 = `{"name":"p1","target":"agent://acme.example/finance/*","deny_tool":["send_wire_transfer"]}`
	cases := []struct {
		name, tail string
	}{
		{"a second policy", `{"name":"second-policy","target":"agent://acme.example/finance/*"}`},
		{"bytes that are not JSON", `second-policy`},
		{"a truncated second policy", `{"name":"second-policy","target":"agent://acme.example/finance/*"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := newTestServer(t)
			rec := doRaw(t, srv.Handler(), http.MethodPut, "/v1/policies/p1", adminKey, policy1+c.tail)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("PUT status = %d, body = %s; want 400: data after the policy is not a second policy, and must not be dropped with a 200", rec.Code, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "second-policy") {
				t.Errorf("the 400 echoes the refused data: %s", rec.Body.String())
			}
			if got := doRequest(t, srv.Handler(), http.MethodGet, "/v1/policies/p1", adminKey, nil).Code; got != http.StatusNotFound {
				t.Fatalf("GET /v1/policies/p1 after the refused PUT = %d, want 404: a refused body must store nothing", got)
			}
		})
	}
}

// The scenario "Whitespace after the policy in a PUT body is not data". The
// refusal above must not refuse a body that is one policy followed by
// whitespace, which is what every ordinary client sends.
func TestAPutBodyWithTrailingWhitespaceIsStillAccepted(t *testing.T) {
	srv := newTestServer(t)
	body := `{"name":"p4","target":"agent://acme.example/finance/*","deny_tool":["send_wire_transfer"]}` + "\n\n  \t"
	rec := doRaw(t, srv.Handler(), http.MethodPut, "/v1/policies/p4", adminKey, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body = %s; want 200: whitespace after one policy is not data", rec.Code, rec.Body.String())
	}
}
