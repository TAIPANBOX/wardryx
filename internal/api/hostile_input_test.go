package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ------------------------------------------------------------------
// What the handlers do with input that is not what they asked for.
//
// Every case here crosses the process boundary, which is the tier that
// requires hostile input rather than a happy path. The existing tests drive
// these routes with well-formed bodies, so the branches below had never run:
// half of them decide a STATUS CODE, and a wrong one is not a cosmetic
// failure. A 500 where 400 belongs turns a client's own mistake into an
// incident against wardryx, and a 200 where 400 belongs is worse.
//
// Two things are asserted every time, and the second is the one that needs
// saying: the code, and that the body does not echo what it failed on. An
// error message is the easiest place for a secret to leave a process, and
// invariant 4's error-text half has no gate.
// ------------------------------------------------------------------

// doRaw sends a body verbatim. The shared doRequest helper JSON-encodes what
// it is given, so it cannot express "this is not JSON", which is the whole
// subject here.
func doRaw(t *testing.T, h http.Handler, method, path, bearer, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAMalformedBodyIsTheClientsFaultAndSaysSo(t *testing.T) {
	srv := newTestServer(t)

	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"decide, truncated JSON", http.MethodPost, "/v1/decide", `{"agent_id":`},
		{"decide, not JSON at all", http.MethodPost, "/v1/decide", `<?xml version="1.0"?><decide/>`},
		{"decide, a JSON array where an object belongs", http.MethodPost, "/v1/decide", `[]`},
		{"decide, empty body", http.MethodPost, "/v1/decide", ``},
		{"approval decide, truncated JSON", http.MethodPost, "/v1/approvals/a1/decide", `{"decided_by":`},
		{"approval decide, empty body", http.MethodPost, "/v1/approvals/a1/decide", ``},
		{"put policy, truncated JSON", http.MethodPut, "/v1/policies/p1", `{"name":`},
		{"put policy, a bare string", http.MethodPut, "/v1/policies/p1", `"just a string"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := doRaw(t, srv.Handler(), c.method, c.path, adminKey, c.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s %s with %q returned %d, want 400: a body the client "+
					"got wrong is not an error on wardryx's side",
					c.method, c.path, c.body, rec.Code)
			}
			if strings.Contains(rec.Body.String(), adminKey) {
				t.Fatalf("the error body echoed the bearer token: %q", rec.Body.String())
			}
		})
	}
}

// A field that is required and absent is a different failure from a body that
// will not parse, and both are the client's. The distinction matters to
// whoever is reading the response: one is "fix your JSON", the other is "you
// left something out".
func TestARequiredFieldLeftOutIsRefusedRatherThanDefaulted(t *testing.T) {
	srv := newTestServer(t)

	cases := []struct {
		name string
		path string
		body string
	}{
		{"a decision with nobody attached", "/v1/approvals/a1/decide", `{"decision":"grant"}`},
		{"a decision that is neither grant nor deny", "/v1/approvals/a1/decide", `{"decision":"maybe","decided_by":"alice"}`},
		{"an empty decision", "/v1/approvals/a1/decide", `{"decision":"","decided_by":"alice"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := doRaw(t, srv.Handler(), http.MethodPost, c.path, adminKey, c.body)
			if rec.Code == http.StatusOK {
				t.Fatalf("%q was accepted. A hold decided by nobody, or decided "+
					"with a word the store does not understand, is a governance "+
					"record that cannot be audited", c.body)
			}
			if rec.Code >= 500 {
				t.Fatalf("%q returned %d. The client's omission became an "+
					"incident against wardryx", c.body, rec.Code)
			}
		})
	}
}

// Deciding a hold that is not there. The store answers ErrNotFound and the
// handler has to turn that into 404 rather than 500: the difference decides
// whether an operator retries or goes looking for an outage.
func TestDecidingAHoldThatDoesNotExistIs404(t *testing.T) {
	srv := newTestServer(t)
	rec := doRaw(t, srv.Handler(), http.MethodPost,
		"/v1/approvals/no-such-hold/decide", adminKey,
		`{"decision":"grant","decided_by":"alice"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("deciding an absent hold returned %d, want 404", rec.Code)
	}
}

// The policy routes, same shape. A GET or DELETE of something absent is a 404
// and not a 500, and a DELETE of something absent must not report success:
// "deleted" about a policy that was never there tells an operator the
// guardrail is gone when it may never have been applied.
func TestPolicyRoutesOnSomethingThatIsNotThere(t *testing.T) {
	srv := newTestServer(t)

	get := doRaw(t, srv.Handler(), http.MethodGet, "/v1/policies/absent", adminKey, "")
	if get.Code != http.StatusNotFound {
		t.Fatalf("GET of an absent policy returned %d, want 404", get.Code)
	}
	del := doRaw(t, srv.Handler(), http.MethodDelete, "/v1/policies/absent", adminKey, "")
	if del.Code != http.StatusNotFound {
		t.Fatalf("DELETE of an absent policy returned %d, want 404: reporting "+
			"success would tell an operator a guardrail was removed when it was "+
			"never there", del.Code)
	}
}
