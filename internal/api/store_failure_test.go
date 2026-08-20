package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/store"
)

// ------------------------------------------------------------------
// What every handler does when the store is broken.
//
// These branches had never run. They matter for two reasons and the second is
// the one that is easy to miss.
//
// The status code: a store that is down is wardryx's problem, so it is a 500
// and not a 400. Getting that backwards tells an operator their request was
// malformed and sends them to fix a client that was never wrong.
//
// The BODY: each of these paths writes err.Error() straight into the response.
// A store error is not a string wardryx composed. It comes from a driver, and
// driver errors are known to carry the connection they failed on, which is
// where the password lives. Invariant 4 says no credential reaches an error
// message, and its error-text half has no gate, so this is the closest thing
// to one that exists.
// ------------------------------------------------------------------

// A DSN shaped exactly like the one wardryx is configured with in production.
// If a handler passes a store error through untouched, this is what comes out.
const leakyDSN = "postgres://wardryx:hunter2@db.internal:5432/wardryx?sslmode=disable"

var errStoreIsDown = errors.New("dial tcp: connect: connection refused (" + leakyDSN + ")")

// brokenStore fails every operation with an error carrying a credential.
type brokenStore struct{}

func (brokenStore) CreateApproval(context.Context, store.Approval) error { return errStoreIsDown }
func (brokenStore) GetApproval(context.Context, string) (store.Approval, error) {
	return store.Approval{}, errStoreIsDown
}
func (brokenStore) ListApprovals(context.Context) ([]store.Approval, error) {
	return nil, errStoreIsDown
}
func (brokenStore) DecideApproval(context.Context, string, string, string, time.Time) (store.Approval, error) {
	return store.Approval{}, errStoreIsDown
}
func (brokenStore) TryRedeem(context.Context, string) (bool, error) { return false, errStoreIsDown }
func (brokenStore) PutPolicy(context.Context, string, policy.Policy, time.Time) error {
	return errStoreIsDown
}
func (brokenStore) GetPolicy(context.Context, string) (store.PolicyRecord, error) {
	return store.PolicyRecord{}, errStoreIsDown
}
func (brokenStore) ListPolicies(context.Context) ([]store.PolicyRecord, error) {
	return nil, errStoreIsDown
}
func (brokenStore) DeletePolicy(context.Context, string) error { return errStoreIsDown }
func (brokenStore) Close() error                               { return nil }

func newServerOnABrokenStore(t *testing.T) *Server {
	t.Helper()
	srv := newTestServer(t)
	srv.store = brokenStore{}
	return srv
}

func TestAStoreThatIsDownIsWardryxsProblemAndNotTheClients(t *testing.T) {
	srv := newServerOnABrokenStore(t)

	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{"list approvals", http.MethodGet, "/v1/approvals", ""},
		{"decide a hold", http.MethodPost, "/v1/approvals/a1/decide", `{"decision":"grant","decided_by":"alice"}`},
		{"list policies", http.MethodGet, "/v1/policies", ""},
		{"get a policy", http.MethodGet, "/v1/policies/p1", ""},
		{"put a policy", http.MethodPut, "/v1/policies/p1", `{"name":"p1","target":"agent://acme.example/*"}`},
		{"delete a policy", http.MethodDelete, "/v1/policies/p1", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := doRaw(t, srv.Handler(), c.method, c.path, adminKey, c.body)
			if rec.Code < 500 {
				t.Fatalf("%s %s returned %d with the store down. Under 500 tells "+
					"the operator their request was wrong and sends them to fix a "+
					"client that was never at fault", c.method, c.path, rec.Code)
			}
		})
	}
}

// The half that is about a secret leaving the process rather than about a
// status code. Asserted on the same six routes, separately, because the two
// failures are unrelated: a handler can get the code right and still hand the
// database password to whoever made the request.
func TestAStoreErrorDoesNotCarryTheDatabasePasswordIntoTheResponse(t *testing.T) {
	srv := newServerOnABrokenStore(t)

	routes := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodGet, "/v1/approvals", ""},
		{http.MethodPost, "/v1/approvals/a1/decide", `{"decision":"grant","decided_by":"alice"}`},
		{http.MethodGet, "/v1/policies", ""},
		{http.MethodGet, "/v1/policies/p1", ""},
		{http.MethodPut, "/v1/policies/p1", `{"name":"p1","target":"agent://acme.example/*"}`},
		{http.MethodDelete, "/v1/policies/p1", ""},
	}
	for _, r := range routes {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			rec := doRaw(t, srv.Handler(), r.method, r.path, adminKey, r.body)
			body := rec.Body.String()
			for _, secret := range []string{"hunter2", leakyDSN} {
				if strings.Contains(body, secret) {
					t.Fatalf("the response carries the database credential.\n"+
						"got: %s\nA driver error is not a string wardryx wrote, and "+
						"this one names the connection it failed on. Invariant 3 "+
						"says no credential reaches an error message.", body)
				}
			}
		})
	}
}
