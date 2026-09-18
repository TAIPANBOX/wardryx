package api

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/store"
)

// ------------------------------------------------------------------
// Issue #62, measured on the appliance proving run of 2026-09-17: with the
// policy store stopped, /healthz answered 200 (right: decisions continued from
// memory, which is the data plane doing its job), a PUT /v1/policies hung for
// eight seconds with no answer at all, and the log had no line about the
// store in that minute.
//
// Two doubles below, for the two ways a store goes away. A store that REFUSES
// fails at once with the driver's own net error, which names the address it
// could not reach. A store that HANGS accepts the call and never answers until
// the caller's context gives up, which is what a stopped container on a bridge
// network looks like from a connection pool: the SYN goes nowhere and nothing
// says no.
//
// The hanging double is the one that matters for the red run: against the
// unfixed handler its ListPolicies blocks on a request context that is never
// done, so the test has to guard its own wait, or it would hang exactly the
// way the issue did.
// ------------------------------------------------------------------

// The address a refusing store fails on. If a handler passes the driver's
// error through, this is the string that leaves the process.
var refusedAddr = &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 5432}

func errRefused(op string) error {
	return fmt.Errorf("store: %s: %w", op, &net.OpError{
		Op: "dial", Net: "tcp", Addr: refusedAddr,
		Err: &os.SyscallError{Syscall: "connect", Err: syscall.ECONNREFUSED},
	})
}

// refusingStore fails every operation the way a connection pool does when
// nothing listens at the address: at once, with a net error.
type refusingStore struct{}

func (refusingStore) Ping(context.Context) error { return errRefused("ping") }
func (refusingStore) CreateApproval(context.Context, store.Approval) error {
	return errRefused("insert approval")
}
func (refusingStore) GetApproval(context.Context, string) (store.Approval, error) {
	return store.Approval{}, errRefused("get approval")
}
func (refusingStore) ListApprovals(context.Context) ([]store.Approval, error) {
	return nil, errRefused("list approvals")
}
func (refusingStore) DecideApproval(context.Context, string, string, string, time.Time) (store.Approval, error) {
	return store.Approval{}, errRefused("decide approval")
}
func (refusingStore) TryRedeem(context.Context, string) (bool, error) {
	return false, errRefused("try redeem")
}
func (refusingStore) PutPolicy(context.Context, string, policy.Policy, time.Time) error {
	return errRefused("put policy")
}
func (refusingStore) GetPolicy(context.Context, string) (store.PolicyRecord, error) {
	return store.PolicyRecord{}, errRefused("get policy")
}
func (refusingStore) ListPolicies(context.Context) ([]store.PolicyRecord, error) {
	return nil, errRefused("list policies")
}
func (refusingStore) DeletePolicy(context.Context, string) error { return errRefused("delete policy") }
func (refusingStore) Close() error                               { return nil }

// hangingStore accepts every call and answers only when the caller's context
// is done, with that context's error wrapped the way the Postgres store wraps
// the driver's.
type hangingStore struct{}

func hang(ctx context.Context, op string) error {
	<-ctx.Done()
	return fmt.Errorf("store: %s: %w", op, ctx.Err())
}

func (hangingStore) Ping(ctx context.Context) error { return hang(ctx, "ping") }
func (hangingStore) CreateApproval(ctx context.Context, _ store.Approval) error {
	return hang(ctx, "insert approval")
}
func (hangingStore) GetApproval(ctx context.Context, _ string) (store.Approval, error) {
	return store.Approval{}, hang(ctx, "get approval")
}
func (hangingStore) ListApprovals(ctx context.Context) ([]store.Approval, error) {
	return nil, hang(ctx, "list approvals")
}
func (hangingStore) DecideApproval(ctx context.Context, _, _, _ string, _ time.Time) (store.Approval, error) {
	return store.Approval{}, hang(ctx, "decide approval")
}
func (hangingStore) TryRedeem(ctx context.Context, _ string) (bool, error) {
	return false, hang(ctx, "try redeem")
}
func (hangingStore) PutPolicy(ctx context.Context, _ string, _ policy.Policy, _ time.Time) error {
	return hang(ctx, "put policy")
}
func (hangingStore) GetPolicy(ctx context.Context, _ string) (store.PolicyRecord, error) {
	return store.PolicyRecord{}, hang(ctx, "get policy")
}
func (hangingStore) ListPolicies(ctx context.Context) ([]store.PolicyRecord, error) {
	return nil, hang(ctx, "list policies")
}
func (hangingStore) DeletePolicy(ctx context.Context, _ string) error {
	return hang(ctx, "delete policy")
}
func (hangingStore) Close() error { return nil }

// The deadline the tests run under, well under the guard below so a deadline
// that is honoured and a hang that is not are far apart.
const testStoreTimeout = 100 * time.Millisecond

// A response that has not arrived by this much after the deadline is a hang,
// not a slow deadline.
const hangGuard = 3 * time.Second

func newServerOnStore(t *testing.T, st store.Store) *Server {
	t.Helper()
	srv := newTestServer(t)
	srv.store = st
	srv.storeTimeout = testStoreTimeout
	return srv
}

// doWithin serves one request on its own goroutine and gives up waiting after
// hangGuard, so a handler that hangs fails the test instead of hanging it.
// The goroutine of a hung handler is left behind on purpose: the test is
// already failed, and there is nothing to unblock it with.
func doWithin(t *testing.T, h http.Handler, req *http.Request) (*httptest.ResponseRecorder, time.Duration) {
	t.Helper()
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	start := time.Now()
	go func() {
		h.ServeHTTP(rec, req)
		close(done)
	}()
	select {
	case <-done:
		return rec, time.Since(start)
	case <-time.After(hangGuard):
		t.Fatalf("%s %s: no answer after %s, which is the hang issue #62 reported; "+
			"the store deadline is %s", req.Method, req.URL.Path, hangGuard, testStoreTimeout)
		return nil, 0
	}
}

func rawRequest(method, path, bearer, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("Content-Type", "application/json")
	return req
}

// captureLog routes the standard logger into a buffer for the rest of the
// test and puts stderr back afterwards.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &buf
}

func countLines(s, needle string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, needle) {
			n++
		}
	}
	return n
}

// The strings a refusing store's error carries and a response must not.
var driverText = []string{"10.0.0.5", "connection refused", "dial tcp"}

func assertNoDriverText(t *testing.T, body string) {
	t.Helper()
	for _, s := range driverText {
		if strings.Contains(body, s) {
			t.Fatalf("the response carries the driver's own error text (%q): %s", s, body)
		}
	}
}

// --- readiness ---

func TestReadyzAnswers503WhenTheStoreRefuses(t *testing.T) {
	srv := newServerOnStore(t, refusingStore{})
	rec, _ := doWithin(t, srv.Handler(), rawRequest(http.MethodGet, "/readyz", "", ""))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz with the store refusing = %d, want 503: a launcher check "+
			"reads the status, and 200 here is what let \"deciding from memory\" pass as \"healthy\"",
			rec.Code)
	}
	got := decodeBody[map[string]string](t, rec)
	if len(got) != 1 || got["store"] != "unreachable" {
		t.Fatalf("body = %s, want exactly {\"store\":\"unreachable\"}", rec.Body.String())
	}
	assertNoDriverText(t, rec.Body.String())
}

func TestReadyzAnswers503WithinTheDeadlineWhenTheStoreHangs(t *testing.T) {
	srv := newServerOnStore(t, hangingStore{})
	rec, took := doWithin(t, srv.Handler(), rawRequest(http.MethodGet, "/readyz", "", ""))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /readyz with the store hanging = %d, want 503", rec.Code)
	}
	if took > hangGuard/2 {
		t.Fatalf("GET /readyz took %s against a store deadline of %s: the ping is not bounded", took, testStoreTimeout)
	}
	if got := decodeBody[map[string]string](t, rec); got["store"] != "unreachable" {
		t.Fatalf("body = %s, want the store named unreachable", rec.Body.String())
	}
}

func TestReadyzAnswers200WhenTheStoreAnswers(t *testing.T) {
	srv := newTestServer(t)
	rec, _ := doWithin(t, srv.Handler(), rawRequest(http.MethodGet, "/readyz", "", ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /readyz on a reachable store = %d, want 200", rec.Code)
	}
	if got := decodeBody[map[string]string](t, rec); got["store"] != "ok" {
		t.Fatalf("body = %s, want {\"store\":\"ok\"}", rec.Body.String())
	}
}

// The behaviour the issue names as right, held in place: liveness is about
// this process, and a decision needs nothing from the store when the answer
// is allow. A readiness check that had been folded into /healthz would fail
// this, and so would a decide route that consulted the store on the way.
func TestHealthzAndDecisionsStayUpWhileTheStoreIsDown(t *testing.T) {
	for name, st := range map[string]store.Store{"refusing": refusingStore{}, "hanging": hangingStore{}} {
		t.Run(name, func(t *testing.T) {
			srv := newServerOnStore(t, st)
			h := srv.Handler()

			health, took := doWithin(t, h, rawRequest(http.MethodGet, "/healthz", "", ""))
			if health.Code != http.StatusOK {
				t.Fatalf("GET /healthz with the store %s = %d, want 200: liveness must not read the store", name, health.Code)
			}
			if took > testStoreTimeout {
				t.Fatalf("GET /healthz took %s with the store %s: liveness waited on the store", took, name)
			}

			decide, took := doWithin(t, h, rawRequest(http.MethodPost, "/v1/decide", adminKey,
				`{"agent_id":"agent://acme.example/finance/bot1","run_id":"r1","tool_names":["generate_report"]}`))
			if decide.Code != http.StatusOK {
				t.Fatalf("POST /v1/decide with the store %s = %d, want 200: decisions continue from memory", name, decide.Code)
			}
			if got := decodeBody[decideResponseDTO](t, decide); got.Decision != pdp.Allow {
				t.Fatalf("decision = %q, want allow from the policy set already in memory", got.Decision)
			}
			if took > testStoreTimeout {
				t.Fatalf("POST /v1/decide took %s with the store %s: the decide route waited on the store", took, name)
			}
		})
	}
}

// T2: the route is unauthenticated and reachable by anything on the network.
// It reads nothing from the request and says nothing but the store's state.
func TestReadyzIgnoresHostileInput(t *testing.T) {
	srv := newServerOnStore(t, refusingStore{})
	h := srv.Handler()
	junk := strings.Repeat("Z", 64<<10)

	t.Run("a method other than GET is refused", func(t *testing.T) {
		for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
			rec, _ := doWithin(t, h, rawRequest(m, "/readyz", "", `{"store":"ok"}`))
			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("%s /readyz = %d, want 405", m, rec.Code)
			}
			if strings.Contains(rec.Body.String(), `"ok"`) {
				t.Fatalf("%s /readyz echoed the request body: %s", m, rec.Body.String())
			}
		}
	})

	t.Run("a body, a query string and a garbage bearer change nothing", func(t *testing.T) {
		cases := []struct {
			name string
			req  *http.Request
		}{
			{"a 64 KiB body on a GET", rawRequest(http.MethodGet, "/readyz", "", junk)},
			{"a query string claiming the store is ok", rawRequest(http.MethodGet, "/readyz?store=ok&"+junk[:512], "", "")},
			{"a garbage bearer of 8 KiB", rawRequest(http.MethodGet, "/readyz", junk[:8<<10], "")},
			{"a valid admin bearer", rawRequest(http.MethodGet, "/readyz", adminKey, "")},
		}
		for _, c := range cases {
			rec, _ := doWithin(t, h, c.req)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("%s: GET /readyz = %d, want 503 from the store's state alone", c.name, rec.Code)
			}
			got := decodeBody[map[string]string](t, rec)
			if len(got) != 1 || got["store"] != "unreachable" {
				t.Fatalf("%s: body = %s, want exactly {\"store\":\"unreachable\"}", c.name, rec.Body.String())
			}
			if strings.Contains(rec.Body.String(), "ZZZZ") || strings.Contains(rec.Body.String(), adminKey) {
				t.Fatalf("%s: the body echoed the request: %s", c.name, rec.Body.String())
			}
			assertNoDriverText(t, rec.Body.String())
		}
	})

	t.Run("a path that is not the route is not answered as ready", func(t *testing.T) {
		for _, p := range []string{"/readyz/", "/readyz/x", "/readyz/../v1/policies"} {
			rec, _ := doWithin(t, h, rawRequest(http.MethodGet, p, "", ""))
			if rec.Code == http.StatusOK {
				t.Fatalf("GET %s = 200, want not-a-ready-answer", p)
			}
			if strings.Contains(rec.Body.String(), `"store"`) || strings.Contains(rec.Body.String(), `"target"`) {
				t.Fatalf("GET %s answered with something it should not have: %s", p, rec.Body.String())
			}
		}
	})
}

// --- policy writes ---

func TestAPolicyWriteOnAHangingStoreAnswers503InsteadOfHanging(t *testing.T) {
	cases := []struct {
		name, method, path, body string
	}{
		{"put", http.MethodPut, "/v1/policies/probe-f4", `{"name":"probe-f4","target":"agent://acme.example/*"}`},
		{"delete", http.MethodDelete, "/v1/policies/probe-f4", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := newServerOnStore(t, hangingStore{})
			before := srv.engine.PolicyVersion()

			rec, took := doWithin(t, srv.Handler(), rawRequest(c.method, c.path, adminKey, c.body))
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("%s %s with the store hanging = %d, want 503", c.method, c.path, rec.Code)
			}
			if took > hangGuard/2 {
				t.Fatalf("%s %s took %s against a store deadline of %s: the write is not bounded", c.method, c.path, took, testStoreTimeout)
			}
			got := decodeBody[errorDTO](t, rec)
			if !strings.Contains(got.Error, "policy store") || !strings.Contains(got.Error, testStoreTimeout.String()) {
				t.Fatalf("reason = %q, want it to name the policy store and the %s deadline", got.Error, testStoreTimeout)
			}
			if after := srv.engine.PolicyVersion(); after != before {
				t.Fatalf("the policy set in force changed from %s to %s on a write the store never confirmed", before, after)
			}
		})
	}
}

func TestAPolicyWriteOnARefusingStoreAnswers503WithAReason(t *testing.T) {
	srv := newServerOnStore(t, refusingStore{})
	rec, took := doWithin(t, srv.Handler(), rawRequest(http.MethodPut, "/v1/policies/probe-f4", adminKey,
		`{"name":"probe-f4","target":"agent://acme.example/*"}`))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("PUT /v1/policies with the store refusing = %d, want 503: the store being gone is a "+
			"temporary condition the caller can retry, not an internal error", rec.Code)
	}
	if took > testStoreTimeout {
		t.Fatalf("a refused connection took %s to answer; it should not wait for the deadline", took)
	}
	got := decodeBody[errorDTO](t, rec)
	if !strings.Contains(got.Error, "policy store") || !strings.Contains(got.Error, "unreachable") {
		t.Fatalf("reason = %q, want it to say the policy store is unreachable", got.Error)
	}
	assertNoDriverText(t, rec.Body.String())
}

// writeRefusingStore lists and reads like the in-memory store and loses the
// connection on the write itself: the store went away between the list and
// the put, after the archive already kept the candidate set.
type writeRefusingStore struct{ *store.Memory }

func (writeRefusingStore) PutPolicy(context.Context, string, policy.Policy, time.Time) error {
	return errRefused("put policy")
}
func (writeRefusingStore) DeletePolicy(context.Context, string) error {
	return errRefused("delete policy")
}

// The issue's own observation, held: after the store came back the write had
// not been applied, and nothing was half-written. Here the list succeeds, the
// candidate compiles, the archive keeps it, and then the write fails: the
// answer is 503 and the live set is exactly what it was.
func TestAWriteThatFailsAfterTheListAnswers503AndLeavesTheLiveSetAlone(t *testing.T) {
	mem := store.NewMemory()
	if err := mem.PutPolicy(context.Background(), "existing", policy.Policy{Name: "existing", Target: "agent://acme.example/ops/*"}, time.Now()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	srv := newServerOnStore(t, writeRefusingStore{mem})
	before := srv.engine.PolicyVersion()

	cases := []struct {
		name, method, path, body string
	}{
		{"put", http.MethodPut, "/v1/policies/probe-f4", `{"name":"probe-f4","target":"agent://acme.example/*"}`},
		{"delete", http.MethodDelete, "/v1/policies/existing", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec, _ := doWithin(t, srv.Handler(), rawRequest(c.method, c.path, adminKey, c.body))
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("%s %s = %d, want 503", c.method, c.path, rec.Code)
			}
			got := decodeBody[errorDTO](t, rec)
			if !strings.Contains(got.Error, "policy store is unreachable") || !strings.Contains(got.Error, "not in force") {
				t.Fatalf("reason = %q", got.Error)
			}
			assertNoDriverText(t, rec.Body.String())
			if after := srv.engine.PolicyVersion(); after != before {
				t.Fatalf("the live set moved from %s to %s on a write the store refused", before, after)
			}
		})
	}
	// And the store itself is as it was: one policy, the seeded one.
	stored, err := mem.ListPolicies(context.Background())
	if err != nil || len(stored) != 1 || stored[0].ID != "existing" {
		t.Fatalf("stored = %v, %v; want only the seeded policy", stored, err)
	}
}

func TestAStoreOutageIsLoggedOncePerOutageNotPerRequest(t *testing.T) {
	logged := captureLog(t)
	srv := newServerOnStore(t, refusingStore{})
	h := srv.Handler()

	for i := 0; i < 5; i++ {
		doWithin(t, h, rawRequest(http.MethodPut, "/v1/policies/p1", adminKey, `{"name":"p1","target":"agent://acme.example/*"}`))
	}
	for i := 0; i < 3; i++ {
		doWithin(t, h, rawRequest(http.MethodGet, "/readyz", "", ""))
	}
	if n := countLines(logged.String(), "policy store unreachable"); n != 1 {
		t.Fatalf("eight requests during one outage produced %d 'policy store unreachable' line(s), want exactly 1.\nlog:\n%s", n, logged.String())
	}
	if n := countLines(logged.String(), "reachable again"); n != 0 {
		t.Fatalf("the store never came back and the log says it did %d time(s):\n%s", n, logged.String())
	}
	if !strings.Contains(logged.String(), "10.0.0.5") {
		t.Fatalf("the one outage line does not carry the driver's detail for the operator:\n%s", logged.String())
	}

	// The store comes back.
	srv.store = store.NewMemory()
	for i := 0; i < 3; i++ {
		doWithin(t, h, rawRequest(http.MethodGet, "/readyz", "", ""))
	}
	doWithin(t, h, rawRequest(http.MethodPut, "/v1/policies/p1", adminKey, `{"name":"p1","target":"agent://acme.example/*"}`))
	if n := countLines(logged.String(), "reachable again"); n != 1 {
		t.Fatalf("the store came back and the log says so %d time(s), want exactly 1:\n%s", n, logged.String())
	}
	if n := countLines(logged.String(), "policy store unreachable"); n != 1 {
		t.Fatalf("the outage was logged %d time(s) in total, want 1:\n%s", n, logged.String())
	}
}

// A store that answers with a failure of its own is not an outage: the row is
// not there, the document does not marshal, the driver said something that is
// not about the network. That stays a 500 naming the operation, logged per
// request as before, and the outage tracker stays quiet.
func TestAStoreFailureThatIsNotAnOutageIsStillA500(t *testing.T) {
	logged := captureLog(t)
	srv := newServerOnStore(t, brokenStore{})
	rec, _ := doWithin(t, srv.Handler(), rawRequest(http.MethodPut, "/v1/policies/p1", adminKey,
		`{"name":"p1","target":"agent://acme.example/*"}`))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("a store failure that is not about reachability = %d, want 500", rec.Code)
	}
	if got := decodeBody[errorDTO](t, rec); !strings.Contains(got.Error, "writing the policy") {
		t.Fatalf("body = %q, want the operation named as before", got.Error)
	}
	if n := countLines(logged.String(), "policy store unreachable"); n != 0 {
		t.Fatalf("an ordinary store failure was logged as an outage:\n%s", logged.String())
	}
}

// A guard for the doubles themselves: the interface must be the one the
// handlers use, so a double that drifted would fail here rather than compile
// into a test that measures nothing.
var (
	_ store.Store = refusingStore{}
	_ store.Store = hangingStore{}
	_ store.Store = brokenStore{}
)
