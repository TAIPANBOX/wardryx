package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// ------------------------------------------------------------------
// Issue #62: a policy write hung for eight seconds against a stopped store.
// The fix in internal/api is a deadline on the context it hands this package,
// and a deadline is only worth something if the driver underneath honours it.
// A double that returns when its context is done proves the handler; it
// proves nothing about pgx. So the tests here run the real driver against two
// things that need no Postgres: a port nothing listens on, and a listener
// that accepts a connection and never says a word, which is what a stopped
// container looks like from a pool that still has its address.
// ------------------------------------------------------------------

// A deadline short enough to keep the suite quick and long enough that a
// call which returned early for some other reason would be told apart from
// one the deadline ended: the assertions check both sides.
const shortDeadline = 300 * time.Millisecond

// Anything past this is a hang the deadline did not end.
const farPast = 3 * time.Second

// silentListener accepts every connection and never writes to it. Connections
// are closed when the test ends so nothing lingers into the next one.
func silentListener(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	return l.Addr().String()
}

// closedPort reserves a port and releases it, so nothing listens there.
func closedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return addr
}

// openWithoutPinging builds a Postgres store over a pool that has not
// connected yet, the state a live store is in once its database has gone
// away and the pool has dropped its dead connections. OpenPostgres pings and
// migrates first and would refuse here, which is the right thing for a
// startup and the wrong thing for this test.
func openWithoutPinging(t *testing.T, addr string) *Postgres {
	t.Helper()
	db, err := sql.Open("pgx", "postgres://wardryx:secret@"+addr+"/wardryx?sslmode=disable")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &Postgres{db: db}
}

func TestPostgresCallsReturnWithinTheDeadlineAgainstAListenerThatNeverAnswers(t *testing.T) {
	p := openWithoutPinging(t, silentListener(t))

	calls := []struct {
		name string
		call func(ctx context.Context) error
	}{
		{"Ping", p.Ping},
		{"ListPolicies", func(ctx context.Context) error { _, err := p.ListPolicies(ctx); return err }},
		{"PutPolicy", func(ctx context.Context) error {
			return p.PutPolicy(ctx, "probe-f4", policy.Policy{Name: "probe-f4", Target: "agent://acme.example/*"}, time.Now())
		}},
		{"DeletePolicy", func(ctx context.Context) error { return p.DeletePolicy(ctx, "probe-f4") }},
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), shortDeadline)
			defer cancel()

			done := make(chan error, 1)
			start := time.Now()
			go func() { done <- c.call(ctx) }()

			var err error
			select {
			case err = <-done:
			case <-time.After(farPast):
				t.Fatalf("%s did not return %s after a %s deadline: the driver does not honour the context, "+
					"and every deadline the API sets on top of it is decoration", c.name, farPast, shortDeadline)
			}
			took := time.Since(start)
			if err == nil {
				t.Fatalf("%s succeeded against a listener that never answered", c.name)
			}
			if took < shortDeadline/2 {
				t.Fatalf("%s returned after %s, before the %s deadline could have ended it; the failure is not the one under test: %v",
					c.name, took, shortDeadline, err)
			}
			if !IsUnavailable(err) {
				t.Fatalf("%s failed with an error IsUnavailable does not recognise, so the API would answer 500 for a store that is merely gone: %v",
					c.name, err)
			}
		})
	}
}

func TestARefusedConnectionIsUnavailable(t *testing.T) {
	p := openWithoutPinging(t, closedPort(t))
	ctx, cancel := context.WithTimeout(context.Background(), farPast)
	defer cancel()

	start := time.Now()
	err := p.Ping(ctx)
	took := time.Since(start)
	if err == nil {
		t.Fatal("Ping succeeded against a port nothing listens on")
	}
	if took > shortDeadline {
		t.Fatalf("a refused connection took %s to report; it should fail at once, not wait", took)
	}
	if !IsUnavailable(err) {
		t.Fatalf("a refused connection is not classified as unavailable: %v", err)
	}
}

func TestMemoryPingAlwaysAnswers(t *testing.T) {
	if err := NewMemory().Ping(context.Background()); err != nil {
		t.Fatalf("Memory.Ping = %v, want nil: the in-memory store is this process, and it is running", err)
	}
}

func TestAnOrdinaryStoreErrorIsNotUnavailable(t *testing.T) {
	notOutages := []struct {
		name string
		err  error
	}{
		{"nil", nil},
		{"a plain error", errors.New("boom")},
		{"not found, wrapped", fmt.Errorf("%w: p1", ErrNotFound)},
		{"already decided", ErrAlreadyDecided},
		{"a cancel, which comes from the client's side and not from the store", context.Canceled},
		{"a marshal failure the store composed", fmt.Errorf("store: marshal policy %q: %w", "p1", errors.New("json: unsupported value"))},
	}
	for _, c := range notOutages {
		if IsUnavailable(c.err) {
			t.Errorf("IsUnavailable(%s) = true, want false: a 503 here would tell a launcher the store is down when it answered", c.name)
		}
	}
	outages := []struct {
		name string
		err  error
	}{
		{"the deadline, bare", context.DeadlineExceeded},
		{"the deadline, wrapped the way this package wraps", fmt.Errorf("store: list policies: %w", context.DeadlineExceeded)},
		{"a net error, wrapped", fmt.Errorf("store: ping: %w", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")})},
		// What database/sql reports when the pool's own connection turned out
		// to be dead and the deadline ended the retry: measured 2026-09-18 on a
		// paused postgres:16 container, "store: ping postgres: driver: bad
		// connection".
		{"a bad connection from the pool, wrapped", fmt.Errorf("store: ping postgres: %w", driver.ErrBadConn)},
	}
	for _, c := range outages {
		if !IsUnavailable(c.err) {
			t.Errorf("IsUnavailable(%s) = false, want true", c.name)
		}
	}
}
