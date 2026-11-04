//go:build integration

// These tests start the built binary on a real Postgres. Run with:
//
//	DATABASE_URL=postgres://user:pass@localhost:5432/wardryx_test?sslmode=disable \
//	    go test -tags integration ./internal/manifest/
package manifest

import (
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// liveDSN is the database a run stands on. A run that asked for the integration
// tests and has no database measured nothing, so it fails rather than skips.
func liveDSN(t testing.TB) string {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Fatal("DATABASE_URL is not set, so this measured nothing")
	}
	return dsn
}

// G3.10, end to end: the same proof, shown to a second process and then to a
// process started after the first was killed. Red on the record that lived in
// the process, where every one of these presentations was an allow.
func TestTheBuiltBinaryRefusesAProofAcrossTwoInstancesAndARestart(t *testing.T) {
	dsn := liveDSN(t)
	bin := buildServe(t)
	k := newLiveKeys(t)
	first, second := startServe(t, bin, k, dsn), startServe(t, bin, k, dsn)
	tok := k.token(t)
	proof := k.proof(t, tok)

	code, body := first.decide(t, tok, proof)
	wantAllow(t, "the first presentation", code, body)
	code, body = second.decide(t, tok, proof)
	wantRefused(t, "the same proof at the second instance", http.StatusForbidden, "agent_token_proof_invalid", code, body)
	code, body = first.decide(t, tok, proof)
	wantRefused(t, "the same proof at the first instance", http.StatusForbidden, "agent_token_proof_invalid", code, body)

	first.stop()
	restarted := startServe(t, bin, k, dsn)
	code, body = restarted.decide(t, tok, proof)
	wantRefused(t, "the same proof after a restart", http.StatusForbidden, "agent_token_proof_invalid", code, body)

	code, body = restarted.decide(t, tok, k.proof(t, tok))
	wantAllow(t, "a fresh proof after the restart", code, body)
}

// forwarder stands between wardryx and Postgres, so a test can take the database
// away from a running process and give it back, with the real driver seeing a
// real connection die, or a real connection stop answering.
type forwarder struct {
	mu     sync.Mutex
	l      net.Listener
	conns  []net.Conn
	target string
	addr   string
	frozen atomic.Bool
}

// copy moves bytes until a side closes, and holds them while the forwarder is
// frozen, which is what a paused database looks like from a connection pool.
func (f *forwarder) copy(dst, src net.Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		for f.frozen.Load() {
			time.Sleep(10 * time.Millisecond)
		}
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				err = werr
			}
		}
		if err != nil {
			_ = dst.Close()
			return
		}
	}
}

func newForwarder(t testing.TB, target string) *forwarder {
	t.Helper()
	f := &forwarder{target: target}
	f.up(t, "127.0.0.1:0")
	t.Cleanup(f.down)
	return f
}

func (f *forwarder) up(t testing.TB, addr string) {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen on %s: %v", addr, err)
	}
	f.mu.Lock()
	f.l, f.addr = l, l.Addr().String()
	f.mu.Unlock()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", f.target)
			if err != nil {
				_ = c.Close()
				continue
			}
			f.mu.Lock()
			f.conns = append(f.conns, c, up)
			f.mu.Unlock()
			go f.copy(up, c)
			go f.copy(c, up)
		}
	}()
}

func (f *forwarder) down() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.l != nil {
		_ = f.l.Close()
		f.l = nil
	}
	for _, c := range f.conns {
		_ = c.Close()
	}
	f.conns = nil
}

func throughForwarder(t testing.TB, dsn string) (string, *forwarder) {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("DATABASE_URL does not parse as a URL: %v", err)
	}
	f := newForwarder(t, u.Host)
	u.Host = f.addr
	return u.String(), f
}

func TestTheBuiltBinaryRefusesAProofWhileItsDatabaseIsGone(t *testing.T) {
	dsn, db := throughForwarder(t, liveDSN(t))
	bin := buildServe(t)
	k := newLiveKeys(t)
	in := startServe(t, bin, k, dsn)
	tok := k.token(t)
	before := k.proof(t, tok)
	code, body := in.decide(t, tok, before)
	wantAllow(t, "a proof with the database up", code, body)

	db.down()
	during := k.proof(t, tok)
	code, body = in.decide(t, tok, during)
	wantRefused(t, "a fresh proof with the database gone", http.StatusServiceUnavailable, "agent_token_proof_unrecorded", code, body)
	code, body = in.decide(t, "", "")
	wantAllow(t, "a request with no proof, decided from memory", code, body)
	ready, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + in.addr + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	_ = ready.Body.Close()
	if ready.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/readyz with the database gone: %d, want 503", ready.StatusCode)
	}

	db.up(t, db.addr)
	code, body = in.decide(t, tok, during)
	wantAllow(t, "the proof the outage refused, which nothing recorded", code, body)
	code, body = in.decide(t, tok, during)
	wantRefused(t, "that proof a second time", http.StatusForbidden, "agent_token_proof_invalid", code, body)
	code, body = in.decide(t, tok, before)
	wantRefused(t, "the proof accepted before the outage", http.StatusForbidden, "agent_token_proof_invalid", code, body)
}

// A paused database refuses nothing: the socket stays open and no byte comes
// back. The answer still arrives, at the store deadline, on the real driver.
func TestTheBuiltBinaryRefusesAProofOnAHangingDatabaseWithinTheDeadline(t *testing.T) {
	dsn, db := throughForwarder(t, liveDSN(t))
	bin := buildServe(t)
	k := newLiveKeys(t)
	in := startServe(t, bin, k, dsn)
	tok := k.token(t)
	code, body := in.decide(t, tok, k.proof(t, tok))
	wantAllow(t, "a proof with the database up", code, body)

	db.frozen.Store(true)
	defer db.frozen.Store(false)
	start := time.Now()
	code, body = in.decide(t, tok, k.proof(t, tok))
	took := time.Since(start)
	wantRefused(t, "a fresh proof with the database paused", http.StatusServiceUnavailable, "agent_token_proof_unrecorded", code, body)
	if took > 5*time.Second {
		t.Fatalf("the refusal took %s against a three-second store deadline", took)
	}
	t.Logf("refused after %s", took.Round(time.Millisecond))
}
