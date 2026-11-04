package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/agenttoken"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// Invariant 44, at the HTTP boundary: an accepted proof is one row on a shared
// record, so a second instance and a restarted one refuse it, and a record that
// cannot be asked refuses the proof. These tests read what a caller reads.

// sharedRecord is the database two instances stand on. fail, while set, is what
// every write answers.
type sharedRecord struct {
	mu   sync.Mutex
	rows map[string]bool
	fail func(ctx context.Context) error
}

func newSharedRecord() *sharedRecord { return &sharedRecord{rows: map[string]bool{}} }

func (r *sharedRecord) TryRecordProof(ctx context.Context, key string, _ time.Time) (bool, error) {
	r.mu.Lock()
	fail := r.fail
	r.mu.Unlock()
	if fail != nil {
		if err := fail(ctx); err != nil {
			return false, err
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rows[key] {
		return false, nil
	}
	r.rows[key] = true
	return true, nil
}

func (r *sharedRecord) PurgeProofs(context.Context, time.Duration) (int64, error) { return 0, nil }

func (r *sharedRecord) failWith(fail func(ctx context.Context) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fail = fail
}

// instanceOn builds a server the way serve does with a database: the verifier
// asks record, and the rest is what agentTokenServer builds.
func instanceOn(t *testing.T, k tokenKeySet, pols []policy.Policy, record agenttoken.ProofRecord, eventsPath string, change func(*agenttoken.Config)) *Server {
	t.Helper()
	srv := agentTokenServer(t, pols, k, false, eventsPath)
	cfg := agenttoken.Config{
		Issuer:      tokIssuer,
		Audiences:   []string{tokAudience},
		JWKSFile:    k.file,
		DoorOrigins: []string{tokDoor},
		ProofRecord: record,
	}
	if change != nil {
		change(&cfg)
	}
	v, err := agenttoken.New(cfg, nil)
	if err != nil {
		t.Fatalf("agenttoken.New: %v", err)
	}
	if err := v.Load(t.Context()); err != nil {
		t.Fatalf("agenttoken Load: %v", err)
	}
	return srv.WithAgentTokens(v)
}

func proofRequest(t *testing.T, k tokenKeySet, tok, jti string) decideRequestDTO {
	t.Helper()
	return decideRequestDTO{AgentID: tokSubject, RunID: "r1", AgentToken: tok,
		AgentDPoPProof: mintDPoPProof(t, k, tok, tokHTU, time.Now().Unix(), jti)}
}

func TestAProofAcceptedByOneInstanceIsRefusedByAnother(t *testing.T) {
	k := newTokenKeySet(t)
	record := newSharedRecord()
	first, second := instanceOn(t, k, requireAgentToken(), record, "", nil), instanceOn(t, k, requireAgentToken(), record, "", nil)
	dto := proofRequest(t, k, mintAgentToken(t, k, tokSubject, nil), "p-two-instances")
	if got := decisionFor(t, first, dto); got.Decision != "allow" {
		t.Fatalf("the first instance: decision %q, reason %q", got.Decision, got.Reason)
	}
	rec := doRequest(t, second.Handler(), http.MethodPost, "/v1/decide", adminKey, dto)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "agent_token_proof_invalid") {
		t.Fatalf("the second instance: status %d, body %s, want 403 agent_token_proof_invalid", rec.Code, rec.Body)
	}
}

func TestAProofIsRefusedWith503WhenTheRecordIsUnreachable(t *testing.T) {
	k := newTokenKeySet(t)
	record := newSharedRecord()
	events := filepath.Join(t.TempDir(), "events.ndjson")
	srv := instanceOn(t, k, requireAgentToken(), record, events, nil)
	record.failWith(func(context.Context) error { return errRefused("record proof") })
	dto := proofRequest(t, k, mintAgentToken(t, k, tokSubject, nil), "p-store-gone")
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, dto)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "agent_token_proof_unrecorded") {
		t.Fatalf("a good proof with the record gone: status %d, body %s, want 503 agent_token_proof_unrecorded", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), refusedAddr.IP.String()) {
		t.Fatalf("the driver's address left the process: %s", rec.Body)
	}
	if strings.Contains(rec.Body.String(), `"decision"`) {
		t.Fatalf("a refusal carried a decision: %s", rec.Body)
	}
	if raw, err := os.ReadFile(events); err == nil && len(raw) > 0 {
		t.Fatalf("a refused proof reached a decision and wrote %q", raw)
	}
}

func TestAProofOnAHangingRecordIsRefusedWithinTheDeadline(t *testing.T) {
	k := newTokenKeySet(t)
	record := newSharedRecord()
	srv := instanceOn(t, k, requireAgentToken(), record, "", nil)
	srv.storeTimeout = testStoreTimeout
	record.failWith(func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })
	dto := proofRequest(t, k, mintAgentToken(t, k, tokSubject, nil), "p-store-hangs")
	body, err := json.Marshal(dto)
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := doWithin(t, srv.Handler(), rawRequest(http.MethodPost, "/v1/decide", adminKey, string(body)))
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "agent_token_proof_unrecorded") {
		t.Fatalf("a hanging record: status %d, body %s, want 503 agent_token_proof_unrecorded", rec.Code, rec.Body)
	}
}

func TestARecordFailureThatIsNotAnOutageIsRefusedWith500(t *testing.T) {
	k := newTokenKeySet(t)
	record := newSharedRecord()
	srv := instanceOn(t, k, requireAgentToken(), record, "", nil)
	const said = `ERROR: relation "agent_proof_replays" does not exist (SQLSTATE 42P01)`
	record.failWith(func(context.Context) error { return errors.New(said) })
	dto := proofRequest(t, k, mintAgentToken(t, k, tokSubject, nil), "p-store-answered")
	logged := captureLog(t)
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, dto)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("a record that answered with a failure of its own: status %d, body %s, want 500", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "SQLSTATE") {
		t.Fatalf("the store's own text left the process: %s", rec.Body)
	}
	if !strings.Contains(logged.String(), "SQLSTATE") {
		t.Fatalf("the operator's log does not carry the cause: %q", logged.String())
	}
}

// Only a presented proof needs the record. A request that carries none decides
// from memory through an outage, which invariant 20 names as right.
func TestARequestWithNoProofStillDecidesWhileTheRecordIsDown(t *testing.T) {
	k := newTokenKeySet(t)
	record := newSharedRecord()
	record.failWith(func(context.Context) error { return errRefused("record proof") })

	noToken := instanceOn(t, k, nil, record, "", nil)
	if got := decisionFor(t, noToken, decideRequestDTO{AgentID: tokSubject, RunID: "r1"}); got.Decision != "allow" {
		t.Fatalf("a request with no token: decision %q, reason %q", got.Decision, got.Reason)
	}

	optional := instanceOn(t, k, requireAgentToken(), record, "", func(c *agenttoken.Config) { c.ProofOptional = true })
	tok := mintAgentToken(t, k, tokSubject, nil)
	if got := decisionFor(t, optional, decideRequestDTO{AgentID: tokSubject, RunID: "r1", AgentToken: tok}); got.Decision != "allow" {
		t.Fatalf("a token where proofs are optional: decision %q, reason %q", got.Decision, got.Reason)
	}
}

func TestARecordOutageIsLoggedOncePerOutage(t *testing.T) {
	k := newTokenKeySet(t)
	record := newSharedRecord()
	srv := instanceOn(t, k, requireAgentToken(), record, "", nil)
	tok := mintAgentToken(t, k, tokSubject, nil)
	logged := captureLog(t)

	record.failWith(func(context.Context) error { return errRefused("record proof") })
	for _, jti := range []string{"p-out-1", "p-out-2", "p-out-3"} {
		doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, proofRequest(t, k, tok, jti))
	}
	if got := strings.Count(logged.String(), "unreachable"); got != 1 {
		t.Fatalf("three refused proofs logged the outage %d times, want once:\n%s", got, logged.String())
	}

	record.failWith(nil)
	for _, jti := range []string{"p-back-1", "p-back-2"} {
		if got := decisionFor(t, srv, proofRequest(t, k, tok, jti)); got.Decision != "allow" {
			t.Fatalf("a proof after the record came back: decision %q, reason %q", got.Decision, got.Reason)
		}
	}
	if got := strings.Count(logged.String(), "reachable again"); got != 1 {
		t.Fatalf("the end of the outage was logged %d times, want once:\n%s", got, logged.String())
	}
}

// Only an answer from the record says the store is back. A decide that carried
// no proof never asked it.
func TestARequestWithNoProofSaysNothingAboutTheRecord(t *testing.T) {
	k := newTokenKeySet(t)
	record := newSharedRecord()
	srv := instanceOn(t, k, requireAgentToken(), record, "", func(c *agenttoken.Config) { c.ProofOptional = true })
	tok := mintAgentToken(t, k, tokSubject, nil)
	logged := captureLog(t)

	record.failWith(func(context.Context) error { return errRefused("record proof") })
	doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, proofRequest(t, k, tok, "p-quiet"))
	if got := decisionFor(t, srv, decideRequestDTO{AgentID: tokSubject, RunID: "r1", AgentToken: tok}); got.Decision != "allow" {
		t.Fatalf("a token with no proof: decision %q, reason %q", got.Decision, got.Reason)
	}
	if strings.Contains(logged.String(), "reachable again") {
		t.Fatalf("a decide that asked the record nothing said the store is back:\n%s", logged.String())
	}
}

// The enforcement point gives up long before the store deadline: 50 ms on a model
// call. Its going away must not read as a failure of this process, and must not
// end the claim mid-statement, which costs a session. The claim runs to its own
// deadline, so a hanging store is seen as what it is.
func TestACallerThatHangsUpDoesNotCutTheClaimShort(t *testing.T) {
	k := newTokenKeySet(t)
	record := newSharedRecord()
	srv := instanceOn(t, k, requireAgentToken(), record, "", nil)
	srv.storeTimeout = testStoreTimeout
	logged := captureLog(t)
	ended := make(chan error, 1)
	record.failWith(func(ctx context.Context) error {
		<-ctx.Done()
		ended <- ctx.Err()
		return ctx.Err()
	})
	dto := proofRequest(t, k, mintAgentToken(t, k, tokSubject, nil), "p-hung-up")
	body, err := json.Marshal(dto)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	req := rawRequest(http.MethodPost, "/v1/decide", adminKey, string(body)).WithContext(ctx)
	time.AfterFunc(testStoreTimeout/10, cancel)
	rec, _ := doWithin(t, srv.Handler(), req)
	select {
	case err := <-ended:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("the claim ended with %v, want its own deadline", err)
		}
	case <-time.After(hangGuard):
		t.Fatal("the claim never ended")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, body %s, want 503", rec.Code, rec.Body)
	}
	if got := countLines(logged.String(), "policy store unreachable"); got != 1 {
		t.Fatalf("the outage was logged %d times, want once:\n%s", got, logged.String())
	}
}
