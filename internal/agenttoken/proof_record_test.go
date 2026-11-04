package agenttoken

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// G3.10 of the estate's gap register: the record of accepted proofs was a map
// inside one process, so a restart forgot it and a second instance never had it.
// With a shared record every verifier asks the same place. fakeRecord stands for
// that place here, with the database's contract and nothing else: a key is
// claimed once. What a real database does with it is held by the integration
// tests beside this file and in internal/store.

type fakeRecord struct {
	mu     sync.Mutex
	rows   map[string]time.Time
	err    error // every call fails with this while it is set
	calls  int
	purges []time.Duration
	purged chan struct{}
	budget time.Duration // what the last purge's context left it
}

func newFakeRecord() *fakeRecord {
	return &fakeRecord{rows: map[string]time.Time{}, purged: make(chan struct{}, 64)}
}

func (r *fakeRecord) TryRecordProof(_ context.Context, key string, until time.Time) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return false, r.err
	}
	if _, seen := r.rows[key]; seen {
		return false, nil
	}
	r.rows[key] = until
	return true, nil
}

func (r *fakeRecord) PurgeProofs(ctx context.Context, grace time.Duration) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.purges = append(r.purges, grace)
	if deadline, ok := ctx.Deadline(); ok {
		r.budget = time.Until(deadline)
	}
	select {
	case r.purged <- struct{}{}:
	default:
	}
	return 0, r.err
}

func (r *fakeRecord) setErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.err = err
}

func (r *fakeRecord) asked() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

// hangingRecord accepts the call and answers only when the caller gives up.
type hangingRecord struct{ fakeRecord }

func (*hangingRecord) TryRecordProof(ctx context.Context, _ string, _ time.Time) (bool, error) {
	<-ctx.Done()
	return false, ctx.Err()
}

func sharedVerifier(t *testing.T, issuer *ecdsa.PrivateKey, record ProofRecord) *Verifier {
	t.Helper()
	return newProofVerifier(t, issuer, func(c *Config) { c.ProofRecord = record })
}

func TestAProofAcceptedByOneVerifierIsRefusedByAnotherOnTheSameRecord(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	record := newFakeRecord()
	a, b := sharedVerifier(t, issuer, record), sharedVerifier(t, issuer, record)
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	proof := mintProof(t, holder, tok, testHTM, testHTU, n.Unix(), "p-two")
	if err := a.CheckProof(t.Context(), proof, tok, verifiedBound(t, a, tok, n), n); err != nil {
		t.Fatalf("the first verifier refused a fresh proof: %v", err)
	}
	err := b.CheckProof(t.Context(), proof, tok, verifiedBound(t, b, tok, n), n)
	if !errors.Is(err, ErrProof) || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("the second verifier on the same record: err %v, want a replay refusal", err)
	}
}

// A restart is a verifier with nothing in its memory.
func TestAVerifierBuiltAfterARestartRefusesAProofTheRecordHolds(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	record := newFakeRecord()
	before := sharedVerifier(t, issuer, record)
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	proof := mintProof(t, holder, tok, testHTM, testHTU, n.Unix(), "p-restart")
	if err := before.CheckProof(t.Context(), proof, tok, verifiedBound(t, before, tok, n), n); err != nil {
		t.Fatalf("the proof before the restart: %v", err)
	}
	after := sharedVerifier(t, issuer, record)
	bound := verifiedBound(t, after, tok, n)
	if err := after.CheckProof(t.Context(), proof, tok, bound, n); !errors.Is(err, ErrProof) {
		t.Fatalf("the same proof after the restart: err %v, want a replay refusal", err)
	}
	fresh := mintProof(t, holder, tok, testHTM, testHTU, n.Unix(), "p-after")
	if err := after.CheckProof(t.Context(), fresh, tok, bound, n); err != nil {
		t.Fatalf("a fresh proof after the restart was refused: %v", err)
	}
}

func TestOneProofIsAcceptedOnceAcrossVerifiersUnderConcurrentPresentation(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	record := newFakeRecord()
	verifiers := []*Verifier{sharedVerifier(t, issuer, record), sharedVerifier(t, issuer, record)}
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	bound := verifiedBound(t, verifiers[0], tok, n)
	proof := mintProof(t, holder, tok, testHTM, testHTU, n.Unix(), "p-race-shared")
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if verifiers[i%2].CheckProof(t.Context(), proof, tok, bound, n) == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := accepted.Load(); got != 1 {
		t.Fatalf("the proof was accepted %d times across two verifiers, want exactly 1", got)
	}
}

// A proof nobody could check for replay may be a replay. It is refused, it is
// refused as a failure of the record and not of the proof, and the process does
// not quietly remember it instead: that would be the per-process record again,
// on exactly the day the shared one is gone.
func TestARecordThatCannotBeAskedRefusesTheProof(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	record := newFakeRecord()
	v := sharedVerifier(t, issuer, record)
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	bound := verifiedBound(t, v, tok, n)
	proof := mintProof(t, holder, tok, testHTM, testHTU, n.Unix(), "p-down")
	down := errors.New("the database went away")
	record.setErr(down)
	for presentation := 1; presentation <= 2; presentation++ {
		err := v.CheckProof(t.Context(), proof, tok, bound, n)
		if err == nil {
			t.Fatalf("presentation %d: a proof was accepted with the record down", presentation)
		}
		if !errors.Is(err, ErrProofRecord) {
			t.Fatalf("presentation %d: err %v, want ErrProofRecord", presentation, err)
		}
		if !errors.Is(err, down) {
			t.Fatalf("presentation %d: err %v does not carry the record's own error, so the API cannot tell an outage", presentation, err)
		}
		if errors.Is(err, ErrProof) {
			t.Fatalf("presentation %d: err %v reads as a bad proof; this proof may be good", presentation, err)
		}
	}
	if got := len(v.proofs); got != 0 {
		t.Fatalf("the process remembered %d proofs while the shared record was down, want 0", got)
	}
	// Nothing was recorded, so the proof is not spent: the same one is accepted
	// once the record is back.
	record.setErr(nil)
	if err := v.CheckProof(t.Context(), proof, tok, bound, n); err != nil {
		t.Fatalf("the proof after the record came back: %v", err)
	}
}

func TestTheRecordIsAskedUnderTheCallersContext(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	v := sharedVerifier(t, issuer, &hangingRecord{})
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	bound := verifiedBound(t, v, tok, n)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- v.CheckProof(ctx, mintProof(t, holder, tok, testHTM, testHTU, n.Unix(), "p-hang"), tok, bound, n)
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrProofRecord) || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err %v, want ErrProofRecord carrying the deadline", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CheckProof did not return five seconds after its context ended")
	}
}

// The record must hold a proof for as long as any instance would accept it, and
// instances on one database may have different windows set. So the row lasts until
// the longest window there is closes, whatever this instance's own window is.
func TestTheRecordIsAskedToKeepAProofUntilTheLongestWindowCloses(t *testing.T) {
	for _, window := range []time.Duration{0, 7 * time.Second, maxProofAge} {
		issuer, holder := newKey(t), newKey(t)
		record := newFakeRecord()
		v := newProofVerifier(t, issuer, func(c *Config) { c.ProofRecord = record; c.ProofMaxAge = window })
		n := now()
		tok := boundToken(t, issuer, holder, testSubject, nil)
		iat := n.Unix() - 3
		if err := v.CheckProof(t.Context(), mintProof(t, holder, tok, testHTM, testHTU, iat, "p-until"), tok, verifiedBound(t, v, tok, n), n); err != nil {
			t.Fatalf("window %s: %v", window, err)
		}
		want := time.Unix(iat, 0).Add(maxProofAge)
		if len(record.rows) != 1 {
			t.Fatalf("window %s: the record holds %d rows, want 1", window, len(record.rows))
		}
		for _, until := range record.rows {
			if !until.Equal(want) {
				t.Fatalf("window %s: the row lasts until %s, want %s (iat plus the longest window)", window, until, want)
			}
		}
	}
}

// A jti is whatever the holder wrote. A database refuses a NUL in text, so a raw
// jti would turn a holder's choice into a store failure; the record keeps a
// digest of fixed size, and no byte the client chose reaches it.
func TestTheRecordKeyIsAFixedSizeDigestWhateverTheJTIHolds(t *testing.T) {
	jtis := []string{
		"plain",
		"nul\x00byte",
		"quote'; DROP TABLE agent_proof_replays; --",
		strings.Repeat("x", maxProofJTI),
		"кириличний-jti",
	}
	issuer, holder := newKey(t), newKey(t)
	record := newFakeRecord()
	v := sharedVerifier(t, issuer, record)
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	bound := verifiedBound(t, v, tok, n)
	for _, jti := range jtis {
		if err := v.CheckProof(t.Context(), mintProof(t, holder, tok, testHTM, testHTU, n.Unix(), jti), tok, bound, n); err != nil {
			t.Fatalf("jti %q: %v", jti, err)
		}
	}
	if len(record.rows) != len(jtis) {
		t.Fatalf("the record holds %d keys for %d different jtis", len(record.rows), len(jtis))
	}
	for key := range record.rows {
		raw, err := hex.DecodeString(key)
		if err != nil || len(raw) != 32 {
			t.Fatalf("key %q is not 64 hex characters", key)
		}
	}
}

// Two holders are two contexts. One holder's jti must not spend another's, which
// matters most on a record every org of a deployment shares.
func TestTwoHoldersMayUseOneJTIAndOneHolderMayNotUseItTwice(t *testing.T) {
	for name, record := range map[string]ProofRecord{"in the process": nil, "shared": newFakeRecord()} {
		t.Run(name, func(t *testing.T) {
			issuer, first, second := newKey(t), newKey(t), newKey(t)
			v := sharedVerifier(t, issuer, record)
			n := now()
			tok1 := boundToken(t, issuer, first, testSubject, nil)
			tok2 := boundToken(t, issuer, second, testSubject, map[string]any{"jti": "tok-second"})
			proof1 := mintProof(t, first, tok1, testHTM, testHTU, n.Unix(), "shared-jti")
			proof2 := mintProof(t, second, tok2, testHTM, testHTU, n.Unix(), "shared-jti")
			if err := v.CheckProof(t.Context(), proof1, tok1, verifiedBound(t, v, tok1, n), n); err != nil {
				t.Fatalf("the first holder: %v", err)
			}
			if err := v.CheckProof(t.Context(), proof2, tok2, verifiedBound(t, v, tok2, n), n); err != nil {
				t.Fatalf("the second holder, same jti: %v", err)
			}
			if err := v.CheckProof(t.Context(), proof1, tok1, verifiedBound(t, v, tok1, n), n); !errors.Is(err, ErrProof) {
				t.Fatalf("the first holder's proof again: err %v, want a replay refusal", err)
			}
		})
	}
}

func TestAProofRefusedForAnythingElseWritesNothingToTheRecord(t *testing.T) {
	issuer, holder, stranger := newKey(t), newKey(t), newKey(t)
	record := newFakeRecord()
	v := sharedVerifier(t, issuer, record)
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	other := boundToken(t, issuer, holder, testSubject, map[string]any{"jti": "tok-other"})
	bound := verifiedBound(t, v, tok, n)
	refused := map[string]string{
		"stale":         mintProof(t, holder, tok, testHTM, testHTU, n.Unix()-int64(DefaultProofAge/time.Second)-1, "p-stale"),
		"another token": mintProof(t, holder, other, testHTM, testHTU, n.Unix(), "p-other"),
		"foreign door":  mintProof(t, holder, tok, testHTM, "https://elsewhere.example/x", n.Unix(), "p-door"),
		"another key":   mintProof(t, stranger, tok, testHTM, testHTU, n.Unix(), "p-key"),
		"not a proof":   "a.b.c",
	}
	for name, proof := range refused {
		if err := v.CheckProof(t.Context(), proof, tok, bound, n); !errors.Is(err, ErrProof) {
			t.Fatalf("%s: err %v, want a refusal of the proof", name, err)
		}
	}
	if got := record.asked(); got != 0 {
		t.Fatalf("the record was asked %d times for proofs that were refused, want 0: anybody could fill it", got)
	}
}

// The in-process record has a cap that fails closed. With a shared record it is
// not in the path at all, so its cap refuses nothing.
func TestTheProcessRecordIsNotUsedBesideASharedOne(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	v := sharedVerifier(t, issuer, newFakeRecord())
	v.proofCap = 1
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	bound := verifiedBound(t, v, tok, n)
	for _, jti := range []string{"p-1", "p-2", "p-3"} {
		if err := v.CheckProof(t.Context(), mintProof(t, holder, tok, testHTM, testHTU, n.Unix(), jti), tok, bound, n); err != nil {
			t.Fatalf("%s: %v", jti, err)
		}
	}
	if got := len(v.proofs); got != 0 {
		t.Fatalf("the process record holds %d proofs beside a shared record, want 0", got)
	}
}

// The purge runs at start and then on its interval, and keeps every row for the
// longest window there is past its own: a row may be read by an instance whose
// clock is behind the purge's, or whose window is set longer.
func TestExpiredProofsArePurgedAtStartAndOnTheInterval(t *testing.T) {
	issuer := newKey(t)
	record := newFakeRecord()
	v := sharedVerifier(t, issuer, record)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	stopped := make(chan struct{})
	go func() { v.RunProofPurge(ctx, 5*time.Millisecond, nil); close(stopped) }()
	for i := 0; i < 3; i++ {
		select {
		case <-record.purged:
		case <-time.After(5 * time.Second):
			t.Fatalf("purge %d never ran", i+1)
		}
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the purge loop did not stop with its context")
	}
	record.mu.Lock()
	defer record.mu.Unlock()
	for _, grace := range record.purges {
		if grace < maxProofAge {
			t.Fatalf("the purge kept rows for %s past their window, want at least %s", grace, maxProofAge)
		}
	}
}

func TestThePurgeRunsOnceAtStartBeforeAnyInterval(t *testing.T) {
	record := newFakeRecord()
	v := sharedVerifier(t, newKey(t), record)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go v.RunProofPurge(ctx, time.Hour, nil)
	select {
	case <-record.purged:
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was purged at start: a process back from a long stop leaves the old rows for a whole interval")
	}
}

// A backlog takes longer than a key set fetch. A purge cut short rolls back, so
// the one after it faces the same backlog and more.
func TestAPurgeHasItsWholeIntervalToFinish(t *testing.T) {
	record := newFakeRecord()
	v := sharedVerifier(t, newKey(t), record)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go v.RunProofPurge(ctx, time.Hour, nil)
	select {
	case <-record.purged:
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was purged at start")
	}
	record.mu.Lock()
	defer record.mu.Unlock()
	if record.budget < 59*time.Minute {
		t.Fatalf("the purge had %s on an hour's interval", record.budget)
	}
}

func TestAFailedPurgeIsReportedAndTheLoopGoesOn(t *testing.T) {
	record := newFakeRecord()
	v := sharedVerifier(t, newKey(t), record)
	down := errors.New("the database went away")
	record.setErr(down)
	reported := make(chan error, 64)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go v.RunProofPurge(ctx, 5*time.Millisecond, func(err error) {
		select {
		case reported <- err:
		default:
		}
	})
	for i := 0; i < 2; i++ {
		select {
		case err := <-reported:
			if !errors.Is(err, down) {
				t.Fatalf("reported %v, want the record's own error", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("failure %d was not reported: the loop stopped, or swallowed it", i+1)
		}
	}
}

func TestWithNoSharedRecordThereIsNothingToPurge(t *testing.T) {
	v := newProofVerifier(t, newKey(t), nil)
	done := make(chan struct{})
	go func() { v.RunProofPurge(t.Context(), time.Hour, nil); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the purge loop ran with no record to purge")
	}
}
