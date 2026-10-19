package agenttoken

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// Finding F-013's residual, held here: a DPoP proof captured within its window
// was presentable again at any door until the token expired, because the
// verifier kept no record of the proofs it had accepted. A proof is single use
// within its window: its jti is remembered until the window closes, a second
// presentation is refused, and the record is bounded. The tests name the
// behaviour and read the record through the verifier's own fields, which only
// the package can see.

func TestAProofIsRefusedTheSecondTimeItIsPresentedInItsWindow(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	v := newProofVerifier(t, issuer, nil)
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	bound := verifiedBound(t, v, tok, n)
	proof := mintProof(t, holder, tok, testHTM, testHTU, n.Unix(), "p-once")
	if err := v.CheckProof(proof, tok, bound, n); err != nil {
		t.Fatalf("the first presentation of a fresh proof was refused: %v", err)
	}
	err := v.CheckProof(proof, tok, bound, n)
	if !errors.Is(err, ErrProof) {
		t.Fatalf("a second presentation of the same proof in its window was accepted: err %v", err)
	}
	if !strings.Contains(err.Error(), "already used") {
		t.Fatalf("the refusal does not say the proof was replayed: %v", err)
	}
}

func TestAFreshProofIsAcceptedWhenAnotherWasReplayed(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	v := newProofVerifier(t, issuer, nil)
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	bound := verifiedBound(t, v, tok, n)
	first := mintProof(t, holder, tok, testHTM, testHTU, n.Unix(), "p-a")
	if err := v.CheckProof(first, tok, bound, n); err != nil {
		t.Fatalf("first: %v", err)
	}
	if err := v.CheckProof(first, tok, bound, n); !errors.Is(err, ErrProof) {
		t.Fatalf("replay of the first proof was accepted: %v", err)
	}
	// One agent call makes one decide with one new proof: a new jti is a new proof.
	second := mintProof(t, holder, tok, testHTM, testHTU, n.Unix(), "p-b")
	if err := v.CheckProof(second, tok, bound, n); err != nil {
		t.Fatalf("a new proof with a new jti was refused after a replay: %v", err)
	}
}

func TestAProofIsForgottenOnceItsWindowHasClosed(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	v := newProofVerifier(t, issuer, nil)
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	bound := verifiedBound(t, v, tok, n)
	if err := v.CheckProof(mintProof(t, holder, tok, testHTM, testHTU, n.Unix(), "p-old"), tok, bound, n); err != nil {
		t.Fatalf("p-old: %v", err)
	}
	if got := len(v.proofs); got != 1 {
		t.Fatalf("the record holds %d proofs after one was accepted, want 1", got)
	}
	// Past the window the old proof is stale whatever the record says, and a
	// proof made now is accepted and makes the old record unnecessary.
	later := n.Add(DefaultProofAge + 1e9)
	if err := v.CheckProof(mintProof(t, holder, tok, testHTM, testHTU, later.Unix(), "p-new"), tok, bound, later); err != nil {
		t.Fatalf("a fresh proof a window later was refused: %v", err)
	}
	if got := len(v.proofs); got != 1 {
		t.Fatalf("the record holds %d proofs a window later, want 1: the closed window was not forgotten", got)
	}
	if _, kept := v.proofs["p-old"]; kept {
		t.Fatal("the record still holds the jti of a proof whose window has closed")
	}
}

func TestTheProofRecordIsBoundedAndFailsClosed(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	v := newProofVerifier(t, issuer, nil)
	v.proofCap = 2
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	bound := verifiedBound(t, v, tok, n)
	for _, jti := range []string{"p-1", "p-2"} {
		if err := v.CheckProof(mintProof(t, holder, tok, testHTM, testHTU, n.Unix(), jti), tok, bound, n); err != nil {
			t.Fatalf("%s within the cap was refused: %v", jti, err)
		}
	}
	err := v.CheckProof(mintProof(t, holder, tok, testHTM, testHTU, n.Unix(), "p-3"), tok, bound, n)
	if !errors.Is(err, ErrProof) || !strings.Contains(err.Error(), "full") {
		t.Fatalf("a proof past the record's cap was not refused as a full record: err %v", err)
	}
	if got := len(v.proofs); got != 2 {
		t.Fatalf("the record grew past its cap: %d entries, want 2", got)
	}
	// The window closes, the record empties, and the same cap accepts again.
	later := n.Add(DefaultProofAge + 1e9)
	if err := v.CheckProof(mintProof(t, holder, tok, testHTM, testHTU, later.Unix(), "p-3"), tok, bound, later); err != nil {
		t.Fatalf("a proof after the window closed was refused by a full record: %v", err)
	}
}

func TestOneProofIsAcceptedOnceUnderConcurrentPresentation(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	v := newProofVerifier(t, issuer, nil)
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	bound := verifiedBound(t, v, tok, n)
	proof := mintProof(t, holder, tok, testHTM, testHTU, n.Unix(), "p-race")
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if v.CheckProof(proof, tok, bound, n) == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := accepted.Load(); got != 1 {
		t.Fatalf("the proof was accepted %d times under concurrent presentation, want exactly 1", got)
	}
}
