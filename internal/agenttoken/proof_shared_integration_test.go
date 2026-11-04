//go:build integration

// These tests stand two verifiers on one real Postgres. Run with:
//
//	DATABASE_URL=postgres://user:pass@localhost:5432/wardryx_test?sslmode=disable \
//	    go test -tags integration ./internal/agenttoken/
package agenttoken

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/store"
)

// pgRecord opens the real store. A run that asked for the integration tests and
// has no database measured nothing, so it fails rather than skips.
func pgRecord(t *testing.T) *store.Postgres {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Fatal("DATABASE_URL is not set, so this measured nothing")
	}
	p, err := store.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func uniqueJTI(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

func TestTwoVerifiersOnOneDatabaseAcceptAProofOnceUnderConcurrentPresentation(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	verifiers := []*Verifier{sharedVerifier(t, issuer, pgRecord(t)), sharedVerifier(t, issuer, pgRecord(t))}
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	bound := verifiedBound(t, verifiers[0], tok, n)
	proof := mintProof(t, holder, tok, testHTM, testHTU, n.Unix(), uniqueJTI(t))
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := verifiers[i%2].CheckProof(t.Context(), proof, tok, bound, n)
			switch {
			case err == nil:
				accepted.Add(1)
			case !errors.Is(err, ErrProof):
				t.Errorf("a presentation failed with something other than a replay refusal: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := accepted.Load(); got != 1 {
		t.Fatalf("the proof was accepted %d times across two verifiers on one database, want exactly 1", got)
	}
}

// Postgres refuses a NUL in text, so a jti that reached the database as it was
// written would fail the store and not the replay check.
func TestAHostileJTIIsHeldByARealDatabase(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	v := sharedVerifier(t, issuer, pgRecord(t))
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	bound := verifiedBound(t, v, tok, n)
	proof := mintProof(t, holder, tok, testHTM, testHTU, n.Unix(), "nul\x00"+uniqueJTI(t))
	if err := v.CheckProof(t.Context(), proof, tok, bound, n); err != nil {
		t.Fatalf("a jti with a NUL in it: %v", err)
	}
	if err := v.CheckProof(t.Context(), proof, tok, bound, n); !errors.Is(err, ErrProof) {
		t.Fatalf("the same proof again: err %v, want a replay refusal", err)
	}
}
