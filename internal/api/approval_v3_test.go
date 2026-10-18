package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/approval"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
)

// apiSigner stands in for Keyryx's sign route for these tests: one ES256 key,
// and a switch that makes it unreachable.
type apiSigner struct {
	key  *ecdsa.PrivateKey
	kid  string
	down bool
}

func newAPISigner(t *testing.T, kid string) *apiSigner {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return &apiSigner{key: k, kid: kid}
}

func (s *apiSigner) Current(ctx context.Context) (string, error) {
	if s.down {
		return "", errors.New("keyryx unreachable")
	}
	return s.kid, nil
}

func (s *apiSigner) Sign(ctx context.Context, input []byte) (string, []byte, error) {
	if s.down {
		return "", nil, errors.New("keyryx unreachable")
	}
	d := sha256.Sum256(input)
	r, sg, err := ecdsa.Sign(rand.Reader, s.key, d[:])
	if err != nil {
		return "", nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sg.FillBytes(sig[32:])
	return s.kid, sig, nil
}

type apiKeySet map[string]*ecdsa.PublicKey

func (k apiKeySet) Key(kid string) (*ecdsa.PublicKey, bool) {
	p, ok := k[kid]
	return p, ok
}

func keyryxKeys(s *apiSigner) approval.Keys {
	return approval.Keys{Signer: s, JWKS: apiKeySet{s.kid: &s.key.PublicKey}}
}

func TestAGrantWithKeyryxMintsAV3TokenThatDecideAccepts(t *testing.T) {
	h := costHarness(t, true)
	s := newAPISigner(t, "k1")
	h.srv.WithApprovalKeys(keyryxKeys(s))

	id := h.hold(t, costAsk())
	tok := h.grant(t, id)
	if strings.Count(tok, ".") != 2 {
		t.Fatalf("a grant with Keyryx must mint a three-part JWS, got %q", tok)
	}
	if got := h.present(t, costAsk(), tok); got.Decision != pdp.Allow {
		t.Fatalf("the v3 token for this call: decision %s (%s), want allow", got.Decision, got.Reason)
	}
}

func TestAnUnknownKidHoldsAgainOnDecide(t *testing.T) {
	h := costHarness(t, true)
	s := newAPISigner(t, "k1")
	h.srv.WithApprovalKeys(keyryxKeys(s))
	id := h.hold(t, costAsk())
	tok := h.grant(t, id)

	// The verifier now holds only a key under another kid.
	h.srv.WithApprovalKeys(approval.Keys{JWKS: apiKeySet{"k2": &s.key.PublicKey}})
	if got := h.present(t, costAsk(), tok); got.Decision == pdp.Allow {
		t.Fatalf("a token under a kid the verifier does not hold was allowed")
	}
}

func TestAV2TokenAfterTheDeadlineHoldsAgain(t *testing.T) {
	h := costHarness(t, true)
	id := h.hold(t, costAsk())
	tok := h.grant(t, id)
	if strings.Count(tok, ".") != 1 {
		t.Fatalf("setup: without Keyryx the grant mints v2, got %q", tok)
	}
	h.srv.WithApprovalKeys(approval.Keys{Secret: []byte(testHMAC), V2: approval.V2Rule{Accepted: true, Until: time.Now().Add(-time.Minute)}})
	if got := h.present(t, costAsk(), tok); got.Decision == pdp.Allow {
		t.Fatalf("a v2 token after WARDRYX_APPROVAL_V2_UNTIL was allowed")
	}
}

func TestAGrantWithKeyryxDownAnswers503AndLeavesTheHoldPending(t *testing.T) {
	h := costHarness(t, true)
	s := newAPISigner(t, "k1")
	h.srv.WithApprovalKeys(keyryxKeys(s))
	id := h.hold(t, costAsk())

	s.down = true
	if w := doRequest(t, h.srv.Handler(), http.MethodPost, "/v1/approvals/"+id+"/decide", adminKey,
		approvalDecideRequestDTO{Decision: "grant", DecidedBy: "alice@acme.example"}); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("grant with Keyryx down: status %d, want 503", w.Code)
	}
	s.down = false
	tok := h.grant(t, id)
	if got := h.present(t, costAsk(), tok); got.Decision != pdp.Allow {
		t.Fatalf("the hold stayed pending, so a later grant must work: decision %s", got.Decision)
	}
}

func TestCachedKeysVerifyWhileKeyryxIsDown(t *testing.T) {
	h := costHarness(t, true)
	s := newAPISigner(t, "k1")
	h.srv.WithApprovalKeys(keyryxKeys(s))
	tok := h.grant(t, h.hold(t, costAsk()))
	if strings.Count(tok, ".") != 2 {
		t.Fatalf("setup: the grant under Keyryx must mint v3, got %q", tok)
	}

	s.down = true
	if got := h.present(t, costAsk(), tok); got.Decision != pdp.Allow {
		t.Fatalf("Keyryx unreachable: a token the cached keys verify must still allow, got %s (%s)", got.Decision, got.Reason)
	}
}
