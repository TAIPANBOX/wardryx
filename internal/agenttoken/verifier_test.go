package agenttoken

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
)

// Test tokens are minted here, by hand, because the library's own signer hard-
// codes typ JWT and an agent token must say at+jwt. The keys are generated per
// run and never written down.

const (
	testIssuer   = "https://vouchryx.example"
	testAudience = "https://wardryx.example"
	testKid      = "k-agent-1"
	testSubject  = "agent://acme.example/support/bot1"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// writeJWKS writes the public half of each key to a file, the way vouchryx
// publishes them, and returns the path.
func writeJWKS(t *testing.T, keys map[string]*ecdsa.PrivateKey) string {
	t.Helper()
	var set delegation.Set
	for kid, k := range keys {
		set.Keys = append(set.Keys, delegation.FromPublic(&k.PublicKey, kid))
	}
	raw, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// mint signs a compact JWS: the header names alg, typ at+jwt and kid; the
// payload is claims. ES256 is signed for real; any other alg gets a signature
// of zeros, which no verifier may accept.
func mint(t *testing.T, key *ecdsa.PrivateKey, kid, alg string, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding
	hdr, err := json.Marshal(map[string]any{"alg": alg, "typ": "at+jwt", "kid": kid})
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := enc.EncodeToString(hdr) + "." + enc.EncodeToString(body)
	sig := make([]byte, 64)
	if alg == "ES256" && key != nil {
		sum := sha256.Sum256([]byte(signingInput))
		r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	}
	return signingInput + "." + enc.EncodeToString(sig)
}

// claimsFor is a valid agent token's claims at now, with the overrides applied.
func claimsFor(now time.Time, over map[string]any) map[string]any {
	c := map[string]any{
		"iss":       testIssuer,
		"sub":       testSubject,
		"client_id": testSubject,
		"aud":       testAudience,
		"iat":       now.Unix(),
		"exp":       now.Add(5 * time.Minute).Unix(),
		"jti":       "jti-" + now.Format("150405"),
		"cnf":       map[string]any{"jkt": "thumbprint-of-the-holder"},
	}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func newVerifier(t *testing.T, keys map[string]*ecdsa.PrivateKey, revocationURL string) *Verifier {
	t.Helper()
	cfg := Config{
		Issuer:        testIssuer,
		Audiences:     []string{testAudience},
		JWKSFile:      writeJWKS(t, keys),
		RevocationURL: revocationURL,
	}
	v, err := New(cfg, http.DefaultClient)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := v.Load(t.Context()); err != nil {
		t.Fatalf("Load: %v", err)
	}
	return v
}

func now() time.Time { return time.Now().UTC().Truncate(time.Second) }

func TestAValidAgentTokenVerifiesAndNamesItsSubject(t *testing.T) {
	key := newKey(t)
	v := newVerifier(t, map[string]*ecdsa.PrivateKey{testKid: key}, "")
	n := now()
	got, err := v.Verify(mint(t, key, testKid, "ES256", claimsFor(n, nil)), n)
	if err != nil {
		t.Fatalf("a valid agent token was refused: %v", err)
	}
	if got.Subject != testSubject {
		t.Fatalf("Subject = %q, want %q", got.Subject, testSubject)
	}
}

func TestAnAgentTokenForAnotherAudienceIsRefused(t *testing.T) {
	key := newKey(t)
	v := newVerifier(t, map[string]*ecdsa.PrivateKey{testKid: key}, "")
	n := now()
	if _, err := v.Verify(mint(t, key, testKid, "ES256", claimsFor(n, nil)), n); err != nil {
		t.Fatalf("the token for the configured audience was refused: %v", err)
	}
	other := mint(t, key, testKid, "ES256", claimsFor(n, map[string]any{"aud": "https://elsewhere.example"}))
	if _, err := v.Verify(other, n); err == nil {
		t.Fatal("a token minted for another resource was accepted")
	}
	none := mint(t, key, testKid, "ES256", claimsFor(n, map[string]any{"aud": nil}))
	if _, err := v.Verify(none, n); err == nil {
		t.Fatal("a token with no audience was accepted")
	}
}

func TestAnExpiredAgentTokenIsRefusedAndOneInTheLeewayAccepted(t *testing.T) {
	key := newKey(t)
	v := newVerifier(t, map[string]*ecdsa.PrivateKey{testKid: key}, "")
	n := now()
	within := mint(t, key, testKid, "ES256", claimsFor(n, map[string]any{"exp": n.Add(-10 * time.Second).Unix()}))
	if _, err := v.Verify(within, n); err != nil {
		t.Fatalf("a token that expired ten seconds ago, inside the leeway, was refused: %v", err)
	}
	past := mint(t, key, testKid, "ES256", claimsFor(n, map[string]any{"exp": n.Add(-time.Minute).Unix()}))
	if _, err := v.Verify(past, n); err == nil {
		t.Fatal("a token that expired a minute ago was accepted")
	}
}

func TestOnlyAnES256TokenFromAKnownKeyVerifies(t *testing.T) {
	key := newKey(t)
	v := newVerifier(t, map[string]*ecdsa.PrivateKey{testKid: key}, "")
	n := now()
	if _, err := v.Verify(mint(t, key, testKid, "ES256", claimsFor(n, nil)), n); err != nil {
		t.Fatalf("an ES256 token under a known kid was refused: %v", err)
	}
	if _, err := v.Verify(mint(t, key, "k-unknown", "ES256", claimsFor(n, nil)), n); err == nil {
		t.Fatal("a token under a kid the set does not hold was accepted")
	}
	if _, err := v.Verify(mint(t, key, testKid, "HS256", claimsFor(n, nil)), n); err == nil {
		t.Fatal("an HS256 token was accepted")
	}
	if _, err := v.Verify(mint(t, key, testKid, "ES384", claimsFor(n, nil)), n); err == nil {
		t.Fatal("an ES384 token was accepted, though the pin is ES256")
	}
}

func TestAForgedSignatureOrOtherIssuerOrFutureNotBeforeIsRefused(t *testing.T) {
	key := newKey(t)
	v := newVerifier(t, map[string]*ecdsa.PrivateKey{testKid: key}, "")
	n := now()
	if _, err := v.Verify(mint(t, key, testKid, "ES256", claimsFor(n, nil)), n); err != nil {
		t.Fatalf("the valid token was refused: %v", err)
	}
	// The payload changes after signing: the signature no longer covers it.
	good := mint(t, key, testKid, "ES256", claimsFor(n, nil))
	parts := strings.Split(good, ".")
	forged := mint(t, key, testKid, "ES256", claimsFor(n, map[string]any{"sub": "agent://acme.example/finance/bot9", "client_id": "agent://acme.example/finance/bot9"}))
	parts[1] = strings.Split(forged, ".")[1]
	if _, err := v.Verify(strings.Join(parts, "."), n); err == nil {
		t.Fatal("a token whose payload changed after signing was accepted")
	}
	if _, err := v.Verify(mint(t, key, testKid, "ES256", claimsFor(n, map[string]any{"iss": "https://other.example"})), n); err == nil {
		t.Fatal("a token from another issuer was accepted")
	}
	future := mint(t, key, testKid, "ES256", claimsFor(n, map[string]any{"nbf": n.Add(10 * time.Minute).Unix()}))
	if _, err := v.Verify(future, n); err == nil {
		t.Fatal("a token not valid until ten minutes from now was accepted")
	}
}

// snapshotServer serves a revocation list whose body the test can change.
type snapshotServer struct {
	mu   sync.Mutex
	body string
	srv  *httptest.Server
}

func newSnapshotServer(t *testing.T, body string) *snapshotServer {
	t.Helper()
	s := &snapshotServer{body: body}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(s.body))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *snapshotServer) set(body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.body = body
}

func TestARevokedTokenIsRefusedEvenAfterItVerified(t *testing.T) {
	key := newKey(t)
	snap := newSnapshotServer(t, `{"as_of": 100, "revocations": []}`)
	v := newVerifier(t, map[string]*ecdsa.PrivateKey{testKid: key}, snap.srv.URL)
	n := now()
	tok := mint(t, key, testKid, "ES256", claimsFor(n, map[string]any{"jti": "revoked-soon"}))
	if _, err := v.Verify(tok, n); err != nil {
		t.Fatalf("the token was refused before any revocation: %v", err)
	}
	snap.set(`{"as_of": 200, "revocations": [{"jti": "revoked-soon"}]}`)
	if err := v.Refresh(t.Context()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if _, err := v.Verify(tok, n); err == nil {
		t.Fatal("a token whose jti is on the revocation list was accepted, though it had verified before")
	}
}

func TestTheCacheIsKeyedByTheTokenNotItsJTI(t *testing.T) {
	key := newKey(t)
	v := newVerifier(t, map[string]*ecdsa.PrivateKey{testKid: key}, "")
	n := now()
	legit := mint(t, key, testKid, "ES256", claimsFor(n, map[string]any{"jti": "shared-jti"}))
	if _, err := v.Verify(legit, n); err != nil {
		t.Fatalf("the valid token was refused: %v", err)
	}
	// Same jti, same claims, signed by a key the set does not hold.
	forged := mint(t, newKey(t), testKid, "ES256", claimsFor(n, map[string]any{"jti": "shared-jti"}))
	if _, err := v.Verify(forged, n); err == nil {
		t.Fatal("a forged token carrying the jti of a cached token was accepted")
	}
}

func TestAFailedKeySetRefreshKeepsTheSetItHeld(t *testing.T) {
	key := newKey(t)
	cfg := Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKSFile: writeJWKS(t, map[string]*ecdsa.PrivateKey{testKid: key})}
	v, err := New(cfg, http.DefaultClient)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	n := now()
	tok := mint(t, key, testKid, "ES256", claimsFor(n, nil))
	if _, err := v.Verify(tok, n); err != nil {
		t.Fatalf("the token under the loaded key was refused: %v", err)
	}
	if err := os.WriteFile(cfg.JWKSFile, []byte(`{"keys": [{"kty": "EC", "crv": "P-384"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := v.Refresh(t.Context()); err == nil {
		t.Fatal("a malformed key set was installed without an error")
	}
	if _, err := v.Verify(tok, n); err != nil {
		t.Fatalf("the set held before a failed refresh no longer verifies: %v", err)
	}
}

func TestAnIncompleteConfigurationIsRefused(t *testing.T) {
	file := writeJWKS(t, map[string]*ecdsa.PrivateKey{testKid: newKey(t)})
	for name, cfg := range map[string]Config{
		"no issuer":                       {Audiences: []string{testAudience}, JWKSFile: file},
		"no audience":                     {Issuer: testIssuer, JWKSFile: file},
		"blank audience":                  {Issuer: testIssuer, Audiences: []string{" "}, JWKSFile: file},
		"no key source":                   {Issuer: testIssuer, Audiences: []string{testAudience}},
		"a revocation URL with no scheme": {Issuer: testIssuer, Audiences: []string{testAudience}, JWKSFile: file, RevocationURL: "vouchryx.example/revoked"},
	} {
		if _, err := New(cfg, http.DefaultClient); err == nil {
			t.Errorf("%s: New accepted the configuration, want a refusal naming what is missing", name)
		}
	}
}

// keySetServer serves a JWK set whose body and status the test can change.
type keySetServer struct {
	mu     sync.Mutex
	body   []byte
	status int
	hits   int
	srv    *httptest.Server
}

func newKeySetServer(t *testing.T, body []byte) *keySetServer {
	t.Helper()
	s := &keySetServer{body: body, status: http.StatusOK}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.hits++
		w.WriteHeader(s.status)
		_, _ = w.Write(s.body)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *keySetServer) set(status int, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status, s.body = status, body
}

func (s *keySetServer) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

// The key set is polled from its URL. A refresh that the URL answers with an
// error keeps the set held, and the token it verified under still verifies.
func TestTheKeySetIsFetchedFromItsURLAndAFailedRefreshKeepsIt(t *testing.T) {
	key := newKey(t)
	raw, err := json.Marshal(delegation.Set{Keys: []delegation.JWK{delegation.FromPublic(&key.PublicKey, testKid)}})
	if err != nil {
		t.Fatal(err)
	}
	ks := newKeySetServer(t, raw)
	v, err := New(Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKSURL: ks.srv.URL}, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := v.Load(t.Context()); err != nil {
		t.Fatalf("Load from the URL: %v", err)
	}
	n := now()
	tok := mint(t, key, testKid, "ES256", claimsFor(n, nil))
	if _, err := v.Verify(tok, n); err != nil {
		t.Fatalf("the token under a key the URL served was refused: %v", err)
	}
	ks.set(http.StatusInternalServerError, []byte("oops"))
	if err := v.Refresh(t.Context()); err == nil {
		t.Fatal("a refresh the URL answered with 500 reported no error")
	}
	if _, err := v.Verify(tok, n); err != nil {
		t.Fatalf("the set held before a refused poll no longer verifies: %v", err)
	}
}

// Run polls the sources on its interval, not once.
func TestTheSourcesArePolledOnTheInterval(t *testing.T) {
	key := newKey(t)
	raw, err := json.Marshal(delegation.Set{Keys: []delegation.JWK{delegation.FromPublic(&key.PublicKey, testKid)}})
	if err != nil {
		t.Fatal(err)
	}
	ks := newKeySetServer(t, raw)
	v, err := New(Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKSURL: ks.srv.URL}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go v.Run(ctx, 5*time.Millisecond, nil)
	deadline := time.Now().Add(5 * time.Second)
	for ks.count() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if ks.count() < 3 {
		t.Fatalf("Run polled the URL %d times in five seconds, want it to poll on its interval", ks.count())
	}
}
