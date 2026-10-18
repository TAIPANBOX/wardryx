package keyryx

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/delegation"
)

const testCredential = "wardryx-test-credential-0123456789"

// thumbprint is RFC 7638 for a P-256 key, written out here rather than shared
// with the code under test, so the test cannot agree with a wrong implementation.
func testThumbprint(k *ecdsa.PublicKey) string {
	x, y := coordinate(k, 0), coordinate(k, 1)
	js := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`, x, y)
	sum := sha256.Sum256([]byte(js))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// coordinate is the base64url x (which 0) or y (which 1) of k, cut from its
// uncompressed encoding.
func coordinate(k *ecdsa.PublicKey, which int) string {
	point, err := k.Bytes()
	if err != nil {
		panic(err)
	}
	start := 1 + 32*which
	return base64.RawURLEncoding.EncodeToString(point[start : start+32])
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return k
}

// jwks is the document Keyryx's /v1/jwks route publishes for the key.
func jwks(keys map[string]*ecdsa.PublicKey) string {
	var out []map[string]any
	for kid, k := range keys {
		out = append(out, map[string]any{"kty": "EC", "crv": "P-256", "x": coordinate(k, 0), "y": coordinate(k, 1),
			"kid": kid, "alg": "ES256", "use": "sig"})
	}
	b, _ := json.Marshal(map[string]any{"keys": out})
	return string(b)
}

// jwksWithKid serves one key under the kid the test names, which need not be its thumbprint.
func jwksWithKid(kid string, k *ecdsa.PublicKey) string {
	b, _ := json.Marshal(map[string]any{"keys": []map[string]any{{"kty": "EC", "crv": "P-256",
		"x": coordinate(k, 0), "y": coordinate(k, 1), "kid": kid, "alg": "ES256", "use": "sig"}}})
	return string(b)
}

// jwksServer serves body on the JWKS route, and fails with status when non-zero.
type jwksServer struct {
	body   atomic.Value // string
	status atomic.Int32
	hits   atomic.Int32
}

func (j *jwksServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	j.hits.Add(1)
	if s := j.status.Load(); s != 0 {
		w.WriteHeader(int(s))
		return
	}
	fmt.Fprint(w, j.body.Load().(string))
}

func newJWKS(t *testing.T, body string) (*jwksServer, *httptest.Server) {
	t.Helper()
	j := &jwksServer{}
	j.body.Store(body)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/jwks/wardryx-approval" {
			http.NotFound(w, r)
			return
		}
		j.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return j, srv
}

func mustClient(t *testing.T, base string) *Client {
	t.Helper()
	c, err := NewClient(base, testCredential)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestSignSendsTheStatementAndReturnsTheKidAndRawSignature(t *testing.T) {
	sig := make([]byte, 64)
	for i := range sig {
		sig[i] = byte(i)
	}
	var sawAuth, sawPath, sawMethod string
	var gotStatement, gotPurpose string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth, sawPath, sawMethod = r.Header.Get("Authorization"), r.URL.Path, r.Method
		var body struct {
			Statement string `json:"statement_b64"`
			Purpose   string `json:"purpose"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		b, _ := base64.StdEncoding.DecodeString(body.Statement)
		gotStatement, gotPurpose = string(b), body.Purpose
		json.NewEncoder(w).Encode(map[string]string{"alg": "ES256", "kid": "k1",
			"signature_b64": base64.StdEncoding.EncodeToString(sig)})
	}))
	defer srv.Close()

	kid, got, err := mustClient(t, srv.URL).Sign(context.Background(), []byte("header.payload"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if kid != "k1" || string(got) != string(sig) {
		t.Fatalf("Sign = kid %q, %d bytes; want k1 and the 64 bytes served", kid, len(got))
	}
	if sawMethod != http.MethodPost || sawPath != "/v1/keys/wardryx-approval/sign" {
		t.Fatalf("request = %s %s, want POST /v1/keys/wardryx-approval/sign", sawMethod, sawPath)
	}
	if sawAuth != "Bearer "+testCredential {
		t.Fatalf("Authorization = %q, want the bearer credential over http", sawAuth)
	}
	if gotStatement != "header.payload" || gotPurpose != "approval" {
		t.Fatalf("body statement %q purpose %q, want the signing input and purpose approval", gotStatement, gotPurpose)
	}
}

func TestSignRefusesAnyAnswerThatIsNotASignatureOfTheRightShape(t *testing.T) {
	cases := map[string]string{
		"an alg other than ES256": `{"alg":"RS256","kid":"k1","signature_b64":"` + base64.StdEncoding.EncodeToString(make([]byte, 64)) + `"}`,
		"no kid":                  `{"alg":"ES256","kid":"","signature_b64":"` + base64.StdEncoding.EncodeToString(make([]byte, 64)) + `"}`,
		"a signature of 63 bytes": `{"alg":"ES256","kid":"k1","signature_b64":"` + base64.StdEncoding.EncodeToString(make([]byte, 63)) + `"}`,
		"a signature not base64":  `{"alg":"ES256","kid":"k1","signature_b64":"***"}`,
		"not JSON":                `<html>`,
	}
	for name, body := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		kid, sig, err := mustClient(t, srv.URL).Sign(context.Background(), []byte("x"))
		srv.Close()
		if err == nil || sig != nil || kid != "" {
			t.Errorf("%s: Sign = kid %q, %d bytes, err %v; want an error and nothing returned", name, kid, len(sig), err)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer srv.Close()
	if _, sig, err := mustClient(t, srv.URL).Sign(context.Background(), []byte("x")); err == nil || sig != nil {
		t.Errorf("a refused sign: err %v, %d bytes; want an error and no signature", err, len(sig))
	}
}

func TestSignDoesNotFollowARedirectWithTheCredential(t *testing.T) {
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		if r.Header.Get("Authorization") != "" {
			t.Errorf("the credential was sent to a redirect target")
		}
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	if _, _, err := mustClient(t, srv.URL).Sign(context.Background(), []byte("x")); err == nil {
		t.Fatal("a redirected sign must fail, not succeed through the redirect")
	}
	if elsewhere.Load() != 0 {
		t.Fatalf("the redirect target was contacted %d times", elsewhere.Load())
	}
}

func TestCurrentReadsTheActiveKidOfTheApprovalKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"keys":[
			{"name":"wardryx-approval","alg":"ES256","kid":"old","state":"retired"},
			{"name":"wardryx-approval","alg":"ES256","kid":"now","state":"active"},
			{"name":"other","alg":"ES256","kid":"theirs","state":"active"}]}`)
	}))
	defer srv.Close()
	kid, err := mustClient(t, srv.URL).Current(context.Background())
	if err != nil || kid != "now" {
		t.Fatalf("Current = %q, %v; want the active kid of wardryx-approval", kid, err)
	}
}

func TestTheCacheHoldsTheSetItFetchedAndRefusesAnUnknownKid(t *testing.T) {
	k := newKey(t)
	kid := testThumbprint(&k.PublicKey)
	_, srv := newJWKS(t, jwks(map[string]*ecdsa.PublicKey{kid: &k.PublicKey}))
	c := NewCache(mustClient(t, srv.URL))
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got, ok := c.Key(kid); !ok || coordinate(got, 0) != coordinate(&k.PublicKey, 0) || coordinate(got, 1) != coordinate(&k.PublicKey, 1) {
		t.Fatalf("the published key is not in the cache under its kid")
	}
	if _, ok := c.Key("nope"); ok {
		t.Fatal("an unknown kid must not resolve")
	}
}

func TestAPollThatFailsKeepsTheSetItHad(t *testing.T) {
	k := newKey(t)
	kid := testThumbprint(&k.PublicKey)
	j, srv := newJWKS(t, jwks(map[string]*ecdsa.PublicKey{kid: &k.PublicKey}))
	c := NewCache(mustClient(t, srv.URL))
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	j.status.Store(http.StatusInternalServerError)
	if err := c.Refresh(context.Background()); err == nil {
		t.Fatal("a failed poll must report an error")
	}
	if _, ok := c.Key(kid); !ok {
		t.Fatal("Keyryx unreachable: the keys already cached must still verify")
	}
}

func TestAMalformedSetIsRefusedWholeAndTheCacheKept(t *testing.T) {
	good := newKey(t)
	goodKid := testThumbprint(&good.PublicKey)
	j, srv := newJWKS(t, jwks(map[string]*ecdsa.PublicKey{goodKid: &good.PublicKey}))
	c := NewCache(mustClient(t, srv.URL))
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	// A second key whose coordinates are not on the curve: the whole set is refused.
	bad := `{"keys":[{"kty":"EC","crv":"P-256","kid":"bad","alg":"ES256","use":"sig",` +
		`"x":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `","y":"` + base64.RawURLEncoding.EncodeToString(make([]byte, 32)) + `"},` +
		`{"kty":"EC","crv":"P-256","kid":"` + goodKid + `","x":"` + coordinate(&good.PublicKey, 0) + `","y":"` + coordinate(&good.PublicKey, 1) + `"}]}`
	j.body.Store(bad)
	if err := c.Refresh(context.Background()); err == nil {
		t.Fatal("a set with an off-curve key must be refused")
	}
	if _, ok := c.Key("bad"); ok {
		t.Fatal("the good member of a refused set must not be taken in part")
	}
	if _, ok := c.Key(goodKid); !ok {
		t.Fatal("a refused set must leave the cache as it was")
	}
}

func TestAKidThatIsNotTheKeysThumbprintIsRefused(t *testing.T) {
	k := newKey(t)
	_, srv := newJWKS(t, jwksWithKid("not-the-thumbprint", &k.PublicKey))
	c := NewCache(mustClient(t, srv.URL))
	if err := c.Refresh(context.Background()); err == nil {
		t.Fatal("a kid that is not the RFC 7638 thumbprint of its key must be refused")
	}
	if _, ok := c.Key("not-the-thumbprint"); ok {
		t.Fatal("a mislabelled key must not be cached")
	}
}

func TestARevokedKidLeavesTheSetAtOnce(t *testing.T) {
	k1, k2 := newKey(t), newKey(t)
	id1, id2 := testThumbprint(&k1.PublicKey), testThumbprint(&k2.PublicKey)
	j, srv := newJWKS(t, jwks(map[string]*ecdsa.PublicKey{id1: &k1.PublicKey, id2: &k2.PublicKey}))
	c := NewCache(mustClient(t, srv.URL))
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	j.body.Store(jwks(map[string]*ecdsa.PublicKey{id2: &k2.PublicKey}))
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if _, ok := c.Key(id1); ok {
		t.Fatal("a kid Keyryx no longer publishes must stop verifying at the next successful poll")
	}
	if _, ok := c.Key(id2); !ok {
		t.Fatal("the key still published must keep verifying")
	}
}

func TestAnEmptySetIsWhatKeyryxSays(t *testing.T) {
	k := newKey(t)
	id := testThumbprint(&k.PublicKey)
	j, srv := newJWKS(t, jwks(map[string]*ecdsa.PublicKey{id: &k.PublicKey}))
	c := NewCache(mustClient(t, srv.URL))
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	j.body.Store(`{"keys":[]}`)
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("an empty set is a valid answer: %v", err)
	}
	if _, ok := c.Key(id); ok {
		t.Fatal("Keyryx published no valid key: nothing may verify")
	}
}

func TestRunRefreshesOnItsInterval(t *testing.T) {
	k := newKey(t)
	j, srv := newJWKS(t, jwks(map[string]*ecdsa.PublicKey{testThumbprint(&k.PublicKey): &k.PublicKey}))
	c := NewCache(mustClient(t, srv.URL))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		c.Run(ctx, 10*time.Millisecond, nil)
		close(done)
	}()
	deadline := time.Now().Add(2 * time.Second)
	for j.hits.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if j.hits.Load() < 3 {
		t.Fatalf("Run fetched %d times in two seconds at a 10ms interval, want at least 3", j.hits.Load())
	}
	cancel()
	<-done
}

func TestTheUnixSocketTransportReachesTheSocket(t *testing.T) {
	k := newKey(t)
	id := testThumbprint(&k.PublicKey)
	dir, err := os.MkdirTemp("", "kx")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "k.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, jwks(map[string]*ecdsa.PublicKey{id: &k.PublicKey}))
	})}
	go srv.Serve(ln)
	defer srv.Close()

	c := NewCache(mustClient(t, "unix://"+sock))
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh over the socket: %v", err)
	}
	if _, ok := c.Key(id); !ok {
		t.Fatal("the key served on the socket is not in the cache")
	}
}

// Keyryx names its keys with agent-stack-go's delegation.Thumbprint, and this
// package checks every published kid against its own thumbprint. The two must
// agree on every key, or a set Keyryx publishes would be refused whole.
func TestTheThumbprintIsTheOneAgentStackGoComputes(t *testing.T) {
	for i := 0; i < 20; i++ {
		k := newKey(t)
		want, err := delegation.Thumbprint(delegation.FromPublic(&k.PublicKey, ""))
		if err != nil {
			t.Fatalf("delegation.Thumbprint: %v", err)
		}
		got, err := thumbprint(&k.PublicKey)
		if err != nil || got != want {
			t.Fatalf("thumbprint = %q, %v; agent-stack-go computes %q", got, err, want)
		}
	}
}

func TestCurrentRefusesNoActiveKeyOrTwo(t *testing.T) {
	answers := map[string]string{
		"no active key":   `{"keys":[{"name":"wardryx-approval","kid":"x","state":"retired"}]}`,
		"two active keys": `{"keys":[{"name":"wardryx-approval","kid":"a","state":"active"},{"name":"wardryx-approval","kid":"b","state":"active"}]}`,
		"not JSON":        `<html>`,
	}
	for name, body := range answers {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		kid, err := mustClient(t, srv.URL).Current(context.Background())
		srv.Close()
		if err == nil || kid != "" {
			t.Errorf("%s: Current = %q, %v; want an error and no kid", name, kid, err)
		}
	}
}

func TestNewClientRefusesAnUnusableBase(t *testing.T) {
	for _, base := range []string{"", "ftp://keyryx", "unix://", "not a url", "http://"} {
		if _, err := NewClient(base, ""); err == nil {
			t.Errorf("NewClient(%q): want an error", base)
		}
	}
}
