package approval

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/store"
)

// testSigner stands in for Keyryx's sign route. It holds one ES256 key per kid
// and signs with the active one. Current reports the active kid; a Sign call
// first moves the active kid to the next one in pending, the way a rotation
// between Current and Sign would.
type testSigner struct {
	keys    map[string]*ecdsa.PrivateKey
	active  string
	pending []string
	down    bool
}

func newTestSigner(t *testing.T, kids ...string) *testSigner {
	t.Helper()
	s := &testSigner{keys: map[string]*ecdsa.PrivateKey{}, active: kids[0]}
	for _, kid := range kids {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		s.keys[kid] = k
	}
	return s
}

func (s *testSigner) Current(ctx context.Context) (string, error) {
	if s.down {
		return "", errors.New("keyryx unreachable")
	}
	return s.active, nil
}

func (s *testSigner) Sign(ctx context.Context, input []byte) (string, []byte, error) {
	if s.down {
		return "", nil, errors.New("keyryx unreachable")
	}
	if len(s.pending) > 0 {
		s.active = s.pending[0]
		s.pending = s.pending[1:]
	}
	d := sha256.Sum256(input)
	r, sg, err := ecdsa.Sign(rand.Reader, s.keys[s.active], d[:])
	if err != nil {
		return "", nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sg.FillBytes(sig[32:])
	return s.active, sig, nil
}

// set is the key set Keyryx's JWKS would publish for this signer.
func (s *testSigner) set() staticKeys {
	out := staticKeys{}
	for kid, k := range s.keys {
		out[kid] = &k.PublicKey
	}
	return out
}

type staticKeys map[string]*ecdsa.PublicKey

func (k staticKeys) Key(kid string) (*ecdsa.PublicKey, bool) {
	p, ok := k[kid]
	return p, ok
}

const testAgent = "agent://acme.example/ops/bot1"

var testTools = []string{"bucket_delete"}

func testDigest() string {
	return ToolCallDigest("bucket_delete", "bucket/prod", []byte(`{"name":"logs"}`), false)
}

// holdFor creates a pending hold the way internal/api does, with the cost that
// triggered it and, when digest is set, the tool call it was about.
func holdFor(t *testing.T, st store.Store, cost float64, digest string) string {
	t.Helper()
	ctx := map[string]any{"est_cost_usd": cost}
	if digest != "" {
		ctx[ContextKeyToolCall] = map[string]any{"name": "bucket_delete", "target": "bucket/prod", ContextKeyDigest: digest}
	}
	a, err := Request(context.Background(), st, testAgent, "run-1", testTools, ctx)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	return a.ApprovalID
}

func v3Keys(s *testSigner) Keys {
	return Keys{Signer: s, JWKS: s.set()}
}

func grantWith(t *testing.T, keys Keys, st store.Store, id string, ttl time.Duration) string {
	t.Helper()
	_, tok, err := DecideWith(context.Background(), st, keys, id, "grant", "key:test", "label", ttl)
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	return tok
}

func segment(t *testing.T, s string) map[string]any {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("segment not base64url: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("segment not JSON: %v", err)
	}
	return m
}

// token re-encodes one segment of tok with edit applied, keeping the others.
func reencode(t *testing.T, tok string, part int, edit func(map[string]any)) string {
	t.Helper()
	parts := strings.Split(tok, ".")
	m := segment(t, parts[part])
	edit(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parts[part] = base64.RawURLEncoding.EncodeToString(b)
	return strings.Join(parts, ".")
}

func TestAGrantMintsAnES256TokenNamingItsKidAndTheApproval(t *testing.T) {
	s := newTestSigner(t, "k1")
	st := store.NewMemory()
	id := holdFor(t, st, 10, testDigest())
	tok := grantWith(t, v3Keys(s), st, id, DefaultTTL)

	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("a v3 token is a compact JWS of three segments, got %d", len(parts))
	}
	hdr := segment(t, parts[0])
	if hdr["alg"] != "ES256" || hdr["kid"] != "k1" || hdr["typ"] != "wardryx-approval+jwt" {
		t.Fatalf("header = %v, want alg ES256, kid k1, typ wardryx-approval+jwt", hdr)
	}
	c := segment(t, parts[1])
	want := map[string]any{"v": float64(3), "aid": id, "agent_id": testAgent, "run_id": "run-1", "max_cost_usd": float64(10), "tcd": testDigest()}
	for k, v := range want {
		if c[k] != v {
			t.Errorf("claim %s = %v, want %v", k, c[k], v)
		}
	}
	if err := v3Keys(s).VerifyForCall(tok, testAgent, "run-1", testTools, 10, testDigest()); err != nil {
		t.Fatalf("the token it minted does not verify for its own call: %v", err)
	}
}

func TestAnUnknownKidIsRefused(t *testing.T) {
	s := newTestSigner(t, "k1")
	st := store.NewMemory()
	tok := grantWith(t, v3Keys(s), st, holdFor(t, st, 10, ""), DefaultTTL)

	// The same key under another kid: a token that names a kid the verifier
	// does not hold must not verify, even though its signature would.
	other := staticKeys{"k2": &s.keys["k1"].PublicKey}
	err := Keys{JWKS: other}.VerifyForCall(tok, testAgent, "run-1", testTools, 1, "")
	if !errors.Is(err, ErrTokenUnknownKid) {
		t.Fatalf("a token under kid k1 with only k2 in the set: err = %v, want ErrTokenUnknownKid", err)
	}
}

func TestAForgedOrAlteredSignatureIsRefused(t *testing.T) {
	s := newTestSigner(t, "k1")
	st := store.NewMemory()
	tok := grantWith(t, v3Keys(s), st, holdFor(t, st, 10, ""), DefaultTTL)

	parts := strings.Split(tok, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	sig[len(sig)-1] ^= 0x01
	altered := parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
	if err := v3Keys(s).VerifyForCall(altered, testAgent, "run-1", testTools, 1, ""); !errors.Is(err, ErrTokenSignature) {
		t.Fatalf("an altered signature: err = %v, want ErrTokenSignature", err)
	}

	// Signed by a different key under the same kid the verifier trusts.
	forger := newTestSigner(t, "k1")
	fst := store.NewMemory()
	forged := grantWith(t, Keys{Signer: forger, JWKS: forger.set()}, fst, holdFor(t, fst, 10, ""), DefaultTTL)
	if err := v3Keys(s).VerifyForCall(forged, testAgent, "run-1", testTools, 1, ""); !errors.Is(err, ErrTokenSignature) {
		t.Fatalf("a token signed by another key under kid k1: err = %v, want ErrTokenSignature", err)
	}
}

func TestTheHeaderMustPinES256AndCarryNoKey(t *testing.T) {
	s := newTestSigner(t, "k1")
	st := store.NewMemory()
	tok := grantWith(t, v3Keys(s), st, holdFor(t, st, 10, ""), DefaultTTL)

	headers := map[string]func(map[string]any){
		"alg HS256":           func(m map[string]any) { m["alg"] = "HS256" },
		"alg none":            func(m map[string]any) { m["alg"] = "none" },
		"a key in the header": func(m map[string]any) { m["jwk"] = map[string]any{"kty": "EC"} },
		"a jku header":        func(m map[string]any) { m["jku"] = "https://attacker.example/jwks" },
		"another typ":         func(m map[string]any) { m["typ"] = "JWT" },
	}
	for name, edit := range headers {
		bad := reencode(t, tok, 0, edit)
		if err := v3Keys(s).VerifyForCall(bad, testAgent, "run-1", testTools, 1, ""); !errors.Is(err, ErrTokenMalformed) {
			t.Errorf("%s: err = %v, want ErrTokenMalformed", name, err)
		}
	}
}

func TestV3BindsWhatV2Binds(t *testing.T) {
	s := newTestSigner(t, "k1")
	st := store.NewMemory()
	tok := grantWith(t, v3Keys(s), st, holdFor(t, st, 10, testDigest()), DefaultTTL)
	keys := v3Keys(s)

	cases := []struct {
		name   string
		agent  string
		run    string
		tools  []string
		cost   float64
		digest string
		want   error
	}{
		{"the call it was granted for", testAgent, "run-1", testTools, 10, testDigest(), nil},
		{"a cheaper retry", testAgent, "run-1", testTools, 3, testDigest(), nil},
		{"another agent", "agent://acme.example/ops/bot2", "run-1", testTools, 10, testDigest(), ErrTokenBinding},
		{"another run", testAgent, "run-2", testTools, 10, testDigest(), ErrTokenBinding},
		{"another tool set", testAgent, "run-1", []string{"bucket_list"}, 10, testDigest(), ErrTokenBinding},
		{"another call of the same tool", testAgent, "run-1", testTools, 10, ToolCallDigest("bucket_delete", "bucket/other", nil, false), ErrTokenToolCall},
		{"no call presented", testAgent, "run-1", testTools, 10, "", ErrTokenToolCall},
		{"a cost above the ceiling", testAgent, "run-1", testTools, 10.5, testDigest(), ErrTokenCostExceeded},
	}
	for _, c := range cases {
		err := keys.VerifyForCall(tok, c.agent, c.run, c.tools, c.cost, c.digest)
		if c.want == nil && err != nil {
			t.Errorf("%s: err = %v, want nil", c.name, err)
		}
		if c.want != nil && !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
	}

	expired := grantWith(t, v3Keys(s), st, holdFor(t, st, 10, ""), -time.Minute)
	if err := keys.VerifyForCall(expired, testAgent, "run-1", testTools, 1, ""); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("an expired token: err = %v, want ErrTokenExpired", err)
	}
}

func TestAV3TokenWithNoCallIsRefusedWhereACallMustBeBound(t *testing.T) {
	s := newTestSigner(t, "k1")
	st := store.NewMemory()
	tok := grantWith(t, v3Keys(s), st, holdFor(t, st, 10, ""), DefaultTTL)
	if err := v3Keys(s).VerifyForCall(tok, testAgent, "run-1", testTools, 1, ""); err != nil {
		t.Fatalf("a token granted with no call verifies on a request with none: %v", err)
	}
	if err := v3Keys(s).VerifyBoundToCall(tok, testAgent, "run-1", testTools, 1, ""); !errors.Is(err, ErrTokenUnbound) {
		t.Fatalf("a token that binds no call must not lift a bound hold: err = %v, want ErrTokenUnbound", err)
	}
}

func TestAV3TokenVerifiesWithNoSignerCall(t *testing.T) {
	s := newTestSigner(t, "k1")
	st := store.NewMemory()
	tok := grantWith(t, v3Keys(s), st, holdFor(t, st, 10, testDigest()), DefaultTTL)

	// Keyryx down: verification uses the key set it already holds.
	s.down = true
	if err := v3Keys(s).VerifyForCall(tok, testAgent, "run-1", testTools, 10, testDigest()); err != nil {
		t.Fatalf("verification must not need the signer: %v", err)
	}
}

func TestV3NeedsAKeySetToVerify(t *testing.T) {
	s := newTestSigner(t, "k1")
	st := store.NewMemory()
	tok := grantWith(t, v3Keys(s), st, holdFor(t, st, 10, ""), DefaultTTL)
	if err := (Keys{}).VerifyForCall(tok, testAgent, "run-1", testTools, 1, ""); !errors.Is(err, ErrNoKeys) {
		t.Fatalf("a v3 token with no key set: err = %v, want ErrNoKeys", err)
	}
}

func TestAV2TokenVerifiesOnlyBeforeTheDeadline(t *testing.T) {
	secret := []byte("v2-secret-for-the-test")
	st := store.NewMemory()
	v2 := grantWith(t, Keys{Secret: secret, V2: V2Rule{Accepted: true}}, st, holdFor(t, st, 10, ""), DefaultTTL)
	if strings.Count(v2, ".") != 1 {
		t.Fatalf("setup: a grant with no signer must mint a v2 token, got %q", v2)
	}

	before := Keys{Secret: secret, V2: V2Rule{Accepted: true, Until: time.Now().Add(time.Hour)}}
	if err := before.VerifyForCall(v2, testAgent, "run-1", testTools, 1, ""); err != nil {
		t.Fatalf("a v2 token before the deadline: %v", err)
	}
	after := Keys{Secret: secret, V2: V2Rule{Accepted: true, Until: time.Now().Add(-time.Minute)}}
	if err := after.VerifyForCall(v2, testAgent, "run-1", testTools, 1, ""); !errors.Is(err, ErrTokenV2Retired) {
		t.Fatalf("a v2 token after the deadline: err = %v, want ErrTokenV2Retired", err)
	}
	off := Keys{Secret: secret}
	if err := off.VerifyForCall(v2, testAgent, "run-1", testTools, 1, ""); !errors.Is(err, ErrTokenV2Retired) {
		t.Fatalf("a v2 token with v2 not accepted: err = %v, want ErrTokenV2Retired", err)
	}
}

func TestWithoutASignerTheGrantMintsTheV2TokenItAlwaysDid(t *testing.T) {
	secret := []byte("v2-secret-for-the-test")
	st := store.NewMemory()
	id := holdFor(t, st, 10, testDigest())
	tok := grantWith(t, Keys{Secret: secret, V2: V2Rule{Accepted: true}}, st, id, DefaultTTL)

	parts := strings.Split(tok, ".")
	if len(parts) != 2 {
		t.Fatalf("v2 is payload.signature, got %d parts", len(parts))
	}
	c := segment(t, parts[0])
	if c["v"] != float64(2) || c["tcd"] != testDigest() || c["aid"] != nil {
		t.Fatalf("v2 claims = %v: want v 2 and tcd, and no aid (the v3 claim)", c)
	}
	if err := (Keys{Secret: secret, V2: V2Rule{Accepted: true}}).VerifyForCall(tok, testAgent, "run-1", testTools, 10, testDigest()); err != nil {
		t.Fatalf("the v2 token verifies as before: %v", err)
	}
}

func TestAGrantWithTheSignerDownLeavesTheHoldPending(t *testing.T) {
	s := newTestSigner(t, "k1")
	st := store.NewMemory()
	id := holdFor(t, st, 10, "")
	s.down = true
	_, tok, err := DecideWith(context.Background(), st, v3Keys(s), id, "grant", "key:test", "label", DefaultTTL)
	if !errors.Is(err, ErrSigner) || tok != "" {
		t.Fatalf("grant with Keyryx down: err = %v, token %q; want ErrSigner and no token", err, tok)
	}
	got, gerr := st.GetApproval(context.Background(), id)
	if gerr != nil || !got.DecidedAt.IsZero() {
		t.Fatalf("the hold must stay pending when no token could be signed: decided at %v, err %v", got.DecidedAt, gerr)
	}
	s.down = false
	if tok := grantWith(t, v3Keys(s), st, id, DefaultTTL); tok == "" {
		t.Fatal("the hold, still pending, grants once Keyryx is back")
	}
}

func TestAKidThatMovesOnceDuringAGrantIsFollowed(t *testing.T) {
	s := newTestSigner(t, "k1", "k2")
	s.pending = []string{"k2"}
	st := store.NewMemory()
	tok := grantWith(t, v3Keys(s), st, holdFor(t, st, 10, ""), DefaultTTL)
	if hdr := segment(t, strings.Split(tok, ".")[0]); hdr["kid"] != "k2" {
		t.Fatalf("the header must name the kid that signed, got %v", hdr["kid"])
	}
	if err := v3Keys(s).VerifyForCall(tok, testAgent, "run-1", testTools, 1, ""); err != nil {
		t.Fatalf("the token signed under the moved kid verifies: %v", err)
	}
}

func TestAKidThatMovesTwiceFailsTheGrant(t *testing.T) {
	s := newTestSigner(t, "k1", "k2", "k3")
	s.pending = []string{"k2", "k3"}
	st := store.NewMemory()
	id := holdFor(t, st, 10, "")
	_, tok, err := DecideWith(context.Background(), st, v3Keys(s), id, "grant", "key:test", "label", DefaultTTL)
	if !errors.Is(err, ErrSigner) || tok != "" {
		t.Fatalf("a kid that moves on every attempt: err = %v, token %q; want ErrSigner", err, tok)
	}
}

func TestSecretNotRequiredWhenASignerIsSet(t *testing.T) {
	s := newTestSigner(t, "k1")
	st := store.NewMemory()
	if tok := grantWith(t, Keys{Signer: s, JWKS: s.set()}, st, holdFor(t, st, 10, ""), DefaultTTL); tok == "" {
		t.Fatal("a grant with a signer and no HMAC secret must mint")
	}
}

func TestNoSecretAndNoSignerStillRefuses(t *testing.T) {
	st := store.NewMemory()
	id := holdFor(t, st, 10, "")
	if _, _, err := DecideWith(context.Background(), st, Keys{}, id, "grant", "key:test", "label", DefaultTTL); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("no secret and no signer: err = %v, want ErrNoSecret", err)
	}
}

// signRaw signs header and payload exactly as given, with the key under kid, so
// a test can present a token whose signature is good and whose claims are not.
func signRaw(t *testing.T, s *testSigner, kid, header, payload string) string {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	d := sha256.Sum256([]byte(input))
	r, sg, err := ecdsa.Sign(rand.Reader, s.keys[kid], d[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sg.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestAV3ClaimsThatAreSignedButNotAGrantAreRefused(t *testing.T) {
	s := newTestSigner(t, "k1")
	hdr := `{"alg":"ES256","kid":"k1","typ":"wardryx-approval+jwt"}`
	now := time.Now().Add(time.Hour).Unix()
	cases := map[string]struct {
		token string
		want  error
	}{
		"a token with no approval id": {
			signRaw(t, s, "k1", hdr, fmt.Sprintf(`{"v":3,"agent_id":%q,"run_id":"run-1","tools":["bucket_delete"],"max_cost_usd":10,"exp":%d,"nonce":"n"}`, testAgent, now)),
			ErrTokenMalformed,
		},
		"a version other than 3": {
			signRaw(t, s, "k1", hdr, fmt.Sprintf(`{"v":2,"aid":"ap_1","agent_id":%q,"run_id":"run-1","tools":["bucket_delete"],"max_cost_usd":10,"exp":%d,"nonce":"n"}`, testAgent, now)),
			ErrTokenVersion,
		},
		"a malformed digest": {
			signRaw(t, s, "k1", hdr, fmt.Sprintf(`{"v":3,"aid":"ap_1","agent_id":%q,"run_id":"run-1","tools":["bucket_delete"],"max_cost_usd":10,"exp":%d,"nonce":"n","tcd":"not-hex"}`, testAgent, now)),
			ErrTokenMalformed,
		},
		"data after the header": {
			signRaw(t, s, "k1", hdr+`{}`, fmt.Sprintf(`{"v":3,"aid":"ap_1","agent_id":%q,"run_id":"run-1","tools":["bucket_delete"],"max_cost_usd":10,"exp":%d,"nonce":"n"}`, testAgent, now)),
			ErrTokenMalformed,
		},
		"a signature of the wrong length": {
			withShortSignature(signRaw(t, s, "k1", hdr, fmt.Sprintf(`{"v":3,"aid":"ap_1","agent_id":%q,"run_id":"run-1","tools":["bucket_delete"],"max_cost_usd":10,"exp":%d,"nonce":"n"}`, testAgent, now))),
			ErrTokenSignature,
		},
	}
	for name, c := range cases {
		err := Keys{JWKS: s.set()}.VerifyForCall(c.token, testAgent, "run-1", testTools, 1, "")
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", name, err, c.want)
		}
	}
}

// withShortSignature replaces a token's signature with ten bytes, which no ES256
// signature is.
func withShortSignature(tok string) string {
	parts := strings.Split(tok, ".")
	return parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 10))
}
