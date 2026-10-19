package approverstmt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
)

// The statement is the wire form genaryx signs and wardryx checks: a compact
// JWS, ES256, under the console key whose RFC 7638 thumbprint is its kid. The
// tests mint statements with the keys they generate, then break them one way at
// a time. The shape is the one in wave3/approval-statement-proposal.md.

const (
	aid  = "approval-7f3a"
	dec  = "grant"
	sub  = "approver-1842"
	cred = "Zm9vYmFyYmF6cXV4"
	jti  = "stmt-0001"
)

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// sign builds a compact JWS over header and claims with key k.
func sign(t *testing.T, k *ecdsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := b64(h) + "." + b64(c)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + b64(sig)
}

// jwkOf is the public key of k as a JWK.
func jwkOf(k *ecdsa.PrivateKey) delegation.JWK { return delegation.FromPublic(&k.PublicKey, "") }

func thumbOf(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	tp, err := delegation.Thumbprint(jwkOf(k))
	if err != nil {
		t.Fatal(err)
	}
	return tp
}

// claimsAt is a valid statement's claims at now, for the approval and decision.
func claimsAt(now time.Time) map[string]any {
	return map[string]any{
		"v": 1, "sub": sub, "cred": cred, "aid": aid, "dec": dec,
		"iat": now.Unix(), "exp": now.Add(60 * time.Second).Unix(), "jti": jti,
	}
}

func headerFor(t *testing.T, k *ecdsa.PrivateKey) map[string]any {
	t.Helper()
	return map[string]any{"alg": "ES256", "typ": Typ, "kid": thumbOf(t, k)}
}

func verifierFor(t *testing.T, keys ...*ecdsa.PrivateKey) *Verifier {
	t.Helper()
	var set []delegation.JWK
	for _, k := range keys {
		set = append(set, jwkOf(k))
	}
	v, err := New(set)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

func refused(err error) bool { return errors.Is(err, ErrStatement) }

func TestAStatementSignedByTheConsoleKeyVerifiesAndNamesTheApprover(t *testing.T) {
	k := newKey(t)
	now := time.Unix(1_800_000_000, 0)
	tok := sign(t, k, headerFor(t, k), claimsAt(now))
	got, err := verifierFor(t, k).Verify(tok, aid, dec, now)
	if err != nil {
		t.Fatalf("a statement the console key signed was refused: %v", err)
	}
	want := Statement{Approver: sub, CredentialID: cred, ApprovalID: aid, Decision: dec, JTI: jti}
	if got != want {
		t.Fatalf("the verified statement names %+v, want %+v", got, want)
	}
}

func TestAStatementForAnotherApprovalOrDecisionIsRefused(t *testing.T) {
	k := newKey(t)
	now := time.Unix(1_800_000_000, 0)
	tok := sign(t, k, headerFor(t, k), claimsAt(now))
	v := verifierFor(t, k)
	if _, err := v.Verify(tok, "approval-other", dec, now); !refused(err) {
		t.Fatalf("a statement for approval %q was accepted for another approval: %v", aid, err)
	}
	if _, err := v.Verify(tok, aid, "deny", now); !refused(err) {
		t.Fatalf("a grant statement was accepted as a deny: %v", err)
	}
}

func TestAStatementSignedByAnotherKeyIsRefused(t *testing.T) {
	console, other := newKey(t), newKey(t)
	now := time.Unix(1_800_000_000, 0)
	v := verifierFor(t, console)
	// Signed by the other key but naming the console's kid: the signature fails.
	forged := sign(t, other, headerFor(t, console), claimsAt(now))
	if _, err := v.Verify(forged, aid, dec, now); !refused(err) {
		t.Fatalf("a statement signed by another key under the console's kid was accepted: %v", err)
	}
	// A kid the set does not hold is refused before any signature is read.
	unknown := sign(t, other, headerFor(t, other), claimsAt(now))
	if _, err := v.Verify(unknown, aid, dec, now); !refused(err) {
		t.Fatalf("a statement under a kid outside the set was accepted: %v", err)
	}
}

func TestTheHeaderIsPinnedAndCarriesNoKey(t *testing.T) {
	k := newKey(t)
	now := time.Unix(1_800_000_000, 0)
	v := verifierFor(t, k)
	cases := map[string]map[string]any{
		"alg none":           {"alg": "none", "typ": Typ, "kid": thumbOf(t, k)},
		"alg HS256":          {"alg": "HS256", "typ": Typ, "kid": thumbOf(t, k)},
		"another typ":        {"alg": "ES256", "typ": "JWT", "kid": thumbOf(t, k)},
		"no kid":             {"alg": "ES256", "typ": Typ},
		"a jwk in the head":  {"alg": "ES256", "typ": Typ, "kid": thumbOf(t, k), "jwk": jwkOf(k)},
		"an x5c in the head": {"alg": "ES256", "typ": Typ, "kid": thumbOf(t, k), "x5c": []string{"AAAA"}},
		"a jku in the head":  {"alg": "ES256", "typ": Typ, "kid": thumbOf(t, k), "jku": "https://attacker.example/keys"},
	}
	for name, h := range cases {
		tok := sign(t, k, h, claimsAt(now))
		if _, err := v.Verify(tok, aid, dec, now); !refused(err) {
			t.Errorf("%s: the statement was accepted: %v", name, err)
		}
	}
}

func TestAStatementOutsideItsWindowIsRefused(t *testing.T) {
	k := newKey(t)
	now := time.Unix(1_800_000_000, 0)
	v := verifierFor(t, k)
	expired := claimsAt(now.Add(-2 * time.Minute)) // exp is a minute before now, past the leeway
	if _, err := v.Verify(sign(t, k, headerFor(t, k), expired), aid, dec, now); !refused(err) {
		t.Fatalf("an expired statement was accepted: %v", err)
	}
	future := claimsAt(now.Add(10 * time.Minute)) // iat ten minutes ahead
	if _, err := v.Verify(sign(t, k, headerFor(t, k), future), aid, dec, now); !refused(err) {
		t.Fatalf("a statement issued in the future was accepted: %v", err)
	}
	long := claimsAt(now)
	long["exp"] = now.Add(MaxLifetime + time.Second).Unix()
	if _, err := v.Verify(sign(t, k, headerFor(t, k), long), aid, dec, now); !refused(err) {
		t.Fatalf("a statement living longer than %s was accepted: %v", MaxLifetime, err)
	}
	// Inside the leeway a little skew is accepted: this one expired ten seconds ago.
	skew := claimsAt(now.Add(-70 * time.Second))
	if _, err := v.Verify(sign(t, k, headerFor(t, k), skew), aid, dec, now); err != nil {
		t.Fatalf("a statement that expired inside the leeway was refused: %v", err)
	}
}

func TestAHostileApproverOrCredentialOrJTIIsRefused(t *testing.T) {
	k := newKey(t)
	now := time.Unix(1_800_000_000, 0)
	v := verifierFor(t, k)
	cases := map[string]map[string]any{
		"empty subject":          {"sub": ""},
		"subject with a newline": {"sub": "approver\n1842"},
		"subject with bidi":      {"sub": "approver‮1842"},
		"oversize subject":       {"sub": strings.Repeat("s", 257)},
		"empty credential":       {"cred": ""},
		"oversize credential":    {"cred": strings.Repeat("c", 513)},
		"empty jti":              {"jti": ""},
		"oversize jti":           {"jti": strings.Repeat("j", 129)},
		"version two":            {"v": 2},
		"no version":             {"v": nil},
	}
	for name, over := range cases {
		c := claimsAt(now)
		for key, val := range over {
			if val == nil {
				delete(c, key)
			} else {
				c[key] = val
			}
		}
		if _, err := v.Verify(sign(t, k, headerFor(t, k), c), aid, dec, now); !refused(err) {
			t.Errorf("%s: the statement was accepted", name)
		}
	}
}

func TestAnUnreadableKeySetIsRefusedWhole(t *testing.T) {
	k := newKey(t)
	good := jwkOf(k)
	rsaLike := good
	rsaLike.Kty = "RSA"
	if _, err := New([]delegation.JWK{good, rsaLike}); err == nil {
		t.Error("a set with an RSA key was accepted")
	}
	if _, err := New(nil); err == nil {
		t.Error("an empty set was accepted")
	}
	noCoords := good
	noCoords.X = ""
	if _, err := New([]delegation.JWK{noCoords}); err == nil {
		t.Error("a key with no x coordinate was accepted")
	}
	if _, err := New([]delegation.JWK{good, good}); err == nil {
		t.Error("two keys with one thumbprint were accepted")
	}
}

func TestAVerifierWithNoKeysRefusesEveryStatement(t *testing.T) {
	k := newKey(t)
	now := time.Unix(1_800_000_000, 0)
	tok := sign(t, k, headerFor(t, k), claimsAt(now))
	var v *Verifier
	if _, err := v.Verify(tok, aid, dec, now); !refused(err) {
		t.Fatalf("a nil verifier accepted a statement: %v", err)
	}
}

func TestHostileStatementsAreRefusedWithoutPanic(t *testing.T) {
	k := newKey(t)
	now := time.Unix(1_800_000_000, 0)
	v := verifierFor(t, k)
	good := sign(t, k, headerFor(t, k), claimsAt(now))
	inputs := []string{"", ".", "..", "a.b", "a.b.c", "a.b.c.d", strings.Repeat("x", maxStatementSize+1), good[:len(good)-4]}
	for i := 1; i < len(good); i += 7 {
		inputs = append(inputs, good[:i])
	}
	for _, in := range inputs {
		if _, err := v.Verify(in, aid, dec, now); !refused(err) {
			t.Fatalf("a hostile input %q was accepted", in[:min(len(in), 24)])
		}
	}
}

// The key set is read from the file the operator names. A file that holds a
// valid set verifies the console's statements; one that is not a set refuses to
// load, so a deployment that meant to verify them does not start without them.
func TestTheKeyFileIsReadAsAJWKSet(t *testing.T) {
	k := newKey(t)
	now := time.Unix(1_800_000_000, 0)
	dir := t.TempDir()
	good := dir + "/console-keys.json"
	set, err := json.Marshal(map[string]any{"keys": []delegation.JWK{jwkOf(k)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(good, set, 0o600); err != nil {
		t.Fatal(err)
	}
	v, err := ReadKeyFile(good)
	if err != nil {
		t.Fatalf("ReadKeyFile on a valid set: %v", err)
	}
	if _, err := v.Verify(sign(t, k, headerFor(t, k), claimsAt(now)), aid, dec, now); err != nil {
		t.Fatalf("a statement the file's key signed was refused: %v", err)
	}
	bad := dir + "/not-a-set.json"
	if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeyFile(bad); err == nil {
		t.Fatal("a file that is not a JWK set was loaded")
	}
	if _, err := ReadKeyFile(dir + "/absent.json"); err == nil {
		t.Fatal("an absent file was loaded")
	}
}
