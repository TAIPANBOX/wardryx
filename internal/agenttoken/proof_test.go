package agenttoken

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
)

// A token is sender-constrained: its cnf.jkt names the key the agent holds. The
// agent proves it holds that key with a DPoP proof sent with the token. The
// proof here is minted by the test, with a key the test generated.

// jktOf is the RFC 7638 thumbprint of a key, the value a token's cnf.jkt holds.
func jktOf(t *testing.T, k *ecdsa.PrivateKey) string {
	t.Helper()
	tp, err := delegation.Thumbprint(delegation.FromPublic(&k.PublicKey, ""))
	if err != nil {
		t.Fatal(err)
	}
	return tp
}

// publicJWK is the public half of a key as a JWK object, for a proof's header.
func publicJWK(t *testing.T, k *ecdsa.PrivateKey) map[string]any {
	t.Helper()
	raw, err := json.Marshal(delegation.FromPublic(&k.PublicKey, ""))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// mintProof signs a DPoP proof with holder for token, made at iat, sent to htu
// with method htm.
func mintProof(t *testing.T, holder *ecdsa.PrivateKey, token, htm, htu string, iat int64, jti string) string {
	t.Helper()
	header := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": publicJWK(t, holder)}
	claims := map[string]any{
		"htm": htm, "htu": htu, "iat": iat, "jti": jti,
		"ath": delegation.AccessTokenHash(token),
	}
	return signJWS(t, holder, header, claims)
}

// boundToken mints an agent token for sub whose cnf.jkt names holder.
func boundToken(t *testing.T, issuer *ecdsa.PrivateKey, holder *ecdsa.PrivateKey, sub string, over map[string]any) string {
	t.Helper()
	n := now()
	claims := claimsFor(n, map[string]any{
		"sub": sub, "client_id": sub,
		"cnf": map[string]any{"jkt": jktOf(t, holder)},
	})
	for k, v := range over {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	return mint(t, issuer, testKid, "ES256", claims)
}

// newProofVerifier builds a verifier over an issuer key set and lets the test
// change its configuration before it is built.
func newProofVerifier(t *testing.T, issuer *ecdsa.PrivateKey, change func(*Config)) *Verifier {
	t.Helper()
	cfg := Config{
		Issuer:      testIssuer,
		Audiences:   []string{testAudience},
		JWKSFile:    writeJWKS(t, map[string]*ecdsa.PrivateKey{testKid: issuer}),
		DoorOrigins: []string{testDoor},
	}
	if change != nil {
		change(&cfg)
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

const (
	testHTM = "POST"
	testHTU = "https://pep.example/v1/tools/call"
)

// verifiedBound verifies a bound token and returns what it says, failing the test
// if the token itself is refused.
func verifiedBound(t *testing.T, v *Verifier, tok string, n time.Time) Verified {
	t.Helper()
	got, err := v.Verify(tok, n)
	if err != nil {
		t.Fatalf("the bound token was refused: %v", err)
	}
	return got
}

func TestAProofBoundToTheTokenVerifies(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	v := newProofVerifier(t, issuer, nil)
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	bound := verifiedBound(t, v, tok, n)
	proof := mintProof(t, holder, tok, testHTM, testHTU, n.Unix(), "p-1")
	if err := v.CheckProof(proof, tok, bound, n); err != nil {
		t.Fatalf("the proof made by the holder of the bound key was refused: %v", err)
	}
}

func TestAProofMadeWithAnotherKeyIsRefused(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	v := newProofVerifier(t, issuer, nil)
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	bound := verifiedBound(t, v, tok, n)
	// Its own signature checks out against the key it carries: only the
	// thumbprint, which must be the token's cnf.jkt, refuses it.
	stranger := newKey(t)
	proof := mintProof(t, stranger, tok, testHTM, testHTU, n.Unix(), "p-2")
	if err := v.CheckProof(proof, tok, bound, n); !errors.Is(err, ErrProof) {
		t.Fatalf("a proof made with a key other than the token's cnf.jkt: err %v, want ErrProof", err)
	}
}

func TestAProofNamingAnotherTokenIsRefused(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	v := newProofVerifier(t, issuer, nil)
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	other := boundToken(t, issuer, holder, testSubject, map[string]any{"jti": "another-token"})
	bound := verifiedBound(t, v, tok, n)
	// The proof is the holder's and is fresh, but its ath names the other token.
	proof := mintProof(t, holder, other, testHTM, testHTU, n.Unix(), "p-3")
	if err := v.CheckProof(proof, tok, bound, n); !errors.Is(err, ErrProof) {
		t.Fatalf("a proof whose ath names another token: err %v, want ErrProof", err)
	}
}

func TestAStaleProofIsRefusedAndAFreshOneAccepted(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	v := newProofVerifier(t, issuer, nil)
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	bound := verifiedBound(t, v, tok, n)
	if err := v.CheckProof(mintProof(t, holder, tok, testHTM, testHTU, n.Unix()-30, "p-fresh"), tok, bound, n); err != nil {
		t.Fatalf("a proof 30 seconds old, inside the 60-second window, was refused: %v", err)
	}
	stale := mintProof(t, holder, tok, testHTM, testHTU, n.Unix()-120, "p-stale")
	if err := v.CheckProof(stale, tok, bound, n); !errors.Is(err, ErrProof) {
		t.Fatalf("a proof 120 seconds old was accepted: err %v, want ErrProof", err)
	}
	future := mintProof(t, holder, tok, testHTM, testHTU, n.Unix()+120, "p-future")
	if err := v.CheckProof(future, tok, bound, n); !errors.Is(err, ErrProof) {
		t.Fatalf("a proof 120 seconds in the future was accepted: err %v, want ErrProof", err)
	}
}

func TestAProofToAForeignDoorIsRefused(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	v := newProofVerifier(t, issuer, nil)
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	bound := verifiedBound(t, v, tok, n)
	// The origin is compared as scheme, host and port, with the default port
	// filled in and the host case-folded: this one is the configured door.
	same := mintProof(t, holder, tok, testHTM, "https://PEP.example:443/v1/tools/call", n.Unix(), "p-same")
	if err := v.CheckProof(same, tok, bound, n); err != nil {
		t.Fatalf("a proof to the configured door, default port and host case differing, was refused: %v", err)
	}
	for _, htu := range []string{
		"https://elsewhere.example/v1/tools/call",
		"http://pep.example/v1/tools/call",
		"https://pep.example:8443/v1/tools/call",
	} {
		proof := mintProof(t, holder, tok, testHTM, htu, n.Unix(), "p-"+htu)
		if err := v.CheckProof(proof, tok, bound, n); !errors.Is(err, ErrProof) {
			t.Fatalf("a proof to %s, which is not a configured door origin, was accepted: err %v", htu, err)
		}
	}
}

func TestAProofWithTheWrongTypOrAlgIsRefused(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	v := newProofVerifier(t, issuer, nil)
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	bound := verifiedBound(t, v, tok, n)
	claims := map[string]any{"htm": testHTM, "htu": testHTU, "iat": n.Unix(), "jti": "p-typ", "ath": delegation.AccessTokenHash(tok)}
	asToken := signJWS(t, holder, map[string]any{"typ": "at+jwt", "alg": "ES256", "jwk": publicJWK(t, holder)}, claims)
	if err := v.CheckProof(asToken, tok, bound, n); !errors.Is(err, ErrProof) {
		t.Fatalf("a proof with typ at+jwt, which is a token and not a proof: err %v, want ErrProof", err)
	}
	asHMAC := signJWS(t, holder, map[string]any{"typ": "dpop+jwt", "alg": "HS256", "jwk": publicJWK(t, holder)}, claims)
	if err := v.CheckProof(asHMAC, tok, bound, n); !errors.Is(err, ErrProof) {
		t.Fatalf("a proof with alg HS256: err %v, want ErrProof", err)
	}
}

func TestAProofWithAPrivateMemberOrNoHTMOrNoJTIIsRefused(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	v := newProofVerifier(t, issuer, nil)
	n := now()
	tok := boundToken(t, issuer, holder, testSubject, nil)
	bound := verifiedBound(t, v, tok, n)
	withPrivate := publicJWK(t, holder)
	withPrivate["d"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	priv := signJWS(t, holder, map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": withPrivate},
		map[string]any{"htm": testHTM, "htu": testHTU, "iat": n.Unix(), "jti": "p-d", "ath": delegation.AccessTokenHash(tok)})
	if err := v.CheckProof(priv, tok, bound, n); !errors.Is(err, ErrProof) {
		t.Fatalf("a proof whose jwk carries a private member: err %v, want ErrProof", err)
	}
	header := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": publicJWK(t, holder)}
	noHTM := signJWS(t, holder, header, map[string]any{"htu": testHTU, "iat": n.Unix(), "jti": "p-h", "ath": delegation.AccessTokenHash(tok)})
	if err := v.CheckProof(noHTM, tok, bound, n); !errors.Is(err, ErrProof) {
		t.Fatalf("a proof with no htm: err %v, want ErrProof", err)
	}
	noJTI := signJWS(t, holder, header, map[string]any{"htm": testHTM, "htu": testHTU, "iat": n.Unix(), "ath": delegation.AccessTokenHash(tok)})
	if err := v.CheckProof(noJTI, tok, bound, n); !errors.Is(err, ErrProof) {
		t.Fatalf("a proof with no jti: err %v, want ErrProof", err)
	}
}

func TestAProofIsRequiredUnlessProofsAreOptional(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	n := now()
	v := newProofVerifier(t, issuer, nil)
	tok := boundToken(t, issuer, holder, testSubject, nil)
	bound := verifiedBound(t, v, tok, n)
	if err := v.CheckProof("", tok, bound, n); !errors.Is(err, ErrProofRequired) {
		t.Fatalf("a token with no proof, proofs required: err %v, want ErrProofRequired", err)
	}
	optional := newProofVerifier(t, issuer, func(c *Config) { c.ProofOptional = true })
	if err := optional.CheckProof("", tok, bound, n); err != nil {
		t.Fatalf("a token with no proof, proofs optional: err %v, want nil", err)
	}
}

func TestTheProofWindowIsConfigurableUpTo300Seconds(t *testing.T) {
	issuer, holder := newKey(t), newKey(t)
	n := now()
	wide := newProofVerifier(t, issuer, func(c *Config) { c.ProofMaxAge = 300 * time.Second })
	tok := boundToken(t, issuer, holder, testSubject, nil)
	bound := verifiedBound(t, wide, tok, n)
	if err := wide.CheckProof(mintProof(t, holder, tok, testHTM, testHTU, n.Unix()-200, "p-wide"), tok, bound, n); err != nil {
		t.Fatalf("a 200-second-old proof, inside a 300-second window, was refused: %v", err)
	}
	def := newProofVerifier(t, issuer, nil)
	if err := def.CheckProof(mintProof(t, holder, tok, testHTM, testHTU, n.Unix()-200, "p-def"), tok, bound, n); !errors.Is(err, ErrProof) {
		t.Fatalf("a 200-second-old proof under the default 60-second window: err %v, want ErrProof", err)
	}
	if _, err := New(Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKSURL: "https://vouchryx.example/jwks",
		DoorOrigins: []string{testDoor}, ProofMaxAge: 301 * time.Second}, nil); err == nil {
		t.Fatal("a proof window of 301 seconds was accepted, the largest allowed is 300")
	}
}

func TestDoorOriginsAreRequiredAndMustBeOrigins(t *testing.T) {
	base := Config{Issuer: testIssuer, Audiences: []string{testAudience}, JWKSURL: "https://vouchryx.example/jwks"}
	if _, err := New(base, nil); err == nil {
		t.Fatal("a configuration with no door origins was accepted")
	}
	for _, origin := range []string{"https://pep.example/v1", "pep.example", "ftp://pep.example"} {
		c := base
		c.DoorOrigins = []string{origin}
		if _, err := New(c, nil); err == nil {
			t.Fatalf("door origin %q was accepted, want a refusal: an origin is scheme://host[:port] and nothing else", origin)
		}
	}
}
