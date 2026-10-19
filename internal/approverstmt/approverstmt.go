// Package approverstmt verifies the approval statement a console signs after a
// person's passkey assertion, and names the approver it proves.
//
// A statement is a compact JWS signed by the console's device key. wardryx
// holds the console's public keys in a static JWK set (WARDRYX_APPROVER_JWKS)
// and verifies the statement against the key its kid names, the RFC 7638
// thumbprint of that key. The statement says who approved (sub), which passkey
// credential confirmed it (cred), which approval and decision it is for (aid,
// dec), and when it is valid (iat, exp).
package approverstmt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
)

// Typ is the statement's pinned typ header.
const Typ = "approver-statement+jwt"

// MaxLifetime bounds exp minus iat. A console issues a statement for the
// decision it is making now, not for later.
const MaxLifetime = 300 * time.Second

// Leeway is how far iat may sit in the future, and exp in the past, when the
// clocks of the console and wardryx differ.
const Leeway = 30 * time.Second

// ErrStatement is a statement that did not verify. The message after it names
// the reason, for the operator and the audit record; it never echoes the token.
var ErrStatement = errors.New("approverstmt: the approver statement did not verify")

const (
	maxKeySetBytes   = 64 << 10
	maxStatementSize = 8 << 10
	maxSubjectBytes  = 256
	maxCredBytes     = 512
	maxJTIBytes      = 128
)

// Verifier holds the console's public keys, each under its thumbprint.
type Verifier struct {
	keys map[string]delegation.JWK
}

// Statement is what a verified statement proves.
type Statement struct {
	Approver     string // sub: the approver the console names
	CredentialID string // cred: the passkey credential that confirmed the decision
	ApprovalID   string // aid
	Decision     string // dec: "grant" or "deny"
	JTI          string // jti: the statement's own id, for the audit record
}

// New builds a verifier from a set of EC P-256 keys. Each key's kid is its RFC
// 7638 thumbprint, computed here and never taken from the input, so a key cannot
// be installed under a kid it does not hold. A set with no key, a key that is
// not EC P-256, or two keys with one thumbprint is refused whole.
func New(keys []delegation.JWK) (*Verifier, error) {
	if len(keys) == 0 {
		return nil, errors.New("the approver key set holds no keys")
	}
	v := &Verifier{keys: map[string]delegation.JWK{}}
	for _, k := range keys {
		if k.Kty != "EC" || k.Crv != "P-256" {
			return nil, errors.New("an approver key is not an EC P-256 key")
		}
		if k.X == "" || k.Y == "" {
			return nil, errors.New("an approver key has no coordinates")
		}
		kid, err := delegation.Thumbprint(k)
		if err != nil {
			return nil, fmt.Errorf("an approver key has no thumbprint: %w", err)
		}
		if _, dup := v.keys[kid]; dup {
			return nil, errors.New("two approver keys have one thumbprint")
		}
		k.Kid = kid
		v.keys[kid] = k
	}
	return v, nil
}

// ReadKeyFile reads a JWK set from path and builds a verifier from it.
func ReadKeyFile(path string) (*Verifier, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the operator names this file in WARDRYX_APPROVER_JWKS
	if err != nil {
		return nil, err
	}
	if len(raw) > maxKeySetBytes {
		return nil, errors.New("the approver key set is larger than the limit")
	}
	var set delegation.Set
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("the approver key set is not a JWK set: %w", err)
	}
	return New(set.Keys)
}

// Verify checks a statement for one approval and one decision at now. Every
// check is on the verified claims, after the signature under the key the kid
// names has verified. The header may carry only alg, typ and kid, so a statement
// cannot name its own key (jwk, x5c, jku and the rest are refused).
func (v *Verifier) Verify(token, approvalID, decision string, now time.Time) (Statement, error) {
	refuse := func(reason string) (Statement, error) {
		return Statement{}, fmt.Errorf("%w: %s", ErrStatement, reason)
	}
	if v == nil || len(v.keys) == 0 {
		return refuse("no approver key set is configured")
	}
	if len(token) == 0 || len(token) > maxStatementSize {
		return refuse("the statement is empty or larger than the limit")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return refuse("not a compact JWS")
	}
	rawHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return refuse("the header is not base64url")
	}
	var header map[string]json.RawMessage
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return refuse("the header is not a JSON object")
	}
	// The header names the algorithm, the type and the key by kid, and nothing
	// else: a header that carries its own key or a key location is refused.
	for name := range header {
		if name != "alg" && name != "typ" && name != "kid" {
			return refuse("the header carries " + name + ", which a statement may not")
		}
	}
	var alg, typ, kid string
	if json.Unmarshal(header["alg"], &alg) != nil || alg != "ES256" {
		return refuse("alg is not ES256")
	}
	if json.Unmarshal(header["typ"], &typ) != nil || typ != Typ {
		return refuse("typ is not " + Typ)
	}
	if json.Unmarshal(header["kid"], &kid) != nil || kid == "" {
		return refuse("the header names no kid")
	}
	key, ok := v.keys[kid]
	if !ok {
		return refuse("the kid is not in the approver key set")
	}
	claims, err := delegation.VerifyWith(token, key)
	if err != nil {
		return refuse("the signature does not verify under the key the kid names")
	}
	if n, ok := claims["v"].(float64); !ok || n != 1 {
		return refuse("v is not 1")
	}
	sub, _ := claims["sub"].(string)
	if !labelOK(sub, maxSubjectBytes) {
		return refuse("sub is not a usable approver id")
	}
	cred, _ := claims["cred"].(string)
	if !labelOK(cred, maxCredBytes) {
		return refuse("cred is not a usable credential id")
	}
	aid, _ := claims["aid"].(string)
	if approvalID == "" || aid != approvalID {
		return refuse("aid does not name this approval")
	}
	dec, _ := claims["dec"].(string)
	if (decision != "grant" && decision != "deny") || dec != decision {
		return refuse("dec does not name this decision")
	}
	jti, _ := claims["jti"].(string)
	if !labelOK(jti, maxJTIBytes) {
		return refuse("jti is not usable")
	}
	iat, okIat := claims["iat"].(float64)
	exp, okExp := claims["exp"].(float64)
	if !okIat || !okExp || iat != float64(int64(iat)) || exp != float64(int64(exp)) {
		return refuse("iat or exp is missing")
	}
	issued, expires := time.Unix(int64(iat), 0), time.Unix(int64(exp), 0)
	switch {
	case !expires.After(issued):
		return refuse("exp is not after iat")
	case expires.Sub(issued) > MaxLifetime:
		return refuse("the statement lives longer than the limit")
	case issued.After(now.Add(Leeway)):
		return refuse("the statement is issued in the future")
	case now.After(expires.Add(Leeway)):
		return refuse("the statement has expired")
	}
	return Statement{Approver: sub, CredentialID: cred, ApprovalID: aid, Decision: dec, JTI: jti}, nil
}

// labelOK reports whether s is short, valid UTF-8, and free of control characters
// and bidirectional overrides, so that a name in a console or a terminal reads as
// it was written.
func labelOK(s string, max int) bool {
	if s == "" || len(s) > max || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) {
			return false
		}
	}
	return true
}
