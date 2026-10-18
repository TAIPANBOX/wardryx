package approval

import (
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/store"
)

// Two generations of approval token verify side by side. A v2 token is
// payload.hex(HMAC-SHA256) under WARDRYX_APPROVAL_SECRET, minted as this
// package always minted them. A v3 token is a compact JWS (ES256, a kid in the
// header) that Keyryx's approval key signed at grant time, verified from a key
// set the caller keeps cached. The rules after the signature are the same for
// both (checkClaims), so a v3 token binds exactly what a v2 token binds.
// CLAUDE.md invariants 4 and 41.

var (
	// ErrTokenUnknownKid means a v3 token names a kid the key set does not hold.
	// It is refused rather than tried against every key the set has.
	ErrTokenUnknownKid = errors.New("approval: token names a key that is not in the verified key set")
	// ErrTokenV2Retired means a v2 HMAC token was presented after its deadline,
	// or with v2 not accepted at all (a signer is set and no deadline is).
	ErrTokenV2Retired = errors.New("approval: v2 HMAC approval tokens are no longer accepted")
	// ErrNoKeys means a v3 token was presented to a verifier with no key set.
	ErrNoKeys = errors.New("approval: no key set is configured for v3 tokens")
	// ErrSigner means no token could be signed for a grant. Nothing was decided:
	// the hold stays pending and the grant can be made again.
	ErrSigner = errors.New("approval: the signing service could not sign the approval")
)

// Signer signs v3 approval tokens. Current names the kid the next signature will
// use, so the token header can carry it before the signature exists. Sign
// returns the kid that actually signed, and the caller checks that it is the one
// the header names.
type Signer interface {
	Current(ctx context.Context) (string, error)
	Sign(ctx context.Context, signingInput []byte) (string, []byte, error)
}

// KeySet resolves a kid to the public key the signing service published under
// it. An implementation returns only keys it has verified.
type KeySet interface {
	Key(kid string) (*ecdsa.PublicKey, bool)
}

// V2Rule says whether v2 HMAC tokens verify, and until when.
type V2Rule struct {
	// Accepted is whether a v2 token verifies at all.
	Accepted bool
	// Until, when not zero, is the instant from which a v2 token is refused.
	Until time.Time
}

// Keys is what approval tokens are minted and verified with.
//
// With Signer nil a grant mints v2 from Secret, as before. With Signer set a
// grant mints v3 through it, and Secret is needed only to verify v2 tokens
// still inside their window. A v3 token verifies against JWKS alone.
type Keys struct {
	Secret []byte
	Signer Signer
	JWKS   KeySet
	V2     V2Rule
}

// VerifyForCall checks token for a request that carries toolCallDigest (or ""
// when it carries no call). It never calls the signer.
func (k Keys) VerifyForCall(token, agentID, runID string, tools []string, estCostUSD float64, toolCallDigest string) error {
	c, err := k.parse(token)
	if err != nil {
		return err
	}
	return checkClaims(c, agentID, runID, tools, estCostUSD, toolCallDigest)
}

// VerifyBoundToCall is VerifyForCall for a hold that only an approval of the
// call itself may lift: a token that binds no call is refused (ErrTokenUnbound).
func (k Keys) VerifyBoundToCall(token, agentID, runID string, tools []string, estCostUSD float64, toolCallDigest string) error {
	c, err := k.parse(token)
	if err != nil {
		return err
	}
	if err := checkClaims(c, agentID, runID, tools, estCostUSD, toolCallDigest); err != nil {
		return err
	}
	if c.ToolCallDigest == "" {
		return ErrTokenUnbound
	}
	return nil
}

// parse dispatches on the token's shape: v2 has one dot, v3 has two. The
// signature is checked before any claim is read, in both.
func (k Keys) parse(token string) (claims, error) {
	switch strings.Count(token, ".") {
	case 1:
		return k.parseV2(token)
	case 2:
		return k.parseV3(token)
	default:
		return claims{}, ErrTokenMalformed
	}
}

func (k Keys) parseV2(token string) (claims, error) {
	if len(k.Secret) == 0 {
		return claims{}, ErrNoSecret
	}
	if !k.V2.Accepted || (!k.V2.Until.IsZero() && !time.Now().Before(k.V2.Until)) {
		return claims{}, ErrTokenV2Retired
	}
	payload, sig, _ := strings.Cut(token, ".")
	if payload == "" || sig == "" {
		return claims{}, ErrTokenMalformed
	}
	if !hmac.Equal([]byte(sig), []byte(sign(k.Secret, payload))) {
		return claims{}, ErrTokenSignature
	}
	body, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return claims{}, fmt.Errorf("%w: %v", ErrTokenMalformed, err)
	}
	var c claims
	if err := json.Unmarshal(body, &c); err != nil {
		return claims{}, fmt.Errorf("%w: %v", ErrTokenMalformed, err)
	}
	// The version is signed, so it is read after the signature and before
	// anything it decides the meaning of. Absent is the original format and
	// carries no digest; 2 carries one, required and well formed; nothing else
	// is understood, and an original-format token that nonetheless carries a
	// digest is not something this package mints, so it is refused.
	switch c.V {
	case 0:
		if c.ToolCallDigest != "" {
			return claims{}, fmt.Errorf("%w: a digest in the original format", ErrTokenVersion)
		}
	case tokenVersionToolCall:
		if !validToolCallDigest(c.ToolCallDigest) {
			return claims{}, fmt.Errorf("%w: no usable tool-call digest", ErrTokenMalformed)
		}
	default:
		return claims{}, fmt.Errorf("%w: %d", ErrTokenVersion, c.V)
	}
	return c, nil
}

// checkClaims is every check after the signature, and the same for v2 and v3.
// It reads the presented call's digest with a constant-time compare.
func checkClaims(c claims, agentID, runID string, tools []string, estCostUSD float64, toolCallDigest string) error {
	if time.Now().Unix() > c.Exp {
		return ErrTokenExpired
	}
	if c.AgentID != agentID || c.RunID != runID {
		return ErrTokenBinding
	}
	if !sameToolSet(c.Tools, sortedCopy(tools)) {
		return ErrTokenBinding
	}
	if c.ToolCallDigest != "" && !hmac.Equal([]byte(c.ToolCallDigest), []byte(toolCallDigest)) {
		return ErrTokenToolCall
	}
	if estCostUSD > c.MaxCostUSD {
		return fmt.Errorf("%w: approved ceiling %s exceeded by requested %s", ErrTokenCostExceeded, formatUSD(c.MaxCostUSD), formatUSD(estCostUSD))
	}
	return nil
}

// DecideWith resolves a pending approval as granted or denied, as Decide does,
// with the keys the grant mints with.
//
// A grant is signed before anything is written. If no token can be made the
// approval stays pending and the error is ErrSigner (or ErrNoSecret, ErrToolCallContext),
// so a human's grant is never recorded without the token it was for.
func DecideWith(ctx context.Context, st store.Store, keys Keys, id, decision, decidedBy, label string, ttl time.Duration) (store.Approval, string, error) {
	if decision != "grant" && decision != "deny" {
		return store.Approval{}, "", fmt.Errorf("%w: got %q", ErrInvalidDecision, decision)
	}
	if decision != "grant" {
		a, err := st.DecideApproval(ctx, id, decision, decidedBy, label, time.Now().UTC())
		return a, "", err
	}
	if keys.Signer == nil && len(keys.Secret) == 0 {
		return store.Approval{}, "", ErrNoSecret
	}
	pre, err := st.GetApproval(ctx, id)
	if err != nil {
		return store.Approval{}, "", err
	}
	digest, err := toolCallDigestFromContext(pre.Context)
	if err != nil {
		return store.Approval{}, "", err
	}
	if !pre.DecidedAt.IsZero() {
		return store.Approval{}, "", store.ErrAlreadyDecided
	}
	tools, cost := toolsFromContext(pre.Context), costFromContext(pre.Context)
	var tok string
	if keys.Signer != nil {
		tok, err = mintV3(ctx, keys.Signer, claims{AID: pre.ApprovalID, AgentID: pre.AgentID, RunID: pre.RunID,
			Tools: sortedCopy(tools), MaxCostUSD: cost, ToolCallDigest: digest}, ttl)
	} else {
		tok, _, err = MintApprovalTokenForCall(keys.Secret, pre.AgentID, pre.RunID, tools, cost, digest, ttl)
	}
	if err != nil {
		return store.Approval{}, "", err
	}
	a, err := st.DecideApproval(ctx, id, decision, decidedBy, label, time.Now().UTC())
	if err != nil {
		return store.Approval{}, "", err
	}
	return a, tok, nil
}
