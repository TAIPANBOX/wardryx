// Package approval implements Wardryx's stateless human-in-the-loop flow.
//
// A "hold" decision never parks a connection or blocks a goroutine waiting
// for a human: internal/store records a pending row and the caller moves
// on. When an admin later grants it (POST /v1/approvals/{id}/decide), this
// package mints a short-lived approval_token bound to the exact
// (agent_id, run_id, tool-set) that was held, signed with HMAC-SHA256 over
// a server secret (WARDRYX_APPROVAL_SECRET). A subsequent /v1/decide call
// for that same action, presenting that token, is verified statelessly --
// no database lookup, no parked connection -- mirroring the stateless
// kill-switch pattern already used elsewhere in the TAIPANBOX stack.
//
// The secret is fail-closed: with WARDRYX_APPROVAL_SECRET unset, minting
// and verifying both refuse rather than accept, so a misconfigured
// deployment cannot silently treat every token as valid (or mint one nobody
// can ever redeem for something other than "invalid").
//
// A valid token is reusable for its full TTL against the same
// (agent_id, run_id, tool set) by default: fine for retry-tolerance, loose
// for spend governance. WARDRYX_APPROVAL_SINGLE_USE (internal/api, backed
// by internal/store's Store.TryRedeem) is an opt-in mode that lets a
// minted token allow exactly one /v1/decide call; see RedemptionKey.
package approval

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/store"
)

// DefaultTTL is how long a minted approval_token remains valid, per the
// spec's own example: 10 minutes from the grant.
const DefaultTTL = 10 * time.Minute

// Sentinel errors. Wrapped with additional context via fmt.Errorf's %w
// verb, so callers can branch with errors.Is.
var (
	// ErrNoSecret means WARDRYX_APPROVAL_SECRET is unset. Both minting and
	// verifying fail closed on it: an empty secret is never treated as "no
	// signature required."
	ErrNoSecret = errors.New("approval: WARDRYX_APPROVAL_SECRET is not configured")
	// ErrTokenMalformed means the token string isn't the shape this
	// package produces (missing separator, bad base64, bad JSON).
	ErrTokenMalformed = errors.New("approval: token is malformed")
	// ErrTokenSignature means the token's signature does not match its
	// payload under the configured secret: either it was signed with a
	// different secret, or it was tampered with.
	ErrTokenSignature = errors.New("approval: token signature is invalid")
	// ErrTokenExpired means the token's embedded expiry has passed.
	ErrTokenExpired = errors.New("approval: token has expired")
	// ErrTokenBinding means the token verified but does not carry the
	// same (agent_id, run_id, tool set) as the request it was presented
	// with.
	ErrTokenBinding = errors.New("approval: token does not match this agent_id/run_id/tool set")
	// ErrInvalidDecision means Decide was called with a decision other
	// than "grant" or "deny".
	ErrInvalidDecision = errors.New("approval: decision must be \"grant\" or \"deny\"")
)

// claims is the payload embedded in a minted approval_token: exactly the
// fields the token is bound to, plus its expiry and a random nonce. Tools is
// always stored sorted so Verify can compare it against a freshly sorted
// request tool set without caring about the order either side supplied them
// in.
//
// Nonce carries no meaning of its own and Verify never checks it; it exists
// purely so that two independent mints for the identical
// (agent_id, run_id, tools) with the same ttl -- e.g. a hold that is
// granted, exhausted under WARDRYX_APPROVAL_SINGLE_USE, and re-granted
// within the same wall-clock second, so Exp (second granularity) does not
// differ either -- still produce distinct token strings. Distinct token
// strings is exactly what RedemptionKey needs from two separate grants: see
// its doc comment.
type claims struct {
	AgentID string   `json:"agent_id"`
	RunID   string   `json:"run_id"`
	Tools   []string `json:"tools"`
	Exp     int64    `json:"exp"` // unix seconds
	Nonce   string   `json:"nonce"`
}

func sortedCopy(ss []string) []string {
	out := append([]string(nil), ss...)
	sort.Strings(out)
	return out
}

func sameToolSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// MintApprovalToken creates a signed, self-contained approval_token bound
// to (agentID, runID, tools) that expires after ttl. It returns ErrNoSecret
// if secret is empty: minting never silently produces an unsigned or
// weakly-signed token.
func MintApprovalToken(secret []byte, agentID, runID string, tools []string, ttl time.Duration) (token string, expiresAt time.Time, err error) {
	if len(secret) == 0 {
		return "", time.Time{}, ErrNoSecret
	}
	nonce, err := randomNonce()
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt = time.Now().Add(ttl)
	c := claims{AgentID: agentID, RunID: runID, Tools: sortedCopy(tools), Exp: expiresAt.Unix(), Nonce: nonce}
	body, err := json.Marshal(c)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("approval: marshal claims: %w", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	sig := sign(secret, payload)
	return payload + "." + sig, expiresAt, nil
}

// VerifyApprovalToken checks token's signature, expiry, and binding to
// (agentID, runID, tools). It returns nil when the token is valid; any
// non-nil error means the caller must not treat the action as approved.
// Verification is entirely stateless: no store lookup, matching the
// package's no-parked-connection design.
func VerifyApprovalToken(secret []byte, token, agentID, runID string, tools []string) error {
	if len(secret) == 0 {
		return ErrNoSecret
	}
	payload, sig, ok := strings.Cut(token, ".")
	if !ok || payload == "" || sig == "" {
		return ErrTokenMalformed
	}
	// Verify the signature over the still-encoded payload before decoding
	// or trusting any of its content.
	want := sign(secret, payload)
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return ErrTokenSignature
	}

	body, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTokenMalformed, err)
	}
	var c claims
	if err := json.Unmarshal(body, &c); err != nil {
		return fmt.Errorf("%w: %v", ErrTokenMalformed, err)
	}

	if time.Now().Unix() > c.Exp {
		return ErrTokenExpired
	}
	if c.AgentID != agentID || c.RunID != runID {
		return ErrTokenBinding
	}
	if !sameToolSet(c.Tools, sortedCopy(tools)) {
		return ErrTokenBinding
	}
	return nil
}

func sign(secret []byte, payload string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// randomNonce returns 8 random bytes (64 bits), hex-encoded, for claims.Nonce.
// It only has to make one mint's claims differ from another's, not resist a
// dedicated attacker (the token's HMAC signature is what actually secures
// it), so 64 bits of entropy is ample headroom for that.
func randomNonce() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("approval: generate nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// RedemptionKey returns a stable identifier for one specific minted
// approval_token, the sha256 hex digest of the token string itself. It is
// how WARDRYX_APPROVAL_SINGLE_USE (internal/api) tracks, via
// store.Store.TryRedeem, whether a given token has already been redeemed:
// the first /v1/decide to successfully claim a key wins, and any later
// presentation of that same token loses the claim.
//
// The key is deliberately derived from the whole token, not from the
// (agent_id, run_id, tool set) triple alone. Every mint embeds its own
// expiry in the signed claims, so two grants for the same triple -- e.g. a
// single-use token that was already spent, re-granted out of band per the
// package doc comment -- produce different token strings and therefore
// different keys. Keying only on the triple would instead make it
// redeemable exactly once ever, permanently blocking any later legitimate
// re-approval of the same agent/run/tool-set rather than just the exhausted
// grant.
//
// The key is not a secret and needs no HMAC: it never proves anything on
// its own (the token's own signature already does that), it only names a
// redemption slot, so collision resistance is all that is required.
func RedemptionKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// newApprovalID returns a fresh, random approval identifier: "ap_" followed
// by 32 hex characters (16 random bytes), unguessable enough that knowing
// one approval's id gives no purchase on any other.
func newApprovalID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("approval: generate id: %w", err)
	}
	return "ap_" + hex.EncodeToString(b), nil
}

// Request creates a new pending approval in st for a held decision: the
// PDP decided "hold" and the caller (internal/api) needs a fresh
// ApprovalID to return to the agent and to hand to an admin. tools is
// stored (sorted) in the returned/persisted Context under "tool_names" so a
// later grant can mint a token bound to the exact set that was held, and
// context carries the rest of the decision's context (org, model,
// est_cost_usd, attestation_method, on_behalf_of, reason, policy_version);
// a nil context is treated as empty.
func Request(ctx context.Context, st store.Store, agentID, runID string, tools []string, context map[string]any) (store.Approval, error) {
	id, err := newApprovalID()
	if err != nil {
		return store.Approval{}, err
	}
	full := make(map[string]any, len(context)+1)
	for k, v := range context {
		full[k] = v
	}
	full["tool_names"] = sortedCopy(tools)

	a := store.Approval{
		ApprovalID:  id,
		AgentID:     agentID,
		RunID:       runID,
		RequestedAt: time.Now().UTC(),
		Context:     full,
	}
	if err := st.CreateApproval(ctx, a); err != nil {
		return store.Approval{}, err
	}
	return a, nil
}

// Decide resolves a pending approval as granted or denied. On "deny", no
// secret is needed and the returned token is empty. On "grant", it mints an
// approval_token bound to the approval's original (agent_id, run_id,
// tool_names) via MintApprovalToken; if secret is empty the grant is
// refused before anything is written, per this package's fail-closed rule
// -- there is no such thing as a recorded grant with no usable token.
func Decide(ctx context.Context, st store.Store, secret []byte, id, decision, decidedBy string, ttl time.Duration) (approved store.Approval, token string, err error) {
	if decision != "grant" && decision != "deny" {
		return store.Approval{}, "", fmt.Errorf("%w: got %q", ErrInvalidDecision, decision)
	}
	if decision == "grant" && len(secret) == 0 {
		return store.Approval{}, "", ErrNoSecret
	}

	a, err := st.DecideApproval(ctx, id, decision, decidedBy, time.Now().UTC())
	if err != nil {
		return store.Approval{}, "", err
	}
	if decision != "grant" {
		return a, "", nil
	}

	tok, _, err := MintApprovalToken(secret, a.AgentID, a.RunID, toolsFromContext(a.Context), ttl)
	if err != nil {
		return a, "", err
	}
	return a, tok, nil
}

// toolsFromContext extracts the "tool_names" entry Request stamped onto an
// approval's Context. It tolerates both []string (a value that was never
// serialized, e.g. in a unit test building an Approval by hand) and []any
// of strings (what every real Context looks like once it has round-tripped
// through JSON -- store.Memory deep-copies via JSON too, so this is the
// only shape either backend actually produces).
func toolsFromContext(ctx map[string]any) []string {
	raw, ok := ctx["tool_names"]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}
