// Package approval implements Wardryx's stateless human-in-the-loop flow.
//
// A "hold" decision never parks a connection or blocks a goroutine waiting
// for a human: internal/store records a pending row and the caller moves
// on. When an admin later grants it (POST /v1/approvals/{id}/decide), this
// package mints a short-lived approval_token bound to the exact
// (agent_id, run_id, tool-set) that was held, and to the est_cost_usd that
// triggered the hold as a cost ceiling (see claims.MaxCostUSD), signed with
// HMAC-SHA256 over a server secret (WARDRYX_APPROVAL_SECRET). A subsequent
// /v1/decide call for that same action, presenting that token, is verified
// statelessly -- no database lookup, no parked connection -- mirroring the
// stateless kill-switch pattern already used elsewhere in the TAIPANBOX
// stack.
//
// The secret is fail-closed: with WARDRYX_APPROVAL_SECRET unset, minting
// and verifying both refuse rather than accept, so a misconfigured
// deployment cannot silently treat every token as valid (or mint one nobody
// can ever redeem for something other than "invalid").
//
// When the held request carried a tool call (name, target, arguments), the
// token is also bound to a digest of that call (ToolCallDigest), so a person
// who approved "delete bucket X" has not approved "delete bucket Y" with the
// same tool; see claims.ToolCallDigest.
//
// A valid token is reusable for its full TTL against the same
// (agent_id, run_id, tool set), at the same or a lower est_cost_usd, by
// default: fine for retry-tolerance, and no longer loose for spend
// governance now that the cost ceiling is enforced too.
// WARDRYX_APPROVAL_SINGLE_USE (internal/api, backed by internal/store's
// Store.TryRedeem) is an opt-in mode that lets a minted token allow exactly
// one /v1/decide call; see RedemptionKey.
package approval

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
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
	// ErrTokenToolCall means the token verified and matched on agent, run and
	// tool set, but it was approved for a different tool call than the one
	// presented: another name, target, arguments or truncation, or a token
	// bound to a call presented on a request that carries none. The message
	// never carries either digest.
	ErrTokenToolCall = errors.New("approval: token was approved for a different tool call")
	// ErrTokenVersion means the token's signed version is not one this
	// build knows. It is refused rather than read as the nearest version it
	// resembles: a newer token may bind something this build cannot check.
	ErrTokenVersion = errors.New("approval: token version is not supported")
	// ErrToolCallContext means a held approval's context says it was about a
	// tool call but does not carry a usable digest of it. Granting it would
	// mint a token that binds nothing, so the grant is refused.
	ErrToolCallContext = errors.New("approval: the held tool call has no usable digest; refusing to grant an unbound approval")
	// ErrTokenCostExceeded means the token verified (signature, expiry,
	// and agent/run/tool-set binding all matched) but the request's
	// est_cost_usd exceeds the token's embedded MaxCostUSD: the ceiling a
	// human actually approved when the hold was granted, not merely the
	// policy threshold it crossed. A token minted before MaxCostUSD
	// existed decodes to a ceiling of 0, so it hits this same error for
	// any positive est_cost_usd; see claims' doc comment.
	ErrTokenCostExceeded = errors.New("approval: token's approved cost ceiling is exceeded by the requested cost")
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
// MaxCostUSD is the est_cost_usd that actually triggered the hold this
// token grants (see Decide and costFromContext), not merely the policy
// threshold it exceeded. It is a ceiling, not an exact-match value:
// VerifyApprovalToken accepts any presented est_cost_usd up to and
// including it, so a legitimate retry at the same or a lower cost still
// works, but rejects anything higher. A decoded MaxCostUSD of zero -- which
// is exactly what a token minted before this field existed decodes to, since
// it is simply absent from that token's JSON -- is deliberately never
// treated as "no ceiling"; see VerifyApprovalToken.
//
// Nonce carries no meaning of its own and Verify never checks it; it exists
// purely so that two independent mints for the identical
// (agent_id, run_id, tools) with the same ttl -- e.g. a hold that is
// granted, exhausted under WARDRYX_APPROVAL_SINGLE_USE, and re-granted
// within the same wall-clock second, so Exp (second granularity) does not
// differ either -- still produce distinct token strings. Distinct token
// strings is exactly what RedemptionKey needs from two separate grants: see
// its doc comment.
//
// V and ToolCallDigest are the tool-call binding (added after 1.1.3). V is the
// signed format version: absent (0) is the format every earlier token has and
// carries no ToolCallDigest; 2 is the format that does, and its digest is
// required. Any other V is refused (ErrTokenVersion). A token minted for a
// hold whose request carried no tool call is minted exactly as before, with
// neither field, so it verifies on any build and on a request with no tool
// call exactly as it always did.
//
// ToolCallDigest is ToolCallDigest(name, target, arguments, truncated) of the
// call a person was shown when the hold was granted. VerifyApprovalTokenForCall
// requires the presented request's digest to equal it, and requires a request
// with no tool call to present none only when the token has none.
type claims struct {
	AgentID        string   `json:"agent_id"`
	RunID          string   `json:"run_id"`
	Tools          []string `json:"tools"`
	MaxCostUSD     float64  `json:"max_cost_usd"`
	Exp            int64    `json:"exp"` // unix seconds
	Nonce          string   `json:"nonce"`
	V              int      `json:"v,omitempty"`
	ToolCallDigest string   `json:"tcd,omitempty"`
}

// tokenVersionToolCall is the claims version that carries a ToolCallDigest.
const tokenVersionToolCall = 2

// toolCallDigestHexLen is the length of a hex sha-256.
const toolCallDigestHexLen = 64

// ArgumentsSHA256 is the sha-256, in hex, of a tool call's arguments exactly
// as received. internal/api records it as tool_call.arguments_sha256 in every
// decision event, and ToolCallDigest folds the same value into the digest a
// token is bound to, so an auditor holding the event can recompute what the
// person approved.
func ArgumentsSHA256(arguments []byte) string {
	sum := sha256.Sum256(arguments)
	return hex.EncodeToString(sum[:])
}

// ToolCallDigest is the digest an approval is bound to: a sha-256 over a
// canonical encoding of the tool call's name, target, the sha-256 of its
// arguments (ArgumentsSHA256's value, as raw bytes) and whether the
// enforcement point truncated them.
//
// The encoding is a fixed domain tag, then each of name and target preceded by
// its 8-byte big-endian length, then the 32 argument-hash bytes, then one byte
// for the truncated flag. The lengths make it unambiguous: name "ab" with
// target "c" and name "a" with target "bc" are different calls and different
// digests, which plain concatenation would not give. Nothing is trimmed or
// case-folded: a different byte is a different call, and the only error that
// can follow is a refused approval, never a wrongly granted one.
//
// A call whose arguments were truncated carries none, so its digest binds only
// name and target (and the flag). That is the most an approval can say about a
// call whose arguments were too large to send.
func ToolCallDigest(name, target string, arguments []byte, truncated bool) string {
	h := sha256.New()
	h.Write([]byte("wardryx.tool-call.v1"))
	var n [8]byte
	for _, f := range []string{name, target} {
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		h.Write(n[:])
		h.Write([]byte(f))
	}
	args := sha256.Sum256(arguments)
	h.Write(args[:])
	if truncated {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// validToolCallDigest reports whether s has the shape ToolCallDigest returns.
func validToolCallDigest(s string) bool {
	if len(s) != toolCallDigestHexLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
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
// to (agentID, runID, tools, maxCostUSD) that expires after ttl. maxCostUSD
// is the ceiling the token authorizes: VerifyApprovalToken rejects any
// presented est_cost_usd greater than it. It returns ErrNoSecret if secret
// is empty: minting never silently produces an unsigned or weakly-signed
// token.
//
// The token is bound to no tool call. Use MintApprovalTokenForCall for a hold
// whose request carried one.
func MintApprovalToken(secret []byte, agentID, runID string, tools []string, maxCostUSD float64, ttl time.Duration) (token string, expiresAt time.Time, err error) {
	return MintApprovalTokenForCall(secret, agentID, runID, tools, maxCostUSD, "", ttl)
}

// MintApprovalTokenForCall is MintApprovalToken for a hold whose request
// carried a tool call: a non-empty toolCallDigest (ToolCallDigest's value)
// is signed into the token, in the versioned format, and the token verifies
// only against a request presenting the same digest. An empty digest mints
// the format every earlier token has. A non-empty one that is not a hex
// sha-256 is refused rather than signed, since a token that binds a value
// nothing can ever present would be a silent denial.
func MintApprovalTokenForCall(secret []byte, agentID, runID string, tools []string, maxCostUSD float64, toolCallDigest string, ttl time.Duration) (token string, expiresAt time.Time, err error) {
	if len(secret) == 0 {
		return "", time.Time{}, ErrNoSecret
	}
	if toolCallDigest != "" && !validToolCallDigest(toolCallDigest) {
		return "", time.Time{}, ErrToolCallContext
	}
	nonce, err := randomNonce()
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt = time.Now().Add(ttl)
	c := claims{AgentID: agentID, RunID: runID, Tools: sortedCopy(tools), MaxCostUSD: maxCostUSD, Exp: expiresAt.Unix(), Nonce: nonce}
	if toolCallDigest != "" {
		c.V = tokenVersionToolCall
		c.ToolCallDigest = toolCallDigest
	}
	body, err := json.Marshal(c)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("approval: marshal claims: %w", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	sig := sign(secret, payload)
	return payload + "." + sig, expiresAt, nil
}

// VerifyApprovalToken checks token's signature, expiry, binding to
// (agentID, runID, tools), and that estCostUSD does not exceed the token's
// approved cost ceiling. It returns nil when the token is valid; any
// non-nil error means the caller must not treat the action as approved.
// Verification is entirely stateless: no store lookup, matching the
// package's no-parked-connection design.
//
// The cost check is a ceiling, not an exact match (see claims.MaxCostUSD's
// doc comment): estCostUSD up to and including the token's embedded
// MaxCostUSD passes, so a legitimate retry at the same or a lower cost
// still works. A token minted before MaxCostUSD existed decodes it as the
// Go zero value (0), and that is deliberately never treated as "no
// ceiling": it fails closed against any positive estCostUSD, exactly like a
// ceiling of 0 would. Tokens are short-lived (DefaultTTL, 10 minutes), so
// refusing a pre-existing token still in flight across a deploy of this
// change is an acceptable, bounded cost for closing the gap where such a
// token would otherwise go on authorizing unbounded spend.
//
// This function is for a request that carries no tool call: it accepts a token
// bound to none and refuses one bound to a call. The decision path never uses
// it (VerifyApprovalTokenForCall, which every caller outside this package
// must use, is the one that takes the call; a test holds that), and it is kept
// for the no-tool-call contract and its existing tests.
func VerifyApprovalToken(secret []byte, token, agentID, runID string, tools []string, estCostUSD float64) error {
	return VerifyApprovalTokenForCall(secret, token, agentID, runID, tools, estCostUSD, "")
}

// VerifyApprovalTokenForCall is VerifyApprovalToken for a request that may
// carry a tool call: toolCallDigest is ToolCallDigest of the presented call,
// or "" when the request carries none.
//
// A token bound to a call verifies only when toolCallDigest is equal to it,
// compared in constant time; a different call, or no call at all, is
// ErrTokenToolCall. A token bound to no call verifies exactly as it always
// has, on a request with no tool call. A token with no digest on a request that
// does carry one also verifies, as it always has: it was granted for a request
// that carried no call, so nobody was shown one, and it binds agent, run, tool
// set and cost, which is all it ever claimed.
func VerifyApprovalTokenForCall(secret []byte, token, agentID, runID string, tools []string, estCostUSD float64, toolCallDigest string) error {
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

	// The version is signed, so it is read after the signature and before
	// anything it decides the meaning of. Absent is the original format and
	// carries no digest; 2 carries one, required and well formed; nothing else
	// is understood, and an original-format token that nonetheless carries a
	// digest is not something this package mints, so it is refused.
	switch c.V {
	case 0:
		if c.ToolCallDigest != "" {
			return fmt.Errorf("%w: a digest in the original format", ErrTokenVersion)
		}
	case tokenVersionToolCall:
		if !validToolCallDigest(c.ToolCallDigest) {
			return fmt.Errorf("%w: no usable tool-call digest", ErrTokenMalformed)
		}
	default:
		return fmt.Errorf("%w: %d", ErrTokenVersion, c.V)
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
	if c.ToolCallDigest != "" && !hmac.Equal([]byte(c.ToolCallDigest), []byte(toolCallDigest)) {
		return ErrTokenToolCall
	}
	if estCostUSD > c.MaxCostUSD {
		return fmt.Errorf("%w: approved ceiling %s exceeded by requested %s", ErrTokenCostExceeded, formatUSD(c.MaxCostUSD), formatUSD(estCostUSD))
	}
	return nil
}

// formatUSD renders a USD amount for this error's text with just enough
// precision that a sub-cent value is never misread as a different amount
// (or, worse, as an actual zero). Byte-for-byte the same algorithm as
// internal/pdp's formatUSD (CLAUDE.md invariant 22), duplicated rather than
// imported: internal/pdp already imports internal/approval on the approval
// branch (invariant 1's documented transitive path, pdp -> approval ->
// store -> pgx), so the reverse import would be a cycle.
//
// Measured 2026-09-27, the same day invariant 22 fixed pdp's two policy-cost
// reasons: a token's MaxCostUSD of $0.0005 and an estCostUSD of $0.0016 both
// printed as "$0.00" under a plain "%.2f", so ErrTokenCostExceeded read
// "approved ceiling $0.00 exceeded by requested $0.00", indistinguishable
// from an actual zero ceiling and no help at all in explaining the refusal.
//
// The common case (a whole number of cents) still prints exactly as before,
// "$100.00"; only a value the two-decimal form cannot represent exactly
// falls back to the shortest exact decimal representation.
func formatUSD(v float64) string {
	// Round to the micro-dollar, the unit money is counted in, and drop
	// trailing zeros: a computed amount carries float64 noise
	// ("0.0055000000000000005"), which is not a figure anybody set.
	micro := strings.TrimRight(strings.TrimRight(strconv.FormatFloat(v, 'f', 6, 64), "0"), ".")
	r, err := strconv.ParseFloat(micro, 64)
	if err != nil {
		return "$" + strconv.FormatFloat(v, 'f', -1, 64)
	}
	// Below a micro-dollar but not zero: never print it as zero, which is
	// the defect this function exists to prevent.
	if r == 0 && v != 0 {
		return "$" + strconv.FormatFloat(v, 'g', -1, 64)
	}
	// A whole number of cents keeps the familiar two-decimal form.
	if twoDecimals := strconv.FormatFloat(r, 'f', 2, 64); mustParse(twoDecimals) == r {
		return "$" + twoDecimals
	}
	return "$" + micro
}

// mustParse reads back a decimal strconv itself just formatted.
func mustParse(s string) float64 {
	f, _ := strconv.ParseFloat(s, 64)
	return f
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
// tool_names) and, when the held request carried a tool call, to the digest
// of that call (ContextKeyToolCall, ErrToolCallContext), with MaxCostUSD set to the est_cost_usd that triggered the
// hold (see costFromContext) -- the amount a human is actually approving,
// not merely the policy threshold it exceeded -- via MintApprovalToken; if
// secret is empty the grant is refused before anything is written, per this
// package's fail-closed rule -- there is no such thing as a recorded grant
// with no usable token.
func Decide(ctx context.Context, st store.Store, secret []byte, id, decision, decidedBy string, ttl time.Duration) (approved store.Approval, token string, err error) {
	if decision != "grant" && decision != "deny" {
		return store.Approval{}, "", fmt.Errorf("%w: got %q", ErrInvalidDecision, decision)
	}
	if decision == "grant" && len(secret) == 0 {
		return store.Approval{}, "", ErrNoSecret
	}
	if decision == "grant" {
		// Refuse before writing anything: a hold that was about a tool call
		// must be granted bound to it, never as a token that binds nothing
		// because its context was damaged. The approval stays pending.
		pre, err := st.GetApproval(ctx, id)
		if err != nil {
			return store.Approval{}, "", err
		}
		if _, err := toolCallDigestFromContext(pre.Context); err != nil {
			return store.Approval{}, "", err
		}
	}

	a, err := st.DecideApproval(ctx, id, decision, decidedBy, time.Now().UTC())
	if err != nil {
		return store.Approval{}, "", err
	}
	if decision != "grant" {
		return a, "", nil
	}

	digest, err := toolCallDigestFromContext(a.Context)
	if err != nil {
		return a, "", err
	}
	tok, _, err := MintApprovalTokenForCall(secret, a.AgentID, a.RunID, toolsFromContext(a.Context), costFromContext(a.Context), digest, ttl)
	if err != nil {
		return a, "", err
	}
	return a, tok, nil
}

// ContextKeyToolCall is the key under which internal/api stamps the held
// call's name, target, truncation flag and digest onto an approval's context
// (never its arguments). It is what a person deciding the hold is shown and
// what Decide binds the minted token to. Absent when the held request carried
// no tool call.
const ContextKeyToolCall = "tool_call"

// ContextKeyDigest is the digest's key inside the ContextKeyToolCall entry.
const ContextKeyDigest = "digest"

// toolCallDigestFromContext reads the digest the hold bound. No tool_call
// entry means the held request carried none: "" and no error. An entry that is
// there but is not a map holding a well-formed digest is ErrToolCallContext:
// the one thing it must never become is an empty digest, which would mint a
// token that binds nothing for a call a person was shown.
func toolCallDigestFromContext(ctx map[string]any) (string, error) {
	raw, ok := ctx[ContextKeyToolCall]
	if !ok {
		return "", nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return "", ErrToolCallContext
	}
	d, ok := m[ContextKeyDigest].(string)
	if !ok || !validToolCallDigest(d) {
		return "", ErrToolCallContext
	}
	return d, nil
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

// costFromContext extracts the "est_cost_usd" entry api.go stamped onto a
// held approval's Context (handleDecide's approval.Request call), the
// estimated cost that actually triggered the hold and therefore the
// ceiling Decide mints the grant's approval_token against. A JSON number
// decoded into a map[string]any is always a float64 -- unlike
// toolsFromContext's Tools, there is no []any-style wrinkle here from
// round-tripping through JSON, but a value that was never serialized at
// all (e.g. a unit test building an Approval by hand with an int or no
// entry) is tolerated by falling back to 0.
func costFromContext(ctx map[string]any) float64 {
	raw, ok := ctx["est_cost_usd"]
	if !ok {
		return 0
	}
	switch v := raw.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	default:
		return 0
	}
}
