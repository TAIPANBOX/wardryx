// Package store persists pending and decided approvals: the durable half of
// Wardryx's stateless human-in-the-loop design (see internal/approval). A
// hold creates one row here; a later admin decision updates it in place.
// Nothing about a hold parks a connection or blocks a goroutine waiting for
// a human -- the caller polls or is notified out of band, and the eventual
// grant is proven by a signed token (internal/approval), not by this store
// being consulted again on the hot path.
//
// Two implementations satisfy Store: Memory (used when no Postgres DSN is
// configured) and Postgres (pgx/v5, embedded schema.sql, additive
// migrations). Both have identical observable behavior, so callers -- the
// HTTP API, the approvals CLI -- depend only on the interface.
package store

import (
	"context"
	"errors"
	"time"
)

// Sentinel errors returned by Store implementations. Wrapped with
// additional context via fmt.Errorf's %w verb, so callers can branch with
// errors.Is.
var (
	// ErrNotFound means no approval exists with the given ApprovalID.
	ErrNotFound = errors.New("store: approval not found")
	// ErrAlreadyDecided means DecideApproval was called on an approval that
	// already carries a decision. An approval may be decided exactly once.
	ErrAlreadyDecided = errors.New("store: approval already decided")
)

// Approval is one pending or decided human-in-the-loop approval, the Go
// shape of one row of the `approvals` table (schema.sql).
type Approval struct {
	// ApprovalID uniquely identifies this approval. Assigned by
	// internal/approval when the hold is created.
	ApprovalID string
	// AgentID is the agent:// URI the held DecideRequest named.
	AgentID string
	// RunID is the run the held DecideRequest named.
	RunID string
	// RequestedAt is when the hold was created.
	RequestedAt time.Time
	// DecidedAt is the zero time until an admin decides the approval.
	DecidedAt time.Time
	// DecidedBy is the admin-supplied identifier of who decided it; empty
	// until decided.
	DecidedBy string
	// Decision is "" while pending, then "grant" or "deny" once decided.
	Decision string
	// Context carries the rest of the held request (tool_names, model,
	// est_cost_usd, attestation_method, on_behalf_of, the org that owns
	// this approval, and the Reason/PolicyVersion the PDP computed) as
	// free-form data, stored as the `context_json` column. internal/api
	// uses Context["org"] to scope GET /v1/approvals per caller, and
	// internal/approval uses Context["tool_names"] to rebind a minted
	// token to the exact tool set that was held.
	Context map[string]any
}

// Pending reports whether the approval has not yet been decided.
func (a Approval) Pending() bool { return a.Decision == "" }

// Store persists approvals. Implementations must make DecideApproval
// atomic: a second decision on an already-decided approval must fail with
// ErrAlreadyDecided rather than silently overwriting the first one, since
// the first decision may already have minted a live approval_token.
type Store interface {
	// CreateApproval inserts a new pending approval. ApprovalID must be
	// unique; Decision, DecidedAt, and DecidedBy on a must be zero values.
	CreateApproval(ctx context.Context, a Approval) error

	// GetApproval returns the approval with the given id, or ErrNotFound.
	GetApproval(ctx context.Context, id string) (Approval, error)

	// ListApprovals returns every approval (pending and decided), ordered
	// by RequestedAt ascending. Callers that need to scope the list (e.g.
	// by org) filter the result themselves using Approval.Context.
	ListApprovals(ctx context.Context) ([]Approval, error)

	// DecideApproval records decision ("grant" or "deny") and decidedBy
	// against the approval with the given id, and returns the updated
	// approval. It returns ErrNotFound if no such approval exists, or
	// ErrAlreadyDecided if it was already decided.
	DecideApproval(ctx context.Context, id, decision, decidedBy string, decidedAt time.Time) (Approval, error)

	// TryRedeem atomically claims key if (and only if) it has not already
	// been claimed, and reports whether this call was the one that did so:
	// true the first time a given key is presented, false on every
	// subsequent call with that same key. It is the check-and-set primitive
	// WARDRYX_APPROVAL_SINGLE_USE is built on (internal/api, keyed by
	// approval.RedemptionKey), and implementations must make it race-safe
	// under concurrent callers -- exactly one concurrent caller for a given
	// key may ever observe true.
	TryRedeem(ctx context.Context, key string) (bool, error)

	// Close releases any resources held by the store (e.g. a Postgres
	// connection pool). Memory's Close is a no-op.
	Close() error
}
