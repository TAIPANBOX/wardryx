package api

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/store"
)

// A hold is closed in three ways and no others (CLAUDE.md invariant 52): a person
// decides it (grant or deny, POST /v1/approvals/{id}/decide), wardryx closes it as
// expired once it has waited WARDRYX_HOLD_TTL, or the held agent withdraws it. An
// admin key closes nothing that is not a decision: the decide route takes only
// grant and deny, and the withdraw route refuses an admin key. Neither expired nor
// withdrawn mints a token, so the held call stays refused; its agent asks again
// and gets a new hold.

// DefaultHoldTTL is how long a hold waits for a person before wardryx closes it as
// expired. A day: longer than anybody leaves a queue they watch, and short enough
// that a hold left by a test or an agent that went away does not sit in the queue
// and under the pending cap (invariant 48) for good.
//
// Override with WARDRYX_HOLD_TTL.
const DefaultHoldTTL = 24 * time.Hour

// MinHoldTTL and MaxHoldTTL bound WARDRYX_HOLD_TTL. Under an hour a person who
// stepped away finds the hold gone; over a week the queue is a log.
const (
	MinHoldTTL = time.Hour
	MaxHoldTTL = 7 * 24 * time.Hour
)

// holdTTLEvery is how often WatchHoldTTL looks for holds past their time.
const holdTTLEvery = time.Minute

// holdTTLApprover is decided_by on a hold wardryx closed as expired. Not a key
// fingerprint and not a person: approverKindOf reads it as "system".
const holdTTLApprover = "wardryx:hold-ttl"

// withdrawnByPrefix starts decided_by on a hold its agent withdrew, followed by
// the agent id, which is the row's own.
const withdrawnByPrefix = "agent:"

// withdrawRoute names the withdraw route in a refusal's record and in the log.
const withdrawRoute = "/v1/approvals/{id}/withdraw"

// ParseHoldTTL reads WARDRYX_HOLD_TTL: unset is the default, anything else is a Go
// duration from MinHoldTTL to MaxHoldTTL, or an error serve refuses to start on.
// There is no value that turns the TTL off.
func ParseHoldTTL(raw string) (time.Duration, error) {
	if raw == "" {
		return DefaultHoldTTL, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < MinHoldTTL || d > MaxHoldTTL {
		return 0, fmt.Errorf("WARDRYX_HOLD_TTL is a duration from %s to %s, like 24h", MinHoldTTL, MaxHoldTTL)
	}
	return d, nil
}

// SetHoldTTL overrides [DefaultHoldTTL]. serve passes what ParseHoldTTL read.
func (s *Server) SetHoldTTL(d time.Duration) { s.holdTTL = d }

// WatchHoldTTL closes the holds past their time once at start and then once a
// minute until ctx ends, so a hold already in the database when this build starts
// is closed by the first check. It blocks, so callers run it in a goroutine. A
// store that cannot expire (no HoldExpirer) returns at once.
func (s *Server) WatchHoldTTL(ctx context.Context) {
	if _, ok := s.store.(store.HoldExpirer); !ok {
		return
	}
	s.expireHolds(ctx, time.Now())
	t := time.NewTicker(holdTTLEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.expireHolds(ctx, time.Now())
		}
	}
}

// expireHolds closes every pending hold requested at or before now minus the TTL,
// and writes one approval_expired for each hold the store says this call closed.
// The store returns a hold to exactly one caller, so two instances on one database
// never record one hold twice. The record is fail-open, as a grant's is (invariant
// 40): the row in the store is the durable record that the hold is closed.
func (s *Server) expireHolds(ctx context.Context, now time.Time) int {
	ex, ok := s.store.(store.HoldExpirer)
	if !ok {
		return 0
	}
	// A check has its whole interval to finish: a backlog is closed in batches.
	cctx, cancel := context.WithTimeout(ctx, holdTTLEvery)
	defer cancel()
	closed, err := ex.ExpireApprovals(cctx, now.Add(-s.holdTTL), holdTTLApprover, now.UTC())
	s.reportHoldTTL(err)
	for _, a := range closed {
		data := map[string]any{
			"approval_id":    a.ApprovalID,
			"waited_seconds": int64(a.DecidedAt.Sub(a.RequestedAt).Seconds()),
			"ttl_seconds":    int64(s.holdTTL.Seconds()),
			"decided_by":     a.DecidedBy,
		}
		if org, _ := a.Context["org"].(string); org != "" {
			data["org"] = org
		}
		s.emit(evApprovalExpired, event.SeverityMedium, a.AgentID, a.RunID, nil, data)
	}
	return len(closed)
}

// reportHoldTTL logs the first failed check of an outage and the first check that
// works after it, and nothing in between. The detail goes to the log only.
func (s *Server) reportHoldTTL(err error) {
	s.holdTTLMu.Lock()
	defer s.holdTTLMu.Unlock()
	switch {
	case err != nil && !s.holdTTLFailing:
		s.holdTTLFailing = true
		log.Printf("wardryx: holds past WARDRYX_HOLD_TTL could not be closed: %v; retrying every %s", err, holdTTLEvery)
	case err == nil && s.holdTTLFailing:
		s.holdTTLFailing = false
		log.Printf("wardryx: holds past WARDRYX_HOLD_TTL are being closed again")
	}
}

// approvalWithdrawRequestDTO is the body of POST /v1/approvals/{id}/withdraw: the
// agent and run the hold was made for, and, where wardryx verifies agent tokens,
// the agent's token and the DPoP proof it sent to the door (invariant 13).
type approvalWithdrawRequestDTO struct {
	AgentID        string `json:"agent_id"`
	RunID          string `json:"run_id"`
	AgentToken     string `json:"agent_token,omitempty"`
	AgentDPoPProof string `json:"agent_dpop_proof,omitempty"`
}

// handleApprovalWithdraw lets the held agent withdraw its own pending hold.
//
// Who may: a key that is not an admin's (an admin key is refused with 403 before
// the body is read: a person decides a hold, wardryx expires it, and an admin key
// does neither), that speaks for the agent the body names (invariant 36), whose
// org is the hold's, for the agent and run the hold names. With
// WARDRYX_AGENT_TOKEN_ISSUER set the agent's token and its DPoP proof are
// required and checked as on /v1/decide, before the hold is read, so a caller that
// is not the agent learns nothing about it. A hold of another agent, run or org is
// the same 404 as an id that does not exist; a hold already closed is 409.
func (s *Server) handleApprovalWithdraw(w http.ResponseWriter, r *http.Request, principal Principal) {
	if principal.isAdmin() {
		writeError(w, http.StatusForbidden, "an admin key does not withdraw a hold: a person decides it, or it expires")
		return
	}
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing approval id")
		return
	}
	var dto approvalWithdrawRequestDTO
	if !decodeJSONBody(w, r, &dto) {
		return
	}
	if dto.AgentID == "" || dto.RunID == "" {
		writeError(w, http.StatusBadRequest, "agent_id and run_id are required")
		return
	}
	if !s.allow.speaksFor(principal, dto.AgentID) {
		s.refuseAgent(w, principal, withdrawRoute, dto.AgentID, dto.RunID)
		return
	}
	if s.agentTokens != nil {
		// Claimed as agent-token, so a request with no token is refused
		// (agent_token_required): where tokens are verified, only the agent
		// withdraws.
		if _, ok := s.identitySourceFor(r.Context(), w, principal, withdrawRoute, dto.AgentID, dto.RunID,
			dto.AgentToken, dto.AgentDPoPProof, policy.IdentitySourceAgentToken); !ok {
			return
		}
	}

	existing, err := s.store.GetApproval(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "approval not found")
		return
	case err != nil:
		writeInternalError(w, "reading the approval", err)
		return
	}
	org, _ := existing.Context["org"].(string)
	if org != principal.Org || existing.AgentID != dto.AgentID || existing.RunID != dto.RunID {
		writeError(w, http.StatusNotFound, "approval not found")
		return
	}
	if !existing.Pending() {
		writeError(w, http.StatusConflict, "approval was already decided")
		return
	}

	withdrawn, err := s.store.DecideApproval(r.Context(), id, store.DecisionWithdrawn, withdrawnByPrefix+existing.AgentID, "", time.Now().UTC())
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "approval not found")
		return
	case errors.Is(err, store.ErrAlreadyDecided):
		writeError(w, http.StatusConflict, "approval was already decided")
		return
	case err != nil:
		writeInternalError(w, "withdrawing the approval", err)
		return
	}
	data := map[string]any{
		"approval_id":    withdrawn.ApprovalID,
		"decided_by":     withdrawn.DecidedBy,
		"key_fp":         principal.KeyFP,
		"waited_seconds": int64(withdrawn.DecidedAt.Sub(withdrawn.RequestedAt).Seconds()),
	}
	if org != "" {
		data["org"] = org
	}
	s.emit(evApprovalWithdrawn, event.SeverityInfo, withdrawn.AgentID, withdrawn.RunID, nil, data)
	writeJSON(w, http.StatusOK, approvalDecideResponseDTO{ApprovalID: withdrawn.ApprovalID, Decision: withdrawn.Decision})
}
