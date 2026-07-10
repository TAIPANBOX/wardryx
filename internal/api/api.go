// Package api is Wardryx's HTTP surface: POST /v1/decide (the decision
// engine), POST /v1/approvals/{id}/decide (admin-only grant/deny), GET
// /v1/approvals (org-scoped list), and GET /healthz.
//
// Every /v1/* route requires a bearer key (Authorization: Bearer <key>)
// resolved through ParseKeys, mirroring the Cloud plane's
// "key:org[:role]" convention; /healthz does not, matching Idryx's own
// unauthenticated liveness endpoint. Only the approvals-decide endpoint
// additionally requires the admin role.
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/wardryx/internal/approval"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/store"
)

// Event types Server emits (source "wardryx"), matching the spec's
// enumerated set exactly. See emit.
const (
	evPolicyAllow       = "policy_allow"
	evPolicyDeny        = "policy_deny"
	evApprovalRequested = "approval_requested"
	evApprovalGranted   = "approval_granted"
	evApprovalDenied    = "approval_denied"
	evApprovalTimeout   = "approval_timeout"
)

// Server is Wardryx's HTTP API.
type Server struct {
	engine            *pdp.Engine
	store             store.Store
	events            *event.Writer
	keys              map[string]Principal
	approvalSecret    []byte
	approvalTTL       time.Duration
	approvalSingleUse bool
}

// New returns a Server. events may be nil, which makes event emission a
// silent no-op (opt-in, per WARDRYX_EVENTS_PATH). keys should come from
// ParseKeys, which never returns an empty map. approvalSingleUse is
// WARDRYX_APPROVAL_SINGLE_USE (internal/config): false preserves the
// original behavior of a granted approval_token staying reusable for its
// full TTL; see handleDecide.
func New(engine *pdp.Engine, st store.Store, events *event.Writer, keys map[string]Principal, approvalSecret []byte, approvalSingleUse bool) *Server {
	return &Server{
		engine:            engine,
		store:             st,
		events:            events,
		keys:              keys,
		approvalSecret:    approvalSecret,
		approvalTTL:       approval.DefaultTTL,
		approvalSingleUse: approvalSingleUse,
	}
}

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("POST /v1/decide", s.requireAuth(s.handleDecide))
	mux.HandleFunc("POST /v1/approvals/{id}/decide", s.requireAdmin(s.handleApprovalDecide))
	mux.HandleFunc("GET /v1/approvals", s.requireAuth(s.handleListApprovals))
	return mux
}

func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// --- auth ---

// authedHandler is an http handler that has already been resolved to an
// authenticated Principal.
type authedHandler func(w http.ResponseWriter, r *http.Request, p Principal)

func (s *Server) authenticate(r *http.Request) (Principal, bool) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return Principal{}, false
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return Principal{}, false
	}
	p, ok := s.keys[token]
	return p, ok
}

func (s *Server) requireAuth(next authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.authenticate(r)
		if !ok {
			writeError(w, http.StatusUnauthorized, "missing or invalid bearer token")
			return
		}
		next(w, r, p)
	}
}

func (s *Server) requireAdmin(next authedHandler) http.HandlerFunc {
	return s.requireAuth(func(w http.ResponseWriter, r *http.Request, p Principal) {
		if p.Role != RoleAdmin {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		next(w, r, p)
	})
}

// --- POST /v1/decide ---

type decideRequestDTO struct {
	AgentID           string   `json:"agent_id"`
	RunID             string   `json:"run_id"`
	OnBehalfOf        []string `json:"on_behalf_of,omitempty"`
	ToolNames         []string `json:"tool_names,omitempty"`
	Domains           []string `json:"domains,omitempty"`
	Steps             int      `json:"steps,omitempty"`
	Model             string   `json:"model,omitempty"`
	EstCostUSD        float64  `json:"est_cost_usd,omitempty"`
	AttestationMethod string   `json:"attestation_method,omitempty"`
	ApprovalToken     string   `json:"approval_token,omitempty"`
}

type decideResponseDTO struct {
	Decision              string `json:"decision"`
	PolicyVersion         string `json:"policy_version"`
	Reason                string `json:"reason"`
	ApprovalID            string `json:"approval_id,omitempty"`
	ApprovalTokenRequired bool   `json:"approval_token_required"`
	// Cacheable mirrors pdp.DecideResponse.Cacheable onto the wire: whether
	// an enforcement point's own decision cache may store and later serve
	// this decision again for the same agent/tool set without calling
	// /v1/decide. No omitempty: false is exactly as meaningful as true
	// here, and must never be silently dropped from the response the way
	// an empty string field would be.
	Cacheable bool `json:"cacheable"`
}

func (s *Server) handleDecide(w http.ResponseWriter, r *http.Request, principal Principal) {
	var dto decideRequestDTO
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}
	if dto.AgentID == "" || dto.RunID == "" {
		writeError(w, http.StatusBadRequest, "agent_id and run_id are required")
		return
	}

	req := pdp.DecideRequest{
		AgentID:           dto.AgentID,
		RunID:             dto.RunID,
		OnBehalfOf:        dto.OnBehalfOf,
		ToolNames:         dto.ToolNames,
		Domains:           dto.Domains,
		Steps:             dto.Steps,
		Model:             dto.Model,
		EstCostUSD:        dto.EstCostUSD,
		AttestationMethod: dto.AttestationMethod,
		ApprovalToken:     dto.ApprovalToken,
	}
	resp := s.engine.Decide(req)

	// WARDRYX_APPROVAL_SINGLE_USE: an Allow with ApprovalTokenRequired set
	// only ever happens when a presented approval_token just verified (see
	// pdp.Engine.Decide's overThreshold branch -- that is the only path
	// that sets ApprovalTokenRequired and can still reach Allow). Off by
	// default, so this block never runs and the decision is returned
	// unchanged, exactly as before single-use mode existed: a valid token
	// stays reusable for its full TTL.
	//
	// When enabled, TryRedeem is the atomic check-and-set that lets a
	// token allow at most once: the first /v1/decide to claim this token's
	// RedemptionKey wins Allow, and any later presentation of that same
	// token -- a genuine retry or a race against it -- loses the claim and
	// falls back to a fresh Hold, indistinguishable from presenting no
	// token at all, rather than silently allowing a second time.
	if s.approvalSingleUse && resp.Decision == pdp.Allow && resp.ApprovalTokenRequired {
		redeemed, rErr := s.store.TryRedeem(r.Context(), approval.RedemptionKey(dto.ApprovalToken))
		if rErr != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to record approval_token redemption: %v", rErr))
			return
		}
		if !redeemed {
			resp.Decision = pdp.Hold
			resp.Reason = "approval_token was already redeemed once under WARDRYX_APPROVAL_SINGLE_USE; a new approval is required"
		}
	}

	switch resp.Decision {
	case pdp.Allow:
		s.emit(evPolicyAllow, event.SeverityInfo, req.AgentID, req.RunID, req.OnBehalfOf,
			map[string]any{"reason": resp.Reason, "tool_names": req.ToolNames})

	case pdp.Deny:
		s.emit(evPolicyDeny, event.SeverityHigh, req.AgentID, req.RunID, req.OnBehalfOf,
			map[string]any{"reason": resp.Reason, "tool_names": req.ToolNames})
		// A presented-but-expired approval_token is a more specific signal
		// than a generic deny: the human-in-the-loop window closed before
		// the agent redeemed it. Surfaced as its own event on top of the
		// policy_deny above, distinct from approval_requested (which
		// covers only a *fresh* hold).
		if dto.ApprovalToken != "" {
			verr := approval.VerifyApprovalToken(s.approvalSecret, dto.ApprovalToken, req.AgentID, req.RunID, req.ToolNames)
			if errors.Is(verr, approval.ErrTokenExpired) {
				s.emit(evApprovalTimeout, event.SeverityHigh, req.AgentID, req.RunID, req.OnBehalfOf,
					map[string]any{"reason": "presented approval_token had expired"})
			}
		}

	case pdp.Hold:
		held, err := approval.Request(r.Context(), s.store, req.AgentID, req.RunID, req.ToolNames, map[string]any{
			"org":                principal.Org,
			"model":              req.Model,
			"est_cost_usd":       req.EstCostUSD,
			"attestation_method": req.AttestationMethod,
			"on_behalf_of":       req.OnBehalfOf,
			"reason":             resp.Reason,
			"policy_version":     resp.PolicyVersion,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to record approval hold: %v", err))
			return
		}
		resp.ApprovalID = held.ApprovalID
		s.emit(evApprovalRequested, event.SeverityMedium, req.AgentID, req.RunID, req.OnBehalfOf,
			map[string]any{"approval_id": held.ApprovalID, "reason": resp.Reason})
	}

	writeJSON(w, http.StatusOK, decideResponseDTO{
		Decision:              resp.Decision,
		PolicyVersion:         resp.PolicyVersion,
		Reason:                resp.Reason,
		ApprovalID:            resp.ApprovalID,
		ApprovalTokenRequired: resp.ApprovalTokenRequired,
		Cacheable:             resp.Cacheable,
	})
}

// --- POST /v1/approvals/{id}/decide ---

type approvalDecideRequestDTO struct {
	Decision  string `json:"decision"`
	DecidedBy string `json:"decided_by"`
}

type approvalDecideResponseDTO struct {
	ApprovalID    string `json:"approval_id"`
	Decision      string `json:"decision"`
	ApprovalToken string `json:"approval_token,omitempty"`
}

func (s *Server) handleApprovalDecide(w http.ResponseWriter, r *http.Request, _ Principal) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing approval id")
		return
	}
	var dto approvalDecideRequestDTO
	if err := json.NewDecoder(r.Body).Decode(&dto); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}
	if dto.Decision != "grant" && dto.Decision != "deny" {
		writeError(w, http.StatusBadRequest, `decision must be "grant" or "deny"`)
		return
	}
	if dto.DecidedBy == "" {
		writeError(w, http.StatusBadRequest, "decided_by is required")
		return
	}

	decided, token, err := approval.Decide(r.Context(), s.store, s.approvalSecret, id, dto.Decision, dto.DecidedBy, s.approvalTTL)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "approval not found")
		return
	case errors.Is(err, store.ErrAlreadyDecided):
		writeError(w, http.StatusConflict, "approval was already decided")
		return
	case errors.Is(err, approval.ErrNoSecret):
		writeError(w, http.StatusInternalServerError, "WARDRYX_APPROVAL_SECRET is not configured; cannot grant")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if dto.Decision == "grant" {
		s.emit(evApprovalGranted, event.SeverityInfo, decided.AgentID, decided.RunID, nil,
			map[string]any{"approval_id": decided.ApprovalID, "decided_by": decided.DecidedBy})
	} else {
		s.emit(evApprovalDenied, event.SeverityHigh, decided.AgentID, decided.RunID, nil,
			map[string]any{"approval_id": decided.ApprovalID, "decided_by": decided.DecidedBy})
	}

	writeJSON(w, http.StatusOK, approvalDecideResponseDTO{
		ApprovalID:    decided.ApprovalID,
		Decision:      decided.Decision,
		ApprovalToken: token,
	})
}

// --- GET /v1/approvals ---

type approvalDTO struct {
	ApprovalID  string         `json:"approval_id"`
	AgentID     string         `json:"agent_id"`
	RunID       string         `json:"run_id"`
	RequestedAt string         `json:"requested_at"`
	DecidedAt   string         `json:"decided_at,omitempty"`
	DecidedBy   string         `json:"decided_by,omitempty"`
	Decision    string         `json:"decision,omitempty"`
	Pending     bool           `json:"pending"`
	Context     map[string]any `json:"context,omitempty"`
}

// handleListApprovals lists every approval belonging to the caller's org.
// Org scoping is applied here, not in internal/store: the schema's
// context_json column carries "org" (stamped at hold time from the
// authenticated principal, see handleDecide), and store stays a dumb,
// auth-agnostic persistence layer.
func (s *Server) handleListApprovals(w http.ResponseWriter, r *http.Request, principal Principal) {
	all, err := s.store.ListApprovals(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]approvalDTO, 0, len(all))
	for _, a := range all {
		if org, _ := a.Context["org"].(string); org != principal.Org {
			continue
		}
		dto := approvalDTO{
			ApprovalID:  a.ApprovalID,
			AgentID:     a.AgentID,
			RunID:       a.RunID,
			RequestedAt: a.RequestedAt.UTC().Format(time.RFC3339),
			DecidedBy:   a.DecidedBy,
			Decision:    a.Decision,
			Pending:     a.Pending(),
			Context:     a.Context,
		}
		if !a.DecidedAt.IsZero() {
			dto.DecidedAt = a.DecidedAt.UTC().Format(time.RFC3339)
		}
		out = append(out, dto)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RequestedAt < out[j].RequestedAt })
	writeJSON(w, http.StatusOK, out)
}

// --- helpers ---

type errorDTO struct {
	Error string `json:"error"`
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorDTO{Error: msg})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// emit writes one agent-event, source "wardryx". A nil Writer (events
// disabled: WARDRYX_EVENTS_PATH unset) makes this a no-op. A write failure
// is logged and dropped, fail-open, matching event.Writer's own contract
// and TokenFuse's exporter: event delivery never blocks or fails the
// decision path it is describing.
func (s *Server) emit(evType, severity, agentID, runID string, onBehalfOf []string, data map[string]any) {
	if s.events == nil {
		return
	}
	e := event.Event{
		Schema:     event.SchemaV02,
		TS:         time.Now().UTC().Format(time.RFC3339),
		Source:     "wardryx",
		Type:       evType,
		AgentID:    agentID,
		Severity:   severity,
		RunID:      runID,
		OnBehalfOf: onBehalfOf,
		Data:       data,
	}
	if err := s.events.Write(e); err != nil {
		log.Printf("wardryx: failed to write %s event: %v", evType, err)
	}
}
