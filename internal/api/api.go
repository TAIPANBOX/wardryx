// Package api is Wardryx's HTTP surface: POST /v1/decide (the decision
// engine), POST /v1/approvals/{id}/decide (admin-only grant/deny), GET
// /v1/approvals (org-scoped list), the admin-only policy-as-code routes
// under /v1/policies (see "Policy-as-code" below), and GET /healthz.
//
// Every /v1/* route requires a bearer key (Authorization: Bearer <key>)
// resolved through ParseKeys, mirroring the Cloud plane's
// "key:org[:role]" convention; /healthz does not, matching Idryx's own
// unauthenticated liveness endpoint. The approvals-decide and every
// /v1/policies route additionally require the admin role.
//
// # Policy-as-code
//
// Wardryx's original policy source is a file (-policy/WARDRYX_POLICY),
// loaded once at startup and never hot-reloaded -- pdp.Engine.SetPolicies
// exists to change that, and this package is what calls it. A Server's
// basePolicies (the file-loaded Set's own Policies(), fixed at
// construction) and its Store's currently-persisted PolicyRecords are
// ALWAYS combined and recompiled together (see recomputePolicySet): the
// file-loaded rules are a permanent floor that no API write can ever make
// disappear, and the store holds only the operator-managed layer on top of
// it. Every successful PUT or DELETE under /v1/policies recomputes and
// swaps the live Engine's policy set atomically; a request that would
// produce an invalid combined set (see policy.Compile) is rejected before
// anything is persisted or swapped, so a bad write can never partially
// apply -- the same "malformed policy is a hard error" rule the file path
// already enforces.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/wardryx/internal/approval"
	"github.com/TAIPANBOX/wardryx/internal/archive"
	wotel "github.com/TAIPANBOX/wardryx/internal/otel"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
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
	// A hold that nobody has decided. Named for what happened rather than
	// for a clock: `approval_timeout` is already taken and means something
	// else entirely (an agent redeeming a token whose window had closed,
	// which usually means a human DID decide and the agent came back late),
	// and `approval_stale` would say the approval decayed when in fact
	// nothing decayed: nobody answered.
	evApprovalUnanswered = "approval_unanswered"
	evPolicyUpdated      = "policy_updated"
)

// systemAgentID is the agent_id agent-event's schema requires on every
// event (agent-passport SPEC.md Sec 3.1: a well-formed agent:// URI).
// evPolicyUpdated describes an admin action against the policy-as-code API
// itself, not any one governed agent's behavior, so there is no real
// agent_id to report -- this synthetic identity names the API as its own
// well-formed subject rather than leaving the field empty (which would
// make the event schema-invalid) or borrowing an unrelated agent's id.
const systemAgentID = "agent://wardryx.internal/admin/policy-api"

// Server is Wardryx's HTTP API.
type Server struct {
	engine            *pdp.Engine
	store             store.Store
	events            *event.ChainedWriter
	otel              *wotel.Exporter
	keys              map[string]Principal
	approvalSecret    []byte
	approvalTTL       time.Duration
	approvalSingleUse bool
	// basePolicies is the file-loaded policy set's own rules, fixed at
	// construction: the permanent floor recomputePolicySet always layers
	// the store's operator-managed policies on top of. See the package doc
	// comment's "Policy-as-code" section.
	basePolicies []policy.Policy
	// policyArchive keeps every set this server makes effective. Nil means
	// archiving is off; see SetPolicyArchive.
	policyArchive *archive.Archive

	// How long a hold may sit undecided before it is worth telling somebody,
	// and which holds have already been reported.
	//
	// The marker is in memory on purpose. Persisting it would mean a schema
	// change to carry a bit that only prevents a repeat, and a restart
	// re-announcing "these holds are still unanswered" is not noise: it is
	// the current truth, said again by a process that has just lost its
	// memory of saying it. Consumers that dedup by condition absorb it.
	unansweredAfter time.Duration
	unansweredMu    sync.Mutex
	unansweredSeen  map[string]bool
}

// New returns a Server. events may be nil, which makes event emission a
// silent no-op (opt-in, per WARDRYX_EVENTS_PATH). otel may also be nil,
// which makes OTLP span export a silent no-op (opt-in, per
// WARDRYX_OTLP_ENDPOINT; see internal/otel and exportSpan). keys should
// come from ParseKeys, which never returns an empty map. approvalSingleUse
// is WARDRYX_APPROVAL_SINGLE_USE (internal/config): false preserves the
// original behavior of a granted approval_token staying reusable for its
// full TTL; see handleDecide. basePolicies is normally the file-loaded
// policy.Set's own Policies() (cmd/wardryx passes policies.Policies()); nil
// or empty is valid and means the file path (-policy unset, or set to an
// empty policy set) contributes no fixed floor, so the admin policy API
// alone determines what Engine decides against.
func New(engine *pdp.Engine, st store.Store, events *event.ChainedWriter, otel *wotel.Exporter, keys map[string]Principal, approvalSecret []byte, approvalSingleUse bool, basePolicies []policy.Policy) *Server {
	return &Server{
		engine:            engine,
		store:             st,
		events:            events,
		otel:              otel,
		keys:              keys,
		approvalSecret:    approvalSecret,
		approvalTTL:       approval.DefaultTTL,
		approvalSingleUse: approvalSingleUse,
		basePolicies:      basePolicies,
		unansweredAfter:   DefaultUnansweredAfter,
		unansweredSeen:    map[string]bool{},
	}
}

// DefaultUnansweredAfter is how long a hold may sit undecided before wardryx
// says so. Fifteen minutes, because a granted approval_token lives ten
// (approval.DefaultTTL): a hold that has outlived a whole token window has
// already cost the agent any chance of acting promptly on a yes.
//
// Override with WARDRYX_APPROVAL_UNANSWERED_AFTER.
const DefaultUnansweredAfter = 15 * time.Minute

// SetUnansweredAfter overrides [DefaultUnansweredAfter]. Zero or negative
// disables the sweep entirely, which is a real choice: an operator who watches
// the approval queue themselves does not need to be told about it.
func (s *Server) SetUnansweredAfter(d time.Duration) { s.unansweredAfter = d }

// SetPolicyArchive attaches the archive that keeps every policy set this
// server makes effective, and immediately keeps the set already in force:
// that set decides from the first request, so an archive recording only
// later swaps would leave every decision before the first edit
// unexaminable.
//
// Attaching nothing is allowed and is the default. What a deployment loses
// then is the ability to replay its own recorded decisions, because the
// PolicyVersion those events name will have no rules behind it.
func (s *Server) SetPolicyArchive(a *archive.Archive) error {
	s.policyArchive = a
	return a.Keep(s.engine.CurrentSet())
}

// WatchUnansweredApprovals reports a hold that nobody has decided.
//
// A SWEEP rather than a check on the request path, and that is the whole
// design: this condition is defined by the ABSENCE of activity, so a check
// that only runs when a request arrives cannot see the case it exists for. The
// hold that nobody answered is exactly the hold nobody is asking about.
//
// It REPORTS and never decides. An event that quietly converted an unanswered
// hold into a denial would be a behaviour change hiding inside an
// observability feature, and the agent's action stays held exactly as the
// policy engine left it.
//
// One event per hold per process lifetime; see the note on `unansweredSeen`.
// Blocks until ctx is done, so callers run it in a goroutine.
func (s *Server) WatchUnansweredApprovals(ctx context.Context) {
	if s.unansweredAfter <= 0 {
		return
	}
	t := time.NewTicker(sweepInterval(s.unansweredAfter))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweepUnansweredApprovals(ctx, time.Now())
		}
	}
}

// sweepInterval is how often the watcher looks, given the threshold it is
// watching for. Often enough that the report is timely, rarely enough that an
// idle wardryx is not listing approvals every second.
//
// Extracted from the loop so the two clamps can be read and tested without
// waiting for a ticker. Both of them are the kind of arithmetic that is
// obviously right until the day it is not: a threshold under four seconds
// would otherwise tick faster than once a second, and a threshold of a day
// would sweep every six hours and report a hold long after anybody cared.
func sweepInterval(threshold time.Duration) time.Duration {
	interval := threshold / 4
	if interval > time.Minute {
		interval = time.Minute
	}
	if interval < time.Second {
		interval = time.Second
	}
	return interval
}

func (s *Server) sweepUnansweredApprovals(ctx context.Context, now time.Time) {
	all, err := s.store.ListApprovals(ctx)
	if err != nil {
		// A store that cannot be listed is already reported elsewhere, and a
		// sweep that logs on every tick would drown it.
		return
	}
	pending := make(map[string]bool, len(all))
	for _, a := range all {
		if a.Pending() {
			pending[a.ApprovalID] = true
		}
		if !a.Pending() || now.Sub(a.RequestedAt) < s.unansweredAfter {
			continue
		}
		s.unansweredMu.Lock()
		seen := s.unansweredSeen[a.ApprovalID]
		if !seen {
			s.unansweredSeen[a.ApprovalID] = true
		}
		s.unansweredMu.Unlock()
		if seen {
			continue
		}
		s.emit(evApprovalUnanswered, event.SeverityHigh, a.AgentID, a.RunID, nil,
			map[string]any{
				"approval_id": a.ApprovalID,
				"waiting_s":   int(now.Sub(a.RequestedAt).Seconds()),
				"threshold_s": int(s.unansweredAfter.Seconds()),
			})
	}
	s.forgetDecidedApprovals(pending)
}

// forgetDecidedApprovals drops markers for approvals that are no longer
// pending, so the map cannot grow for the life of the process. Done at the end
// of each sweep rather than when this replica decides one, because a hold can
// also be decided by another replica or straight in the store.
func (s *Server) forgetDecidedApprovals(pending map[string]bool) {
	s.unansweredMu.Lock()
	defer s.unansweredMu.Unlock()
	for id := range s.unansweredSeen {
		if !pending[id] {
			delete(s.unansweredSeen, id)
		}
	}
}

// Handler returns the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz)
	mux.HandleFunc("POST /v1/decide", s.requireAuth(s.handleDecide))
	mux.HandleFunc("POST /v1/approvals/{id}/decide", s.requireAdmin(s.handleApprovalDecide))
	mux.HandleFunc("GET /v1/approvals", s.requireAuth(s.handleListApprovals))
	mux.HandleFunc("GET /v1/status", s.requireAuth(s.handleStatus))
	mux.HandleFunc("GET /v1/policies", s.requireAdmin(s.handleListPolicies))
	mux.HandleFunc("GET /v1/policies/{id}", s.requireAdmin(s.handleGetPolicy))
	mux.HandleFunc("PUT /v1/policies/{id}", s.requireAdmin(s.handlePutPolicy))
	mux.HandleFunc("DELETE /v1/policies/{id}", s.requireAdmin(s.handleDeletePolicy))
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
	// ChainProven: the enforcement point VERIFIED this request's delegation
	// proof (agent-passport SPEC 5.2) before calling. Absent means it did
	// not, never "it did and forgot to say": a default of true would make
	// every caller that has not been upgraded look like one that verifies.
	ChainProven   bool   `json:"chain_proven,omitempty"`
	ApprovalToken string `json:"approval_token,omitempty"`
}

// decisionInput is the question a decision answered: every input Decide read,
// plus the two facts a replay compares itself against. It exists so a recorded
// decision can be re-evaluated against a different policy version without
// guessing what was asked. A record that keeps only the verdict replays as
// whatever the missing fields default to, and those defaults are permissive:
// a denial that turned on Domains replays as an allow once Domains is gone.
//
// Two omissions, both deliberate and both load-bearing:
//
//   - agent_id, run_id and on_behalf_of are typed members of the shared
//     envelope and are read from there. Repeating them here would put one
//     fact in a typed field and in the erasable payload plane at once, and
//     the estate's record mapper documents that split as a MUST.
//   - ApprovalToken is a live credential. This record is append-only,
//     replicated, and outlives any token's TTL, so writing one down turns a
//     short-lived secret into a permanent one. A replay does not need it:
//     whether a token verified is already visible in Decision and Reason.
//
// TestDecisionInputCoversEveryDecideRequestField holds this to the shape of
// pdp.DecideRequest itself, so a new PDP input cannot quietly skip the record.
func decisionInput(req pdp.DecideRequest, resp pdp.DecideResponse) map[string]any {
	return map[string]any{
		"tool_names":         req.ToolNames,
		"domains":            req.Domains,
		"steps":              req.Steps,
		"model":              req.Model,
		"est_cost_usd":       req.EstCostUSD,
		"attestation_method": req.AttestationMethod,
		"chain_proven":       req.ChainProven,
		"policy_version":     resp.PolicyVersion,
		"reason":             resp.Reason,
		// Not the token, the FACT about it. Decide's own doc comment says
		// Allow together with this flag uniquely identifies an allow produced
		// by redeeming a valid token, and a replay that cannot tell those
		// apart reports a human's approval as the record and the code
		// disagreeing about the past.
		"approval_token_required": resp.ApprovalTokenRequired,
	}
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
		ChainProven:       dto.ChainProven,
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
			decisionInput(req, resp))
		s.exportSpan(req.AgentID, req.RunID, resp.Decision, resp.Reason, resp.PolicyVersion, req.ToolNames)

	case pdp.Deny:
		s.emit(evPolicyDeny, event.SeverityHigh, req.AgentID, req.RunID, req.OnBehalfOf,
			decisionInput(req, resp))
		s.exportSpan(req.AgentID, req.RunID, resp.Decision, resp.Reason, resp.PolicyVersion, req.ToolNames)
		// A presented-but-expired approval_token is a more specific signal
		// than a generic deny: the human-in-the-loop window closed before
		// the agent redeemed it. Surfaced as its own event on top of the
		// policy_deny above, distinct from approval_requested (which
		// covers only a *fresh* hold).
		if dto.ApprovalToken != "" {
			verr := approval.VerifyApprovalToken(s.approvalSecret, dto.ApprovalToken, req.AgentID, req.RunID, req.ToolNames, req.EstCostUSD)
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
			"chain_proven":       req.ChainProven,
			"reason":             resp.Reason,
			"policy_version":     resp.PolicyVersion,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to record approval hold: %v", err))
			return
		}
		resp.ApprovalID = held.ApprovalID
		// A hold is a verdict like the other two, so it records the same
		// question: an operator tuning the approvable band needs to replay
		// holds, not only denials.
		heldInput := decisionInput(req, resp)
		heldInput["approval_id"] = held.ApprovalID
		s.emit(evApprovalRequested, event.SeverityMedium, req.AgentID, req.RunID, req.OnBehalfOf,
			heldInput)
		s.exportSpan(req.AgentID, req.RunID, resp.Decision, resp.Reason, resp.PolicyVersion, req.ToolNames)
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
		writeInternalError(w, "deciding the approval", err)
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
		writeInternalError(w, "listing approvals", err)
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

// --- /v1/policies (admin only) ---

// policyDTO is policy.Policy's wire shape for the admin policy API, plus
// the id/updated_at store.PolicyRecord carries alongside it. Reuses
// policy.Policy's own JSON tags directly (embedded) rather than a parallel
// hand-copied field list, so a new Policy field is visible over the wire
// the moment it's added there, with no second struct to keep in sync.
type policyDTO struct {
	ID string `json:"id"`
	policy.Policy
	UpdatedAt string `json:"updated_at,omitempty"`
}

func policyRecordToDTO(r store.PolicyRecord) policyDTO {
	dto := policyDTO{ID: r.ID, Policy: r.Policy}
	if !r.UpdatedAt.IsZero() {
		dto.UpdatedAt = r.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return dto
}

// ComputePolicySet is the shared "layer the store's currently-persisted
// policies on top of a fixed base, then compile" rule the package doc
// comment's "Policy-as-code" section describes. cmd/wardryx calls this
// once at startup (after building st but before serving) to restore
// whatever an earlier process wrote through the admin policy API on top of
// basePolicies (the file-loaded Set's own Policies()); handlePutPolicy and
// handleDeletePolicy apply the same combination rule inline, since they
// additionally need to validate one specific mutation (a put or delete)
// before it is persisted, not just recompile whatever is already stored.
// A pure computation: it never touches Engine or the store beyond the
// ListPolicies read.
func ComputePolicySet(ctx context.Context, st store.Store, basePolicies []policy.Policy) (*policy.Set, error) {
	stored, err := st.ListPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("list stored policies: %w", err)
	}
	all := make([]policy.Policy, 0, len(basePolicies)+len(stored))
	all = append(all, basePolicies...)
	for _, r := range stored {
		all = append(all, r.Policy)
	}
	return policy.Compile(all)
}

// statusDTO is what /v1/status answers: how many rules are actually being
// enforced, and where they came from.
//
// This exists because /v1/policies answers a narrower question than it looks
// like it does. It lists the STORE's operator-managed policies only, so a
// deployment whose rules come from a -policy file sees an empty list there
// while every one of those rules is being enforced on /v1/decide. A console
// reading only that list concludes "no policies, everything is allowed" and
// says so, which is the most damaging thing a posture check can do: it
// reports enforcement as off while it is on, and an operator who verifies
// that claim once stops trusting the other warnings beside it.
type statusDTO struct {
	// The effective set's version, the same value every decision carries.
	PolicyVersion string `json:"policy_version"`
	// Rules loaded from the -policy file or directory at startup. These never
	// appear in /v1/policies and cannot be edited through the API.
	BasePolicies int `json:"base_policies"`
	// Operator-managed rules held in the store, layered on top of the base.
	StorePolicies int `json:"store_policies"`
	// What /v1/decide actually evaluates against. Zero here, and only here,
	// means every request really is allowed.
	EffectivePolicies int `json:"effective_policies"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, _ Principal) {
	stored, err := s.store.ListPolicies(r.Context())
	if err != nil {
		writeInternalError(w, "reading status", err)
		return
	}
	writeJSON(w, http.StatusOK, statusDTO{
		PolicyVersion:     s.engine.PolicyVersion(),
		BasePolicies:      len(s.basePolicies),
		StorePolicies:     len(stored),
		EffectivePolicies: len(s.basePolicies) + len(stored),
	})
}

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request, _ Principal) {
	all, err := s.store.ListPolicies(r.Context())
	if err != nil {
		writeInternalError(w, "listing policies", err)
		return
	}
	out := make([]policyDTO, 0, len(all))
	for _, rec := range all {
		out = append(out, policyRecordToDTO(rec))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request, _ Principal) {
	id := r.PathValue("id")
	rec, err := s.store.GetPolicy(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	if err != nil {
		writeInternalError(w, "reading the policy", err)
		return
	}
	writeJSON(w, http.StatusOK, policyRecordToDTO(rec))
}

// handlePutPolicy creates or replaces the policy stored under {id}. The
// request body is one policy.Policy document (id is the URL path segment,
// not a body field). Validate-then-apply, never partial: the full
// candidate set (basePolicies + every stored policy with id's entry
// replaced/added) is compiled BEFORE anything is persisted, so a body that
// would make the combined set invalid (empty target, a negative threshold,
// ...) is rejected with the store and the live Engine both left exactly as
// they were. Only once policy.Compile succeeds does this persist the write
// and swap Engine -- and swapping an atomic.Pointer cannot itself fail, so
// there is no window where the store and the live decision engine disagree
// about what was just written.
func (s *Server) handlePutPolicy(w http.ResponseWriter, r *http.Request, principal Principal) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing policy id")
		return
	}
	var p policy.Policy
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
		return
	}

	ctx := r.Context()
	stored, err := s.store.ListPolicies(ctx)
	if err != nil {
		writeInternalError(w, "writing the policy", err)
		return
	}
	candidate := make([]policy.Policy, 0, len(s.basePolicies)+len(stored)+1)
	candidate = append(candidate, s.basePolicies...)
	replaced := false
	for _, rec := range stored {
		if rec.ID == id {
			candidate = append(candidate, p)
			replaced = true
			continue
		}
		candidate = append(candidate, rec.Policy)
	}
	if !replaced {
		candidate = append(candidate, p)
	}

	newSet, err := policy.Compile(candidate)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid policy: %v", err))
		return
	}

	// Archived BEFORE the store write, not after it. A set archived and then
	// not stored is a harmless spare copy under a name nothing references. The
	// reverse is not harmless: a stored set is restored on the next start and
	// becomes effective, so a failure between the two would put rules into
	// force that no recorded decision could ever be replayed against.
	if err := s.policyArchive.Keep(newSet); err != nil {
		writeInternalError(w, "archiving the policy set", err)
		return
	}

	now := time.Now().UTC()
	if err := s.store.PutPolicy(ctx, id, p, now); err != nil {
		writeInternalError(w, "writing the policy", err)
		return
	}
	s.engine.SetPolicies(newSet)
	s.emit(evPolicyUpdated, event.SeverityHigh, systemAgentID, "", nil,
		map[string]any{"action": "put", "policy_id": id, "policy_version": newSet.Version(), "decided_by": principal.Org})

	rec, err := s.store.GetPolicy(ctx, id)
	if err != nil {
		writeInternalError(w, "writing the policy", err)
		return
	}
	writeJSON(w, http.StatusOK, policyRecordToDTO(rec))
}

// handleDeletePolicy removes the policy stored under {id}. Same
// validate-then-apply discipline as handlePutPolicy: the resulting set
// (basePolicies + every remaining stored policy) is compiled before the
// delete is persisted or Engine is swapped, even though removing one valid
// policy from an already-valid set cannot itself make policy.Compile fail
// -- kept symmetric with the put path rather than special-cased, so both
// handlers are provably held to the same "never partially apply" rule.
func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request, principal Principal) {
	id := r.PathValue("id")
	ctx := r.Context()

	stored, err := s.store.ListPolicies(ctx)
	if err != nil {
		writeInternalError(w, "deleting the policy", err)
		return
	}
	found := false
	candidate := make([]policy.Policy, 0, len(s.basePolicies)+len(stored))
	candidate = append(candidate, s.basePolicies...)
	for _, rec := range stored {
		if rec.ID == id {
			found = true
			continue
		}
		candidate = append(candidate, rec.Policy)
	}
	if !found {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}

	newSet, err := policy.Compile(candidate)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid resulting policy set: %v", err))
		return
	}

	// Archived BEFORE the store write, not after it. A set archived and then
	// not stored is a harmless spare copy under a name nothing references. The
	// reverse is not harmless: a stored set is restored on the next start and
	// becomes effective, so a failure between the two would put rules into
	// force that no recorded decision could ever be replayed against.
	if err := s.policyArchive.Keep(newSet); err != nil {
		writeInternalError(w, "archiving the policy set", err)
		return
	}

	if err := s.store.DeletePolicy(ctx, id); err != nil {
		writeInternalError(w, "deleting the policy", err)
		return
	}
	s.engine.SetPolicies(newSet)
	s.emit(evPolicyUpdated, event.SeverityHigh, systemAgentID, "", nil,
		map[string]any{"action": "delete", "policy_id": id, "policy_version": newSet.Version(), "decided_by": principal.Org})

	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

type errorDTO struct {
	Error string `json:"error"`
}

// writeInternalError answers a failure that is wardryx's own: a fixed message
// to the client, the detail in the log where the operator can read it.
//
// The detail is not the client's business, and more to the point it is not
// wardryx's string to give away. It comes from a driver, and what a driver
// puts in an error text is the driver's choice, revisited on every upgrade.
// pgx today keeps the password out of its connection errors and puts the
// host, user and database in. Passing that through means invariant 3 is held
// by somebody else's formatting decisions rather than by this code.
//
// The op is named in the response on purpose. It is a string wardryx wrote,
// so it reveals nothing, and without it a client has a 500 with nothing to
// report to anybody.
func writeInternalError(w http.ResponseWriter, op string, err error) {
	log.Printf("wardryx: %s: %v", op, err)
	writeError(w, http.StatusInternalServerError, "internal error while "+op)
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

// emit writes one agent-event, source "wardryx", chained via the SPEC 6.5
// prev_hash the ChainedWriter stamps on it. A nil ChainedWriter (events
// disabled: WARDRYX_EVENTS_PATH unset) makes this a no-op. A write failure
// is logged and dropped, fail-open, matching event.ChainedWriter's own
// contract and TokenFuse's exporter: event delivery never blocks or fails
// the decision path it is describing.
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

// exportSpan posts one OTLP span for a /v1/decide outcome. A nil otel
// exporter (WARDRYX_OTLP_ENDPOINT unset) makes this a no-op, matching
// emit's contract for a nil events Writer. Export itself is fire-and-forget
// (see internal/otel), so this never blocks handleDecide.
func (s *Server) exportSpan(agentID, runID, decision, reason, policyVersion string, toolNames []string) {
	if s.otel == nil {
		return
	}
	s.otel.Export(wotel.Span{
		AgentID:       agentID,
		RunID:         runID,
		Decision:      decision,
		Reason:        reason,
		PolicyVersion: policyVersion,
		ToolNames:     toolNames,
		TimestampNs:   time.Now().UnixNano(),
	})
}
