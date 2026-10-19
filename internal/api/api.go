// Package api is Wardryx's HTTP surface: POST /v1/decide (the decision
// engine), POST /v1/approvals/{id}/decide (admin-only grant/deny), GET
// /v1/approvals (org-scoped list), the admin-only policy-as-code routes
// under /v1/policies (see "Policy-as-code" below), GET /healthz (liveness)
// and GET /readyz (readiness, see "Liveness and readiness" below).
//
// Every /v1/* route requires a bearer key (Authorization: Bearer <key>)
// resolved through ParseKeys, mirroring the Cloud plane's
// "key:org[:role]" convention; /healthz and /readyz do not, matching
// Idryx's own unauthenticated liveness endpoint. The approvals-decide and
// every /v1/policies route additionally require the admin role.
//
// # Liveness and readiness
//
// /healthz says this process is up and answers 200 for as long as it does,
// store or no store: with the store gone, /v1/decide keeps answering from the
// policy set already in memory, which is the data plane doing its job, and a
// liveness check that restarted it for that would trade a working PDP for a
// crash loop. /readyz is the check that reads the store: it pings it under
// DefaultStoreTimeout and answers 200 {"store":"ok"} or 503
// {"store":"unreachable"}, so a launcher can tell "deciding from memory" from
// "healthy" by the status alone (issue #62). The same deadline bounds every
// store call a policy write makes, so PUT and DELETE /v1/policies/{id}
// answer 503 with a reason rather than hanging; and an outage is logged once
// when it starts and once when it ends, not once per request in between.
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
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
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
	// A request named an agent its key may not speak for, and was refused
	// with no decision (F-001 of the 2026-10-17 review). Not a decision, so
	// replay counts it as none.
	evAgentAssertionRefused = "agent_assertion_refused"
)

// authAgentID is the agent_id of an agent_assertion_refused event. The agent
// the request named did not act, and naming it as the event's subject would
// attribute the attempt to the agent it was made in the name of; it is in the
// event's data as asserted_agent_id instead.
const authAgentID = "agent://wardryx.internal/auth/agent-binding"

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
	engine *pdp.Engine
	store  store.Store
	// records is what every event is written through. Nil when no event file
	// is configured (WARDRYX_EVENTS_PATH unset): no record, so none can fail.
	records recordSink
	// recordOpen is the record fail mode. False, the default, refuses an allow
	// or a hold whose record was not written; true returns it and lets
	// /readyz say so. See recordDecision and invariant 40.
	recordOpen bool
	// record remembers whether the last record write failed, for /readyz.
	record recordHealth
	otel   *wotel.Exporter
	keys   map[string]Principal
	// allow is compiled from keys once: whether they name one org, and each
	// listed key's agent patterns. See speaksFor.
	allow             allowance
	approvals         approval.Keys
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

	// storeTimeout bounds every store call made on behalf of a policy write
	// and the readiness ping. See DefaultStoreTimeout.
	storeTimeout time.Duration
	// outage remembers whether the store was reachable the last time a
	// bounded call asked, so the log carries one line per outage.
	outage storeOutage
}

// storeOutage is the one bit that turns "the store failed" into "the store
// went down", so the log says so once when it happens and once when it is
// over. Without it every request during an outage writes its own line, and
// a launcher retrying a write every second buries the line that matters.
// It is in memory on purpose: a restart that logs "unreachable" again is
// saying something true about a process that has just lost its memory of
// saying it.
type storeOutage struct {
	mu   sync.Mutex
	down bool
}

// failed records a failure that store.IsUnavailable classified as the store
// being gone, and logs it only if it is the first since the store was last
// seen. The detail goes to the log and nowhere else (invariant 10).
func (o *storeOutage) failed(op string, err error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.down {
		return
	}
	o.down = true
	log.Printf("wardryx: policy store unreachable while %s: %v; policy writes and /readyz answer 503 until it is back", op, err)
}

// recovered records a store call that succeeded, and logs it only if an
// outage was in progress.
func (o *storeOutage) recovered() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.down {
		return
	}
	o.down = false
	log.Printf("wardryx: policy store reachable again")
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
	s := &Server{
		engine:            engine,
		store:             st,
		otel:              otel,
		keys:              keys,
		allow:             newAllowance(keys),
		approvals:         approval.Keys{Secret: approvalSecret, V2: approval.V2Rule{Accepted: true}},
		approvalTTL:       approval.DefaultTTL,
		approvalSingleUse: approvalSingleUse,
		basePolicies:      basePolicies,
		unansweredAfter:   DefaultUnansweredAfter,
		unansweredSeen:    map[string]bool{},
		storeTimeout:      DefaultStoreTimeout,
	}
	if events != nil {
		s.records = events
	}
	return s
}

// DefaultStoreTimeout is how long a policy write, or the readiness ping,
// waits for the store before answering 503. Three seconds: a healthy
// Postgres answers these in milliseconds, a launcher's probe gives up at
// somewhere between one and ten, and the request issue #62 measured had
// still not answered at eight.
const DefaultStoreTimeout = 3 * time.Second

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

// recordSink is the write side of the record: what emit writes an event to.
// *event.ChainedWriter satisfies it. Tests substitute a writer that refuses.
type recordSink interface {
	Write(event.Event) error
}

// SetRecordFailOpen selects the record fail mode (invariant 40). False is the
// closed default: an allow or a hold whose record was not written is refused.
// True is the explicit open mode: it is returned, and /readyz answers 503 with
// the record named as failing until a write succeeds again.
func (s *Server) SetRecordFailOpen(open bool) { s.recordOpen = open }

// recordHealth remembers whether the last record write failed, so the log
// carries one line when the record starts failing and one when it writes
// again, and /readyz can say so. Like storeOutage it is in memory: a restart
// that starts healthy is saying something true about a process that has lost
// its memory of the failure.
type recordHealth struct {
	mu      sync.Mutex
	failing bool
}

// failed records a write that failed, and logs the first one since the record
// last wrote. The detail goes to the log and nowhere else (invariant 10).
func (h *recordHealth) failed(evType string, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.failing {
		return
	}
	h.failing = true
	log.Printf("wardryx: the record is failing (%s: %v); /readyz answers 503 until a write succeeds", evType, err)
}

// recovered records a write that succeeded, and logs it only if the record was
// failing.
func (h *recordHealth) recovered() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.failing {
		return
	}
	h.failing = false
	log.Printf("wardryx: the record is writing again")
}

func (h *recordHealth) isFailing() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.failing
}

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
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("POST /v1/decide", s.requireAuth(s.handleDecide))
	mux.HandleFunc("POST /v1/filter-tools", s.requireAuth(s.handleFilterTools))
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

// readyDTO is what /readyz answers: "ok" or "unreachable" for the store, and
// "failing" for the record only while a record write is failing (absent
// otherwise). Neither says why: the why is the driver's or the writer's text
// and goes to the log.
type readyDTO struct {
	Store  string `json:"store"`
	Record string `json:"record,omitempty"`
}

// handleReadyz reads nothing from the request: no body, no query, no bearer.
// It is unauthenticated because the launcher checks that need it (a compose
// healthcheck, a Kubernetes readiness probe, install.sh's own probe) carry no
// credential, and what it reveals is whether the store answered and whether
// the record is being written. Either one failing is a 503 (invariant 20 for
// the store, invariant 40 for the record).
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), s.storeTimeout)
	defer cancel()
	dto := readyDTO{Store: "ok"}
	status := http.StatusOK
	if err := s.store.Ping(ctx); err != nil {
		s.outage.failed("pinging the store", err)
		dto.Store = "unreachable"
		status = http.StatusServiceUnavailable
	} else {
		s.outage.recovered()
	}
	if s.record.isFailing() {
		dto.Record = "failing"
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, dto)
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
	if !ok {
		return Principal{}, false
	}
	p.KeyFP = keyFingerprint(token)
	return p, true
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
		if !p.isAdmin() {
			writeError(w, http.StatusForbidden, "admin role required")
			return
		}
		next(w, r, p)
	})
}

// refuseAgent answers a request that names an agent its key may not speak
// for: a 403 that echoes nothing the request sent, and one event saying who
// tried, so the attempt is visible to whoever reads the record. Nothing is
// decided, nothing is held and no approval token is read or spent.
func (s *Server) refuseAgent(w http.ResponseWriter, p Principal, route, agentID, runID string) {
	s.emit(evAgentAssertionRefused, event.SeverityHigh, authAgentID, "", nil, map[string]any{
		"route":             route,
		"asserted_agent_id": agentID,
		"asserted_run_id":   runID,
		"org":               p.Org,
		"role":              p.Role,
		"key_fp":            p.KeyFP,
	})
	writeError(w, http.StatusForbidden, "this key may not speak for the agent this request names")
}

// --- POST /v1/decide ---

type decideRequestDTO struct {
	AgentID    string   `json:"agent_id"`
	RunID      string   `json:"run_id"`
	OnBehalfOf []string `json:"on_behalf_of,omitempty"`
	ToolNames  []string `json:"tool_names,omitempty"`
	Domains    []string `json:"domains,omitempty"`
	Steps      int      `json:"steps,omitempty"`
	// Model is a pointer so that a model sent empty, a model call naming
	// none, is told from no model sent at all, a decision that is not about a
	// model call (pdp.DecideRequest.ModelAbsent).
	Model             *string `json:"model,omitempty"`
	EstCostUSD        float64 `json:"est_cost_usd,omitempty"`
	AttestationMethod string  `json:"attestation_method,omitempty"`
	// IdentitySource: how the enforcement point knew the agent, "agent-token" when
	// it verified an agent token at its own door, "client-key" for a static key,
	// "none" for neither. Absent is none, and so is any other value, so a caller
	// that predates this field is decided exactly as before, and no source it
	// sends can earn more than it says. Set by the enforcement point from its door,
	// never from the agent (CLAUDE.md invariant 39).
	IdentitySource string `json:"identity_source,omitempty"`
	// ChainProven: the enforcement point VERIFIED this request's delegation
	// proof (agent-passport SPEC 5.2) before calling. Absent means it did
	// not, never "it did and forgot to say": a default of true would make
	// every caller that has not been upgraded look like one that verifies.
	ChainProven   bool   `json:"chain_proven,omitempty"`
	ApprovalToken string `json:"approval_token,omitempty"`
	// Signals are typed facts the caller established before asking.
	Signals []signalDTO `json:"signals,omitempty"`
	// ToolCall is the concrete call this request is about to make.
	ToolCall *toolCallDTO `json:"tool_call,omitempty"`
}

type signalDTO struct {
	Name        string   `json:"name"`
	Value       string   `json:"value"`
	Probability *float64 `json:"probability"`
	Source      string   `json:"source"`
	AnswerID    string   `json:"answer_id,omitempty"`
}

type toolCallDTO struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	Target    string          `json:"target,omitempty"`
	// ArgumentsTruncated: the enforcement point could not send the arguments
	// (too large). Then there are none to read, and none are asked about.
	ArgumentsTruncated bool `json:"arguments_truncated,omitempty"`
}

// decideSignalInputs turns the optional signals and tool call of a decide
// request into what the engine reads, refusing anything malformed with a
// sentence that names the field and never echoes the value.
//
// A signal's source is the caller's own claim about who established it. It is
// recorded and never branched on, and it is believed the way chain_proven is.
func decideSignalInputs(dto decideRequestDTO) ([]pdp.Signal, *pdp.ToolCall, string) {
	var signals []pdp.Signal
	if len(dto.Signals) > pdp.MaxSignals {
		return nil, nil, fmt.Sprintf("at most %d signals per request, got %d", pdp.MaxSignals, len(dto.Signals))
	}
	for i, d := range dto.Signals {
		if d.Probability == nil {
			return nil, nil, fmt.Sprintf("signals[%d].probability is required", i)
		}
		signals = append(signals, pdp.Signal{Name: d.Name, Value: d.Value, Probability: *d.Probability, Source: d.Source, AnswerID: d.AnswerID})
	}
	if err := pdp.ValidateSignals(signals); err != nil {
		return nil, nil, err.Error()
	}
	if dto.ToolCall == nil {
		return signals, nil, ""
	}
	tc := pdp.ToolCall{Name: dto.ToolCall.Name, Arguments: dto.ToolCall.Arguments, Target: dto.ToolCall.Target, ArgumentsTruncated: dto.ToolCall.ArgumentsTruncated}
	if err := pdp.ValidateToolCall(tc); err != nil {
		return nil, nil, err.Error()
	}
	return signals, &tc, ""
}

// signalsRecord is how a list of signals is written into an event and into an
// approval's context: every field of every signal used, so a replay feeds back
// exactly what the decision read and an approver sees what was claimed.
func signalsRecord(signals []pdp.Signal) []any {
	out := make([]any, 0, len(signals))
	for _, sg := range signals {
		out = append(out, map[string]any{
			"name":        sg.Name,
			"value":       sg.Value,
			"probability": sg.Probability,
			"source":      sg.Source,
			"answer_id":   sg.AnswerID,
		})
	}
	return out
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
// identity_source is recorded normalized, as the rule read it, so a replay feeds
// back the source the decision stood on; a record from before the field reads as
// none.
//
// TestDecisionInputCoversEveryDecideRequestField holds this to the shape of
// pdp.DecideRequest itself, so a new PDP input cannot quietly skip the record.
func decisionInput(req pdp.DecideRequest, resp pdp.DecideResponse) map[string]any {
	in := map[string]any{
		// The org the decision was asked in decides which policies applied,
		// so a replay needs it to ask the same question.
		"org":                req.Org,
		"tool_names":         req.ToolNames,
		"domains":            req.Domains,
		"steps":              req.Steps,
		"model":              req.Model,
		"est_cost_usd":       req.EstCostUSD,
		"attestation_method": req.AttestationMethod,
		"identity_source":    policy.IdentitySourceOf(req.IdentitySource),
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
	// A request that sent no model at all says so, and only then, so every
	// earlier record and every model call is recorded as it was. Replay reads
	// it back: allow_models judges a model call only.
	if req.ModelAbsent {
		in["model_absent"] = true
	}
	// Every signal the decision read, and only when there were any: a decision
	// that used none is recorded exactly as it was before signals existed. The
	// tool call is recorded as name, target and a hash only.
	if len(req.Signals) > 0 {
		in["signals"] = signalsRecord(req.Signals)
	}
	// What the signals were derived from, without the data itself: the tool
	// and target by name, and a hash of the arguments exactly as received, so
	// an auditor can tie a recorded signal to the call it was about and replay
	// can say the call was truncated. The arguments can carry customer data and
	// are never written down. Replay feeds back the name, target and truncated
	// flag: Decide reads the name (deny_tool, allow_tool) and whether a call was
	// there at all (hold_if_signal with when_absent: hold).
	if tc := req.ToolCall; tc != nil {
		in["tool_call"] = map[string]any{
			"name":                tc.Name,
			"target":              tc.Target,
			"arguments_sha256":    approval.ArgumentsSHA256(tc.Arguments),
			"arguments_truncated": tc.ArgumentsTruncated,
			// The digest an approval of this call is bound to, so the record
			// ties a hold and its token to the exact call.
			"digest": tc.Digest(),
		}
	}
	return in
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

// valueOf is the string a pointer holds, or "" for none.
func valueOf(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func (s *Server) handleDecide(w http.ResponseWriter, r *http.Request, principal Principal) {
	var dto decideRequestDTO
	if !decodeJSONBody(w, r, &dto) {
		return
	}
	if dto.AgentID == "" || dto.RunID == "" {
		writeError(w, http.StatusBadRequest, "agent_id and run_id are required")
		return
	}
	// The agent is bound to the key before anything else in the request is
	// read: a refused request reaches no rule, holds nothing, and presents no
	// approval token, so a token cannot be spent by a key that may not use it.
	if !s.allow.speaksFor(principal, dto.AgentID) {
		s.refuseAgent(w, principal, "/v1/decide", dto.AgentID, dto.RunID)
		return
	}

	signals, toolCall, refusal := decideSignalInputs(dto)
	if refusal != "" {
		writeError(w, http.StatusBadRequest, refusal)
		return
	}

	req := pdp.DecideRequest{
		AgentID:           dto.AgentID,
		Org:               principal.Org,
		RunID:             dto.RunID,
		OnBehalfOf:        dto.OnBehalfOf,
		ToolNames:         dto.ToolNames,
		Domains:           dto.Domains,
		Steps:             dto.Steps,
		Model:             valueOf(dto.Model),
		ModelAbsent:       dto.Model == nil,
		EstCostUSD:        dto.EstCostUSD,
		AttestationMethod: dto.AttestationMethod,
		IdentitySource:    policy.IdentitySourceOf(dto.IdentitySource),
		ChainProven:       dto.ChainProven,
		ApprovalToken:     dto.ApprovalToken,
		Signals:           signals,
		ToolCall:          toolCall,
	}
	resp := s.engine.Decide(req)

	// WARDRYX_APPROVAL_SINGLE_USE: an Allow with ApprovalTokenRequired set
	// only ever happens when a presented approval_token just verified (see
	// pdp.Engine.Decide's overThreshold and heldBySignal branches -- the
	// only paths that set ApprovalTokenRequired and can still reach Allow).
	// On by default since 1.0 (invariant 5; internal/config's
	// parseBoolClosed reads unset or unparsable as true), so this block runs
	// unless an operator set the variable to an explicit false, which
	// restores the pre-1.0 behaviour: the decision is returned unchanged and
	// a valid token stays reusable for its full TTL.
	//
	// When it runs, TryRedeem is the atomic check-and-set that lets a
	// token allow at most once: the first /v1/decide to claim this token's
	// RedemptionKey wins Allow, and any later presentation of that same
	// token -- a genuine retry or a race against it -- loses the claim and
	// falls back to a fresh Hold, indistinguishable from presenting no
	// token at all, rather than silently allowing a second time.
	if s.approvalSingleUse && resp.Decision == pdp.Allow && resp.ApprovalTokenRequired {
		redeemed, rErr := s.store.TryRedeem(r.Context(), approval.RedemptionKey(dto.ApprovalToken))
		if rErr != nil {
			writeInternalError(w, "recording the approval_token redemption", rErr)
			return
		}
		if !redeemed {
			resp.Decision = pdp.Hold
			resp.Reason = pdp.ReasonApprovalSpent
		}
	}

	switch resp.Decision {
	case pdp.Allow:
		// A refused allow has already redeemed its token above. The token stays
		// spent and a person grants again: an allow the record does not hold is
		// not returned (invariant 40).
		if !s.recordDecision(evPolicyAllow, event.SeverityInfo, req.AgentID, req.RunID, req.OnBehalfOf,
			decisionInput(req, resp)) {
			writeRecordUnavailable(w)
			return
		}
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
			verr := s.approvals.VerifyForCall(dto.ApprovalToken, req.AgentID, req.RunID, req.ToolNames, req.EstCostUSD, req.ToolCall.Digest())
			if errors.Is(verr, approval.ErrTokenExpired) {
				s.emit(evApprovalTimeout, event.SeverityHigh, req.AgentID, req.RunID, req.OnBehalfOf,
					map[string]any{"reason": "presented approval_token had expired"})
			}
		}

	case pdp.Hold:
		holdContext := map[string]any{
			"org":                principal.Org,
			"model":              req.Model,
			"est_cost_usd":       req.EstCostUSD,
			"attestation_method": req.AttestationMethod,
			"identity_source":    policy.IdentitySourceOf(req.IdentitySource),
			"on_behalf_of":       req.OnBehalfOf,
			"chain_proven":       req.ChainProven,
			"reason":             resp.Reason,
			"policy_version":     resp.PolicyVersion,
		}
		// A person deciding this hold sees every signal that was used, with
		// who said it and the answer id that finds the classifier's record.
		if len(req.Signals) > 0 {
			holdContext["signals"] = signalsRecord(req.Signals)
		}
		// The call a person is asked to approve, by name and target and the
		// digest the grant will bind the token to; never the arguments, which
		// can carry customer data. Absent when the request carried no call, in
		// which case the grant binds none, as it always did.
		if tc := req.ToolCall; tc != nil {
			holdContext[approval.ContextKeyToolCall] = map[string]any{
				"name":                    tc.Name,
				"target":                  tc.Target,
				"arguments_truncated":     tc.ArgumentsTruncated,
				approval.ContextKeyDigest: tc.Digest(),
			}
		}
		held, err := approval.Request(r.Context(), s.store, req.AgentID, req.RunID, req.ToolNames, holdContext)
		if err != nil {
			writeInternalError(w, "recording the approval hold", err)
			return
		}
		resp.ApprovalID = held.ApprovalID
		// A hold is a verdict like the other two, so it records the same
		// question: an operator tuning the approvable band needs to replay
		// holds, not only denials.
		heldInput := decisionInput(req, resp)
		heldInput["approval_id"] = held.ApprovalID
		// A refused hold leaves its approval pending in the queue: nobody was
		// given its ID, so nobody waits on it (named in invariant 40).
		if !s.recordDecision(evApprovalRequested, event.SeverityMedium, req.AgentID, req.RunID, req.OnBehalfOf,
			heldInput) {
			writeRecordUnavailable(w)
			return
		}
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

// --- POST /v1/filter-tools ---

// filterToolsRequestDTO is the wire request for POST /v1/filter-tools. It
// carries only what pdp.Filter reads: no approval token, no cost, no chain --
// Filter applies no rule about those (see pdp.Filter's doc comment).
type filterToolsRequestDTO struct {
	AgentID   string   `json:"agent_id"`
	RunID     string   `json:"run_id,omitempty"`
	ToolNames []string `json:"tool_names,omitempty"`
}

// deniedToolDTO mirrors pdp.DeniedTool onto the wire.
type deniedToolDTO struct {
	Name   string `json:"name"`
	Policy string `json:"policy"`
	Rule   string `json:"rule"`
}

// filterToolsResponseDTO is the wire response for POST /v1/filter-tools.
// Allowed and Denied carry no `omitempty`: an empty list must serialize as
// `[]`, never `null`, so a caller's JSON decoder never has to special-case an
// absent field as "nothing offered" versus "nothing denied".
type filterToolsResponseDTO struct {
	Allowed       []string        `json:"allowed"`
	Denied        []deniedToolDTO `json:"denied"`
	PolicyVersion string          `json:"policy_version"`
}

// handleFilterTools answers pdp.Filter over HTTP: the same auth
// (s.requireAuth, wired at registration), the same maxRequestBodyBytes cap
// and the same JSON-decoding discipline as handleDecide (decodeJSONBody), but
// no event is emitted -- nothing acts on this answer yet, so nothing records
// it (see the Filter invariant in CLAUDE.md).
func (s *Server) handleFilterTools(w http.ResponseWriter, r *http.Request, principal Principal) {
	var dto filterToolsRequestDTO
	if !decodeJSONBody(w, r, &dto) {
		return
	}
	if dto.AgentID == "" {
		writeError(w, http.StatusBadRequest, "agent_id is required")
		return
	}
	// Bound like /v1/decide: the partition is another agent's policy, and a
	// key that may not ask for the agent may not read it either. The refusal
	// is recorded; a filter answer still is not.
	if !s.allow.speaksFor(principal, dto.AgentID) {
		s.refuseAgent(w, principal, "/v1/filter-tools", dto.AgentID, dto.RunID)
		return
	}

	resp := s.engine.Filter(pdp.FilterRequest{
		AgentID:   dto.AgentID,
		Org:       principal.Org,
		RunID:     dto.RunID,
		ToolNames: dto.ToolNames,
	})

	denied := make([]deniedToolDTO, 0, len(resp.Denied))
	for _, d := range resp.Denied {
		denied = append(denied, deniedToolDTO{Name: d.Name, Policy: d.Policy, Rule: d.Rule})
	}
	allowed := resp.Allowed
	if allowed == nil {
		allowed = []string{}
	}

	writeJSON(w, http.StatusOK, filterToolsResponseDTO{
		Allowed:       allowed,
		Denied:        denied,
		PolicyVersion: resp.PolicyVersion,
	})
}

// --- POST /v1/approvals/{id}/decide ---

type approvalDecideRequestDTO struct {
	Decision string `json:"decision"`
	// DecidedBy is display text, what a console calls the person who decided.
	// It is recorded as the approval's decided_by_label and never as who
	// decided: that is the key that authenticated the request. Optional.
	DecidedBy string `json:"decided_by,omitempty"`
}

// maxLabelBytes caps the display label a decision is sent with: a name, not a
// document. It is shown in a console and in the approvals table a terminal
// prints, so it is refused rather than trimmed.
const maxLabelBytes = 256

// labelRefusal says why a display label is refused, or "" for a good one. It
// never quotes the label: a refusal that echoed a terminal escape would print
// it.
func labelRefusal(label string) string {
	if len(label) > maxLabelBytes {
		return fmt.Sprintf("decided_by is a display label of at most %d bytes", maxLabelBytes)
	}
	if !utf8.ValidString(label) {
		return "decided_by must be UTF-8 text"
	}
	for _, r := range label {
		if unicode.IsControl(r) || isBidiControl(r) {
			return "decided_by must not contain a control character or a bidirectional override"
		}
	}
	return ""
}

// isBidiControl reports the Unicode characters that reorder how the text
// around them is displayed, so a label could show an approver's name the
// table or the console does not hold.
func isBidiControl(r rune) bool {
	switch {
	case r == 0x061C, r == 0x200E, r == 0x200F:
		return true
	case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

// approverID is who decided an approval, as recorded: the key that
// authenticated the decision, by fingerprint, the form policy_updated's key_fp
// already uses. The text a request sends is the label beside it.
func approverID(p Principal) string { return "key:" + p.KeyFP }

type approvalDecideResponseDTO struct {
	ApprovalID    string `json:"approval_id"`
	Decision      string `json:"decision"`
	ApprovalToken string `json:"approval_token,omitempty"`
}

func (s *Server) handleApprovalDecide(w http.ResponseWriter, r *http.Request, principal Principal) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing approval id")
		return
	}
	var dto approvalDecideRequestDTO
	if !decodeJSONBody(w, r, &dto) {
		return
	}
	if dto.Decision != "grant" && dto.Decision != "deny" {
		writeError(w, http.StatusBadRequest, `decision must be "grant" or "deny"`)
		return
	}
	if refusal := labelRefusal(dto.DecidedBy); refusal != "" {
		writeError(w, http.StatusBadRequest, refusal)
		return
	}

	// An admin may decide only an approval belonging to their own org.
	// handleListApprovals already scopes by org (see its own comment); this
	// route did not, so an admin key for one org could grant or deny a hold
	// it never listed. An approval with NO org in its context (a row written
	// before org scoping existed) belongs to no org, so only a principal
	// allowed across orgs decides it: a cross-org admin, or the admin of the
	// only org there is, who decides it exactly as before (F-012).
	//
	// The response is the same 404 body as an unknown id, deliberately: a
	// distinct "wrong org" answer would make this route an oracle for
	// which ids belong to another org.
	existing, err := s.store.GetApproval(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "approval not found")
		return
	case err != nil:
		writeInternalError(w, "reading the approval", err)
		return
	}
	if org, _ := existing.Context["org"].(string); org != principal.Org && !s.allow.acrossOrgs(principal) {
		writeError(w, http.StatusNotFound, "approval not found")
		return
	}

	decided, token, err := approval.DecideWith(r.Context(), s.store, s.approvals, id, dto.Decision, approverID(principal), dto.DecidedBy, s.approvalTTL)
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
	case errors.Is(err, approval.ErrSigner):
		writeError(w, http.StatusServiceUnavailable, "the approval signing service is unavailable; the hold stays pending")
		return
	case err != nil:
		writeInternalError(w, "deciding the approval", err)
		return
	}

	// decided_by names the key that decided; key_fp is the same fingerprint
	// on its own, the field policy_updated carries; the label is the text the
	// request sent, only when it sent one.
	data := map[string]any{"approval_id": decided.ApprovalID, "decided_by": decided.DecidedBy, "key_fp": principal.KeyFP}
	if decided.DecidedByLabel != "" {
		data["decided_by_label"] = decided.DecidedByLabel
	}
	if dto.Decision == "grant" {
		s.emit(evApprovalGranted, event.SeverityInfo, decided.AgentID, decided.RunID, nil, data)
	} else {
		s.emit(evApprovalDenied, event.SeverityHigh, decided.AgentID, decided.RunID, nil, data)
	}

	writeJSON(w, http.StatusOK, approvalDecideResponseDTO{
		ApprovalID:    decided.ApprovalID,
		Decision:      decided.Decision,
		ApprovalToken: token,
	})
}

// --- GET /v1/approvals ---

type approvalDTO struct {
	ApprovalID  string `json:"approval_id"`
	AgentID     string `json:"agent_id"`
	RunID       string `json:"run_id"`
	RequestedAt string `json:"requested_at"`
	DecidedAt   string `json:"decided_at,omitempty"`
	DecidedBy   string `json:"decided_by,omitempty"`
	// DecidedByLabel is the display text the decision was sent with. Who
	// decided is DecidedBy.
	DecidedByLabel string         `json:"decided_by_label,omitempty"`
	Decision       string         `json:"decision,omitempty"`
	Pending        bool           `json:"pending"`
	Context        map[string]any `json:"context,omitempty"`
}

// handleListApprovals lists every approval belonging to the caller's org, and
// to a principal allowed across orgs every approval, of every org and of none,
// since it is the one that may decide them. Org scoping is applied here, not
// in internal/store: the schema's context_json column carries "org" (stamped
// at hold time from the authenticated principal, see handleDecide), and store
// stays a dumb, auth-agnostic persistence layer.
func (s *Server) handleListApprovals(w http.ResponseWriter, r *http.Request, principal Principal) {
	all, err := s.store.ListApprovals(r.Context())
	if err != nil {
		writeInternalError(w, "listing approvals", err)
		return
	}
	out := make([]approvalDTO, 0, len(all))
	across := s.allow.acrossOrgs(principal)
	for _, a := range all {
		if org, _ := a.Context["org"].(string); org != principal.Org && !across {
			continue
		}
		dto := approvalDTO{
			ApprovalID:     a.ApprovalID,
			AgentID:        a.AgentID,
			RunID:          a.RunID,
			RequestedAt:    a.RequestedAt.UTC().Format(time.RFC3339),
			DecidedBy:      a.DecidedBy,
			DecidedByLabel: a.DecidedByLabel,
			Decision:       a.Decision,
			Pending:        a.Pending(),
			Context:        a.Context,
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

// handleStatus counts the policies that govern the caller's decisions: those
// of its org and those across orgs, and every one for a principal allowed
// across orgs. With one org that is every policy, as it always was.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, principal Principal) {
	stored, err := s.store.ListPolicies(r.Context())
	if err != nil {
		writeInternalError(w, "reading status", err)
		return
	}
	base := 0
	for _, p := range s.basePolicies {
		if s.canRead(principal, p.Org) {
			base++
		}
	}
	inStore := 0
	for _, rec := range stored {
		if s.canRead(principal, rec.Policy.Org) {
			inStore++
		}
	}
	writeJSON(w, http.StatusOK, statusDTO{
		PolicyVersion:     s.engine.PolicyVersion(),
		BasePolicies:      base,
		StorePolicies:     inStore,
		EffectivePolicies: base + inStore,
	})
}

// canRead reports whether a principal may see a policy of org: one that
// governs its decisions (its own org's, or one across orgs), or any policy
// for a principal allowed across orgs. Another org's policy is not shown.
func (s *Server) canRead(p Principal, org string) bool {
	return org == "" || org == p.Org || s.allow.acrossOrgs(p)
}

// canWrite reports whether a principal may write, replace or delete a policy
// of org: its own org's, and, for a principal allowed across orgs, any,
// including one with no org, which governs every org's decisions.
func (s *Server) canWrite(p Principal, org string) bool {
	return org == p.Org || s.allow.acrossOrgs(p)
}

// notYourPolicy is the refusal of a policy write a key may not make. It names
// no other org and says the same thing whether the policy belongs to another
// org or to none, so it tells a caller only that the id is not theirs to use.
const notYourPolicy = "an admin key writes the policies of its own org only; a policy of another org, or one that applies across orgs, needs a " + RoleCrossOrgAdmin + " key"

func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request, principal Principal) {
	all, err := s.store.ListPolicies(r.Context())
	if err != nil {
		writeInternalError(w, "listing policies", err)
		return
	}
	out := make([]policyDTO, 0, len(all))
	for _, rec := range all {
		if !s.canRead(principal, rec.Policy.Org) {
			continue
		}
		out = append(out, policyRecordToDTO(rec))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request, principal Principal) {
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
	// Another org's policy reads as missing, the same answer an unknown id
	// gets, as an approval of another org does.
	if !s.canRead(principal, rec.Policy.Org) {
		writeError(w, http.StatusNotFound, "policy not found")
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
	// The body is decoded into the shape GET emits, so the read-only id and
	// updated_at a copy of a GET carries are accepted, and only the policy
	// is taken from it: the URL names the policy, and the write stamps the time.
	var body policyDTO
	if !decodePolicyBody(w, r, &body) {
		return
	}
	p := body.Policy
	// The org a policy belongs to is the writer's. An org admin's policy is
	// its org's whatever the body says, and a body naming another org is
	// refused rather than rewritten; a principal allowed across orgs writes
	// the org the body names, and a body naming none applies across orgs.
	if !s.allow.acrossOrgs(principal) {
		if p.Org != "" && p.Org != principal.Org {
			writeError(w, http.StatusForbidden, notYourPolicy)
			return
		}
		p.Org = principal.Org
	}

	// Bounded: every store call below shares one deadline, so a store that
	// has gone away answers 503 in storeTimeout rather than holding the
	// request for as long as the kernel takes to give up on a dial that
	// nothing refuses (issue #62 measured eight seconds and no answer).
	ctx, cancel := context.WithTimeout(r.Context(), s.storeTimeout)
	defer cancel()
	stored, err := s.store.ListPolicies(ctx)
	if err != nil {
		s.writeStoreFailure(w, "writing the policy", err)
		return
	}
	candidate := make([]policy.Policy, 0, len(s.basePolicies)+len(stored)+1)
	candidate = append(candidate, s.basePolicies...)
	replaced := false
	for _, rec := range stored {
		if rec.ID == id {
			// Replacing a policy is changing it: the one stored must be the
			// writer's to change, or an org admin could take over a policy
			// that governs every org and narrow it to its own.
			if !s.canWrite(principal, rec.Policy.Org) {
				writeError(w, http.StatusForbidden, notYourPolicy)
				return
			}
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
		s.writeStoreFailure(w, "writing the policy", err)
		return
	}
	s.outage.recovered()
	s.engine.SetPolicies(newSet)
	s.emit(evPolicyUpdated, event.SeverityHigh, systemAgentID, "", nil,
		map[string]any{"action": "put", "policy_id": id, "policy_version": newSet.Version(), "decided_by": principal.Org, "key_fp": principal.KeyFP, "policy_org": p.Org})

	// Rendered from what was just written rather than read back from the
	// store: the record is id, the body and now, all three in hand, and a
	// read-back that failed after the write succeeded and the engine was
	// swapped would answer 503 "not in force" about a change that is.
	writeJSON(w, http.StatusOK, policyRecordToDTO(store.PolicyRecord{ID: id, Policy: p, UpdatedAt: now}))
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
	// Bounded, for the same reason handlePutPolicy is.
	ctx, cancel := context.WithTimeout(r.Context(), s.storeTimeout)
	defer cancel()

	stored, err := s.store.ListPolicies(ctx)
	if err != nil {
		s.writeStoreFailure(w, "deleting the policy", err)
		return
	}
	var found *store.PolicyRecord
	candidate := make([]policy.Policy, 0, len(s.basePolicies)+len(stored))
	candidate = append(candidate, s.basePolicies...)
	for i, rec := range stored {
		if rec.ID == id {
			found = &stored[i]
			continue
		}
		candidate = append(candidate, rec.Policy)
	}
	// Another org's policy is missing to this key, as on GET; one across orgs
	// is visible and is not this key's to remove.
	if found == nil || !s.canRead(principal, found.Policy.Org) {
		writeError(w, http.StatusNotFound, "policy not found")
		return
	}
	if !s.canWrite(principal, found.Policy.Org) {
		writeError(w, http.StatusForbidden, notYourPolicy)
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
		s.writeStoreFailure(w, "deleting the policy", err)
		return
	}
	s.outage.recovered()
	s.engine.SetPolicies(newSet)
	s.emit(evPolicyUpdated, event.SeverityHigh, systemAgentID, "", nil,
		map[string]any{"action": "delete", "policy_id": id, "policy_version": newSet.Version(), "decided_by": principal.Org, "key_fp": principal.KeyFP, "policy_org": found.Policy.Org})

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

// writeRecordUnavailable answers an allow or a hold that the closed fail mode
// refused because its record could not be written. The body names the refusal
// and nothing about the write: the cause is in the log (invariant 10).
func writeRecordUnavailable(w http.ResponseWriter) {
	writeError(w, http.StatusServiceUnavailable, "record_unavailable")
}

// writeStoreFailure answers a store call that failed on a bounded path. A
// store that is gone (store.IsUnavailable: the deadline passed, or the
// network said no) is a 503 with a reason wardryx composed, and the outage
// is noted once; anything else is the 500 writeInternalError has always
// answered, because the store did answer, and what it said is a fault of
// this process's own.
//
// "The change is not in force" is a statement about this process: its
// engine was not swapped. A write the store applied after this process
// stopped waiting is restored on the next start, the way any stored policy
// is (see cmd/wardryx), and until then the store and the live set differ;
// the reason names the store so a caller retries the write once the store
// is back rather than assuming either state.
func (s *Server) writeStoreFailure(w http.ResponseWriter, op string, err error) {
	if !store.IsUnavailable(err) {
		writeInternalError(w, op, err)
		return
	}
	s.outage.failed(op, err)
	why := "is unreachable"
	if errors.Is(err, context.DeadlineExceeded) {
		why = "did not answer within " + s.storeTimeout.String()
	}
	writeError(w, http.StatusServiceUnavailable, "the policy store "+why+" while "+op+"; the change is not in force")
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

// maxRequestBodyBytes caps every request body this server decodes as JSON.
// Every route here answers with a handful of fields; there is no legitimate
// caller of this API whose request body approaches 1 MiB, and an uncapped
// json.NewDecoder(r.Body) will happily read as much as a caller sends before
// deciding the JSON is invalid, which is memory an authenticated (or, before
// requireAuth runs, merely connected) caller can spend on this process for
// free.
const maxRequestBodyBytes = 1 << 20 // 1 MiB

// decodeJSONBody wraps r.Body in http.MaxBytesReader and decodes it into v,
// writing the appropriate error response itself and reporting false when it
// did: a body over maxRequestBodyBytes gets 413 with a fixed message rather
// than whatever the decoder's own error text happens to say, and anything
// else that fails to decode still gets the existing 400 (the client's own
// malformed body, echoed back to them, which is not a leak: see
// scripts/no-raw-error-in-response.sh).
func decodeJSONBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return writeBodyError(w, err)
	}
	return true
}

// decodePolicyBody decodes a PUT /v1/policies/{id} body, which is one policy.
// json.Decoder stops at the first JSON value, so decodeJSONBody would read a
// body with data after the policy as that one policy and drop the rest without
// a word. Here that data is refused with a 400, which does not echo it, and
// nothing is stored. Whitespace after the policy is not data.
//
// A key the target does not declare is refused as well, with a 400 that names
// it and echoes no value. Without that check a misspelled rule was stored
// without the rule and the write answered 200. Invariant 31. The target is a
// policyDTO, so the two read-only fields GET emits (id, updated_at) are
// declared and accepted.
func decodePolicyBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return writeBodyError(w, err)
	}
	var extra json.RawMessage
	err := dec.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return true
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "request body exceeds the 1 MiB limit")
		return false
	}
	writeError(w, http.StatusBadRequest, "invalid request body: a body holds one policy, and data after it is refused")
	return false
}

// writeBodyError answers a request body that did not decode, and reports false.
func writeBodyError(w http.ResponseWriter, err error) bool {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "request body exceeds the 1 MiB limit")
		return false
	}
	writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid request body: %v", err))
	return false
}

// writeRecord writes one agent-event, source "wardryx", chained via the SPEC
// 6.5 prev_hash the ChainedWriter stamps on it, and reports whether the write
// succeeded. A nil record writer (events disabled: WARDRYX_EVENTS_PATH unset)
// writes nothing and reports nothing wrong: no record is configured, so none
// can fail. A failed write marks the record as failing for /readyz.
func (s *Server) writeRecord(evType, severity, agentID, runID string, onBehalfOf []string, data map[string]any) error {
	if s.records == nil {
		return nil
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
	if err := s.records.Write(e); err != nil {
		s.record.failed(evType, err)
		return err
	}
	s.record.recovered()
	return nil
}

// emit writes an event whose failure no decision depends on: a policy write,
// an approval grant or denial, a refusal, the unanswered-approval sweep. It is
// fail-open, as event.ChainedWriter and TokenFuse's exporter are: event
// delivery never blocks or fails the request it describes. A failure is
// visible on /readyz (recordHealth), and the caller carries on.
func (s *Server) emit(evType, severity, agentID, runID string, onBehalfOf []string, data map[string]any) {
	_ = s.writeRecord(evType, severity, agentID, runID, onBehalfOf, data)
}

// recordDecision writes the record of an allow or a hold, the two answers a
// caller acts on, and reports whether the answer may be returned. Under the
// closed fail mode, the default, it may not when the write failed, and the
// caller answers 503 record_unavailable (invariant 40). Under the open fail
// mode it may, and /readyz says the record is failing until a write succeeds.
// A deny is not written through here. It puts no action in motion, so
// refusing it would only trade a known refusal for an unknown one, and it
// stays fail-open through emit.
func (s *Server) recordDecision(evType, severity, agentID, runID string, onBehalfOf []string, data map[string]any) bool {
	if s.writeRecord(evType, severity, agentID, runID, onBehalfOf, data) == nil {
		return true
	}
	return s.recordOpen
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
