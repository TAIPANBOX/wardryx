// Package pdp is Wardryx's decision engine: the Policy Decision Point that
// decides whether one operator-owned agent may take one action.
//
// Decide is a pure function of (loaded policy set, approval secret,
// request): it never performs an action, never calls out to a model, and
// never touches storage or the network. Given the same Engine and the same
// DecideRequest, it always returns the same DecideResponse. That
// determinism is deliberate and matches Idryx's rule for its own detection
// path: an authorization decision has to be auditable and reproducible, so
// an LLM never appears anywhere in it.
//
// Decide alone cannot create a pending approval row (it has no storage
// access by design), so a "hold" response leaves ApprovalID empty. The
// caller -- internal/api's /v1/decide handler -- is the one that calls
// internal/approval.Request to persist the hold and stamps the resulting
// ApprovalID onto the response before returning it.
//
// A request over a matched policy's cost threshold resolves three ways: no
// ApprovalToken presented resolves to Hold (the normal, expected path: go
// get a human to grant one); a valid ApprovalToken resolves to Allow; a
// *presented but invalid* token (expired, forged, or bound to a different
// agent/run/tool-set) resolves to Deny rather than falling back to Hold --
// a stale or mismatched credential is a stronger signal that something is
// wrong than simply not having approval yet, so it is rejected outright
// instead of silently being treated the same as the no-token case.
package pdp

import (
	"fmt"

	"github.com/TAIPANBOX/agent-stack-go/chain"
	"github.com/TAIPANBOX/wardryx/internal/approval"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// Decision values for DecideResponse.Decision.
const (
	Allow = "allow"
	Deny  = "deny"
	Hold  = "hold"
)

// DecideRequest describes one action an agent is about to take, submitted
// to POST /v1/decide.
type DecideRequest struct {
	// AgentID is the requesting agent's agent:// URI. Matched against each
	// loaded policy's Target glob.
	AgentID string
	// RunID identifies the run this action belongs to. Part of the
	// approval_token binding.
	RunID string
	// OnBehalfOf is the request's delegation chain, root-first
	// (agent-passport SPEC §5), if the agent is acting for another
	// principal. When present it must be a valid chain (acyclic, within
	// chain.MaxDepth, every entry an agent:// or user:// URI): Decide
	// denies outright on an invalid chain, independent of any policy.
	OnBehalfOf []string
	// ToolNames are the tools this action would invoke. Checked against
	// every matched policy's DenyTool.
	ToolNames []string
	// Domains are the network destinations this action's declared tools
	// would reach (already-extracted hostnames, e.g. "api.example.com").
	// Checked against every matched policy's AllowDomains. Empty means the
	// caller declared no domains for this action, which imposes no
	// restriction: Decide only restricts domains the caller actually
	// declares, it never invents one to check.
	Domains []string
	// Steps is the run's accumulated step count so far -- how many prior
	// actions on this run have already gone through, not counting the
	// action this request is deciding (a run's first action reports 0).
	// Checked against every matched policy's MaxSteps: Decide denies once
	// Steps reaches or exceeds MaxSteps, so exactly MaxSteps actions are
	// ever let through before the rule starts firing.
	Steps int
	// Model is the model the agent is running, carried through for
	// logging/events; Decide does not branch on it.
	Model string
	// EstCostUSD is the action's estimated cost. Checked against every
	// matched policy's RequireHumanAboveUSD.
	EstCostUSD float64
	// AttestationMethod is the agent's current attestation method (e.g.
	// "spiffe-svid"), or "" / "none" for no live attestation. Checked
	// against every matched policy's DenyIfUnattested.
	AttestationMethod string
	// ApprovalToken, if non-empty, is presented as proof that a human
	// already approved this exact (agent_id, run_id, tool-set) after an
	// earlier hold. A valid token turns what would be a "hold" into an
	// "allow".
	ApprovalToken string
}

// DecideResponse is the PDP's verdict.
type DecideResponse struct {
	// Decision is one of Allow, Deny, or Hold.
	Decision string
	// PolicyVersion is the loaded policy set's PolicyVersion at decision
	// time, so callers can correlate a decision with the exact rule
	// generation that produced it.
	PolicyVersion string
	// Reason explains, in one sentence, which rule fired (or that none
	// did).
	Reason string
	// ApprovalID is set by the caller (internal/api), not by Decide
	// itself, when Decision is Hold and a pending approval was created for
	// it. Empty on Allow and Deny, and empty on the value Decide itself
	// returns.
	ApprovalID string
	// ApprovalTokenRequired reports whether this action is gated by human
	// approval at all -- true whenever the estimated cost exceeds a
	// matched policy's threshold, whether or not a valid token ultimately
	// satisfied it. False when no cost rule was ever reached (e.g. a
	// deny fired first) or no matched policy sets a threshold.
	//
	// Decision == Allow && ApprovalTokenRequired uniquely identifies an
	// allow produced by redeeming a valid token (the only path that can
	// set this field and still return Allow): the caller (internal/api)
	// uses exactly that combination, under WARDRYX_APPROVAL_SINGLE_USE, to
	// decide whether to additionally consult store.Store.TryRedeem and
	// possibly downgrade this Allow to a fresh Hold. Decide itself stays
	// storage-free either way; it never performs that check.
	ApprovalTokenRequired bool
	// Cacheable reports whether this decision is a pure function of
	// (agent_id, tool set), independent of any per-request value such as
	// Steps, Domains, or EstCostUSD. True when no policy matched by
	// AgentID sets MaxSteps, AllowDomains, or RequireHumanAboveUSD -- the
	// only fields Decide checks against per-request state -- or when no
	// policy matched at all. False whenever a matched policy sets any of
	// those three, even if the rule that actually produced this Decision
	// was something else entirely (e.g. DenyTool): a later call against
	// the same agent and tool set could still resolve differently once
	// Steps, Domains, or EstCostUSD change, so the decision as a whole is
	// never safe to reuse, regardless of which rule happened to fire this
	// time. Independent of Decision -- a cacheable decision can be Allow,
	// Deny, or Hold alike -- and computed before any rule runs, so it
	// covers every return path uniformly.
	//
	// Intended for an enforcement point's own decision cache (e.g. the
	// TokenFuse gateway's, keyed only on (agent_id, tool-set hash),
	// coarser than the full request) to gate what it stores: a decision
	// with Cacheable false must never be served again from that cache,
	// only ever re-decided.
	Cacheable bool
}

// Engine evaluates DecideRequests against one compiled policy.Set. It holds
// no mutable state after construction and is safe for concurrent use by
// many goroutines, which is exactly how the HTTP API uses it: one Engine,
// many concurrent /v1/decide calls.
type Engine struct {
	policies       *policy.Set
	approvalSecret []byte
}

// New returns an Engine over policies, using approvalSecret (may be nil) to
// verify any approval_token presented in a DecideRequest. A nil policies is
// treated as policy.Empty(): every request falls through to Allow.
func New(policies *policy.Set, approvalSecret []byte) *Engine {
	if policies == nil {
		policies = policy.Empty()
	}
	return &Engine{policies: policies, approvalSecret: approvalSecret}
}

// PolicyVersion returns the Engine's loaded policy set's PolicyVersion.
func (e *Engine) PolicyVersion() string { return e.policies.Version() }

// Decide evaluates req against the Engine's policy set, in this order:
//  1. an invalid on_behalf_of delegation chain denies, independent of any
//     policy;
//  2. a requested tool in a matched policy's deny_tool denies;
//  3. a matched policy's deny_if_unattested with no live attestation
//     denies;
//  4. a matched policy's max_steps, reached or exceeded by req.Steps,
//     denies;
//  5. a matched policy's allow_domains, missing an entry from req.Domains,
//     denies;
//  6. a matched policy's require_human_above_usd, exceeded by EstCostUSD,
//     resolves to Hold, unless a valid ApprovalToken was presented (then
//     Allow) or an *invalid* one was presented (then Deny);
//  7. otherwise, Allow.
//
// A deny from any rule wins outright: it short-circuits every later rule
// and Decide never has to reconcile a deny against a later hold or allow.
// Rules 1-5 are all deny-or-continue and carry no state, so their relative
// order only changes which single Reason string is reported when a request
// happens to violate more than one of them at once -- it never changes
// whether the final Decision is Deny. Rule 6 is ordered last because it is
// the only rule that can resolve to something other than Deny or
// fall-through (Hold, or Allow via a redeemed token), so every unconditional
// deny check runs first.
func (e *Engine) Decide(req DecideRequest) DecideResponse {
	resp := DecideResponse{PolicyVersion: e.policies.Version()}

	// Defense in depth, independent of any policy: a malformed delegation
	// chain (a cycle, one too deep, or an entry that isn't an
	// agent://user:// URI) is refused outright. A well-formed chain isn't
	// otherwise interpreted by Decide today -- no policy field targets
	// on_behalf_of -- but an agent presenting a chain that violates the
	// stack-wide v0.2 delegation rule (package chain) is never safe to
	// wave through.
	if len(req.OnBehalfOf) > 0 {
		if err := chain.Validate(req.OnBehalfOf); err != nil {
			resp.Decision = Deny
			resp.Reason = fmt.Sprintf("invalid on_behalf_of delegation chain: %v", err)
			// Cacheable stays false (the zero value): OnBehalfOf is a
			// per-request value like Steps or Domains, not a stable
			// per-agent fact, so a chain-validity deny must never be
			// reused for a later call that presents a different chain.
			return resp
		}
	}

	matched := e.policies.Match(req.AgentID)
	// Set once, before any rule runs, so every return path below --
	// whichever rule ends up firing -- carries the same answer. See the
	// field doc comment for why this depends on the matched policy set as
	// a whole, not on which specific rule produced Decision.
	resp.Cacheable = !requestSpecific(matched)

	if tool, pol, ok := deniedTool(matched, req.ToolNames); ok {
		resp.Decision = Deny
		resp.Reason = fmt.Sprintf("tool %q is denied by policy %q (target %s)", tool, pol.Name, pol.Target)
		return resp
	}

	if pol, ok := unattestedDenied(matched, req.AttestationMethod); ok {
		resp.Decision = Deny
		resp.Reason = fmt.Sprintf("policy %q requires a live attestation; agent attestation is %q", pol.Name, attestationLabel(req.AttestationMethod))
		return resp
	}

	if pol, ok := exceededMaxSteps(matched, req.Steps); ok {
		resp.Decision = Deny
		resp.Reason = fmt.Sprintf("policy %q step budget exhausted: %d >= max_steps %d", pol.Name, req.Steps, pol.MaxSteps)
		return resp
	}

	if domain, pol, ok := deniedDomain(matched, req.Domains); ok {
		resp.Decision = Deny
		resp.Reason = fmt.Sprintf("domain %q is not allowed by policy %q (target %s)", domain, pol.Name, pol.Target)
		return resp
	}

	if pol, ok := overThreshold(matched, req.EstCostUSD); ok {
		resp.ApprovalTokenRequired = true
		if req.ApprovalToken != "" {
			verr := approval.VerifyApprovalToken(e.approvalSecret, req.ApprovalToken, req.AgentID, req.RunID, req.ToolNames)
			if verr == nil {
				resp.Decision = Allow
				resp.Reason = fmt.Sprintf("estimated cost $%.2f exceeds policy %q threshold $%.2f; allowed via a valid approval_token", req.EstCostUSD, pol.Name, pol.RequireHumanAboveUSD)
				return resp
			}
			// A token was presented but failed verification: expired,
			// forged, or bound to a different agent/run/tool-set. Denied
			// outright rather than downgraded to Hold, so a stale or
			// mismatched credential is never treated the same as simply
			// not having approval yet (see the package doc comment).
			resp.Decision = Deny
			resp.Reason = fmt.Sprintf("estimated cost $%.2f exceeds policy %q threshold $%.2f; presented approval_token is invalid (%v)", req.EstCostUSD, pol.Name, pol.RequireHumanAboveUSD, verr)
			return resp
		}
		resp.Decision = Hold
		resp.Reason = fmt.Sprintf("estimated cost $%.2f exceeds policy %q threshold $%.2f; human approval required", req.EstCostUSD, pol.Name, pol.RequireHumanAboveUSD)
		return resp
	}

	resp.Decision = Allow
	if len(matched) == 0 {
		resp.Reason = fmt.Sprintf("allowed: no policy targets agent %s", req.AgentID)
	} else {
		resp.Reason = "allowed: request satisfies all matched policy rules"
	}
	return resp
}

// requestSpecific reports whether any policy in matched checks a
// per-request value that can differ from one call to the next even when
// the agent and tool set stay the same: MaxSteps (checked against Steps),
// AllowDomains (checked against Domains), or RequireHumanAboveUSD (checked
// against EstCostUSD). DenyTool and DenyIfUnattested are deliberately not
// considered: both are checked against facts that are stable for a given
// agent and tool set (the tool set itself, and the agent's attestation
// method), not anything that varies call to call the way a step count,
// declared domains, or an estimated cost do.
func requestSpecific(matched []policy.Policy) bool {
	for _, p := range matched {
		if p.MaxSteps > 0 || p.RequireHumanAboveUSD > 0 || len(p.AllowDomains) > 0 {
			return true
		}
	}
	return false
}

func deniedTool(policies []policy.Policy, tools []string) (tool string, pol policy.Policy, ok bool) {
	for _, t := range tools {
		for _, p := range policies {
			if contains(p.DenyTool, t) {
				return t, p, true
			}
		}
	}
	return "", policy.Policy{}, false
}

func unattestedDenied(policies []policy.Policy, method string) (policy.Policy, bool) {
	if method != "" && method != "none" {
		return policy.Policy{}, false
	}
	for _, p := range policies {
		if p.DenyIfUnattested {
			return p, true
		}
	}
	return policy.Policy{}, false
}

// overThreshold returns the matched policy with the smallest positive
// RequireHumanAboveUSD that cost exceeds, if any. Taking the strictest
// (lowest) exceeded threshold, rather than e.g. the first matched policy,
// means Decide reports the most specific binding constraint when several
// policies target the same agent.
func overThreshold(policies []policy.Policy, cost float64) (policy.Policy, bool) {
	var best policy.Policy
	found := false
	for _, p := range policies {
		if p.RequireHumanAboveUSD > 0 && cost > p.RequireHumanAboveUSD {
			if !found || p.RequireHumanAboveUSD < best.RequireHumanAboveUSD {
				best = p
				found = true
			}
		}
	}
	return best, found
}

// exceededMaxSteps returns the matched policy with the smallest positive
// MaxSteps that steps has reached or exceeded, if any. As with
// overThreshold, taking the strictest (lowest) exceeded cap means Decide
// reports the most specific binding constraint when several policies
// target the same agent.
func exceededMaxSteps(policies []policy.Policy, steps int) (policy.Policy, bool) {
	var best policy.Policy
	found := false
	for _, p := range policies {
		if p.MaxSteps > 0 && steps >= p.MaxSteps {
			if !found || p.MaxSteps < best.MaxSteps {
				best = p
				found = true
			}
		}
	}
	return best, found
}

// deniedDomain returns the first requested domain absent from some matched
// policy's non-empty AllowDomains, and that policy, if any. It walks
// domains outer, policies inner -- the same shape deniedTool uses -- so the
// reported violation is deterministic for a given request. A policy whose
// AllowDomains is empty imposes no restriction (skipped: AllowDomains is an
// opt-in allow-list, not a default-deny), and an empty req.Domains makes
// the whole check a no-op because the outer loop never runs: Decide only
// restricts domains the caller actually declared, it never invents a
// restriction the caller didn't ask to be checked against.
//
// When more than one matched policy declares a non-empty AllowDomains, a
// domain must appear in every one of them: allow-lists compose by
// intersection, not union, so the most restrictive matched policy governs
// -- the same "strictest constraint wins" precedent as overThreshold and
// exceededMaxSteps.
func deniedDomain(policies []policy.Policy, domains []string) (domain string, pol policy.Policy, ok bool) {
	for _, d := range domains {
		for _, p := range policies {
			if len(p.AllowDomains) == 0 {
				continue
			}
			if !contains(p.AllowDomains, d) {
				return d, p, true
			}
		}
	}
	return "", policy.Policy{}, false
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func attestationLabel(method string) string {
	if method == "" {
		return "none"
	}
	return method
}
