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
	ApprovalTokenRequired bool
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

// Decide evaluates req against the Engine's policy set. See the package
// doc comment for the exact rule order: an invalid delegation chain denies
// first, then deny_tool, then deny_if_unattested, then the cost threshold
// (which resolves to Hold unless a valid ApprovalToken was presented, in
// which case it resolves to Allow); a request that trips none of those
// rules is Allow.
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
			return resp
		}
	}

	matched := e.policies.Match(req.AgentID)

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
