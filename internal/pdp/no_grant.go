package pdp

import (
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// maxReasonFieldBytes bounds a caller's text inside the rule-15 reason. An agent
// id reaches this package unchecked past "not empty", and the reason goes on to
// the approvals list, the console and whatever assistant reads the console for a
// person, so it is cut here and quoted with %q: a line break, a bidirectional
// override or a sentence written to be obeyed arrives as visibly quoted data of
// bounded length. The cut is deterministic, so a replay reaches the same sentence.
const maxReasonFieldBytes = 200

// reasonField cuts s to at most maxReasonFieldBytes on a rune boundary, marking
// the cut. It does not quote: the caller formats the result with %q.
func reasonField(s string) string {
	if len(s) <= maxReasonFieldBytes {
		return s
	}
	cut := maxReasonFieldBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

// noGrant is what rule 15 found: the floor that holds and the first requested tool
// nothing grants.
type noGrant struct {
	floor policy.Policy
	tool  string
}

// reason is the hold's sentence, before what became of it. An id with no agent://
// scheme is told so: no target can pin a trust domain for it, so no grant ever will
// reach it and only a person can let its calls through, one at a time.
func (h noGrant) reason(agentID string) string {
	why := fmt.Sprintf("policy %q when_no_grant: no policy grants tool %q to agent %q",
		reasonField(h.floor.Name), reasonField(h.tool), reasonField(agentID))
	if !strings.HasPrefix(agentID, "agent://") {
		why += " (the id has no agent:// scheme, so no grant can name it; give the agent an agent:// id)"
	}
	return why
}

// heldWithoutGrant reports whether the floor holds this request: it carries a tool
// call, a matched policy sets when_no_grant: hold, and some requested tool is not
// granted. The tool list counts as well as the call's name, as it does for rules
// 2 and 3: a grant for the call's tool does not cover another tool the same
// request names. matched is the org-scoped list, so a grant of another org does
// not count here, and neither does a floor of another org.
func heldWithoutGrant(matched []policy.Policy, req DecideRequest) (noGrant, bool) {
	if req.ToolCall == nil {
		return noGrant{}, false
	}
	floor, ok := noGrantFloor(matched)
	if !ok {
		return noGrant{}, false
	}
	for _, tool := range requestedTools(req) {
		if !toolGranted(matched, tool) {
			return noGrant{floor: floor, tool: tool}, true
		}
	}
	return noGrant{}, false
}

// noGrantFloor returns the first matched policy, in compiled order, that holds.
func noGrantFloor(matched []policy.Policy) (policy.Policy, bool) {
	for _, p := range matched {
		if p.WhenNoGrant == policy.WhenNoGrantHold {
			return p, true
		}
	}
	return policy.Policy{}, false
}

// toolGranted reports whether a matched policy grants tool: its target pins a trust
// domain, and it names the tool in allow_tool or grant_tool, or grants every tool.
// Nothing else counts. A restriction of any kind lifts no hold, and neither does a
// list on a target that reaches domains nobody named: allow_tool on agent://* is a
// restriction on the fleet and says nothing about what any one agent was given.
func toolGranted(matched []policy.Policy, tool string) bool {
	for _, p := range matched {
		if !policy.PinsTrustDomain(p.Target) {
			continue
		}
		if containsFold(p.AllowTool, tool) || containsFold(p.GrantTool, tool) ||
			containsFold(p.GrantTool, policy.GrantAllTools) {
			return true
		}
	}
	return false
}

// Ungranted lists every requested tool of req that rule 15 would hold under the
// Engine's set, without repeats, in the order the request names them. It is empty
// for a request the floor does not judge. internal/replay reads it to name, per
// tool, what a candidate would hold: the reason names only the first.
func (e *Engine) Ungranted(req DecideRequest) []string {
	matched := e.policies.Load().MatchIn(req.AgentID, req.Org)
	if _, ok := heldWithoutGrant(matched, req); !ok {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, tool := range requestedTools(req) {
		if !seen[tool] && !toolGranted(matched, tool) {
			seen[tool] = true
			out = append(out, tool)
		}
	}
	return out
}

// ToolPosture is what a policy set says about one agent's tool calls, for the
// offline check, which has an agent and no call.
type ToolPosture struct {
	// Floor names the policy that holds, or is empty when no floor matches.
	Floor string
	// All says every tool is granted.
	All bool
	// Granted lists the tools a grant names, sorted, without repeats. Any other
	// tool is held. Empty with All false: every tool call of this agent is held.
	Granted []string
}

// ToolPosture reads the posture of agentID in org. A posture with no Floor says
// nothing about tools: without a floor, this rule holds nothing.
func (e *Engine) ToolPosture(agentID, org string) ToolPosture {
	matched := e.policies.Load().MatchIn(agentID, org)
	floor, ok := noGrantFloor(matched)
	if !ok {
		return ToolPosture{}
	}
	posture := ToolPosture{Floor: floor.Name}
	seen := map[string]bool{}
	for _, p := range matched {
		if !policy.PinsTrustDomain(p.Target) {
			continue
		}
		for _, list := range [][]string{p.AllowTool, p.GrantTool} {
			for _, tool := range list {
				name := strings.TrimSpace(tool)
				switch {
				case containsFold(p.GrantTool, policy.GrantAllTools):
					posture.All = true
				case !seen[name]:
					seen[name] = true
					posture.Granted = append(posture.Granted, name)
				}
			}
		}
	}
	if posture.All {
		posture.Granted = nil
	}
	sort.Strings(posture.Granted)
	return posture
}
