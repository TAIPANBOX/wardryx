package pdp

// FilterRequest describes one set of tools an agent is offering to a model,
// submitted to POST /v1/filter-tools.
type FilterRequest struct {
	// AgentID is the requesting agent's agent:// URI, matched against each
	// loaded policy's Target glob the same way Decide matches it.
	AgentID string
	// RunID identifies the run this offer belongs to. Carried through for
	// logging; Filter does not branch on it.
	RunID string
	// ToolNames are the tools being offered. Checked against every matched
	// policy's DenyTool, one at a time.
	ToolNames []string
}

// DeniedTool is one tool Filter refused, and which policy refused it.
type DeniedTool struct {
	// Name is the tool name as given in the request.
	Name string
	// Policy is the name of the policy that denied it.
	Policy string
	// Rule is always "deny_tool" in 1.x: Filter applies no other rule.
	Rule string
}

// FilterResponse partitions a FilterRequest's ToolNames into what a matched
// policy's deny_tool refuses and what it does not.
type FilterResponse struct {
	// Allowed lists the offered tools no matched policy denies, in the order
	// they were offered. Never nil.
	Allowed []string
	// Denied lists every offered tool a matched policy's deny_tool refuses,
	// each naming the policy that refused it. Never nil.
	Denied []DeniedTool
	// PolicyVersion is the loaded policy set's PolicyVersion at filter time,
	// the same value Decide would report for the same request.
	PolicyVersion string
}

// Filter is Decide's rule 2 (deny_tool) applied to each offered tool alone,
// through the same matcher Decide uses (policy.Set.Match, one load of the
// Engine's current policy set): it is pure (no clock, randomness, network or
// database), and nothing records it while no enforcement point acts on its
// answer.
//
// For each name in req.ToolNames, in input order, first occurrence only
// (a later duplicate is dropped): the policies Match returns for AgentID are
// checked in the order Match returns them, and the first one whose DenyTool
// contains the name under containsFold denies it. No other rule is applied:
// no chain rule, no attestation, no max_steps, no allow_domains, no cost
// rule, no approval token -- those are rules about the action as a whole,
// not about one offered tool, and Filter answers a narrower question than
// Decide does.
func (e *Engine) Filter(req FilterRequest) FilterResponse {
	policies := e.policies.Load()
	resp := FilterResponse{
		PolicyVersion: policies.Version(),
		Allowed:       []string{},
		Denied:        []DeniedTool{},
	}
	matched := policies.Match(req.AgentID)

	seen := make(map[string]bool, len(req.ToolNames))
	for _, name := range req.ToolNames {
		if seen[name] {
			continue
		}
		seen[name] = true

		denied := false
		for _, p := range matched {
			if containsFold(p.DenyTool, name) {
				resp.Denied = append(resp.Denied, DeniedTool{Name: name, Policy: p.Name, Rule: "deny_tool"})
				denied = true
				break
			}
		}
		if !denied {
			resp.Allowed = append(resp.Allowed, name)
		}
	}
	return resp
}
