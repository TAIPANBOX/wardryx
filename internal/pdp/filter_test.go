package pdp

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// filterEngine builds an Engine over the given policies, failing the test on
// a compile error.
func filterEngine(t *testing.T, policies []policy.Policy) *Engine {
	t.Helper()
	set, err := policy.Compile(policies)
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	return New(set, []byte(testSecret))
}

// TestFilterNamesEveryDeniedToolNotOnlyTheFirst is the scenario "Every denied
// tool is named, not only the first" (features/filter-tools.feature).
func TestFilterNamesEveryDeniedToolNotOnlyTheFirst(t *testing.T) {
	engine := filterEngine(t, []policy.Policy{
		{
			Name:     "acme-guardrail",
			Target:   "agent://acme/*",
			DenyTool: []string{"shell", "email_send"},
		},
	})

	resp := engine.Filter(FilterRequest{
		AgentID:   "agent://acme/bot",
		RunID:     "r1",
		ToolNames: []string{"shell", "search", "email_send"},
	})

	if len(resp.Denied) != 2 {
		t.Fatalf("Denied = %+v, want 2 entries (shell, email_send), not only the first", resp.Denied)
	}
	if resp.Denied[0].Name != "shell" || resp.Denied[1].Name != "email_send" {
		t.Fatalf("Denied names = %q, %q; want shell, email_send in that order", resp.Denied[0].Name, resp.Denied[1].Name)
	}
	if len(resp.Allowed) != 1 || resp.Allowed[0] != "search" {
		t.Fatalf("Allowed = %v, want [search]", resp.Allowed)
	}
}

// TestFilterAppliesNoRuleThatIsNotAboutATool is the scenario "A rule about
// the action does not remove a tool".
func TestFilterAppliesNoRuleThatIsNotAboutATool(t *testing.T) {
	engine := filterEngine(t, []policy.Policy{
		{
			Name:                 "acme-action-rules",
			Target:               "agent://acme/*",
			MaxSteps:             1,
			DenyAboveUSD:         0.01,
			RequireHumanAboveUSD: 0.01,
			DenyIfUnattested:     true,
			AllowDomains:         []string{"example.com"},
		},
	})

	resp := engine.Filter(FilterRequest{
		AgentID:   "agent://acme/bot",
		RunID:     "r1",
		ToolNames: []string{"search"},
	})

	if len(resp.Allowed) != 1 || resp.Allowed[0] != "search" {
		t.Fatalf("Allowed = %v, want [search]: no deny_tool rule was set, so no other rule may remove a tool", resp.Allowed)
	}
	if len(resp.Denied) != 0 {
		t.Fatalf("Denied = %+v, want empty: max_steps/deny_above_usd/require_human_above_usd/deny_if_unattested/allow_domains are about the action, not one tool", resp.Denied)
	}
}

// TestFilterMatchesToolsTheWayDecideDoes is the case matching deniedTool's
// containsFold semantics: case- and whitespace-insensitive, exact otherwise.
func TestFilterMatchesToolsTheWayDecideDoes(t *testing.T) {
	engine := filterEngine(t, []policy.Policy{
		{
			Name:     "acme-guardrail",
			Target:   "agent://acme/*",
			DenyTool: []string{"Shell"},
		},
	})

	resp := engine.Filter(FilterRequest{
		AgentID:   "agent://acme/bot",
		RunID:     "r1",
		ToolNames: []string{" shell ", "SHELL", "shellx"},
	})

	deniedNames := map[string]bool{}
	for _, d := range resp.Denied {
		deniedNames[d.Name] = true
	}
	if !deniedNames[" shell "] || !deniedNames["SHELL"] {
		t.Fatalf("Denied = %+v, want both %q and %q denied under containsFold", resp.Denied, " shell ", "SHELL")
	}
	if len(resp.Denied) != 2 {
		t.Fatalf("Denied = %+v, want exactly 2 (not shellx)", resp.Denied)
	}
	if len(resp.Allowed) != 1 || resp.Allowed[0] != "shellx" {
		t.Fatalf("Allowed = %v, want [shellx]: it is not the same tool as Shell", resp.Allowed)
	}
}

// TestFilterIgnoresPoliciesForOtherAgents proves Filter reads the policy set
// through Set.Match (agent-scoped), not the whole set.
func TestFilterIgnoresPoliciesForOtherAgents(t *testing.T) {
	engine := filterEngine(t, []policy.Policy{
		{
			Name:     "other-guardrail",
			Target:   "agent://other/*",
			DenyTool: []string{"shell"},
		},
	})

	resp := engine.Filter(FilterRequest{
		AgentID:   "agent://acme/bot",
		RunID:     "r1",
		ToolNames: []string{"shell"},
	})

	if len(resp.Denied) != 0 {
		t.Fatalf("Denied = %+v, want empty: the only deny_tool policy targets a different agent", resp.Denied)
	}
	if len(resp.Allowed) != 1 || resp.Allowed[0] != "shell" {
		t.Fatalf("Allowed = %v, want [shell]", resp.Allowed)
	}
}

// TestFilterDropsLaterDuplicates proves a repeated tool name is reported
// once, under its first occurrence.
func TestFilterDropsLaterDuplicates(t *testing.T) {
	engine := filterEngine(t, []policy.Policy{
		{Name: "noop", Target: "agent://acme/*"},
	})

	resp := engine.Filter(FilterRequest{
		AgentID:   "agent://acme/bot",
		RunID:     "r1",
		ToolNames: []string{"search", "search"},
	})

	if len(resp.Allowed) != 1 || resp.Allowed[0] != "search" {
		t.Fatalf("Allowed = %v, want [search] exactly once", resp.Allowed)
	}
}

// TestFilterAgreesWithDecideOnEveryToolAlone is the property sweep: for a
// seeded, randomized set of policies and a fixed tool pool, Decide called on
// exactly one tool at a time denies by deny_tool if and only if Filter lists
// that tool in Denied. Seeds are fixed (1..200) so a failure reproduces; the
// seed is printed on failure.
func TestFilterAgreesWithDecideOnEveryToolAlone(t *testing.T) {
	const agentUnderTest = "agent://acme/bot"
	targets := []string{"agent://acme/*", "agent://acme/bot", "agent://other/*"}
	toolPool := []string{"shell", "email_send", "search", "delete_account", "http_get"}
	caseVariants := []func(string) string{
		func(s string) string { return s },
		func(s string) string { return " " + s + " " },
		func(s string) string { return strings.ToUpper(s) },
		func(s string) string { return "  " + strings.ToUpper(s) },
	}

	for seed := int64(1); seed <= 200; seed++ {
		rng := rand.New(rand.NewSource(seed))

		numPolicies := 1 + rng.Intn(4) // 1..4
		policies := make([]policy.Policy, 0, numPolicies)
		for i := 0; i < numPolicies; i++ {
			target := targets[rng.Intn(len(targets))]
			numDenied := rng.Intn(len(toolPool) + 1) // 0..len(toolPool)
			denySet := map[string]bool{}
			for len(denySet) < numDenied {
				tool := toolPool[rng.Intn(len(toolPool))]
				variant := caseVariants[rng.Intn(len(caseVariants))](tool)
				denySet[variant] = true
			}
			denyTool := make([]string, 0, len(denySet))
			for tool := range denySet {
				denyTool = append(denyTool, tool)
			}
			policies = append(policies, policy.Policy{
				Name:     fmt.Sprintf("p%d", i),
				Target:   target,
				DenyTool: denyTool,
			})
		}

		set, err := policy.Compile(policies)
		if err != nil {
			t.Fatalf("seed %d: policy.Compile: %v", seed, err)
		}
		engine := New(set, []byte(testSecret))

		for _, tool := range toolPool {
			decideResp := engine.Decide(DecideRequest{
				AgentID:   agentUnderTest,
				RunID:     "r",
				ToolNames: []string{tool},
			})
			decideDenied := decideResp.Decision == Deny

			filterResp := engine.Filter(FilterRequest{
				AgentID:   agentUnderTest,
				RunID:     "r",
				ToolNames: []string{tool},
			})
			filterDenied := len(filterResp.Denied) == 1 && filterResp.Denied[0].Name == tool

			if decideDenied != filterDenied {
				t.Fatalf("seed %d, tool %q: Decide denied=%v (reason %q), Filter denied=%v; policies=%+v",
					seed, tool, decideDenied, decideResp.Reason, filterDenied, policies)
			}
		}
	}
}
