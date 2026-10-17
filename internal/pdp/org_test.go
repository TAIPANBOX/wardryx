package pdp

import (
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// F-012, the policy half: a policy with an org governs only the decisions
// asked in that org, so one org's admin cannot reach another org's agents. A
// policy with no org applies across orgs, as every policy did before.
func TestAPolicyWithAnOrgAppliesOnlyToThatOrgsDecisions(t *testing.T) {
	set, err := policy.Compile([]policy.Policy{
		{Name: "acme-deny", Target: "agent://*", Org: "acme", DenyTool: []string{"report"}},
		{Name: "floor", Target: "agent://*", DenyTool: []string{"shell"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	e := New(set, []byte(testSecret))
	ask := func(org, tool string) DecideResponse {
		return e.Decide(DecideRequest{AgentID: "agent://acme.example/bot", Org: org, RunID: "r", ToolNames: []string{tool}})
	}
	cases := []struct {
		org, tool, want string
	}{
		{"acme", "report", Deny},
		{"globex", "report", Allow},
		{"", "report", Allow},
		{"ACME", "report", Allow},
		{"acme", "shell", Deny},
		{"globex", "shell", Deny},
		{"", "shell", Deny},
	}
	for _, c := range cases {
		if got := ask(c.org, c.tool); got.Decision != c.want {
			t.Errorf("asked in %q for %s: %s (%s), want %s", c.org, c.tool, got.Decision, got.Reason, c.want)
		}
	}
	f := e.Filter(FilterRequest{AgentID: "agent://acme.example/bot", Org: "globex", ToolNames: []string{"report", "shell"}})
	if len(f.Denied) != 1 || f.Denied[0].Name != "shell" {
		t.Fatalf("Filter asked in globex = %+v, want only shell denied", f)
	}
}
