package replay

import (
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// A policy with an org governs only the decisions asked in that org, so the
// org a decision was asked in is part of its question (F-012). Replay reads it
// from the record; a record from before the field carries none and asks in no
// org, where only the policies across orgs apply, as every policy then did.
func TestARecordedOrgIsFedBackToThePDP(t *testing.T) {
	set, err := policy.Compile([]policy.Policy{{Name: "acme-deny", Target: "agent://*", Org: "acme", DenyTool: []string{"http_get"}}})
	if err != nil {
		t.Fatal(err)
	}
	reason := `tool "http_get" is denied by policy "acme-deny" (target agent://*)`
	deny := decisionEvent("policy_deny", set.Version(), reason, map[string]any{"org": "acme", "domains": nil})
	allow := decisionEvent("policy_allow", set.Version(), "allowed: no policy targets agent agent://acme.example/finance/bot1", map[string]any{"org": "globex", "domains": nil})
	report := Run([]event.Event{deny, allow}, archiveOf(t, set), nil)
	if report.Reproduced != 2 || report.Diverged != 0 {
		t.Fatalf("the org-scoped decisions did not reproduce:\n%s", Format(report, "x", ""))
	}
	// The same denial recorded in another org would have been an allow, so
	// the org is what replay reads.
	deny.Data["org"] = "globex"
	if report := Run([]event.Event{deny}, archiveOf(t, set), nil); report.Diverged != 1 {
		t.Fatalf("a denial recorded in an org the policy does not govern must diverge:\n%s", Format(report, "x", ""))
	}
	// An org that is not text is not a question that can be put again.
	deny.Data["org"] = 7.0
	if report := Run([]event.Event{deny}, archiveOf(t, set), nil); report.Unreadable != 1 {
		t.Fatalf("a record whose org is not text must be unreadable:\n%s", Format(report, "x", ""))
	}
}
