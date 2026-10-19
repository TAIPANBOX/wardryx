package replay

import (
	"encoding/json"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// A decision that refused a model was about the model the record names, and
// replay puts that model back: the denial reproduces, and the same record read
// without its model would be a different question.

func modelSet(t *testing.T) *policy.Set {
	t.Helper()
	var p policy.Policy
	if err := json.Unmarshal([]byte(`{"name":"fleet","target":"agent://acme.example/finance/*","allow_models":["claude-sonnet-*"]}`), &p); err != nil {
		t.Fatal(err)
	}
	set, err := policy.Compile([]policy.Policy{p})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	return set
}

func TestARecordedModelDenialReproducesFromTheRecordedModel(t *testing.T) {
	set := modelSet(t)
	deny := decisionEvent("policy_deny", set.Version(),
		`model "claude-opus-5" is not in the allow_models of policy "fleet" (target agent://acme.example/finance/*)`,
		map[string]any{"model": "claude-opus-5"})
	allow := decisionEvent("policy_allow", set.Version(), "allowed: request satisfies all matched policy rules",
		map[string]any{"model": "claude-sonnet-5-5"})
	report := Run([]event.Event{deny, allow}, archiveOf(t, set), nil)
	if report.Reproduced != 2 || report.Diverged != 0 {
		t.Fatalf("the recorded model decisions did not reproduce:\n%s", Format(report, "x", ""))
	}
	// The recorded allow on a listed model replayed as a model the list refuses
	// is a divergence, so the model is what replay reads.
	allow.Data["model"] = "claude-opus-5"
	if report := Run([]event.Event{allow}, archiveOf(t, set), nil); report.Diverged != 1 {
		t.Fatalf("an allow recorded for a model the list refuses must diverge:\n%s", Format(report, "x", ""))
	}
}
