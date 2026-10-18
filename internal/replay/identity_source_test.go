package replay

import (
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// A record carries the identity source its decision stood on. A record from
// before the field existed carries none, and that is a request that came with no
// source, which replays as none: it is not an unreadable record, because the
// question needs nothing else the field would have supplied.

func allowRecord(source any) event.Event {
	data := map[string]any{
		"tool_names":              []any{"lookup"},
		"domains":                 nil,
		"steps":                   float64(0),
		"model":                   "",
		"est_cost_usd":            float64(0),
		"attestation_method":      "",
		"chain_proven":            false,
		"policy_version":          "v1",
		"approval_token_required": false,
		"reason":                  "allowed",
	}
	if source != nil {
		data["identity_source"] = source
	}
	return event.Event{Type: "policy_allow", AgentID: "agent://acme.example/support/bot1", RunID: "r1", Data: data}
}

func TestAnOldRecordWithoutASourceIsReadAsNone(t *testing.T) {
	req, _, _, err := question(allowRecord(nil))
	if err != nil {
		t.Fatalf("a record from before identity_source was refused as unreadable: %v", err)
	}
	if req.IdentitySource != policy.IdentitySourceNone {
		t.Fatalf("an absent source replays as %q, want none", req.IdentitySource)
	}
}

func TestARecordedSourceIsReadBack(t *testing.T) {
	req, _, _, err := question(allowRecord("agent-token"))
	if err != nil {
		t.Fatalf("question: %v", err)
	}
	if req.IdentitySource != policy.IdentitySourceAgentToken {
		t.Fatalf("a recorded agent-token replays as %q: the source the decision stood on is lost", req.IdentitySource)
	}
}

func TestAnUnknownRecordedSourceReplaysAsNone(t *testing.T) {
	req, _, _, err := question(allowRecord("banana"))
	if err != nil {
		t.Fatalf("question: %v", err)
	}
	if req.IdentitySource != policy.IdentitySourceNone {
		t.Fatalf("an unknown recorded source replays as %q, want none", req.IdentitySource)
	}
}
