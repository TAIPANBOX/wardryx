package pdp

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/approval"
)

// An approval token for one tool call lifts a hold only for that call. The
// engine is the one place the digest of the presented call is computed, so these
// tests hold it without the HTTP layer.

func mintFor(t *testing.T, req DecideRequest, cost float64) string {
	t.Helper()
	tok, _, err := approval.MintApprovalTokenForCall([]byte("signal-test-secret"), req.AgentID, req.RunID, req.ToolNames, cost, req.ToolCall.Digest(), time.Minute)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return tok
}

func TestAToolCallDigestIsTheOneApprovalComputes(t *testing.T) {
	tc := toolCallRequest().ToolCall
	want := approval.ToolCallDigest(tc.Name, tc.Target, tc.Arguments, tc.ArgumentsTruncated)
	if got := tc.Digest(); got != want {
		t.Fatalf("pdp digest %s, approval digest %s", got, want)
	}
	var none *ToolCall
	if none.Digest() != "" {
		t.Fatal("a request with no tool call must present the empty digest")
	}
}

func TestASignalHoldIsLiftedOnlyForTheCallThatWasApproved(t *testing.T) {
	e := signalEngine(t, riskPolicy())
	approved := toolCallRequest(riskSignal("destructive", 0.95))
	tok := mintFor(t, approved, 0)

	approved.ApprovalToken = tok
	if got := e.Decide(approved); got.Decision != Allow {
		t.Fatalf("the approved call is %s (%s), want allow", got.Decision, got.Reason)
	}

	other := toolCallRequest(riskSignal("destructive", 0.95))
	other.ToolCall.Arguments = json.RawMessage(`{"bucket":"prod-customers","key":"2026/db.dump"}`)
	other.ApprovalToken = tok
	if got := e.Decide(other); got.Decision != Hold {
		t.Fatalf("another call of the same tool is %s (%s), want a hold of its own, never a deny and never an allow", got.Decision, got.Reason)
	}

	retarget := toolCallRequest(riskSignal("destructive", 0.95))
	retarget.ToolCall.Target = "s3://prod-customers"
	retarget.ApprovalToken = tok
	if got := e.Decide(retarget); got.Decision != Hold {
		t.Fatalf("the same arguments at another target are %s (%s), want hold", got.Decision, got.Reason)
	}

	noCall := toolCallRequest(riskSignal("destructive", 0.95))
	noCall.ToolCall = nil
	noCall.ApprovalToken = tok
	if got := e.Decide(noCall); got.Decision != Hold {
		t.Fatalf("a request with no tool call is %s (%s), want hold", got.Decision, got.Reason)
	}
}

func TestACostGateTokenForOneCallDeniesAnotherAndNamesNeitherDigest(t *testing.T) {
	cost := riskPolicy()
	cost.RequireHumanAboveUSD = f64(10)
	e := signalEngine(t, cost)

	approved := toolCallRequest()
	approved.EstCostUSD = 50
	tok := mintFor(t, approved, 50)
	approved.ApprovalToken = tok
	if got := e.Decide(approved); got.Decision != Allow {
		t.Fatalf("the approved call is %s (%s), want allow", got.Decision, got.Reason)
	}

	other := toolCallRequest()
	other.EstCostUSD = 50
	other.ToolCall.Arguments = json.RawMessage(`{"bucket":"prod-customers"}`)
	other.ApprovalToken = tok
	got := e.Decide(other)
	if got.Decision != Deny || !strings.Contains(got.Reason, ReasonApprovalRefused) {
		t.Fatalf("another call under a cost token is %s (%s), want the refused-token deny", got.Decision, got.Reason)
	}
	for _, d := range []string{approved.ToolCall.Digest(), other.ToolCall.Digest()} {
		if strings.Contains(got.Reason, d) {
			t.Fatalf("the reason names a digest: %s", got.Reason)
		}
	}
}
