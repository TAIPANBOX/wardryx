package api

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/wardryx/internal/archive"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/replay"
	"github.com/TAIPANBOX/wardryx/internal/store"
)

// TestASpentTokenHoldReplaysAsApprovalSpent is the seam between this package
// and internal/replay (wardryx#57). internal/replay tells a spent-token hold
// from a divergence by one exact sentence, pdp.ReasonApprovalSpent; this test
// drives the real handler under single-use, closes the real writer, and puts
// the file it wrote to the real replay, so the sentence cannot drift in one
// package without this going red. The unit test on the replay side plants
// the sentence by hand and cannot see that.
func TestASpentTokenHoldReplaysAsApprovalSpent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	ew, err := event.NewChainedWriter(path)
	if err != nil {
		t.Fatalf("NewChainedWriter: %v", err)
	}
	set, err := policy.Compile([]policy.Policy{{
		Name: "finance-guardrail", Target: "agent://acme.example/finance/*",
		RequireHumanAboveUSD: 500,
	}})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	keys := map[string]Principal{adminKey: {Org: "acme", Role: RoleAdmin}}
	srv := New(pdp.New(set, []byte(testHMAC)), store.NewMemory(), ew, nil, keys, []byte(testHMAC), true, set.Policies())
	a, err := archive.New(t.TempDir())
	if err != nil {
		t.Fatalf("archive.New: %v", err)
	}
	if err := srv.SetPolicyArchive(a); err != nil {
		t.Fatalf("SetPolicyArchive: %v", err)
	}

	ask := decideRequestDTO{AgentID: "agent://acme.example/finance/bot1", RunID: "run-57", ToolNames: []string{"generate_report"}, EstCostUSD: 999}
	held := decodeBody[decideResponseDTO](t, doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, ask))
	if held.Decision != pdp.Hold {
		t.Fatalf("Decision = %q, want hold", held.Decision)
	}
	granted := decodeBody[approvalDecideResponseDTO](t, doRequest(t, srv.Handler(), http.MethodPost,
		"/v1/approvals/"+held.ApprovalID+"/decide", adminKey, approvalDecideRequestDTO{Decision: "grant", DecidedBy: "alice@acme.example"}))
	ask.ApprovalToken = granted.ApprovalToken
	first := decodeBody[decideResponseDTO](t, doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, ask))
	second := decodeBody[decideResponseDTO](t, doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, ask))
	if first.Decision != pdp.Allow || second.Decision != pdp.Hold {
		t.Fatalf("first = %q, second = %q, want allow then hold", first.Decision, second.Decision)
	}
	if second.Reason != pdp.ReasonApprovalSpent {
		t.Fatalf("the spent-token hold's reason = %q, want pdp.ReasonApprovalSpent", second.Reason)
	}
	if err := ew.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	events, err := event.ReadFile(path)
	if err != nil {
		t.Fatalf("event.ReadFile: %v", err)
	}
	report := replay.Run(events, a, nil)
	// The hold, the human's allow, and the spent-token hold: three decisions,
	// every one replayable, none a divergence.
	if report.Total != 3 || report.Diverged != 0 {
		t.Fatalf("total = %d, diverged = %d, want 3 and 0:\n%s", report.Total, report.Diverged, replay.Format(report, path, ""))
	}
	if report.Reproduced != 1 || report.ApprovalDecided != 1 || report.ApprovalSpent != 1 {
		t.Fatalf("reproduced = %d, approval-decided = %d, approval-spent = %d, want 1, 1, 1:\n%s",
			report.Reproduced, report.ApprovalDecided, report.ApprovalSpent, replay.Format(report, path, ""))
	}
}
