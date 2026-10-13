package pdp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// TestARuleInTheSecondDocumentIsEnforced is the scenario "A rule in the second
// document is enforced" (features/multi-document-policy-file.feature). It goes
// from the file on disk through policy.Load and Decide, because the defect was
// at the file boundary: the load reported one policy, and the request the
// second document refuses was allowed.
func TestARuleInTheSecondDocumentIsEnforced(t *testing.T) {
	path := filepath.Join(t.TempDir(), "finance.yaml")
	src := "name: finance-floor\ntarget: \"agent://acme.example/finance/*\"\n" +
		"deny_tool:\n  - delete_account\n" +
		"---\n" +
		"name: finance-wire-deny\ntarget: \"agent://acme.example/finance/*\"\n" +
		"deny_tool:\n  - send_wire_transfer\n"
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := policy.Load(path)
	if err != nil {
		t.Fatalf("policy.Load: %v", err)
	}
	e := New(set, []byte("signal-test-secret"))

	resp := e.Decide(DecideRequest{AgentID: "agent://acme.example/finance/bot1", RunID: "r1", ToolNames: []string{"send_wire_transfer"}})
	if resp.Decision != Deny {
		t.Fatalf("Decision = %q (reason %q), want deny: the second document refuses send_wire_transfer, and the file loaded without it", resp.Decision, resp.Reason)
	}
	if !strings.Contains(resp.Reason, "finance-wire-deny") {
		t.Fatalf("Reason = %q, want it to name the policy of the second document", resp.Reason)
	}

	// The first document's rule still holds, and a tool neither document names
	// is still allowed: loading every document must not turn into refusing more.
	if resp := e.Decide(DecideRequest{AgentID: "agent://acme.example/finance/bot1", RunID: "r1", ToolNames: []string{"delete_account"}}); resp.Decision != Deny {
		t.Fatalf("Decision for delete_account = %q, want deny from the first document", resp.Decision)
	}
	if resp := e.Decide(DecideRequest{AgentID: "agent://acme.example/finance/bot1", RunID: "r1", ToolNames: []string{"search"}}); resp.Decision != Allow {
		t.Fatalf("Decision for search = %q (reason %q), want allow: no document names it", resp.Decision, resp.Reason)
	}
}
