package api

import (
	"bytes"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Supervisor decision, relayed 2026-10-19 (`@decided 2026-10-19`, paraphrased):
// once a console key set is configured, an approval is decided by a verified
// statement, not by a bearer key alone. A key-kind decision is refused unless
// the operator allows it (WARDRYX_ALLOW_KEY_APPROVALS=1), and an allowed one is
// logged every time it happens. With no key set nothing changes.

// captureApproverLog points the standard logger at a buffer for the test.
func captureApproverLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func TestAGrantWithNoStatementIsRefusedWhenAKeySetIsConfigured(t *testing.T) {
	console := newConsoleKey(t)
	h := newOrgHarness(t, "gw:acme:pep,"+approverKey+":acme:admin", false, supportFloor())
	h.srv.WithApprovers(consoleVerifier(t, console))
	id := h.holdFor(t, "gw", bot1)
	rec := h.do(t, http.MethodPost, "/v1/approvals/"+id+"/decide", approverKey,
		approvalDecideRequestDTO{Decision: "grant"})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "approver_statement_required") {
		t.Fatalf("a key-kind grant with a key set configured: %d %s, want 403 approver_statement_required", rec.Code, rec.Body)
	}
	if granted := h.eventsOfType(t, "approval_granted"); len(granted) != 0 {
		t.Fatalf("a refused key-kind grant was recorded as granted: %v", granted)
	}
	if a := approvalByID(h.approvalsAs(t, approverKey), id); a == nil || a["pending"] != true {
		t.Fatalf("the hold is not pending after a refused key-kind grant: %v", a)
	}
}

func TestAKeyApprovalIsAllowedOnlyWhenTheOperatorAllowsIt(t *testing.T) {
	console := newConsoleKey(t)
	h := newOrgHarness(t, "gw:acme:pep,"+approverKey+":acme:admin", false, supportFloor())
	h.srv.WithApprovers(consoleVerifier(t, console)).WithAllowKeyApprovals(true)
	id := h.holdFor(t, "gw", bot1)
	if code := h.decideApproval(t, approverKey, id, approvalDecideRequestDTO{Decision: "grant"}); code != http.StatusOK {
		t.Fatalf("a key-kind grant with WARDRYX_ALLOW_KEY_APPROVALS=1: %d, want 200", code)
	}
	a := approvalByID(h.approvalsAs(t, approverKey), id)
	if a == nil || a["decided_by"] != "key:"+fp(approverKey) || a["approver_kind"] != "key" {
		t.Fatalf("listed approval = %v, want decided_by the key and approver_kind key", a)
	}
	granted := h.eventsOfType(t, "approval_granted")
	if len(granted) != 1 || granted[0]["approver_kind"] != "key" {
		t.Fatalf("approval_granted = %v, want approver_kind key", granted)
	}
}

func TestAKeyApprovalIsWrittenToTheLogEveryTime(t *testing.T) {
	console := newConsoleKey(t)
	h := newOrgHarness(t, "gw:acme:pep,"+approverKey+":acme:admin", false, supportFloor())
	h.srv.WithApprovers(consoleVerifier(t, console)).WithAllowKeyApprovals(true)
	buf := captureApproverLog(t)
	first := h.holdFor(t, "gw", bot1)
	second := h.holdFor(t, "gw", bot1)
	for _, id := range []string{first, second} {
		if code := h.decideApproval(t, approverKey, id, approvalDecideRequestDTO{Decision: "deny"}); code != http.StatusOK {
			t.Fatalf("key-kind deny of %s: %d", id, code)
		}
	}
	out := buf.String()
	for _, id := range []string{first, second} {
		if !strings.Contains(out, "WARNING") || !strings.Contains(out, id) {
			t.Fatalf("no warning in the log for the key-kind decision of %s; log:\n%s", id, out)
		}
	}
}

func TestAStatementStillDecidesWhenKeyApprovalsAreNotAllowed(t *testing.T) {
	console := newConsoleKey(t)
	h := newOrgHarness(t, "gw:acme:pep,"+approverKey+":acme:admin", false, supportFloor())
	h.srv.WithApprovers(consoleVerifier(t, console))
	id := h.holdFor(t, "gw", bot1)
	stmt := mintApproverStatement(t, console, id, "grant", "approver-1842", time.Now())
	if code := h.decideApproval(t, approverKey, id, approvalDecideRequestDTO{Decision: "grant", ApproverStatement: stmt}); code != http.StatusOK {
		t.Fatalf("a verified statement with key approvals not allowed: %d, want 200", code)
	}
}

func TestWithNoKeySetTheFlagChangesNothing(t *testing.T) {
	h := newOrgHarness(t, "gw:acme:pep,"+approverKey+":acme:admin", false, supportFloor())
	h.srv.WithAllowKeyApprovals(true)
	buf := captureApproverLog(t)
	id := h.holdFor(t, "gw", bot1)
	if code := h.decideApproval(t, approverKey, id, approvalDecideRequestDTO{Decision: "grant"}); code != http.StatusOK {
		t.Fatalf("a key-kind grant with no key set: %d, want 200 as before", code)
	}
	if strings.Contains(buf.String(), "WARNING") {
		t.Fatalf("a key-kind grant with no key set was logged as a warning: %s", buf.String())
	}
}
