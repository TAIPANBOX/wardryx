package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/store"
)

// F-012, the approval half: the approver an approval recorded was whatever
// text the request sent in decided_by, and an approval with no org could be
// decided by an admin of any org.

const approverKey = "approver-test-key-51c2"

// holdFor makes one hold through the gateway's key and returns its id.
func (h *orgHarness) holdFor(t *testing.T, key, agent string) string {
	t.Helper()
	held := decodeBody[decideResponseDTO](t, h.decide(t, key, decideRequestDTO{AgentID: agent, RunID: "r1", ToolNames: []string{"lookup"}, EstCostUSD: 500}))
	if held.Decision != pdp.Hold || held.ApprovalID == "" {
		t.Fatalf("setup: %s (%s), want a hold", held.Decision, held.Reason)
	}
	return held.ApprovalID
}

func (h *orgHarness) decideApproval(t *testing.T, key, id string, body any) int {
	t.Helper()
	return h.do(t, http.MethodPost, "/v1/approvals/"+id+"/decide", key, body).Code
}

func TestTheApproverRecordedIsTheKeyNotTheText(t *testing.T) {
	h := newOrgHarness(t, "gw:acme:pep,"+approverKey+":acme:admin", false, supportFloor())
	id := h.holdFor(t, "gw", bot1)
	if code := h.decideApproval(t, approverKey, id, approvalDecideRequestDTO{Decision: "grant", DecidedBy: "someone-who-is-not-a-person-42"}); code != http.StatusOK {
		t.Fatalf("grant: %d", code)
	}
	want := "key:" + fp(approverKey)
	a := approvalByID(h.approvalsAs(t, approverKey), id)
	if a == nil || a["decided_by"] != want {
		t.Fatalf("listed approval decided_by = %#v, want %q (the key, not the text)", a["decided_by"], want)
	}
	granted := h.eventsOfType(t, "approval_granted")
	if len(granted) != 1 || granted[0]["decided_by"] != want || granted[0]["key_fp"] != fp(approverKey) {
		t.Fatalf("approval_granted = %v, want decided_by %q and key_fp %q", granted, want, fp(approverKey))
	}
	for _, e := range h.allEvents(t) {
		for _, v := range e.Data {
			if s, ok := v.(string); ok && strings.Contains(s, approverKey) {
				t.Fatalf("the raw key reached the event file in %s", e.Type)
			}
		}
	}
}

func TestTheTextSentIsKeptAsALabelBesideTheApprover(t *testing.T) {
	h := newOrgHarness(t, "gw:acme:pep,"+approverKey+":acme:admin", false, supportFloor())
	id := h.holdFor(t, "gw", bot1)
	if code := h.decideApproval(t, approverKey, id, approvalDecideRequestDTO{Decision: "deny", DecidedBy: "alice"}); code != http.StatusOK {
		t.Fatalf("deny: %d", code)
	}
	a := approvalByID(h.approvalsAs(t, approverKey), id)
	if a["decided_by_label"] != "alice" || a["decided_by"] != "key:"+fp(approverKey) {
		t.Fatalf("listed approval = %v, want decided_by the key and decided_by_label alice", a)
	}
	denied := h.eventsOfType(t, "approval_denied")
	if len(denied) != 1 || denied[0]["decided_by_label"] != "alice" {
		t.Fatalf("approval_denied = %v, want decided_by_label alice", denied)
	}
}

func TestAnApprovalDecisionNeedsNoLabel(t *testing.T) {
	h := newOrgHarness(t, "gw:acme:pep,"+approverKey+":acme:admin", false, supportFloor())
	id := h.holdFor(t, "gw", bot1)
	if code := h.decideApproval(t, approverKey, id, map[string]string{"decision": "grant"}); code != http.StatusOK {
		t.Fatalf("a grant with no decided_by: %d, want 200", code)
	}
	a := approvalByID(h.approvalsAs(t, approverKey), id)
	if a["decided_by"] != "key:"+fp(approverKey) {
		t.Fatalf("decided_by = %#v, want the key", a["decided_by"])
	}
	if _, ok := a["decided_by_label"]; ok {
		t.Fatalf("a label was recorded that nobody sent: %v", a)
	}
	granted := h.eventsOfType(t, "approval_granted")
	if _, ok := granted[0]["decided_by_label"]; ok {
		t.Fatalf("the event carries a label nobody sent: %v", granted[0])
	}
}

func TestAHostileLabelIsRefusedAndTheApprovalStaysPending(t *testing.T) {
	h := newOrgHarness(t, "gw:acme:pep,"+approverKey+":acme:admin", false, supportFloor())
	id := h.holdFor(t, "gw", bot1)
	for name, label := range map[string]string{
		"escape":   "ok\x1b[2Jcleared",
		"newline":  "alice\nbob",
		"too long": strings.Repeat("a", 257),
		"c1":       "alice\u0085cleared",
		"bidi":     "alice\u202ecleared",
	} {
		rec := h.do(t, http.MethodPost, "/v1/approvals/"+id+"/decide", approverKey, approvalDecideRequestDTO{Decision: "grant", DecidedBy: label})
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s label: %d %s, want 400", name, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "cleared") || strings.Contains(rec.Body.String(), "aaaaaaaa") {
			t.Errorf("%s label: the refusal echoes it: %s", name, rec.Body.String())
		}
	}
	if a := approvalByID(h.approvalsAs(t, approverKey), id); a == nil || a["pending"] != true {
		t.Fatalf("after refused labels the approval is %v, want still pending", a)
	}
	// Exactly 256 bytes is the limit, not over it.
	if code := h.decideApproval(t, approverKey, id, approvalDecideRequestDTO{Decision: "grant", DecidedBy: strings.Repeat("a", 256)}); code != http.StatusOK {
		t.Fatalf("a 256-byte label: %d, want 200", code)
	}
}

// seedApprovalWithNoOrg writes a pending approval whose context names no org,
// the shape a row written before org scoping has.
func seedApprovalWithNoOrg(t *testing.T, st store.Store, id string) {
	t.Helper()
	if err := st.CreateApproval(context.Background(), store.Approval{
		ApprovalID:  id,
		AgentID:     bot1,
		RunID:       "r1",
		RequestedAt: time.Now().UTC(),
		Context:     map[string]any{"tool_names": []string{"lookup"}},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func TestAnApprovalWithNoOrgNeedsAPrincipalAllowedAcrossOrgs(t *testing.T) {
	h := newOrgHarness(t, "adma:acme:admin,admb:globex:admin,root:ops:cross-org-admin", false, supportFloor())
	seedApprovalWithNoOrg(t, h.st, "legacy-1")
	rec := h.do(t, http.MethodPost, "/v1/approvals/legacy-1/decide", "adma", approvalDecideRequestDTO{Decision: "grant", DecidedBy: "mallory"})
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "approval not found") {
		t.Fatalf("an org admin decided an approval with no org: %d %s, want the 404 an unknown id gets", rec.Code, rec.Body.String())
	}
	if code := h.decideApproval(t, "root", "legacy-1", approvalDecideRequestDTO{Decision: "grant", DecidedBy: "ops"}); code != http.StatusOK {
		t.Fatalf("the cross-org admin: %d, want 200", code)
	}
}

func TestWithOneOrgItsAdminDecidesAnApprovalWithNoOrg(t *testing.T) {
	h := newOrgHarness(t, "adm:default:admin,gw:default:viewer", false, supportFloor())
	seedApprovalWithNoOrg(t, h.st, "legacy-1")
	if code := h.decideApproval(t, "adm", "legacy-1", approvalDecideRequestDTO{Decision: "grant", DecidedBy: "ops"}); code != http.StatusOK {
		t.Fatalf("the only org's admin: %d, want 200 as before", code)
	}
}

func TestACrossOrgAdminListsTheApprovalsOfEveryOrg(t *testing.T) {
	spec := "gwa:acme:pep:agent://acme.example/*,gwb:globex:pep:agent://globex.example/*,adma:acme:admin,root:ops:cross-org-admin"
	h := newOrgHarness(t, spec, false, supportFloor())
	a := h.holdFor(t, "gwa", bot1)
	b := h.holdFor(t, "gwb", "agent://globex.example/bot2")
	seedApprovalWithNoOrg(t, h.st, "legacy-1")
	all := h.approvalsAs(t, "root")
	if len(all) != 3 || approvalByID(all, a) == nil || approvalByID(all, b) == nil || approvalByID(all, "legacy-1") == nil {
		t.Fatalf("the cross-org admin lists %v, want all three", all)
	}
	own := h.approvalsAs(t, "adma")
	if len(own) != 1 || approvalByID(own, a) == nil {
		t.Fatalf("acme's admin lists %v, want only acme's hold", own)
	}
}
