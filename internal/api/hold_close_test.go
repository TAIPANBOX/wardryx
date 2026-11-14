package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/store"
)

// A hold is closed in three ways and no others (CLAUDE.md invariant 52): a person
// decides it, wardryx closes it as expired once it has waited WARDRYX_HOLD_TTL, or
// the held agent withdraws it. An admin key closes nothing that is not a decision.
// Every test here was run first against the tree with the TTL check and the
// withdraw route left out, and failed there.

// holdKeys: an enforcement point of acme that speaks for bot1 and bot9, another
// org's enforcement point that also names acme's agents, acme's admin, and a
// cross-org admin. Two orgs, so nothing is reached by an org's admin across orgs.
const holdKeys = "gw:acme:pep:" + bot1 + "|" + bot9 + ",gwb:beta:pep:agent://acme.example/*,adm:acme:admin,xadm:acme:cross-org-admin,vw:acme:viewer"

// heldRun makes a hold for agent and run through the enforcement point's key and
// returns its approval id.
func (h *orgHarness) heldRun(t *testing.T, key, agent, run string) string {
	t.Helper()
	got := decodeBody[decideResponseDTO](t, h.decide(t, key, decideRequestDTO{AgentID: agent, RunID: run, EstCostUSD: 500}))
	if got.Decision != pdp.Hold || got.ApprovalID == "" {
		t.Fatalf("setup: wanted a hold, got %s (%s)", got.Decision, got.Reason)
	}
	return got.ApprovalID
}

func (h *orgHarness) withdraw(t *testing.T, key, id string, body approvalWithdrawRequestDTO) (int, string) {
	t.Helper()
	rec := h.do(t, http.MethodPost, "/v1/approvals/"+id+"/withdraw", key, body)
	return rec.Code, rec.Body.String()
}

func (h *orgHarness) approval(t *testing.T, id string) store.Approval {
	t.Helper()
	a, err := h.st.GetApproval(context.Background(), id)
	if err != nil {
		t.Fatalf("GetApproval %s: %v", id, err)
	}
	return a
}

// listed is the approval as GET /v1/approvals shows it to acme's admin.
func (h *orgHarness) listed(t *testing.T, id string) map[string]any {
	t.Helper()
	for _, a := range h.approvalsAs(t, "adm") {
		if a["approval_id"] == id {
			return a
		}
	}
	t.Fatalf("approval %s is not on the list", id)
	return nil
}

// --- the TTL ---

func TestAHoldPastItsTTLIsClosedAsExpiredWithNoToken(t *testing.T) {
	h := newOrgHarness(t, holdKeys, true, supportFloor())
	id := h.heldRun(t, "gw", bot1, "r1")
	requested := h.approval(t, id).RequestedAt

	if n := h.srv.expireHolds(context.Background(), requested.Add(DefaultHoldTTL)); n != 1 {
		t.Fatalf("the check closed %d hold(s), want the one that waited its TTL", n)
	}
	a := h.approval(t, id)
	if a.Decision != store.DecisionExpired || a.DecidedBy != holdTTLApprover {
		t.Fatalf("the hold is %q by %q, want %q by %q", a.Decision, a.DecidedBy, store.DecisionExpired, holdTTLApprover)
	}
	got := h.listed(t, id)
	if got["decision"] != "expired" || got["pending"] != false || got["approver_kind"] != "system" || got["decided_by"] != "wardryx:hold-ttl" {
		t.Fatalf("the list shows %v, want decision expired, not pending, approver_kind system", got)
	}
	evs := h.eventsOfType(t, "approval_expired")
	if len(evs) != 1 || evs[0]["approval_id"] != id || evs[0]["waited_seconds"] != float64(DefaultHoldTTL/time.Second) || evs[0]["org"] != "acme" {
		t.Fatalf("approval_expired events %v, want one for %s with waited_seconds %d", evs, id, int(DefaultHoldTTL/time.Second))
	}
	if sev := h.severityOf(t, "approval_expired"); sev != event.SeverityMedium {
		t.Fatalf("approval_expired was written at %q, want medium", sev)
	}
	// No token exists for it, a person cannot grant it any more, and the agent's
	// next call is a new hold.
	rec := h.do(t, http.MethodPost, "/v1/approvals/"+id+"/decide", "adm", approvalDecideRequestDTO{Decision: "grant"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("a grant of an expired hold: %d %s, want 409", rec.Code, rec.Body.String())
	}
	if again := h.heldRun(t, "gw", bot1, "r1"); again == id {
		t.Fatal("the next call after the expiry reused the expired hold")
	}
	if n := len(h.eventsOfType(t, "approval_granted")); n != 0 {
		t.Fatalf("an expired hold wrote %d approval_granted", n)
	}
}

func TestAHoldIsExpiredAtItsTTLAndNotASecondBefore(t *testing.T) {
	h := newOrgHarness(t, holdKeys, true, supportFloor())
	h.srv.SetHoldTTL(2 * time.Hour)
	id := h.heldRun(t, "gw", bot1, "r1")
	requested := h.approval(t, id).RequestedAt
	if n := h.srv.expireHolds(context.Background(), requested.Add(2*time.Hour-time.Second)); n != 0 {
		t.Fatalf("a hold a second short of its TTL was closed (%d)", n)
	}
	if !h.approval(t, id).Pending() {
		t.Fatal("a hold a second short of its TTL is not pending")
	}
	if n := h.srv.expireHolds(context.Background(), requested.Add(2*time.Hour)); n != 1 {
		t.Fatalf("a hold at its TTL was not closed (%d)", n)
	}
	if evs := h.eventsOfType(t, "approval_expired"); len(evs) != 1 || evs[0]["ttl_seconds"] != float64(7200) {
		t.Fatalf("approval_expired %v, want one carrying ttl_seconds 7200", evs)
	}
}

func TestAHoldAPersonDecidedIsNeverExpired(t *testing.T) {
	h := newOrgHarness(t, holdKeys, true, supportFloor())
	id := h.heldRun(t, "gw", bot1, "r1")
	if rec := h.do(t, http.MethodPost, "/v1/approvals/"+id+"/decide", "adm", approvalDecideRequestDTO{Decision: "deny"}); rec.Code != http.StatusOK {
		t.Fatalf("setup deny: %d %s", rec.Code, rec.Body.String())
	}
	if n := h.srv.expireHolds(context.Background(), time.Now().Add(30*24*time.Hour)); n != 0 {
		t.Fatalf("a check closed %d hold(s) a person had decided", n)
	}
	if a := h.approval(t, id); a.Decision != "deny" {
		t.Fatalf("the decided hold is now %q", a.Decision)
	}
	if n := len(h.eventsOfType(t, "approval_expired")); n != 0 {
		t.Fatalf("%d approval_expired for a hold a person decided", n)
	}
}

// Two instances on one store check at the same moment, as two wardryx on one
// database do: every hold is recorded as expired once, by one of them.
func TestTwoInstancesRecordEachExpiredHoldOnce(t *testing.T) {
	h := newOrgHarness(t, holdKeys, true, supportFloor())
	var held []string
	for i := 0; i < 20; i++ {
		held = append(held, h.heldRun(t, "gw", bot1, fmt.Sprintf("r%d", i)))
	}
	second := newOrgHarnessKeys(t, h.srv.keys, true, supportFloor())
	second.srv.store = h.st
	at := time.Now().Add(DefaultHoldTTL + time.Minute)
	var wg sync.WaitGroup
	for k := 0; k < 4; k++ {
		for _, srv := range []*Server{h.srv, second.srv} {
			wg.Add(1)
			go func(srv *Server) { defer wg.Done(); srv.expireHolds(context.Background(), at) }(srv)
		}
	}
	wg.Wait()
	seen := map[any]int{}
	for _, e := range append(h.eventsOfType(t, "approval_expired"), second.eventsOfType(t, "approval_expired")...) {
		seen[e["approval_id"]]++
	}
	for _, id := range held {
		if seen[id] != 1 {
			t.Errorf("hold %s was recorded expired %d times across the two instances, want once", id, seen[id])
		}
	}
}

// A hold already waiting when the process starts (the forge holds of 14.11 among
// them) is closed by the first check, which runs at start, not a minute later.
func TestHoldsAlreadyWaitingAreClosedByTheFirstCheckAtStart(t *testing.T) {
	h := newOrgHarness(t, holdKeys, true, supportFloor())
	old := time.Date(2026, 11, 14, 0, 9, 0, 0, time.UTC)
	if time.Since(old) < DefaultHoldTTL {
		old = time.Now().Add(-DefaultHoldTTL - time.Hour)
	}
	for i := 0; i < 3; i++ {
		if err := h.st.CreateApproval(context.Background(), store.Approval{ApprovalID: fmt.Sprintf("ap-before-%d", i), AgentID: bot1, RunID: "r", RequestedAt: old, Context: map[string]any{"org": "acme"}}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.srv.WatchHoldTTL(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if p, _ := h.st.ListPendingApprovals(context.Background()); len(p) == 0 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("holds already waiting were not closed by the check at start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	if n := len(h.eventsOfType(t, "approval_expired")); n != 3 {
		t.Fatalf("%d approval_expired at start, want 3", n)
	}
}

func TestAnExpiredHoldFreesItsPlaceUnderThePendingCap(t *testing.T) {
	h := newSigHarness(t, true, floorPol())
	h.srv.SetPendingPerAgent(1)
	if first := h.brokerDecide(t, "fetch_url", `{"u":1}`, ""); first.ApprovalID == "" {
		t.Fatal("setup: the first call wrote no row")
	}
	if full := h.brokerDecide(t, "fetch_url", `{"u":2}`, ""); full.ApprovalID != "" {
		t.Fatal("setup: the cap of one did not stop the second call")
	}
	h.srv.expireHolds(context.Background(), time.Now().Add(DefaultHoldTTL+time.Minute))
	if got := h.brokerDecide(t, "fetch_url", `{"u":2}`, ""); got.ApprovalID == "" {
		t.Fatal("an expired hold still counted against the cap")
	}
}

func TestAFailingCheckIsLoggedOncePerOutage(t *testing.T) {
	logged := captureLog(t)
	srv := New(pdp.New(mustCompile(t, supportFloor()), []byte(testHMAC)), failingExpirer{store.NewMemory()}, nil, nil,
		map[string]Principal{keyDigest(adminKey): {Org: "acme", Role: RoleAdmin}}, []byte(testHMAC), true, nil)
	for i := 0; i < 3; i++ {
		srv.expireHolds(context.Background(), time.Now())
	}
	if n := countLines(logged.String(), "could not be closed"); n != 1 {
		t.Fatalf("three failed checks wrote %d line(s), want one:\n%s", n, logged.String())
	}
	srv.store = store.NewMemory()
	srv.expireHolds(context.Background(), time.Now())
	if n := countLines(logged.String(), "being closed again"); n != 1 {
		t.Fatalf("the recovery was logged %d time(s), want once", n)
	}
}

type failingExpirer struct{ *store.Memory }

func (failingExpirer) ExpireApprovals(context.Context, time.Time, string, time.Time) ([]store.Approval, error) {
	return nil, fmt.Errorf("dial tcp 10.0.0.9:5432: connect: connection refused")
}

func TestHoldTTLIsBounded(t *testing.T) {
	if d, err := ParseHoldTTL(""); err != nil || d != 24*time.Hour {
		t.Fatalf("unset reads as %v %v, want 24h", d, err)
	}
	for _, ok := range []string{"1h", "24h", "168h", "90m"} {
		if _, err := ParseHoldTTL(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"59m59s", "168h0m1s", "0", "-1h", "forever", "1d", " 24h"} {
		if _, err := ParseHoldTTL(bad); err == nil {
			t.Errorf("%q accepted, want a refusal serve does not start on", bad)
		}
	}
}

// --- the withdraw route ---

func TestTheHeldAgentWithdrawsItsHold(t *testing.T) {
	h := newOrgHarness(t, holdKeys, true, supportFloor())
	id := h.heldRun(t, "gw", bot1, "r1")
	code, body := h.withdraw(t, "gw", id, approvalWithdrawRequestDTO{AgentID: bot1, RunID: "r1"})
	var answer map[string]any
	_ = json.Unmarshal([]byte(body), &answer)
	if code != http.StatusOK || answer["decision"] != "withdrawn" || answer["approval_id"] != id || strings.Contains(body, "approval_token") {
		t.Fatalf("withdraw: %d %s, want 200 withdrawn with no token", code, body)
	}
	got := h.listed(t, id)
	if got["decision"] != "withdrawn" || got["pending"] != false || got["approver_kind"] != "agent" || got["decided_by"] != "agent:"+bot1 {
		t.Fatalf("the list shows %v, want withdrawn by the agent", got)
	}
	evs := h.eventsOfType(t, "approval_withdrawn")
	if len(evs) != 1 || evs[0]["approval_id"] != id || evs[0]["key_fp"] == "" || evs[0]["key_fp"] == nil {
		t.Fatalf("approval_withdrawn %v, want one for %s naming the key", evs, id)
	}
	if sev := h.severityOf(t, "approval_withdrawn"); sev != event.SeverityInfo {
		t.Fatalf("approval_withdrawn was written at %q, want info", sev)
	}
	if code, _ := h.withdraw(t, "gw", id, approvalWithdrawRequestDTO{AgentID: bot1, RunID: "r1"}); code != http.StatusConflict {
		t.Fatalf("a second withdraw: %d, want 409", code)
	}
	if rec := h.do(t, http.MethodPost, "/v1/approvals/"+id+"/decide", "adm", approvalDecideRequestDTO{Decision: "grant"}); rec.Code != http.StatusConflict {
		t.Fatalf("a grant of a withdrawn hold: %d, want 409", rec.Code)
	}
}

func TestAnAdminKeyCannotWithdrawAHold(t *testing.T) {
	h := newOrgHarness(t, holdKeys, true, supportFloor())
	id := h.heldRun(t, "gw", bot1, "r1")
	for _, key := range []string{"adm", "xadm"} {
		code, body := h.withdraw(t, key, id, approvalWithdrawRequestDTO{AgentID: bot1, RunID: "r1"})
		if code != http.StatusForbidden {
			t.Fatalf("%s withdrew a hold: %d %s, want 403", key, code, body)
		}
	}
	if !h.approval(t, id).Pending() {
		t.Fatal("an admin key closed the hold")
	}
	// With one org the admin speaks for every agent of it (invariant 36), so the
	// refusal is the withdraw route's own and not the agent binding's.
	one := newOrgHarness(t, "gw:acme:pep,adm:acme:admin", true, supportFloor())
	held := one.heldRun(t, "gw", bot1, "r1")
	if code, body := one.withdraw(t, "adm", held, approvalWithdrawRequestDTO{AgentID: bot1, RunID: "r1"}); code != http.StatusForbidden || !strings.Contains(body, "admin key does not withdraw") {
		t.Fatalf("the admin of the only org withdrew a hold: %d %s, want 403", code, body)
	}
	if !one.approval(t, held).Pending() {
		t.Fatal("the admin of the only org closed the hold")
	}
}

func TestAnotherAgentOrRunCannotWithdrawAndLearnsNothing(t *testing.T) {
	h := newOrgHarness(t, holdKeys, true, supportFloor())
	id := h.heldRun(t, "gw", bot1, "r1")
	_, unknown := h.withdraw(t, "gw", "ap-does-not-exist", approvalWithdrawRequestDTO{AgentID: bot9, RunID: "r1"})
	for name, body := range map[string]approvalWithdrawRequestDTO{
		"another agent of the same key": {AgentID: bot9, RunID: "r1"},
		"another run of the same agent": {AgentID: bot1, RunID: "r2"},
	} {
		code, got := h.withdraw(t, "gw", id, body)
		if code != http.StatusNotFound || got != unknown {
			t.Fatalf("%s: %d %s, want the same 404 as an unknown id (%s)", name, code, got, unknown)
		}
	}
	if !h.approval(t, id).Pending() {
		t.Fatal("somebody other than the held agent withdrew the hold")
	}
	// The control: the same key for the agent and run the hold names withdraws it,
	// so the 404s above are the route refusing, not a route that is not there.
	if code, body := h.withdraw(t, "gw", id, approvalWithdrawRequestDTO{AgentID: bot1, RunID: "r1"}); code != http.StatusOK {
		t.Fatalf("the held agent itself: %d %s, want 200", code, body)
	}
}

func TestAKeyOfAnotherOrgCannotWithdrawAndLearnsNothing(t *testing.T) {
	h := newOrgHarness(t, holdKeys, true, supportFloor())
	id := h.heldRun(t, "gw", bot1, "r1")
	_, unknown := h.withdraw(t, "gwb", "ap-does-not-exist", approvalWithdrawRequestDTO{AgentID: bot1, RunID: "r1"})
	code, got := h.withdraw(t, "gwb", id, approvalWithdrawRequestDTO{AgentID: bot1, RunID: "r1"})
	if code != http.StatusNotFound || got != unknown {
		t.Fatalf("another org's key: %d %s, want the same 404 as an unknown id", code, got)
	}
	if !h.approval(t, id).Pending() {
		t.Fatal("another org's key withdrew the hold")
	}
	if code, body := h.withdraw(t, "gw", id, approvalWithdrawRequestDTO{AgentID: bot1, RunID: "r1"}); code != http.StatusOK {
		t.Fatalf("the hold's own org: %d %s, want 200", code, body)
	}
}

func TestAKeyThatDoesNotSpeakForTheAgentIsRefusedAndRecorded(t *testing.T) {
	h := newOrgHarness(t, holdKeys, true, supportFloor())
	id := h.heldRun(t, "gw", bot1, "r1")
	code, body := h.withdraw(t, "vw", id, approvalWithdrawRequestDTO{AgentID: bot1, RunID: "r1"})
	if code != http.StatusForbidden || strings.Contains(body, bot1) {
		t.Fatalf("a viewer key with no agents: %d %s, want 403 echoing nothing", code, body)
	}
	evs := h.eventsOfType(t, "agent_assertion_refused")
	if len(evs) != 1 || evs[0]["route"] != withdrawRoute {
		t.Fatalf("agent_assertion_refused %v, want one naming the withdraw route", evs)
	}
	if !h.approval(t, id).Pending() {
		t.Fatal("a refused key withdrew the hold")
	}
}

func TestAWithdrawNeedsTheAgentAndTheRun(t *testing.T) {
	h := newOrgHarness(t, holdKeys, true, supportFloor())
	id := h.heldRun(t, "gw", bot1, "r1")
	for _, body := range []approvalWithdrawRequestDTO{{RunID: "r1"}, {AgentID: bot1}} {
		if code, _ := h.withdraw(t, "gw", id, body); code != http.StatusBadRequest {
			t.Fatalf("withdraw with %+v: %d, want 400", body, code)
		}
	}
	if rec := h.raw(t, http.MethodPost, "/v1/approvals/"+id+"/withdraw", "gw", `{"agent_id":`); rec.Code != http.StatusBadRequest {
		t.Fatalf("a broken body: %d, want 400", rec.Code)
	}
	if rec := h.raw(t, http.MethodPost, "/v1/approvals/"+id+"/withdraw", "", `{}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no key: %d, want 401", rec.Code)
	}
	if !h.approval(t, id).Pending() {
		t.Fatal("a refused withdraw closed the hold")
	}
}

// The decide route takes grant and deny and nothing else: an admin key cannot close
// a hold as expired or withdrawn through it.
func TestTheDecideRouteDoesNotTakeExpiredOrWithdrawn(t *testing.T) {
	h := newOrgHarness(t, holdKeys, true, supportFloor())
	id := h.heldRun(t, "gw", bot1, "r1")
	for _, d := range []string{"expired", "withdrawn", "EXPIRED", " withdrawn"} {
		rec := h.do(t, http.MethodPost, "/v1/approvals/"+id+"/decide", "adm", approvalDecideRequestDTO{Decision: d})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("decide %q: %d %s, want 400", d, rec.Code, rec.Body.String())
		}
	}
	if !h.approval(t, id).Pending() {
		t.Fatal("the decide route closed a hold as something other than grant or deny")
	}
}

// --- the agent's token, where wardryx verifies it ---

func withdrawTokenHarness(t *testing.T) (*orgHarness, tokenKeySet) {
	t.Helper()
	k := newTokenKeySet(t)
	h := newOrgHarness(t, "gw:acme:pep:agent://acme.example/*,adm:acme:admin", true, supportFloor())
	srv := agentTokenServer(t, nil, k, true, "")
	h.srv.WithAgentTokens(srv.agentTokens)
	return h, k
}

func TestWithAgentTokensAWithdrawNeedsTheAgentsTokenAndProof(t *testing.T) {
	h, k := withdrawTokenHarness(t)
	tok := mintAgentToken(t, k, tokSubject, nil)
	id := h.heldRun(t, "gw", tokSubject, "r1")

	cases := []struct {
		name string
		body approvalWithdrawRequestDTO
		want string
	}{
		{"no token", approvalWithdrawRequestDTO{AgentID: tokSubject, RunID: "r1"}, "agent_token_required"},
		{"a token with no proof", approvalWithdrawRequestDTO{AgentID: tokSubject, RunID: "r1", AgentToken: tok}, "agent_token_proof_required"},
		{"a token for another agent", approvalWithdrawRequestDTO{AgentID: tokSubject, RunID: "r1", AgentToken: mintAgentToken(t, k, tokOther, nil),
			AgentDPoPProof: mintDPoPProof(t, k, tok, tokHTU, time.Now().Unix(), "p-other")}, "agent_contradicts_token"},
		{"a proof for another token", approvalWithdrawRequestDTO{AgentID: tokSubject, RunID: "r1", AgentToken: tok,
			AgentDPoPProof: mintDPoPProof(t, k, "another-token", tokHTU, time.Now().Unix(), "p-bad")}, "agent_token_proof_invalid"},
	}
	for _, c := range cases {
		code, body := h.withdraw(t, "gw", id, c.body)
		if code != http.StatusForbidden || !strings.Contains(body, c.want) {
			t.Fatalf("%s: %d %s, want 403 %s", c.name, code, body, c.want)
		}
	}
	if !h.approval(t, id).Pending() {
		t.Fatal("a withdraw without the agent's verified token closed the hold")
	}
	good := approvalWithdrawRequestDTO{AgentID: tokSubject, RunID: "r1", AgentToken: tok,
		AgentDPoPProof: mintDPoPProof(t, k, tok, tokHTU, time.Now().Unix(), "p-good")}
	if code, body := h.withdraw(t, "gw", id, good); code != http.StatusOK {
		t.Fatalf("the agent with its token and proof: %d %s, want 200", code, body)
	}
}

// The token is checked before the hold is read: a caller with no verified token
// gets the same refusal for a hold that exists and one that does not.
func TestWithAgentTokensTheTokenIsCheckedBeforeTheHoldIsRead(t *testing.T) {
	h, _ := withdrawTokenHarness(t)
	id := h.heldRun(t, "gw", tokSubject, "r1")
	_, onUnknown := h.withdraw(t, "gw", "ap-does-not-exist", approvalWithdrawRequestDTO{AgentID: tokSubject, RunID: "r1"})
	_, onReal := h.withdraw(t, "gw", id, approvalWithdrawRequestDTO{AgentID: tokSubject, RunID: "r1"})
	if onUnknown != onReal || !strings.Contains(onReal, "agent_token_required") {
		t.Fatalf("with no token the refusals differ: %s / %s", onUnknown, onReal)
	}
}

func TestAWithdrawnOrExpiredHoldIsNotADecisionByAPerson(t *testing.T) {
	h := newOrgHarness(t, holdKeys, true, supportFloor())
	w := h.heldRun(t, "gw", bot1, "r1")
	if code, _ := h.withdraw(t, "gw", w, approvalWithdrawRequestDTO{AgentID: bot1, RunID: "r1"}); code != http.StatusOK {
		t.Fatal("setup withdraw")
	}
	e := h.heldRun(t, "gw", bot1, "r2")
	h.srv.expireHolds(context.Background(), time.Now().Add(DefaultHoldTTL+time.Minute))
	for _, typ := range []string{"approval_denied", "approval_granted"} {
		if n := len(h.eventsOfType(t, typ)); n != 0 {
			t.Fatalf("closing holds %s and %s wrote %d %s", w, e, n, typ)
		}
	}
}

// severityOf reads the severity of the first event of a type.
func (h *orgHarness) severityOf(t *testing.T, typ string) string {
	t.Helper()
	raw, err := os.ReadFile(h.events)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var e struct{ Type, Severity string }
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad event line %q: %v", line, err)
		}
		if e.Type == typ {
			return e.Severity
		}
	}
	t.Fatalf("no %s event", typ)
	return ""
}

func mustCompile(t *testing.T, pols ...policy.Policy) *policy.Set {
	t.Helper()
	set, err := policy.Compile(pols)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// --- the store failing under a withdraw or a check ---

// decideFails is a memory store whose DecideApproval answers err: a person who
// decided between the withdraw's read and its write, a row gone, or a store down.
type decideFails struct {
	*store.Memory
	err error
}

func (d decideFails) DecideApproval(context.Context, string, string, string, string, time.Time) (store.Approval, error) {
	return store.Approval{}, d.err
}

func TestAWithdrawThatLosesToAPersonOrTheStoreAnswersWhatHappened(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want int
	}{
		{"a person decided first", store.ErrAlreadyDecided, http.StatusConflict},
		{"the row went", store.ErrNotFound, http.StatusNotFound},
		{"the store is down", errStoreIsDown, http.StatusInternalServerError},
	} {
		h := newOrgHarness(t, holdKeys, true, supportFloor())
		id := h.heldRun(t, "gw", bot1, "r1")
		h.srv.store = decideFails{h.st.(*store.Memory), c.err}
		code, body := h.withdraw(t, "gw", id, approvalWithdrawRequestDTO{AgentID: bot1, RunID: "r1"})
		if code != c.want || strings.Contains(body, "placeholder-not-a-password") {
			t.Fatalf("%s: %d %s, want %d and no driver text", c.name, code, body, c.want)
		}
		if n := len(h.eventsOfType(t, "approval_withdrawn")); n != 0 {
			t.Fatalf("%s: %d approval_withdrawn for a withdraw that did not happen", c.name, n)
		}
	}
}

func TestAWithdrawOnAStoreThatCannotBeReadAnswers500WithoutTheDriverText(t *testing.T) {
	keys, _ := ParseKeys(holdKeys, false)
	srv := New(pdp.New(mustCompile(t, supportFloor()), []byte(testHMAC)), brokenStore{}, nil, nil, keys, []byte(testHMAC), true, nil)
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/approvals/ap-x/withdraw", "gw", approvalWithdrawRequestDTO{AgentID: bot1, RunID: "r1"})
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "placeholder-not-a-password") {
		t.Fatalf("withdraw on a broken store: %d %s, want 500 with no driver text", rec.Code, rec.Body.String())
	}
}

// A store that cannot expire (one written before invariant 52, or a test double)
// keeps every hold until a person decides it, and the watcher returns at once.
func TestAStoreThatCannotExpireKeepsItsHoldsAndTheWatcherReturns(t *testing.T) {
	srv := New(pdp.New(mustCompile(t, supportFloor()), []byte(testHMAC)), brokenStore{}, nil, nil,
		map[string]Principal{keyDigest(adminKey): {Org: "acme", Role: RoleAdmin}}, []byte(testHMAC), true, nil)
	done := make(chan struct{})
	go func() { srv.WatchHoldTTL(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watcher did not return for a store that cannot expire")
	}
	if n := srv.expireHolds(context.Background(), time.Now()); n != 0 {
		t.Fatalf("a store that cannot expire closed %d hold(s)", n)
	}
}
