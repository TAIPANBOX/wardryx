package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/replay"
)

// F-012, the policy half: a policy had no org, so the admin of one org could
// write a rule that changed another org's decisions (live L3 P6).

const (
	twoOrgsListed = "adma:acme:admin:agent://acme.example/*,admb:globex:admin:agent://globex.example/*,root:ops:cross-org-admin"
	globexBot     = "agent://globex.example/bot1"
	denyReport    = `{"name":"deny-report","target":"agent://globex.example/*","deny_tool":["report"]}`
)

func (h *orgHarness) decision(t *testing.T, key, agent, tool string) decideResponseDTO {
	t.Helper()
	rec := h.decide(t, key, decideRequestDTO{AgentID: agent, RunID: "r1", ToolNames: []string{tool}})
	if rec.Code != http.StatusOK {
		t.Fatalf("decide as %s for %s: %d %s", key, agent, rec.Code, rec.Body.String())
	}
	return decodeBody[decideResponseDTO](t, rec)
}

// storedPolicy reads one policy back with a key, generically, so its org is
// read by the wire name.
func (h *orgHarness) storedPolicy(t *testing.T, key, id string) (int, map[string]any) {
	t.Helper()
	rec := h.do(t, http.MethodGet, "/v1/policies/"+id, key, nil)
	var out map[string]any
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode policy: %v", err)
		}
	}
	return rec.Code, out
}

func TestOneOrgsAdminCannotChangeAnotherOrgsDecisions(t *testing.T) {
	h := newOrgHarness(t, twoOrgsListed, false)
	if got := h.decision(t, "admb", globexBot, "report"); got.Decision != pdp.Allow {
		t.Fatalf("baseline: %s (%s)", got.Decision, got.Reason)
	}
	if rec := h.raw(t, http.MethodPut, "/v1/policies/deny-report", "adma", denyReport); rec.Code != http.StatusOK {
		t.Fatalf("acme's admin PUT: %d %s", rec.Code, rec.Body.String())
	}
	if got := h.decision(t, "admb", globexBot, "report"); got.Decision != pdp.Allow {
		t.Fatalf("after acme's admin wrote a deny for globex's agents, globex's decision is %s (%s), want allow", got.Decision, got.Reason)
	}
	code, stored := h.storedPolicy(t, "root", "deny-report")
	if code != http.StatusOK || stored["org"] != "acme" {
		t.Fatalf("the stored policy is %d %v, want org acme", code, stored)
	}
	updated := h.eventsOfType(t, "policy_updated")
	if len(updated) != 1 || updated[0]["policy_org"] != "acme" {
		t.Fatalf("policy_updated = %v, want policy_org acme", updated)
	}
}

func TestAnOrgAdminCannotWriteForAnotherOrgOrAcrossOrgs(t *testing.T) {
	h := newOrgHarness(t, twoOrgsListed, false)
	other := `{"name":"x","target":"agent://globex.example/*","deny_tool":["report"],"org":"globex"}`
	if rec := h.raw(t, http.MethodPut, "/v1/policies/x", "adma", other); rec.Code != http.StatusForbidden {
		t.Fatalf("acme's admin wrote a policy naming globex: %d %s, want 403", rec.Code, rec.Body.String())
	}
	if code, _ := h.storedPolicy(t, "root", "x"); code != http.StatusNotFound {
		t.Fatalf("after the refused write the policy is %d, want 404", code)
	}

	// A policy that applies across orgs, stored before this change.
	if err := h.st.PutPolicy(context.Background(), "floor", policy.Policy{Name: "floor", Target: "agent://*", DenyTool: []string{"shell_exec"}}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	narrowed := `{"name":"floor","target":"agent://acme.example/*","deny_tool":["shell_exec"]}`
	if rec := h.raw(t, http.MethodPut, "/v1/policies/floor", "adma", narrowed); rec.Code != http.StatusForbidden {
		t.Fatalf("acme's admin replaced a policy that applies across orgs: %d %s, want 403", rec.Code, rec.Body.String())
	}
	if rec := h.do(t, http.MethodDelete, "/v1/policies/floor", "adma", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("acme's admin deleted a policy that applies across orgs: %d %s, want 403", rec.Code, rec.Body.String())
	}
	if _, stored := h.storedPolicy(t, "root", "floor"); stored["target"] != "agent://*" {
		t.Fatalf("the cross-org policy changed: %v", stored)
	}
}

func TestAnOrgAdminNeitherSeesNorRemovesAnotherOrgsPolicy(t *testing.T) {
	h := newOrgHarness(t, twoOrgsListed, false)
	if rec := h.raw(t, http.MethodPut, "/v1/policies/globex-own", "admb", denyReport); rec.Code != http.StatusOK {
		t.Fatalf("globex's admin PUT: %d %s", rec.Code, rec.Body.String())
	}
	var listed []map[string]any
	rec := h.do(t, http.MethodGet, "/v1/policies", "adma", nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	for _, p := range listed {
		if p["id"] == "globex-own" {
			t.Fatalf("acme's admin lists globex's policy: %v", listed)
		}
	}
	if code, _ := h.storedPolicy(t, "adma", "globex-own"); code != http.StatusNotFound {
		t.Fatalf("acme's admin GET globex's policy: %d, want 404", code)
	}
	if rec := h.do(t, http.MethodDelete, "/v1/policies/globex-own", "adma", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("acme's admin DELETE globex's policy: %d, want 404", rec.Code)
	}
	if got := h.decision(t, "admb", globexBot, "report"); got.Decision != pdp.Deny {
		t.Fatalf("globex's own policy stopped deciding: %s (%s)", got.Decision, got.Reason)
	}
}

func TestACrossOrgAdminWritesAPolicyThatAppliesAcrossOrgs(t *testing.T) {
	h := newOrgHarness(t, twoOrgsListed, false)
	floor := `{"name":"floor","target":"agent://*","deny_tool":["report"]}`
	if rec := h.raw(t, http.MethodPut, "/v1/policies/floor", "root", floor); rec.Code != http.StatusOK {
		t.Fatalf("the cross-org admin PUT: %d %s", rec.Code, rec.Body.String())
	}
	if _, stored := h.storedPolicy(t, "root", "floor"); stored == nil || stored["org"] != nil {
		t.Fatalf("the stored policy is %v, want no org", stored)
	}
	if got := h.decision(t, "adma", bot1, "report"); got.Decision != pdp.Deny {
		t.Fatalf("acme after a cross-org deny: %s (%s)", got.Decision, got.Reason)
	}
	if got := h.decision(t, "admb", globexBot, "report"); got.Decision != pdp.Deny {
		t.Fatalf("globex after a cross-org deny: %s (%s)", got.Decision, got.Reason)
	}
	// An org admin reads a policy that applies to its own decisions.
	if code, _ := h.storedPolicy(t, "adma", "floor"); code != http.StatusOK {
		t.Fatalf("acme's admin cannot read a policy that governs it: %d", code)
	}
}

func TestWithOneOrgItsAdminWritesPoliciesAsBefore(t *testing.T) {
	h := newOrgHarness(t, "adm:default:admin,gw:default:pep", false)
	if err := h.st.PutPolicy(context.Background(), "old", policy.Policy{Name: "old", Target: "agent://*", DenyTool: []string{"a"}}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if rec := h.raw(t, http.MethodPut, "/v1/policies/old", "adm", `{"name":"old","target":"agent://*","deny_tool":["b"]}`); rec.Code != http.StatusOK {
		t.Fatalf("replacing a policy stored before this change: %d %s", rec.Code, rec.Body.String())
	}
	if rec := h.raw(t, http.MethodPut, "/v1/policies/new", "adm", `{"name":"new","target":"agent://*","deny_tool":["c"]}`); rec.Code != http.StatusOK {
		t.Fatalf("a new policy: %d %s", rec.Code, rec.Body.String())
	}
	for _, id := range []string{"old", "new"} {
		code, stored := h.storedPolicy(t, "adm", id)
		if code != http.StatusOK {
			t.Fatalf("%s: %d", id, code)
		}
		if _, has := stored["org"]; has {
			t.Fatalf("%s is stored with an org in a one-org deployment: %v", id, stored)
		}
	}
	if got := h.decision(t, "gw", bot1, "b"); got.Decision != pdp.Deny {
		t.Fatalf("the replaced policy: %s", got.Decision)
	}
	if rec := h.do(t, http.MethodDelete, "/v1/policies/old", "adm", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
}

func TestAnOrgScopedDenialReplaysFromTheRecord(t *testing.T) {
	h := newOrgHarness(t, twoOrgsListed, false)
	if rec := h.raw(t, http.MethodPut, "/v1/policies/acme-deny", "adma", `{"name":"acme-deny","target":"agent://*","deny_tool":["report"]}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
	}
	if got := h.decision(t, "adma", bot1, "report"); got.Decision != pdp.Deny {
		t.Fatalf("acme: %s", got.Decision)
	}
	if got := h.decision(t, "admb", globexBot, "report"); got.Decision != pdp.Allow {
		t.Fatalf("globex: %s", got.Decision)
	}
	for _, e := range h.allEvents(t) {
		if e.Type == "policy_deny" && e.Data["org"] != "acme" {
			t.Fatalf("the recorded denial carries org %#v, want acme", e.Data["org"])
		}
		if e.Type == "policy_allow" && e.Data["org"] != "globex" {
			t.Fatalf("the recorded allow carries org %#v, want globex", e.Data["org"])
		}
	}
	if err := h.ew.Close(); err != nil {
		t.Fatal(err)
	}
	events := readEventsFile(t, h.events)
	report := replay.Run(events, h.arch, nil)
	if report.Total != 2 || report.Reproduced != 2 || report.Diverged != 0 {
		t.Fatalf("the org-scoped decisions did not reproduce:\n%s", replay.Format(report, "events", ""))
	}
}
