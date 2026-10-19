package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/pdp"
)

// F-001, the decision point's half: the agent_id of a decide request was the
// caller's claim, checked only for being non-empty, so any key could ask in
// any agent's name and get that agent's decisions and approvals.

const (
	bot1 = "agent://acme.example/support/bot1"
	bot9 = "agent://acme.example/finance/bot9"
)

func TestAKeyThatListsItsAgentsCannotAskForAnother(t *testing.T) {
	h := newOrgHarness(t, "lk:acme:viewer:"+bot1+",adm:acme:admin", false, supportFloor())
	rec := h.decide(t, "lk", decideRequestDTO{AgentID: bot9, RunID: "r1", EstCostUSD: 500})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("a key listing only %s asked for %s: %d %s, want 403", bot1, bot9, rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), bot9) {
		t.Fatalf("the refusal echoes the asserted agent: %s", rec.Body.String())
	}
	if got := h.approvalsAs(t, "adm"); len(got) != 0 {
		t.Fatalf("a refused request held something: %v", got)
	}
}

func TestAKeyThatListsItsAgentsAsksForThemAsBefore(t *testing.T) {
	h := newOrgHarness(t, "lk:acme:viewer:"+bot1+",adm:acme:admin", false, supportFloor())
	got := decodeBody[decideResponseDTO](t, h.decide(t, "lk", decideRequestDTO{AgentID: bot1, RunID: "r1", ToolNames: []string{"shell_exec"}}))
	if got.Decision != pdp.Deny || !strings.Contains(got.Reason, "shell_exec") {
		t.Fatalf("a listed agent got %s (%s), want the policy's deny", got.Decision, got.Reason)
	}
	got = decodeBody[decideResponseDTO](t, h.decide(t, "lk", decideRequestDTO{AgentID: bot1, RunID: "r1", ToolNames: []string{"lookup"}}))
	if got.Decision != pdp.Allow {
		t.Fatalf("a listed agent got %s (%s), want allow", got.Decision, got.Reason)
	}
}

func TestAnAgentPatternCoversOnlyTheAgentsUnderIt(t *testing.T) {
	h := newOrgHarness(t, "pk:acme:viewer:agent://acme.example/*,adm:acme:admin", false, supportFloor())
	cases := []struct {
		agent string
		want  int
	}{
		{"agent://acme.example/a/b", http.StatusOK},
		{"agent://acme.example/x", http.StatusOK},
		{"agent://acme.example.evil/x", http.StatusForbidden},
		{"agent://acme.exampl/x", http.StatusForbidden},
		{"agent://acme.example", http.StatusForbidden},
		{"agent://acme.example/x\nagent://acme.example/y", http.StatusForbidden},
		{"agent://other.example/acme.example/x", http.StatusForbidden},
	}
	for _, c := range cases {
		rec := h.decide(t, "pk", decideRequestDTO{AgentID: c.agent, RunID: "r1"})
		if rec.Code != c.want {
			t.Errorf("agent %q: %d %s, want %d", c.agent, rec.Code, rec.Body.String(), c.want)
		}
	}
}

func TestAViewerKeyWithNoListSpeaksForNoAgent(t *testing.T) {
	h := newOrgHarness(t, "vk:acme:viewer,adm:acme:admin", false, supportFloor())
	for _, agent := range []string{bot1, bot9, "agent://elsewhere.example/x"} {
		if rec := h.decide(t, "vk", decideRequestDTO{AgentID: agent, RunID: "r1"}); rec.Code != http.StatusForbidden {
			t.Errorf("an unlisted viewer key asked for %s: %d %s, want 403", agent, rec.Code, rec.Body.String())
		}
	}
	// A viewer still reads what a viewer reads.
	if rec := h.do(t, http.MethodGet, "/v1/status", "vk", nil); rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/status as a viewer: %d", rec.Code)
	}
}

func TestAPepKeySpeaksForAnyAgentWhenThereIsOneOrg(t *testing.T) {
	h := newOrgHarness(t, "gw:default:pep,adm:default:admin", false, supportFloor())
	for _, agent := range []string{bot1, bot9, "agent://mockryx.local/allow-list-rehearsal"} {
		got := decodeBody[decideResponseDTO](t, h.decide(t, "gw", decideRequestDTO{AgentID: agent, RunID: "r1", ToolNames: []string{"shell_exec"}}))
		if got.Decision != pdp.Deny {
			t.Errorf("the gateway's key for %s: %s (%s), want the policy's deny", agent, got.Decision, got.Reason)
		}
	}
	// A pep key is not an admin.
	if rec := h.do(t, http.MethodGet, "/v1/policies", "gw", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("GET /v1/policies with the pep key: %d, want 403", rec.Code)
	}
}

func TestWithTwoOrgsAnUnlistedKeySpeaksForNoAgent(t *testing.T) {
	h := newOrgHarness(t, "gwa:acme:pep,adma:acme:admin,admb:globex:admin", false, supportFloor())
	for _, key := range []string{"gwa", "adma", "admb"} {
		if rec := h.decide(t, key, decideRequestDTO{AgentID: bot1, RunID: "r1"}); rec.Code != http.StatusForbidden {
			t.Errorf("key %s, two orgs, no list: %d %s, want 403", key, rec.Code, rec.Body.String())
		}
	}
}

func TestACrossOrgAdminKeySpeaksForAnyAgent(t *testing.T) {
	h := newOrgHarness(t, "root:ops:cross-org-admin,adma:acme:admin,admb:globex:admin", false, supportFloor())
	for _, agent := range []string{bot1, "agent://globex.example/bot2"} {
		got := decodeBody[decideResponseDTO](t, h.decide(t, "root", decideRequestDTO{AgentID: agent, RunID: "r1", ToolNames: []string{"shell_exec"}}))
		if got.Decision != pdp.Deny {
			t.Errorf("the cross-org admin for %s: %s (%s), want the policy's deny", agent, got.Decision, got.Reason)
		}
	}
}

func TestARefusedRequestSpendsNoApprovalToken(t *testing.T) {
	spec := "gw:acme:pep:" + bot1 + ",other:acme:pep:agent://acme.example/finance/*,adm:acme:admin"
	h := newOrgHarness(t, spec, true, supportFloor())
	ask := decideRequestDTO{AgentID: bot1, RunID: "r1", ToolNames: []string{"lookup"}, EstCostUSD: 500}
	held := decodeBody[decideResponseDTO](t, h.decide(t, "gw", ask))
	if held.Decision != pdp.Hold {
		t.Fatalf("setup: %s (%s), want hold", held.Decision, held.Reason)
	}
	granted := decodeBody[approvalDecideResponseDTO](t, h.do(t, http.MethodPost, "/v1/approvals/"+held.ApprovalID+"/decide", "adm",
		approvalDecideRequestDTO{Decision: "grant", DecidedBy: "alice"}))
	if granted.ApprovalToken == "" {
		t.Fatalf("setup: no token")
	}
	ask.ApprovalToken = granted.ApprovalToken
	if rec := h.decide(t, "other", ask); rec.Code != http.StatusForbidden {
		t.Fatalf("a key that may not speak for %s presented its token: %d %s, want 403", bot1, rec.Code, rec.Body.String())
	}
	got := decodeBody[decideResponseDTO](t, h.decide(t, "gw", ask))
	if got.Decision != pdp.Allow {
		t.Fatalf("after the refused presentation the token gives %s (%s), want allow: the refusal spent it", got.Decision, got.Reason)
	}
}

func TestARefusalIsRecordedAndNamesTheKeyByFingerprint(t *testing.T) {
	const key = "refusal-test-key-0b1d"
	h := newOrgHarness(t, key+":acme:viewer:"+bot1+",adm:acme:admin", false, supportFloor())
	if rec := h.decide(t, key, decideRequestDTO{AgentID: bot9, RunID: "run-77", ToolNames: []string{"shell_exec"}}); rec.Code != http.StatusForbidden {
		t.Fatalf("setup: %d, want 403", rec.Code)
	}
	all := h.allEvents(t)
	if len(all) != 1 || all[0].Type != "agent_assertion_refused" {
		t.Fatalf("events = %+v, want exactly one agent_assertion_refused and no decision", all)
	}
	d := all[0].Data
	want := map[string]string{
		"asserted_agent_id": bot9,
		"asserted_run_id":   "run-77",
		"org":               "acme",
		"role":              RoleViewer,
		"key_fp":            fp(key),
		"route":             "/v1/decide",
	}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("data[%q] = %#v, want %q", k, d[k], v)
		}
	}
	if all[0].AgentID == bot9 {
		t.Fatalf("the envelope names the asserted agent as the actor: %+v", all[0])
	}
	raw := strings.Join(func() []string {
		var s []string
		for _, e := range all {
			s = append(s, e.AgentID, e.RunID)
			for k, v := range e.Data {
				s = append(s, k, toText(v))
			}
		}
		return s
	}(), " ")
	if strings.Contains(raw, key) {
		t.Fatalf("the raw key reached the event file")
	}
}

func toText(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func TestFilterToolsIsBoundToTheKeyLikeDecide(t *testing.T) {
	h := newOrgHarness(t, "lk:acme:pep:"+bot1+",adm:acme:admin", false, supportFloor())
	rec := h.do(t, http.MethodPost, "/v1/filter-tools", "lk", filterToolsRequestDTO{AgentID: bot9, ToolNames: []string{"shell_exec", "lookup"}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("filter-tools for an agent outside the list: %d %s, want 403", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "shell_exec") {
		t.Fatalf("the refusal shows the partition: %s", rec.Body.String())
	}
	ok := decodeBody[filterToolsResponseDTO](t, h.do(t, http.MethodPost, "/v1/filter-tools", "lk", filterToolsRequestDTO{AgentID: bot1, ToolNames: []string{"shell_exec", "lookup"}}))
	if len(ok.Denied) != 1 || ok.Denied[0].Name != "shell_exec" {
		t.Fatalf("filter-tools for a listed agent: %+v", ok)
	}
	refused := h.eventsOfType(t, "agent_assertion_refused")
	if len(refused) != 1 || refused[0]["route"] != "/v1/filter-tools" {
		t.Fatalf("refusal events = %v, want one naming /v1/filter-tools", refused)
	}
}

func TestTheDevkeySpeaksForAnyAgent(t *testing.T) {
	keys, _ := ParseKeys("", true)
	h := newOrgHarnessKeys(t, keys, false, supportFloor())
	for _, agent := range []string{bot1, "agent://anything.local/x"} {
		got := decodeBody[decideResponseDTO](t, h.decide(t, "devkey", decideRequestDTO{AgentID: agent, RunID: "r1", ToolNames: []string{"shell_exec"}}))
		if got.Decision != pdp.Deny {
			t.Errorf("the devkey for %s: %s (%s), want the policy's deny", agent, got.Decision, got.Reason)
		}
	}
}

func TestParseKeysReadsAnAgentListAfterTheRole(t *testing.T) {
	keys, warnings := ParseKeys("a:acme, b:acme:viewer , c:acme:pep:agent://a.example/x| agent://b.example/* |,d:acme::agent://d.example/y,e:acme:viewer:", false)
	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none", warnings)
	}
	want := map[string]Principal{
		"a": {Org: "acme", Role: RoleAdmin},
		"b": {Org: "acme", Role: RoleViewer},
		"c": {Org: "acme", Role: RolePEP, Agents: "agent://a.example/x|agent://b.example/*"},
		"d": {Org: "acme", Role: RoleAdmin, Agents: "agent://d.example/y"},
		"e": {Org: "acme", Role: RoleViewer},
	}
	for k, w := range want {
		if keys[keyDigest(k)] != w {
			t.Errorf("%s = %+v, want %+v", k, keys[keyDigest(k)], w)
		}
	}
	if got := keys[keyDigest("c")].agentPatterns(); len(got) != 2 || got[1] != "agent://b.example/*" {
		t.Fatalf("patterns of c = %q", got)
	}
	// The two new roles are known: no warning.
	if _, w := ParseKeys("p:acme:pep,r:ops:cross-org-admin", false); len(w) != 0 {
		t.Fatalf("warnings for pep and cross-org-admin = %v, want none", w)
	}
}

func TestKeyPostureNamesEveryKeyThatSpeaksForNoAgent(t *testing.T) {
	const viewer, gw = "posture-viewer-key", "posture-gw-key"
	one, _ := ParseKeys(viewer+":default:viewer,"+gw+":default:pep,adm:default:admin,lv:default:viewer:agent://x.example/*", false)
	lines := KeyPosture(one)
	if len(lines) != 1 || !strings.Contains(lines[0], fp(viewer)) || !strings.Contains(lines[0], "role pep") {
		t.Fatalf("one org: posture = %q, want one line naming the unlisted viewer by fingerprint", lines)
	}
	two, _ := ParseKeys(gw+":acme:pep,adma:acme:admin,admb:globex:admin:agent://globex.example/*,root:ops:cross-org-admin", false)
	lines = KeyPosture(two)
	joined := strings.Join(lines, "\n")
	for _, want := range []string{fp(gw), fp("adma"), "names 2 orgs", RoleCrossOrgAdmin} {
		if !strings.Contains(joined, want) {
			t.Errorf("two orgs: posture does not mention %q:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, fp("admb")) || strings.Contains(joined, fp("root")) {
		t.Errorf("two orgs: posture names a key that speaks for agents:\n%s", joined)
	}
	for _, key := range []string{viewer, gw, "adma"} {
		if strings.Contains(joined+strings.Join(KeyPosture(one), ""), key) {
			t.Fatalf("posture prints the raw key %q", key)
		}
	}
}

// A principal whose list the server did not compile at start (one built in
// code rather than parsed from WARDRYX_KEYS) is read the same way, never as
// unlisted.
func TestSpeaksForReadsAListItWasNotGivenAtStart(t *testing.T) {
	a := newAllowance(map[string]Principal{"adm": {Org: "acme", Role: RoleAdmin}})
	p := Principal{Org: "acme", Role: RoleViewer, Agents: "agent://acme.example/support/*"}
	if !a.speaksFor(p, bot1) || a.speaksFor(p, bot9) {
		t.Fatalf("a list compiled on the fly does not bind: bot1 %v, bot9 %v", a.speaksFor(p, bot1), a.speaksFor(p, bot9))
	}
	if a.speaksFor(Principal{Org: "acme", Role: "admni"}, bot1) {
		t.Fatalf("a role this service does not know speaks for an agent")
	}
}
