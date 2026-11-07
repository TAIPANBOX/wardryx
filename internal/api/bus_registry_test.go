package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// The shared event bus carries, under source wardryx, only the types agent-passport
// SPEC.md 6.2 lists for it, each at the severity the row gives it (invariant 50). A
// fact the row has no type for goes to the log: an agent reaching the pending cap
// (invariant 48) and the policy set a process starts under (invariant 49). Each of
// these tests was run against 2.6.0 first, which wrote approval_queue_full and
// policy_loaded onto the bus, and failed there.

// The log lines are matched as an operator greps for them, so they are spelled out
// here rather than taken from the constants that write them.
const (
	pendingCapLine = "wardryx: an agent reached its pending cap"
	policySetLine  = "wardryx: policy set loaded"
)

// specRow is testdata/spec-6.2-wardryx.json, the copy of SPEC 6.2's wardryx row
// that scripts/bus-types-are-registered.sh reads too.
type specRow struct {
	Source string            `json:"source"`
	Types  map[string]string `json:"types"`
}

func readSpecRow(t *testing.T) specRow {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "spec-6.2-wardryx.json"))
	if err != nil {
		t.Fatalf("the copy of SPEC 6.2's wardryx row is not readable, so nothing here can be compared: %v", err)
	}
	var row specRow
	if err := json.Unmarshal(raw, &row); err != nil {
		t.Fatalf("the copy of SPEC 6.2's wardryx row is not JSON: %v", err)
	}
	if row.Source != "wardryx" || len(row.Types) == 0 {
		t.Fatalf("the copy of SPEC 6.2's wardryx row names source %q and %d type(s): it measures nothing", row.Source, len(row.Types))
	}
	return row
}

func TestTheStartPutsNothingOnTheBus(t *testing.T) {
	h := newSigHarness(t, true, floorPol(), policy.Policy{Name: "g", Target: floorAgentID, GrantTool: []string{"ask"}})
	h.srv.RecordPolicyLoaded()
	if evs := h.read(t); len(evs) != 0 {
		t.Fatalf("the start wrote %d event(s) onto the bus, first %q: SPEC 6.2 lists no start type under wardryx", len(evs), evs[0].Type)
	}
}

func TestTheStartIsLoggedWithTheVersionTheFirstDecisionNames(t *testing.T) {
	logged := captureLog(t)
	h := newSigHarness(t, true, floorPol(), policy.Policy{Name: "g", Target: floorAgentID, GrantTool: []string{"ask"}})
	h.srv.RecordPolicyLoaded()
	got := h.brokerDecide(t, "ask", `{}`, "")
	if got.Decision != pdp.Allow || got.PolicyVersion == "" {
		t.Fatalf("setup: the granted call is %s (%s) under version %q", got.Decision, got.Reason, got.PolicyVersion)
	}
	if n := countLines(logged.String(), policySetLine); n != 1 {
		t.Fatalf("the start wrote %d line(s) saying %q, want one:\n%s", n, policySetLine, logged.String())
	}
	line := lineWith(logged.String(), policySetLine)
	for _, want := range []string{
		"policy_version=" + got.PolicyVersion + " ",
		"policies=2 ",
		"base_policies=2 ",
		"no_grant_floors=[tool-hold] ",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("the start line does not carry %q: %s", want, line)
		}
	}
	// The set itself is in the archive, kept before the first decision; the line
	// says which file holds it.
	_, kept, ok := strings.Cut(line, "archived=")
	kept = strings.TrimSpace(kept)
	if !ok || filepath.Base(kept) != got.PolicyVersion+".json" {
		t.Fatalf("the start line does not name the archived set of version %s: %s", got.PolicyVersion, line)
	}
	if _, err := os.Stat(kept); err != nil {
		t.Fatalf("the start line names %s and the archive has no such file: %v", kept, err)
	}
}

func TestTheStartLineSaysWhenNothingKeepsTheSet(t *testing.T) {
	logged := captureLog(t)
	set, err := policy.Compile([]policy.Policy{floorPol()})
	if err != nil {
		t.Fatal(err)
	}
	srv := New(pdp.New(set, []byte(testHMAC)), nil, nil, nil, map[string]Principal{keyDigest(adminKey): {Org: "acme", Role: RoleAdmin}}, []byte(testHMAC), true, set.Policies())
	srv.RecordPolicyLoaded()
	line := lineWith(logged.String(), policySetLine)
	if !strings.Contains(line, "policy_version="+set.Version()+" ") || !strings.HasSuffix(strings.TrimSpace(line), "archived=none") {
		t.Fatalf("with no archive the start line is %q, want the version and archived=none", line)
	}
}

// pastTheCap drives one agent six calls and another three past a cap of one.
func pastTheCap(t *testing.T, h *sigHarness) (string, string) {
	t.Helper()
	h.srv.SetPendingPerAgent(1)
	for i := 0; i < 6; i++ {
		h.brokerDecide(t, "fetch_url", fmt.Sprintf(`{"u":%d}`, i), "")
	}
	other := "agent://acme.example/agents/other"
	for i := 0; i < 3; i++ {
		h.decideRaw(t, brokerCall(other, "r", "fetch_url", fmt.Sprintf(`{"u":%d}`, i), ""))
	}
	return floorAgentID, other
}

func TestAnAgentPastTheCapPutsNoNewTypeOnTheBus(t *testing.T) {
	h := newSigHarness(t, true, floorPol())
	pastTheCap(t, h)
	full := 0
	for _, ev := range h.read(t) {
		if ev.Type != evApprovalRequested {
			t.Errorf("past the cap the bus carries %q (%s): the holds are recorded as approval_requested and nothing else", ev.Type, ev.Severity)
			continue
		}
		if ev.Data["queue_full"] == true {
			full++
		}
	}
	// Five holds of the first agent and two of the other found the queue full, and
	// each says so in its own record: the fact stays on the bus, in the type the row
	// lists.
	if full != 7 {
		t.Fatalf("%d hold(s) carry queue_full, want 7", full)
	}
}

func TestAnAgentPastTheCapIsLoggedOncePerProcess(t *testing.T) {
	logged := captureLog(t)
	h := newSigHarness(t, true, floorPol())
	first, other := pastTheCap(t, h)
	out := logged.String()
	if n := countLines(out, pendingCapLine); n != 2 {
		t.Fatalf("%d line(s) say %q, want one for each of the two agents:\n%s", n, pendingCapLine, out)
	}
	for agent, run := range map[string]string{first: "mcp:run", other: "r"} {
		line := lineWith(out, pendingCapLine+" agent_id="+agent+" ")
		if line == "" {
			t.Fatalf("no line names %s:\n%s", agent, out)
		}
		if !strings.Contains(line, " run_id="+run+" ") || !strings.HasSuffix(strings.TrimSpace(line), " pending_limit=1") {
			t.Errorf("the line for %s does not carry its run and the limit: %s", agent, line)
		}
		if !strings.Contains(line, " WARN ") {
			t.Errorf("the line for %s is not a warning, and holds nobody is asked about are worth one: %s", agent, line)
		}
	}
}

// TestAnAgentIDWithALineBreakStaysOneLogLine: an agent id is whatever a caller
// wrote, so the line quotes it rather than letting it start a line of its own.
func TestAnAgentIDWithALineBreakStaysOneLogLine(t *testing.T) {
	logged := captureLog(t)
	h := newSigHarness(t, true, floorPol())
	h.srv.SetPendingPerAgent(1)
	hostile := "agent://acme.example/x\nwardryx: forged line"
	for i := 0; i < 2; i++ {
		h.decideRaw(t, brokerCall(hostile, "r", "fetch_url", fmt.Sprintf(`{"u":%d}`, i), ""))
	}
	out := logged.String()
	if n := countLines(out, pendingCapLine); n != 1 {
		t.Fatalf("%d line(s) say %q, want one:\n%s", n, pendingCapLine, out)
	}
	if strings.Contains(out, "\nwardryx: forged line") {
		t.Fatalf("the caller's line break reached the log as a line of its own:\n%s", out)
	}
	if !strings.Contains(out, `agent_id="agent://acme.example/x\nwardryx: forged line"`) {
		t.Fatalf("the agent id is not quoted in the line:\n%s", out)
	}
}

// TestEveryEventTheServerWritesIsInTheSpecRowAtItsSeverity drives the paths 2.6.0
// touched and the ones around them, and reads back what reached the bus.
func TestEveryEventTheServerWritesIsInTheSpecRowAtItsSeverity(t *testing.T) {
	row := readSpecRow(t)
	h := newSigHarness(t, true,
		floorPol(),
		policy.Policy{Name: "g", Target: floorAgentID, GrantTool: []string{"ask"}},
		policy.Policy{Name: "no-exec", Target: "agent://*", DenyTool: []string{"exec"}},
	)
	h.srv.RecordPolicyLoaded()
	h.srv.SetPendingPerAgent(2)
	if got := h.brokerDecide(t, "ask", `{}`, ""); got.Decision != pdp.Allow {
		t.Fatalf("setup: the granted call is %s (%s)", got.Decision, got.Reason)
	}
	if got := h.brokerDecide(t, "exec", `{}`, ""); got.Decision != pdp.Deny {
		t.Fatalf("setup: the denied call is %s (%s)", got.Decision, got.Reason)
	}
	var held []string
	for i := 0; i < 4; i++ {
		got := h.brokerDecide(t, "fetch_url", fmt.Sprintf(`{"u":%d}`, i), "")
		if got.Decision != pdp.Hold {
			t.Fatalf("setup: an ungranted call is %s (%s)", got.Decision, got.Reason)
		}
		if got.ApprovalID != "" {
			held = append(held, got.ApprovalID)
		}
	}
	if len(held) != 2 {
		t.Fatalf("setup: %d hold(s) wrote a row under a cap of two", len(held))
	}
	h.grant(t, held[0])
	if rec := doRequest(t, h.srv.Handler(), http.MethodPost, "/v1/approvals/"+held[1]+"/decide", adminKey, approvalDecideRequestDTO{Decision: "deny"}); rec.Code != http.StatusOK {
		t.Fatalf("setup: the denial answered %d: %s", rec.Code, rec.Body.String())
	}
	if rec := doRaw(t, h.srv.Handler(), http.MethodPut, "/v1/policies/grant-more", adminKey,
		`{"name":"grant-more","target":"`+floorAgentID+`","grant_tool":["fetch_url"]}`); rec.Code != http.StatusOK {
		t.Fatalf("setup: PUT answered %d: %s", rec.Code, rec.Body.String())
	}
	if got := h.brokerDecide(t, "browse", `{}`, ""); got.ApprovalID == "" {
		t.Fatalf("setup: the hold after the answers wrote no row (%s)", got.Reason)
	}
	h.srv.sweepUnansweredApprovals(context.Background(), time.Now().Add(time.Hour))

	seen := map[string]int{}
	for _, ev := range h.read(t) {
		seen[ev.Type]++
		want, listed := row.Types[ev.Type]
		switch {
		case ev.Source != "wardryx":
			t.Errorf("an event carries source %q", ev.Source)
		case !listed:
			t.Errorf("the bus carries %q under wardryx, a type SPEC 6.2 does not list for it", ev.Type)
		case ev.Severity != want:
			t.Errorf("the bus carries %q at %q, and SPEC 6.2 gives it %q", ev.Type, ev.Severity, want)
		}
	}
	// Seven types reached the bus, so the comparison above read something.
	var types []string
	for k := range seen {
		types = append(types, k)
	}
	sort.Strings(types)
	if len(types) < 7 {
		t.Fatalf("only %v reached the bus, so this compared too little to say anything", types)
	}
}

// lineWith is the first line of s that contains needle, or "".
func lineWith(s, needle string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	return ""
}
