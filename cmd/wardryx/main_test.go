package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/wardryx/internal/archive"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

func TestRunNoArgsErrors(t *testing.T) {
	if err := run(nil); err == nil {
		t.Fatal("run(nil): expected an error, got nil")
	}
}

func TestRunUnknownCommandErrors(t *testing.T) {
	if err := run([]string{"bogus"}); err == nil {
		t.Fatal("run([bogus]): expected an error, got nil")
	}
}

func TestRunVersion(t *testing.T) {
	if err := run([]string{"version"}); err != nil {
		t.Fatalf("run([version]): %v", err)
	}
}

func TestRunApprovalsRequiresDB(t *testing.T) {
	t.Setenv("WARDRYX_DB", "")
	if err := run([]string{"approvals"}); err == nil {
		t.Fatal("run([approvals]) with no -db and no WARDRYX_DB: expected an error, got nil")
	}
}

// TestCheckAgents exercises the offline `check` dry-run path end to end:
// load a directory of passports, evaluate each against a policy requiring
// attestation, confirm the attested agent is allowed and the unattested one
// is denied, and confirm PolicyVersion is surfaced.
func TestCheckAgents(t *testing.T) {
	results, rep, policyVersion, err := checkAgents("testdata/passports", "testdata/policy.yaml")
	if err != nil {
		t.Fatalf("checkAgents: %v", err)
	}
	if rep.Files != 2 || rep.Malformed != 0 {
		t.Fatalf("Report = %+v, want 2 files, 0 malformed", rep)
	}
	if len(results) != 2 {
		t.Fatalf("results = %d, want 2: %+v", len(results), results)
	}
	if policyVersion == "" {
		t.Error("policyVersion is empty")
	}

	byAgent := map[string]checkResult{}
	for _, r := range results {
		byAgent[r.AgentID] = r
	}

	bot1 := byAgent["agent://acme.example/finance/bot1"]
	if bot1.Decision != pdp.Allow {
		t.Errorf("bot1 (attested) Decision = %q, want %q (reason: %s)", bot1.Decision, pdp.Allow, bot1.Reason)
	}
	if bot1.Owner != "team-finance@acme.example" {
		t.Errorf("bot1 Owner = %q", bot1.Owner)
	}

	bot2 := byAgent["agent://acme.example/support/bot2"]
	if bot2.Decision != pdp.Deny {
		t.Errorf("bot2 (unattested) Decision = %q, want %q (reason: %s)", bot2.Decision, pdp.Deny, bot2.Reason)
	}
	if !strings.Contains(bot2.Reason, "attestation") {
		t.Errorf("bot2 Reason = %q, want it to mention attestation", bot2.Reason)
	}
}

func TestCheckAgentsMissingPassportDirErrors(t *testing.T) {
	if _, _, _, err := checkAgents("testdata/does-not-exist", "testdata/policy.yaml"); err == nil {
		t.Fatal("checkAgents with a missing passport dir: expected an error, got nil")
	}
}

func TestCheckAgentsMissingPolicyErrors(t *testing.T) {
	if _, _, _, err := checkAgents("testdata/passports", "testdata/does-not-exist.yaml"); err == nil {
		t.Fatal("checkAgents with a missing policy file: expected an error, got nil")
	}
}

func TestRunCheckHumanFormat(t *testing.T) {
	if err := run([]string{"check", "testdata/passports", "testdata/policy.yaml"}); err != nil {
		t.Fatalf("run([check ...]): %v", err)
	}
}

func TestRunCheckJSONFormat(t *testing.T) {
	if err := run([]string{"check", "-format", "json", "testdata/passports", "testdata/policy.yaml"}); err != nil {
		t.Fatalf("run([check -format json ...]): %v", err)
	}
}

func TestRunCheckWrongArgCountErrors(t *testing.T) {
	if err := run([]string{"check", "testdata/passports"}); err == nil {
		t.Fatal("run([check <one-arg>]): expected an error, got nil")
	}
}

func TestPrintCheckJSONRoundTrips(t *testing.T) {
	results := []checkResult{
		{AgentID: "agent://x/bot1", Owner: "team@x", Decision: pdp.Allow, Reason: "allowed: no policy targets agent agent://x/bot1"},
		{AgentID: "agent://x/bot2", Owner: "team@x", Decision: pdp.Deny, Reason: "policy requires attestation"},
	}
	var buf bytes.Buffer
	if err := printCheckJSON(&buf, results); err != nil {
		t.Fatalf("printCheckJSON: %v", err)
	}
	var out []checkResultJSON
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v (body: %s)", err, buf.String())
	}
	if len(out) != 2 || out[0].AgentID != "agent://x/bot1" || out[1].Decision != pdp.Deny {
		t.Errorf("round-tripped = %+v", out)
	}
}

func TestPrintCheckHumanListsEveryAgent(t *testing.T) {
	results := []checkResult{
		{AgentID: "agent://x/bot1", Owner: "team@x", Decision: pdp.Allow, Reason: "ok"},
	}
	var buf bytes.Buffer
	printCheckHuman(&buf, results, "abc123")
	out := buf.String()
	if !strings.Contains(out, "agent://x/bot1") || !strings.Contains(out, "abc123") {
		t.Errorf("human output missing expected content: %s", out)
	}
}

func TestPrintCheckHumanEmptyResults(t *testing.T) {
	var buf bytes.Buffer
	printCheckHuman(&buf, nil, "abc123")
	if !strings.Contains(buf.String(), "No passports found") {
		t.Errorf("expected a no-passports message, got: %s", buf.String())
	}
}

func TestOrDefault(t *testing.T) {
	if got := orDefault("", "fallback"); got != "fallback" {
		t.Errorf("orDefault(\"\", fallback) = %q, want fallback", got)
	}
	if got := orDefault("set", "fallback"); got != "set" {
		t.Errorf("orDefault(set, fallback) = %q, want set", got)
	}
}

func TestDisplayAddr(t *testing.T) {
	if got := displayAddr(":8090"); got != "localhost:8090" {
		t.Errorf("displayAddr(:8090) = %q, want localhost:8090", got)
	}
	if got := displayAddr("0.0.0.0:8090"); got != "0.0.0.0:8090" {
		t.Errorf("displayAddr(0.0.0.0:8090) = %q, want unchanged", got)
	}
}

// TestSingleUseInMemoryWarning covers singleUseInMemoryWarning's three
// cases: single-use off (no warning regardless of -db), single-use on with
// no -db (warns), single-use on with -db set (no warning: Postgres is
// durable and shared across instances, so the in-memory caveat doesn't
// apply). This is the startup warning path from
// WARDRYX_APPROVAL_SINGLE_USE=true with an in-memory store, exercised as a
// pure unit test rather than by parsing serve's stderr.
func TestSingleUseInMemoryWarning(t *testing.T) {
	cases := []struct {
		name      string
		singleUse bool
		dbDSN     string
		wantEmpty bool
	}{
		{"off, no db", false, "", true},
		{"off, with db", false, "postgres://x", true},
		{"on, no db: warns", true, "", false},
		{"on, with db: no warning", true, "postgres://x", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := singleUseInMemoryWarning(c.singleUse, c.dbDSN)
			if c.wantEmpty && got != "" {
				t.Errorf("singleUseInMemoryWarning(%v, %q) = %q, want empty", c.singleUse, c.dbDSN, got)
			}
			if !c.wantEmpty {
				if got == "" {
					t.Errorf("singleUseInMemoryWarning(%v, %q) = empty, want a warning", c.singleUse, c.dbDSN)
				}
				if !strings.Contains(got, "WARDRYX_APPROVAL_SINGLE_USE") || !strings.Contains(got, "in-memory") {
					t.Errorf("warning = %q, want it to mention WARDRYX_APPROVAL_SINGLE_USE and in-memory", got)
				}
			}
		})
	}
}

// ------------------------------------------------------------------
// W1: startupKeyPosture, the pure decision runServe consults before it ever
// opens a store or binds a socket. Driven directly rather than by spawning
// the binary, per the spec's guidance to avoid binding a real port where
// avoidable.
// ------------------------------------------------------------------

// TestServeRefusesToStartWithNoKeysAndNoOptIn is the security-critical
// default: no valid WARDRYX_KEYS and no WARDRYX_ALLOW_DEVKEY opt-in refuses
// to start, naming both ways out, rather than silently authenticating
// nobody (or, before this fix, everybody as devkey).
func TestServeRefusesToStartWithNoKeysAndNoOptIn(t *testing.T) {
	refuse, warn := startupKeyPosture("", false, ":8090")
	if refuse == "" {
		t.Fatal("startupKeyPosture(\"\", false, \":8090\") returned no refusal, want one: " +
			"no keys and no opt-in must refuse to start")
	}
	if !strings.Contains(refuse, "WARDRYX_KEYS") || !strings.Contains(refuse, "WARDRYX_ALLOW_DEVKEY") {
		t.Errorf("refusal = %q, want it to name both ways out: WARDRYX_KEYS and WARDRYX_ALLOW_DEVKEY", refuse)
	}
	if len(warn) != 0 {
		t.Errorf("warnings = %v, want none alongside a refusal", warn)
	}
}

// TestDevkeyOnARoutableBindIsRefused is the GOTCHAS 20 pairing exactly:
// devkey fallback active AND a non-loopback bind. Refused outright, not
// merely warned about, because that exact pair is the incident.
func TestDevkeyOnARoutableBindIsRefused(t *testing.T) {
	for _, addr := range []string{":8090", "0.0.0.0:8090", "[::]:8090"} {
		refuse, _ := startupKeyPosture("", true, addr)
		if refuse == "" {
			t.Errorf("startupKeyPosture(\"\", true, %q) returned no refusal, want one: "+
				"devkey plus a non-loopback bind is the GOTCHAS 20 incident", addr)
		}
	}
}

// TestDevkeyOnLoopbackStartsWithAWarning: the same devkey fallback bound to
// loopback only is a legitimate local dev run (make serve's own shape) and
// must start, loudly warning that the insecure credential is active rather
// than refusing.
func TestDevkeyOnLoopbackStartsWithAWarning(t *testing.T) {
	refuse, warn := startupKeyPosture("", true, "127.0.0.1:8090")
	if refuse != "" {
		t.Fatalf("startupKeyPosture(\"\", true, \"127.0.0.1:8090\") refused: %q, want it to start", refuse)
	}
	if len(warn) == 0 {
		t.Fatal("no warning printed for an active devkey fallback on loopback, want one naming it")
	}
	found := false
	for _, w := range warn {
		if strings.Contains(strings.ToLower(w), "devkey") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings = %v, want at least one naming the active devkey credential", warn)
	}
}

// TestAllowDevkeySetButKeysAlreadyValidWarnsTheFlagIsUnused mirrors
// tokenfuse-cloud's main.rs: the flag is harmless when real keys are already
// configured, but silence would leave an operator wondering whether it did
// anything, so serve says it did not.
func TestAllowDevkeySetButKeysAlreadyValidWarnsTheFlagIsUnused(t *testing.T) {
	refuse, warn := startupKeyPosture("a:acme", true, "127.0.0.1:8090")
	if refuse != "" {
		t.Fatalf("refused: %q, want it to start (real keys are configured)", refuse)
	}
	found := false
	for _, w := range warn {
		if strings.Contains(w, "WARDRYX_ALLOW_DEVKEY") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings = %v, want one saying WARDRYX_ALLOW_DEVKEY has no effect", warn)
	}
}

// TestARealKeySpecOnANonLoopbackBindOnlyWarns: bindWarning fires
// independently of the devkey question. A k8s deployment binds 0.0.0.0 on
// purpose with real keys configured, and must be allowed to start, merely
// warned.
func TestARealKeySpecOnANonLoopbackBindOnlyWarns(t *testing.T) {
	refuse, warn := startupKeyPosture("a:acme", false, ":8090")
	if refuse != "" {
		t.Fatalf("refused: %q, want it to start: a wide bind with real keys is a normal k8s deployment", refuse)
	}
	if len(warn) == 0 {
		t.Error("no warning for a non-loopback bind, want one: an operator should still see it")
	}
}

// TestBindWarning pins bindWarning's own cases directly, independent of
// startupKeyPosture's key logic.
func TestBindWarning(t *testing.T) {
	cases := []struct {
		addr      string
		wantEmpty bool
	}{
		{":8090", false},
		{"0.0.0.0:8090", false},
		{"[::]:8090", false},
		{"127.0.0.1:8090", true},
		{"localhost", true}, // no port: SplitHostPort errors, warning suppressed rather than guessed
	}
	for _, c := range cases {
		got := bindWarning(c.addr)
		if c.wantEmpty && got != "" {
			t.Errorf("bindWarning(%q) = %q, want empty", c.addr, got)
		}
		if !c.wantEmpty && got == "" {
			t.Errorf("bindWarning(%q) = empty, want a warning", c.addr)
		}
	}
}

func TestOrDash(t *testing.T) {
	if got := orDash(""); got != "-" {
		t.Errorf("orDash(\"\") = %q, want -", got)
	}
	if got := orDash("alice"); got != "alice" {
		t.Errorf("orDash(alice) = %q, want alice", got)
	}
}

// The offline check has no call in hand, so it sends no model: a policy with
// allow_models must not report every agent as refused for a model nobody named.
// The rule is judged on /v1/decide, against a real model call.
func TestCheckDoesNotJudgeAModelItWasNotShown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	doc := "name: fleet\ntarget: \"agent://acme.example/*\"\nallow_models: [\"claude-sonnet-*\"]\n"
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	results, _, _, err := checkAgents("testdata/passports", path)
	if err != nil {
		t.Fatalf("checkAgents: %v", err)
	}
	for _, r := range results {
		if r.Decision != pdp.Allow {
			t.Errorf("%s: %s (%s), want allow: the check named no model", r.AgentID, r.Decision, r.Reason)
		}
	}
}

// The offline check has an agent and no call, so its decision never reflects the
// floor. The table says what the floor does to each agent instead.

func writeCheckPolicy(t *testing.T, doc string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckSaysWhatTheFloorDoesToEachAgent(t *testing.T) {
	pol := writeCheckPolicy(t, `- name: tool-hold
  target: "*"
  when_no_grant: hold
- name: grant-bot1
  target: agent://acme.example/finance/bot1
  grant_tool: [search, ask]
`)
	results, _, _, err := checkAgents("testdata/passports", pol)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Fatalf("%+v", results)
	}
	var granted, held bool
	for _, r := range results {
		if r.Decision != pdp.Allow {
			t.Errorf("%s is %s (%s): a passport names no call, so the floor does not judge it", r.AgentID, r.Decision, r.Reason)
		}
		granted = granted || r.ToolCalls == "granted: ask, search; any other tool is held"
		held = held || r.ToolCalls == "held: nothing grants a tool"
	}
	if !granted || !held {
		t.Fatalf("the table does not tell the two agents apart: %+v", results)
	}
	var out bytes.Buffer
	printCheckHuman(&out, results, "v1")
	for _, want := range []string{"TOOL CALLS", "any other tool is held", "nothing grants a tool"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the table does not say %q:\n%s", want, out.String())
		}
	}
	out.Reset()
	if err := printCheckJSON(&out, results); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `"tool_calls": "held: nothing grants a tool"`) {
		t.Errorf("the JSON form has no tool_calls:\n%s", out.String())
	}
}

func TestToolCallsLineSaysEveryToolAndNoFloor(t *testing.T) {
	if got := toolCallsLine(pdp.ToolPosture{Floor: "f", All: true}); got != "granted: every tool" {
		t.Fatalf("%q", got)
	}
	if got := toolCallsLine(pdp.ToolPosture{}); got != "" {
		t.Fatalf("%q", got)
	}
}

func TestCheckPrintsWhatItAlwaysPrintedWithNoFloor(t *testing.T) {
	results, _, _, err := checkAgents("testdata/passports", "testdata/policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	printCheckHuman(&out, results, "v1")
	if strings.Contains(out.String(), "TOOL CALLS") {
		t.Fatalf("a file with no floor changed the table:\n%s", out.String())
	}
	out.Reset()
	if err := printCheckJSON(&out, results); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "tool_calls") {
		t.Fatalf("a file with no floor changed the JSON:\n%s", out.String())
	}
}

// The example an operator is pointed at is the floor as it is meant to be written,
// so it is loaded and driven: an id with no scheme stays held, which is why its
// target is "*". A seed with agent://* would let that id through.
func TestTheExampleFloorHoldsAnIDWithoutTheScheme(t *testing.T) {
	set, err := policy.Load("../../docs/examples/tool-hold.yaml")
	if err != nil {
		t.Fatalf("the example does not load: %v", err)
	}
	engine := pdp.New(set, nil)
	call := func(agent, tool string) pdp.DecideResponse {
		return engine.Decide(pdp.DecideRequest{
			AgentID: agent, RunID: "r", ToolNames: []string{tool}, IdentitySource: "agent-token",
			ToolCall: &pdp.ToolCall{Name: tool, Target: "t"},
		})
	}
	if got := call("aws-comparable-agent", "ask"); got.Decision != pdp.Hold {
		t.Fatalf("an id with no scheme is %s (%s) under the example, want hold", got.Decision, got.Reason)
	}
	if got := call("agent://acme.example/agents/operator", "fetch_url"); got.Decision != pdp.Allow {
		t.Fatalf("a granted tool is %s (%s)", got.Decision, got.Reason)
	}
	if got := call("agent://acme.example/agents/operator", "exec"); got.Decision != pdp.Hold {
		t.Fatalf("an ungranted tool is %s (%s)", got.Decision, got.Reason)
	}
	if got := call("agent://drills.acme.example/any", "exec"); got.Decision != pdp.Allow {
		t.Fatalf("a tool under the wide grant is %s (%s)", got.Decision, got.Reason)
	}
}

func replayFixture(t *testing.T) (eventsPath, archiveDir, candidate string) {
	t.Helper()
	dir := t.TempDir()
	eventsPath, archiveDir = filepath.Join(dir, "events.ndjson"), filepath.Join(dir, "archive")
	arch, err := archive.New(archiveDir)
	if err != nil {
		t.Fatal(err)
	}
	old := policy.Empty()
	if err := arch.Keep(old); err != nil {
		t.Fatal(err)
	}
	w, err := event.NewChainedWriter(eventsPath)
	if err != nil {
		t.Fatal(err)
	}
	agent := "agent://acme.example/agents/worker"
	if err := w.Write(event.Event{
		Schema: event.SchemaV02, TS: "2026-11-01T10:00:00Z", Source: "wardryx", Type: "policy_allow", AgentID: agent, Severity: event.SeverityInfo, RunID: "r",
		Data: map[string]any{
			"tool_names": []string{"fetch_url"}, "domains": nil, "steps": 0, "model": "", "est_cost_usd": 0, "attestation_method": "",
			"chain_proven": false, "policy_version": old.Version(), "reason": "allowed: no policy targets agent " + agent, "approval_token_required": false,
			"tool_call": map[string]any{"name": "fetch_url", "target": "t", "arguments_sha256": "00", "arguments_truncated": false, "digest": "00"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return eventsPath, archiveDir, writeCheckPolicy(t, "name: tool-hold\ntarget: \"*\"\nwhen_no_grant: hold\n")
}

func capture(t *testing.T, f func() error) (string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdout")
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = out
	ferr := f()
	os.Stdout = old
	_ = out.Close()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw), ferr
}

func TestReplayReportsWhatACandidateFloorWouldHold(t *testing.T) {
	events, arch, cand := replayFixture(t)
	out, err := capture(t, func() error { return run([]string{"replay", "-events", events, "-archive", arch, "-policy", cand}) })
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"would wait for a person", `"fetch_url"`, "agent://acme.example/agents/worker", "2026-11-01T10:00:00Z"} {
		if !strings.Contains(out, want) {
			t.Errorf("the report does not say %q:\n%s", want, out)
		}
	}
}

func TestReplayJSONIsWhatAnInstallerReads(t *testing.T) {
	events, arch, cand := replayFixture(t)
	out, err := capture(t, func() error {
		return run([]string{"replay", "-events", events, "-archive", arch, "-policy", cand, "-format", "json"})
	})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var got struct {
		Total      int `json:"total"`
		Unexamined int `json:"unexamined"`
		WouldHold  []struct {
			AgentID string `json:"agent_id"`
			Tool    string `json:"tool"`
			Calls   int    `json:"calls"`
			Last    string `json:"last"`
		} `json:"would_hold"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if got.Total != 1 || got.Unexamined != 0 || len(got.WouldHold) != 1 || got.WouldHold[0].Tool != "fetch_url" || got.WouldHold[0].Calls != 1 || got.WouldHold[0].Last != "2026-11-01T10:00:00Z" {
		t.Fatalf("%+v\n%s", got, out)
	}
}

func TestReplayRefusesAFormatItDoesNotHave(t *testing.T) {
	events, arch, _ := replayFixture(t)
	if err := run([]string{"replay", "-events", events, "-archive", arch, "-format", "yaml"}); err == nil || !strings.Contains(err.Error(), "unknown format") {
		t.Fatalf("%v", err)
	}
}

func TestServeRefusesAPendingCapItCannotRead(t *testing.T) {
	t.Setenv("WARDRYX_PENDING_PER_AGENT", "many")
	t.Setenv("WARDRYX_KEYS", "k:acme:admin")
	// On its own goroutine: a serve that does not refuse does not return.
	done := make(chan error, 1)
	go func() { done <- run([]string{"serve", "-addr", "127.0.0.1:0"}) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "WARDRYX_PENDING_PER_AGENT") {
			t.Fatalf("serve answered %v, want a refusal naming the variable", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve started on a cap it could not read")
	}
}
