package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/pdp"
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

func TestOrDash(t *testing.T) {
	if got := orDash(""); got != "-" {
		t.Errorf("orDash(\"\") = %q, want -", got)
	}
	if got := orDash("alice"); got != "alice" {
		t.Errorf("orDash(alice) = %q, want alice", got)
	}
}
