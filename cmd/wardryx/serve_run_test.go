package main

// serve, approvals, replay, check and preview-key driven end to end through
// run, up to the point where serve would accept connections. Every serve here
// is given an address no listener can take (port 99999), so a start that got
// through every check returns at ListenAndServe with that error instead of
// serving: what it printed on the way, and what it refused, is the subject.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/wardryx/internal/approval"
	"github.com/TAIPANBOX/wardryx/internal/archive"
	"github.com/TAIPANBOX/wardryx/internal/config"
	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/previewseal"
)

// unbindable is an address serve resolves and cannot listen on.
const unbindable = "127.0.0.1:99999"

var serveEnvNames = []string{
	"WARDRYX_ADDR", "WARDRYX_AGENT_TOKEN_AUDIENCES", "WARDRYX_AGENT_TOKEN_DOOR_ORIGINS",
	"WARDRYX_AGENT_TOKEN_ISSUER", "WARDRYX_AGENT_TOKEN_JWKS_FILE", "WARDRYX_AGENT_TOKEN_JWKS_URL",
	"WARDRYX_AGENT_TOKEN_PROOF_MAX_AGE_SECONDS", "WARDRYX_AGENT_TOKEN_REQUIRE_PROOF",
	"WARDRYX_AGENT_TOKEN_REVOCATION_URL", "WARDRYX_ALLOW_DEVKEY", "WARDRYX_ALLOW_KEY_APPROVALS",
	"WARDRYX_APPROVAL_SECRET", "WARDRYX_APPROVAL_SIGNER", "WARDRYX_APPROVAL_SINGLE_USE",
	"WARDRYX_APPROVAL_V2_UNTIL", "WARDRYX_APPROVER_JWKS", "WARDRYX_DB",
	"WARDRYX_EVENTS_PATH", "WARDRYX_HOLD_TTL", "WARDRYX_KEYRYX_CREDENTIAL_FILE", "WARDRYX_KEYRYX_URL",
	"WARDRYX_KEYS", "WARDRYX_OTLP_ENDPOINT", "WARDRYX_PENDING_PER_AGENT", "WARDRYX_POLICY",
	"WARDRYX_POLICY_ARCHIVE", "WARDRYX_PREVIEW_RECIPIENT", "WARDRYX_PREVIEW_TTL",
	"WARDRYX_RECORD_FAILMODE", "WARDRYX_SIGNAL_EVENTS", "WARDRYX_SIGNAL_EVENTS_MAX_AGE",
}

// cleanServeEnv empties every variable serve reads, so the machine running the
// test cannot change what it measures, and unsets the one whose presence is
// itself a setting.
func cleanServeEnv(t *testing.T) {
	t.Helper()
	for _, n := range serveEnvNames {
		t.Setenv(n, "")
	}
	t.Setenv("WARDRYX_APPROVAL_UNANSWERED_AFTER", "")
	if err := os.Unsetenv("WARDRYX_APPROVAL_UNANSWERED_AFTER"); err != nil {
		t.Fatal(err)
	}
}

// serveCaptured runs serve with args on its own goroutine, with os.Stderr sent
// to a file, and returns what it printed and the error it returned. A serve
// that does not return within the guard is a serve that started listening.
func serveCaptured(t *testing.T, args ...string) (string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stderr")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = f
	done := make(chan error, 1)
	go func() { done <- run(append([]string{"serve"}, args...)) }()
	var serveErr error
	select {
	case serveErr = <-done:
	case <-time.After(10 * time.Second):
		os.Stderr = old
		t.Fatal("serve did not return: it is listening")
	}
	os.Stderr = old
	_ = f.Close()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw), serveErr
}

// captureStderr runs f with os.Stderr sent to a file and returns what it wrote.
func captureStderr(t *testing.T, f func() error) (string, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stderr")
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = out
	ferr := f()
	os.Stderr = old
	_ = out.Close()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw), ferr
}

func emptyFile(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func previewRecipient(t *testing.T) string {
	t.Helper()
	_, recipient, err := previewseal.GenerateKey(previewseal.KEMX25519)
	if err != nil {
		t.Fatal(err)
	}
	return recipient
}

// A start with every optional part configured says, before it serves, what
// each part is doing, and keeps the set it starts under in the archive.
func TestServeWithEveryOptionSaysWhatItIsDoingBeforeItServes(t *testing.T) {
	cleanServeEnv(t)
	events, _, _ := replayFixture(t) // a chain already started, so the start resumes it
	pol := writeCheckPolicy(t, "name: wires\ntarget: \"agent://acme.example/*\"\nrequire_human_above_usd: 100\n")
	archiveDir := filepath.Join(t.TempDir(), "archive")
	signal := emptyFile(t, "signal.ndjson")
	jwks := writeKeyFile(t)

	t.Setenv("WARDRYX_KEYS", "k:acme:admin")
	t.Setenv("WARDRYX_APPROVAL_SECRET", "s3cret-for-tests")
	t.Setenv("WARDRYX_POLICY_ARCHIVE", archiveDir)
	t.Setenv("WARDRYX_APPROVER_JWKS", jwks)
	t.Setenv("WARDRYX_ALLOW_KEY_APPROVALS", "1")
	t.Setenv("WARDRYX_PREVIEW_RECIPIENT", previewRecipient(t))
	t.Setenv("WARDRYX_PREVIEW_TTL", "2h")
	t.Setenv("WARDRYX_HOLD_TTL", "3h")
	t.Setenv("WARDRYX_RECORD_FAILMODE", "open")
	t.Setenv("WARDRYX_APPROVAL_UNANSWERED_AFTER", "0")
	t.Setenv("WARDRYX_SIGNAL_EVENTS", signal)
	t.Setenv("WARDRYX_AGENT_TOKEN_ISSUER", "https://vouchryx.example")
	t.Setenv("WARDRYX_AGENT_TOKEN_AUDIENCES", "https://wardryx.example")
	t.Setenv("WARDRYX_AGENT_TOKEN_JWKS_FILE", writeKeyFile(t))
	t.Setenv("WARDRYX_AGENT_TOKEN_DOOR_ORIGINS", "https://pep.example")

	out, err := serveCaptured(t, "-addr", unbindable, "-policy", pol, "-events", events, "-otlp-endpoint", "http://127.0.0.1:1/v1/traces")
	if err == nil || !strings.Contains(err.Error(), "invalid port") {
		t.Fatalf("serve returned %v, want the listen failure: every check before it passed\n%s", err, out)
	}
	for _, want := range []string{
		"loaded 1 policy(ies) from " + pol,
		"using an in-memory approval store",
		"single-use is only enforced within this one process",
		"resumed the event chain in " + events + " from sha256:",
		"exporting OTLP decision spans to http://127.0.0.1:1/v1/traces",
		"approval statements are verified against the console keys in " + jwks,
		"held calls keep a preview of their arguments sealed to the console key",
		"for at most 2h0m0s",
		"WARNING: WARDRYX_ALLOW_KEY_APPROVALS=1: approvals may be decided by a bearer key",
		"agent tokens are verified: issuer https://vouchryx.example, audiences https://wardryx.example",
		"WARNING: the record of accepted DPoP proofs is in this process",
		"the slo_burn signal is read from " + signal,
		"WARDRYX_RECORD_FAILMODE=open",
		`unanswered-approval reporting OFF (WARDRYX_APPROVAL_UNANSWERED_AFTER="0")`,
		"a hold nobody decides is closed as expired after 3h0m0s",
		"serving on http://" + unbindable,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the start did not say %q:\n%s", want, out)
		}
	}
	for _, never := range []string{"WARDRYX_APPROVAL_SECRET is empty", "WARDRYX_POLICY_ARCHIVE is unset", "starting a fresh event chain"} {
		if strings.Contains(out, never) {
			t.Errorf("the start said %q, which is not true of this configuration:\n%s", never, out)
		}
	}
	// The set the process started under was kept before anything decided.
	set, err := policy.Load(pol)
	if err != nil {
		t.Fatal(err)
	}
	arch, err := archive.New(archiveDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := arch.Get(set.Version()); err != nil {
		t.Fatalf("the starting set %s is not in the archive: %v", set.Version(), err)
	}
}

// A bare start says what it is missing: no policy, no archive, a fresh chain.
func TestServeWithTheMinimumSaysWhatItIsMissing(t *testing.T) {
	cleanServeEnv(t)
	t.Setenv("WARDRYX_KEYS", "k:acme:admin")
	t.Setenv("WARDRYX_APPROVAL_SINGLE_USE", "false")
	events := filepath.Join(t.TempDir(), "events.ndjson")
	out, err := serveCaptured(t, "-addr", unbindable, "-events", events)
	if err == nil || !strings.Contains(err.Error(), "invalid port") {
		t.Fatalf("serve returned %v\n%s", err, out)
	}
	for _, want := range []string{
		"no -policy given; running with zero policies, every request will be allowed",
		"starting a fresh event chain in " + events,
		"WARDRYX_POLICY_ARCHIVE is unset, so policy sets are not kept",
		"a hold nobody decides is closed as expired after",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the start did not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "single-use is only enforced") {
		t.Errorf("with single use turned off the start still warned about it:\n%s", out)
	}
}

// A policy that can hold, with nothing to sign a grant, is said at start.
func TestServeWarnsWhenAPolicyCanHoldAndNothingCanSignTheGrant(t *testing.T) {
	cleanServeEnv(t)
	t.Setenv("WARDRYX_KEYS", "k:acme:admin")
	pol := writeCheckPolicy(t, "name: wires\ntarget: \"*\"\nrequire_human_above_usd: 100\n")
	out, err := serveCaptured(t, "-addr", unbindable, "-policy", pol)
	if err == nil || !strings.Contains(err.Error(), "invalid port") {
		t.Fatalf("serve returned %v\n%s", err, out)
	}
	if !strings.Contains(out, "WARDRYX_APPROVAL_SECRET is empty but a policy requires human approval") {
		t.Fatalf("no warning that holds cannot be granted:\n%s", out)
	}
}

// Every setting that cannot work refuses the start, naming itself, before
// anything listens.
func TestServeRefusesEverySettingThatCannotWork(t *testing.T) {
	file := emptyFile(t, "a-file")
	underAFile := filepath.Join(file, "x")
	cases := []struct {
		name string
		env  map[string]string
		args []string
		want string
	}{
		{"a policy that is not there", map[string]string{"WARDRYX_POLICY": filepath.Join(t.TempDir(), "none.yaml")}, nil, "load policy"},
		{"a preview TTL out of range", map[string]string{"WARDRYX_PREVIEW_TTL": "1s"}, nil, "WARDRYX_PREVIEW_TTL"},
		{"a preview recipient that does not parse", map[string]string{"WARDRYX_PREVIEW_RECIPIENT": "not-a-key"}, nil, "WARDRYX_PREVIEW_RECIPIENT"},
		{"a hold TTL out of range", map[string]string{"WARDRYX_HOLD_TTL": "1s"}, nil, "WARDRYX_HOLD_TTL"},
		{"a database that cannot be reached", map[string]string{"WARDRYX_DB": "postgres://wardryx:x@127.0.0.1:1/wardryx?sslmode=disable&connect_timeout=2"}, nil, "open postgres"},
		{"an events file in a directory that is a file", nil, []string{"-events", underAFile}, "open events writer"},
		{"no keys and no opt-in", map[string]string{"WARDRYX_KEYS": ""}, nil, "refusing to start"},
		{"a signer this build does not know", map[string]string{"WARDRYX_APPROVAL_SIGNER": "hsm"}, nil, "approval tokens"},
		{"an approver key file that is not there", map[string]string{"WARDRYX_APPROVER_JWKS": filepath.Join(t.TempDir(), "none.json")}, nil, "approver statements"},
		{"an agent-token setting with no issuer", map[string]string{"WARDRYX_AGENT_TOKEN_AUDIENCES": "https://wardryx.example"}, nil, "agent tokens"},
		{"a signal age with no file", map[string]string{"WARDRYX_SIGNAL_EVENTS_MAX_AGE": "24h"}, nil, "signal events"},
		{"a policy archive under a file", map[string]string{"WARDRYX_POLICY_ARCHIVE": underAFile}, nil, "open policy archive"},
		{"a flag serve does not have", nil, []string{"-no-such-flag"}, "no-such-flag"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cleanServeEnv(t)
			t.Setenv("WARDRYX_KEYS", "k:acme:admin")
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			out, err := serveCaptured(t, append([]string{"-addr", unbindable}, c.args...)...)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("serve returned %v, want a refusal naming %q\n%s", err, c.want, out)
			}
			if strings.Contains(err.Error(), "invalid port") || strings.Contains(out, "serving on") {
				t.Fatalf("serve got as far as listening on a setting that cannot work: %v\n%s", err, out)
			}
		})
	}
}

func TestApprovalsAgainstADatabaseItCannotReachRefuses(t *testing.T) {
	cleanServeEnv(t)
	err := run([]string{"approvals", "-db", "postgres://wardryx:x@127.0.0.1:1/wardryx?sslmode=disable&connect_timeout=2"})
	if err == nil || !strings.Contains(err.Error(), "open postgres") {
		t.Fatalf("approvals returned %v, want the database named as what failed", err)
	}
}

// ------------------------------------------------------------------ approval keys

func TestApprovalKeysWithNoSignerMintV2UnderTheSecret(t *testing.T) {
	keys, refresh, err := buildApprovalKeys(config.Config{ApprovalSecret: "s"})
	if err != nil || refresh != nil {
		t.Fatalf("err %v refresh %v", err, refresh != nil)
	}
	if string(keys.Secret) != "s" || !keys.V2.Accepted || !keys.V2.Until.IsZero() || keys.Signer != nil {
		t.Fatalf("keys %+v: want v2 under the secret, accepted with no deadline", keys)
	}
	// A deadline with no signer still bounds v2.
	keys, _, err = buildApprovalKeys(config.Config{ApprovalSecret: "s", ApprovalV2Until: "2026-12-01T00:00:00Z"})
	if err != nil || !keys.V2.Accepted || !keys.V2.Until.Equal(time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("keys %+v err %v", keys.V2, err)
	}
}

func TestApprovalKeysRefuseWhatCannotWork(t *testing.T) {
	cred := emptyFile(t, "cred")
	cases := []struct {
		name string
		cfg  config.Config
		want string
	}{
		{"a deadline that is not RFC 3339", config.Config{ApprovalV2Until: "tomorrow"}, "WARDRYX_APPROVAL_V2_UNTIL"},
		{"a signer this build does not know", config.Config{ApprovalSigner: "vault"}, `"vault" is not a signer`},
		{"keyryx with no URL", config.Config{ApprovalSigner: "keyryx"}, "needs WARDRYX_KEYRYX_URL"},
		{"a credential file that is not there", config.Config{ApprovalSigner: "keyryx", KeyryxURL: "https://keyryx.example", KeyryxCredentialFile: cred + ".missing"}, "WARDRYX_KEYRYX_CREDENTIAL_FILE"},
		{"a URL keyryx cannot use", config.Config{ApprovalSigner: "keyryx", KeyryxURL: "ftp://keyryx.example", KeyryxCredentialFile: cred}, "neither http, https nor unix"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			keys, refresh, err := buildApprovalKeys(c.cfg)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q", err, c.want)
			}
			if refresh != nil || keys.Signer != nil || keys.Secret != nil {
				t.Fatalf("a refusal returned keys %+v", keys)
			}
		})
	}
}

// With Keyryx as the signer, v2 tokens verify only until the deadline, and not
// at all without one: tokens in flight at the switch go back to a person.
func TestApprovalKeysWithKeyryxAcceptV2OnlyUntilTheDeadline(t *testing.T) {
	cred := filepath.Join(t.TempDir(), "cred")
	if err := os.WriteFile(cred, []byte("  credential-for-tests\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := captureStderr(t, func() error {
		keys, refresh, err := buildApprovalKeys(config.Config{ApprovalSigner: " Keyryx ", KeyryxURL: "https://keyryx.example", KeyryxCredentialFile: cred})
		if err != nil {
			return err
		}
		if keys.Signer == nil || keys.JWKS == nil || refresh == nil {
			t.Errorf("keyryx keys %+v refresh %v: want a signer, a key set and its refresh", keys, refresh != nil)
		}
		if keys.V2.Accepted {
			t.Errorf("v2 accepted with a signer and no deadline: %+v", keys.V2)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "signed by Keyryx") || !strings.Contains(out, "https://keyryx.example") || !strings.Contains(out, "not at all (WARDRYX_APPROVAL_V2_UNTIL is unset)") {
		t.Fatalf("the start line %q", out)
	}

	out, err = captureStderr(t, func() error {
		keys, _, err := buildApprovalKeys(config.Config{ApprovalSigner: "keyryx", KeyryxURL: "https://keyryx.example", ApprovalV2Until: "2026-12-01T00:00:00Z"})
		if err == nil && (!keys.V2.Accepted || keys.V2.Until.IsZero()) {
			t.Errorf("v2 with a deadline: %+v", keys.V2)
		}
		return err
	})
	if err != nil || !strings.Contains(out, "until 2026-12-01T00:00:00Z") {
		t.Fatalf("err %v, start line %q", err, out)
	}
}

func TestV2ClauseSaysEachRule(t *testing.T) {
	until := time.Date(2026, 12, 1, 1, 0, 0, 0, time.FixedZone("x", 3600))
	for _, c := range []struct {
		rule approval.V2Rule
		want string
	}{
		{approval.V2Rule{}, "not at all (WARDRYX_APPROVAL_V2_UNTIL is unset)"},
		{approval.V2Rule{Accepted: true}, "without a deadline"},
		{approval.V2Rule{Accepted: true, Until: until}, "until 2026-12-01T00:00:00Z"},
	} {
		if got := v2Clause(c.rule); got != c.want {
			t.Errorf("v2Clause(%+v) = %q, want %q", c.rule, got, c.want)
		}
	}
}

// ------------------------------------------------------------------ approvers

func TestApproversAreOffUnsetAndAFileThatDoesNotReadRefuses(t *testing.T) {
	if v, err := buildApprovers(config.Config{}); v != nil || err != nil {
		t.Fatalf("unset: %v %v", v, err)
	}
	if v, err := buildApprovers(config.Config{ApproverJWKSFile: filepath.Join(t.TempDir(), "none.json")}); v != nil || err == nil {
		t.Fatalf("missing file: %v %v", v, err)
	}
	notASet := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(notASet, []byte("[1,2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if v, err := buildApprovers(config.Config{ApproverJWKSFile: notASet}); v != nil || err == nil {
		t.Fatalf("not a key set: %v %v", v, err)
	}
	if v, err := buildApprovers(config.Config{ApproverJWKSFile: writeKeyFile(t)}); v == nil || err != nil {
		t.Fatalf("a key set: %v %v", v, err)
	}
}

// ------------------------------------------------------------------ preview key

func TestPreviewKeyX25519PrintsARecipientServeAccepts(t *testing.T) {
	out := filepath.Join(t.TempDir(), "preview.key")
	printed, err := capture(t, func() error { return run([]string{"preview-key", "-x25519", "-out", out}) })
	if err != nil {
		t.Fatal(err)
	}
	r, err := previewseal.ParseRecipient(strings.TrimSpace(printed))
	if err != nil {
		t.Fatalf("the printed recipient %q does not parse: %v", printed, err)
	}
	// 0x0020 is DHKEM(X25519, HKDF-SHA256); the hybrid default is 0x647a.
	if !strings.HasPrefix(r.Suite(), "kem=0x0020,") {
		t.Fatalf("-x25519 produced suite %q, want the X25519 KEM", r.Suite())
	}
	if _, _, err := buildPreview(config.Config{PreviewRecipient: strings.TrimSpace(printed)}); err != nil {
		t.Fatalf("serve refuses the recipient preview-key printed: %v", err)
	}
}

func TestPreviewKeyRefusesWithoutAnOutputFileOrWithABadFlag(t *testing.T) {
	if err := runPreviewKey(nil); err == nil || !strings.Contains(err.Error(), "-out") {
		t.Fatalf("no -out: %v", err)
	}
	if err := runPreviewKey([]string{"-bogus"}); err == nil {
		t.Fatal("an unknown flag was accepted")
	}
	dir := filepath.Join(t.TempDir(), "missing", "preview.key")
	if err := runPreviewKey([]string{"-out", dir}); err == nil || !strings.Contains(err.Error(), "preview-key:") {
		t.Fatalf("an output in a missing directory: %v", err)
	}
}

// ------------------------------------------------------------------ replay

func TestReplayRefusesWhatItCannotReplay(t *testing.T) {
	events, arch, _ := replayFixture(t)
	file := emptyFile(t, "a-file")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no events file", []string{"-archive", arch}, "needs an events file"},
		{"no archive", []string{"-events", events}, "needs the policy archive"},
		{"an events file that is not there", []string{"-events", events + ".missing", "-archive", arch}, "read events"},
		{"an archive under a file", []string{"-events", events, "-archive", filepath.Join(file, "x")}, "open policy archive"},
		{"a candidate that does not load", []string{"-events", events, "-archive", arch, "-policy", filepath.Join(t.TempDir(), "none.yaml")}, "load candidate policy"},
		{"a flag replay does not have", []string{"-nope"}, "nope"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("WARDRYX_EVENTS_PATH", "")
			t.Setenv("WARDRYX_POLICY_ARCHIVE", "")
			_, err := captureStderr(t, func() error { return run(append([]string{"replay"}, c.args...)) })
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q", err, c.want)
			}
		})
	}
}

// A recorded decision the version it names does not reproduce fails the
// command: the record and this build disagree about the past.
func TestReplayFailsWhenARecordedDecisionDoesNotReproduce(t *testing.T) {
	dir := t.TempDir()
	eventsPath, archiveDir := filepath.Join(dir, "events.ndjson"), filepath.Join(dir, "archive")
	arch, err := archive.New(archiveDir)
	if err != nil {
		t.Fatal(err)
	}
	empty := policy.Empty()
	if err := arch.Keep(empty); err != nil {
		t.Fatal(err)
	}
	w, err := event.NewChainedWriter(eventsPath)
	if err != nil {
		t.Fatal(err)
	}
	agent := "agent://acme.example/agents/worker"
	// A deny recorded under the empty set, which allows everything.
	if err := w.Write(event.Event{
		Schema: event.SchemaV02, TS: "2026-11-01T10:00:00Z", Source: "wardryx", Type: "policy_deny", AgentID: agent, Severity: event.SeverityMedium, RunID: "r",
		Data: map[string]any{
			"tool_names": []string{"fetch_url"}, "domains": nil, "steps": 0, "model": "", "est_cost_usd": 0, "attestation_method": "",
			"chain_proven": false, "policy_version": empty.Version(), "reason": "denied: tool \"fetch_url\" is denied by policy x", "approval_token_required": false,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := capture(t, func() error {
		return run([]string{"replay", "-events", eventsPath, "-archive", archiveDir, "-format", "json"})
	})
	if err == nil || !strings.Contains(err.Error(), "1 decision(s) do not reproduce") {
		t.Fatalf("err %v, want the divergence to fail the command\n%s", err, out)
	}
	var report struct {
		Total int `json:"total"`
	}
	if jerr := json.Unmarshal([]byte(out), &report); jerr != nil || report.Total != 1 {
		t.Fatalf("the report was not printed before the failure: %v %+v\n%s", jerr, report, out)
	}
}

// ------------------------------------------------------------------ check

func TestCheckRefusesAFormatItDoesNotHaveAndAFlagItDoesNotKnow(t *testing.T) {
	pol := writeCheckPolicy(t, "name: p\ntarget: \"*\"\n")
	if err := run([]string{"check", "-format", "yaml", t.TempDir(), pol}); err == nil || !strings.Contains(err.Error(), `unknown format "yaml"`) {
		t.Fatalf("err %v", err)
	}
	if _, err := captureStderr(t, func() error { return run([]string{"check", "-nope"}) }); err == nil {
		t.Fatal("an unknown flag was accepted")
	}
}

func TestCheckSaysHowManyPassportsWereMalformed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	pol := writeCheckPolicy(t, "name: p\ntarget: \"*\"\n")
	var printed string
	errOut, err := captureStderr(t, func() error {
		var rerr error
		printed, rerr = capture(t, func() error { return run([]string{"check", dir, pol}) })
		return rerr
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errOut, "1 malformed") {
		t.Fatalf("stderr %q does not count the malformed passport", errOut)
	}
	if !strings.Contains(printed, "0 passport(s) checked") {
		t.Fatalf("stdout %q", printed)
	}
}
