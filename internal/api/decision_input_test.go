package api

import (
	"net/http"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// A recorded decision is only replayable if the record carries the QUESTION,
// not just the answer. These tests hold the emitter to that: everything
// Decide reads must reach the event, or be excluded on purpose and by name.

// fieldHome says where each DecideRequest field is recorded. It is an
// ANSWER sheet, never a subject list: the subjects come from reflecting over
// the struct itself, so a field added to DecideRequest with no entry here
// fails rather than being silently dropped from the record.
var fieldHome = map[string]string{
	"AgentID":           "envelope",
	"RunID":             "envelope",
	"OnBehalfOf":        "envelope",
	"ToolNames":         "data:tool_names",
	"Domains":           "data:domains",
	"Steps":             "data:steps",
	"Model":             "data:model",
	"EstCostUSD":        "data:est_cost_usd",
	"AttestationMethod": "data:attestation_method",
	"ChainProven":       "data:chain_proven",
	"ApprovalToken":     "excluded: a live credential never enters an append-only record",
}

// fullRequest populates every DecideRequest field with a distinguishable
// non-zero value, so a field that fails to reach the event shows up as a
// missing or zero key rather than as an accidental match on a zero value.
func fullRequest() pdp.DecideRequest {
	return pdp.DecideRequest{
		AgentID:           "agent://acme.example/finance/bot1",
		RunID:             "r-input",
		OnBehalfOf:        []string{"user://acme.example/alice"},
		ToolNames:         []string{"http_get"},
		Domains:           []string{"payouts.evil.example"},
		Steps:             3,
		Model:             "claude-sonnet-5",
		EstCostUSD:        12.40,
		AttestationMethod: "tpm",
		ChainProven:       true,
		ApprovalToken:     "tok-secret-must-not-be-recorded",
	}
}

// TestDecisionInputCoversEveryDecideRequestField is the gate. It reflects
// over DecideRequest so the set of things to check is read from the code,
// and requires each field to be recorded in the envelope, recorded in data,
// or excluded with a stated reason. Adding an input to the PDP without
// giving it a home breaks this test, which is the point: an unrecorded
// input makes every future replay of that decision quietly wrong.
func TestDecisionInputCoversEveryDecideRequestField(t *testing.T) {
	req := fullRequest()
	data := decisionInput(req, pdp.DecideResponse{
		Decision:      pdp.Deny,
		Reason:        "domain is not allowed",
		PolicyVersion: "e0d7fd6dd2a0",
	})

	typ := reflect.TypeOf(req)
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		home, known := fieldHome[name]
		if !known {
			t.Fatalf("DecideRequest.%s has no recorded home. Every input Decide reads must be "+
				"recorded in the envelope, recorded in data, or excluded by name in fieldHome; "+
				"an unrecorded input makes every replay of this decision wrong.", name)
		}
		key, isData := dataKey(home)
		if !isData {
			continue
		}
		got, present := data[key]
		if !present {
			t.Errorf("DecideRequest.%s claims data[%q] and the emitter did not write it", name, key)
			continue
		}
		if reflect.ValueOf(got).IsZero() {
			t.Errorf("DecideRequest.%s reached data[%q] as a zero value %#v, so the field is not really recorded", name, key, got)
		}
	}

	// The verdict's own two facts. Neither is a DecideRequest field, and
	// replay needs both: the version names the set that answered, the
	// reason is what a replay compares against.
	for _, key := range []string{"reason", "policy_version"} {
		if v, ok := data[key]; !ok || v == "" {
			t.Errorf("data[%q] missing or empty: a replay cannot say which set answered, or what it answered", key)
		}
	}
}

// dataKey reports whether home names a data key, and which.
func dataKey(home string) (string, bool) {
	const prefix = "data:"
	if len(home) > len(prefix) && home[:len(prefix)] == prefix {
		return home[len(prefix):], true
	}
	return "", false
}

// TestDecisionInputNeverCarriesTheApprovalToken pins the one deliberate
// exclusion. An approval token is a live credential; the record outlives it
// and is replicated, so writing one down converts a short-lived secret into
// a permanent one.
func TestDecisionInputNeverCarriesTheApprovalToken(t *testing.T) {
	data := decisionInput(fullRequest(), pdp.DecideResponse{Reason: "r", PolicyVersion: "v"})
	for key, value := range data {
		if s, ok := value.(string); ok && s == "tok-secret-must-not-be-recorded" {
			t.Fatalf("data[%q] carries the approval token verbatim", key)
		}
	}
	if _, present := data["approval_token"]; present {
		t.Fatal("data carries an approval_token key")
	}
}

// TestDecisionInputDoesNotRepeatTypedEnvelopeMembers keeps the two planes
// apart. agent_id, run_id and on_behalf_of are typed members of the shared
// envelope, and the estate's record mapper reads them from there; repeating
// them in data would put the same fact in a typed field and in the
// erasable payload plane at once.
func TestDecisionInputDoesNotRepeatTypedEnvelopeMembers(t *testing.T) {
	data := decisionInput(fullRequest(), pdp.DecideResponse{Reason: "r", PolicyVersion: "v"})
	for _, key := range []string{"agent_id", "run_id", "on_behalf_of", "schema", "ts", "type", "severity"} {
		if _, present := data[key]; present {
			t.Errorf("data[%q] duplicates a typed envelope member", key)
		}
	}
}

// decideAndReadEvents drives one /v1/decide and returns what was emitted.
func decideAndReadEvents(t *testing.T, dto decideRequestDTO) []event.Event {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.ndjson")
	srv, ew := newTestServerWithEvents(t, path)
	doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, dto)
	if err := ew.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	events, err := event.ReadFile(path)
	if err != nil {
		t.Fatalf("event.ReadFile: %v", err)
	}
	return events
}

// TestEveryDecisionOutcomeRecordsTheQuestion covers all three verdicts. A
// replay that could reproduce denials but not holds would leave the
// approvable band unexaminable, which is the band an operator most wants to
// tune.
func TestEveryDecisionOutcomeRecordsTheQuestion(t *testing.T) {
	// newTestServerWithEvents compiles: DenyTool send_wire_transfer,
	// AllowDomains good.example.com, RequireHumanAboveUSD 500, MaxSteps 5.
	cases := []struct {
		name      string
		dto       decideRequestDTO
		wantEvent string
	}{
		{
			name: "allow",
			dto: decideRequestDTO{
				AgentID: "agent://acme.example/finance/bot1", RunID: "r-allow",
				ToolNames: []string{"generate_report"}, Domains: []string{"good.example.com"},
				Steps: 2, Model: "claude-sonnet-5", EstCostUSD: 1.25, AttestationMethod: "tpm",
			},
			wantEvent: "policy_allow",
		},
		{
			name: "deny",
			dto: decideRequestDTO{
				AgentID: "agent://acme.example/finance/bot1", RunID: "r-deny",
				ToolNames: []string{"generate_report"}, Domains: []string{"payouts.evil.example"},
				Steps: 2, Model: "claude-sonnet-5", EstCostUSD: 1.25, AttestationMethod: "tpm",
			},
			wantEvent: "policy_deny",
		},
		{
			name: "hold",
			dto: decideRequestDTO{
				AgentID: "agent://acme.example/finance/bot1", RunID: "r-hold",
				ToolNames: []string{"generate_report"}, Domains: []string{"good.example.com"},
				Steps: 2, Model: "claude-sonnet-5", EstCostUSD: 900, AttestationMethod: "tpm",
			},
			wantEvent: "approval_requested",
		},
	}

	want := []string{"tool_names", "domains", "steps", "model", "est_cost_usd",
		"attestation_method", "chain_proven", "policy_version", "reason"}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			events := decideAndReadEvents(t, tc.dto)
			var found *event.Event
			for i := range events {
				if events[i].Type == tc.wantEvent {
					found = &events[i]
				}
			}
			if found == nil {
				t.Fatalf("no %s event among %d emitted", tc.wantEvent, len(events))
			}
			for _, key := range want {
				if _, present := found.Data[key]; !present {
					t.Errorf("%s event data has no %q: this decision cannot be replayed", tc.wantEvent, key)
				}
			}
		})
	}
}

// --- the loop, closed: a record replays ---

// str, num and strs decode one data member the way a replayer must. Nothing
// here assumes Go types survive the file: JSON gives back float64 for every
// number and []any for every list, and a replayer that forgets this rebuilds
// a request full of zero values, which is the failure this whole change is
// against.
func str(t *testing.T, v any) string {
	t.Helper()
	s, ok := v.(string)
	if !ok {
		t.Fatalf("want a string, got %T (%#v)", v, v)
	}
	return s
}

func num(t *testing.T, v any) float64 {
	t.Helper()
	f, ok := v.(float64)
	if !ok {
		t.Fatalf("want a JSON number, got %T (%#v)", v, v)
	}
	return f
}

func strs(t *testing.T, v any) []string {
	t.Helper()
	raw, ok := v.([]any)
	if !ok {
		t.Fatalf("want a JSON array, got %T (%#v)", v, v)
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		out = append(out, str(t, item))
	}
	return out
}

// replayRequest rebuilds a DecideRequest from one emitted event and nothing
// else, exactly as a replayer reading the record would have to.
func replayRequest(t *testing.T, ev event.Event) pdp.DecideRequest {
	t.Helper()
	return pdp.DecideRequest{
		AgentID:           ev.AgentID,
		RunID:             ev.RunID,
		OnBehalfOf:        ev.OnBehalfOf,
		ToolNames:         strs(t, ev.Data["tool_names"]),
		Domains:           strs(t, ev.Data["domains"]),
		Steps:             int(num(t, ev.Data["steps"])),
		Model:             str(t, ev.Data["model"]),
		EstCostUSD:        num(t, ev.Data["est_cost_usd"]),
		AttestationMethod: str(t, ev.Data["attestation_method"]),
		ChainProven:       ev.Data["chain_proven"] == true,
	}
}

// testServerPolicy is the set newTestServerWithEvents compiles, restated so a
// replay can be run against the same rules the server decided under.
func testServerPolicy(t *testing.T, allowDomains []string) *policy.Set {
	t.Helper()
	set, err := policy.Compile([]policy.Policy{{
		Name:                 "finance-guardrail",
		Target:               "agent://acme.example/finance/*",
		DenyTool:             []string{"send_wire_transfer"},
		AllowDomains:         allowDomains,
		RequireHumanAboveUSD: 500,
		MaxSteps:             5,
	}})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	return set
}

// TestARecordedDenialReplaysToTheSameVerdict is what the whole change is for.
// It drives a real denial over HTTP, reads the event off disk, rebuilds the
// question from that record alone, and puts it back to the PDP: first to the
// set that decided, which must answer identically, then to a candidate set,
// which must answer differently. Before this change the first half returned
// allow, because the field the denial turned on was never written down.
func TestARecordedDenialReplaysToTheSameVerdict(t *testing.T) {
	events := decideAndReadEvents(t, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "r-replay",
		ToolNames: []string{"http_get"}, Domains: []string{"payouts.evil.example"},
		Steps: 3, Model: "claude-sonnet-5", EstCostUSD: 12.40, AttestationMethod: "tpm",
	})
	if len(events) != 1 || events[0].Type != "policy_deny" {
		t.Fatalf("want exactly one policy_deny, got %d events", len(events))
	}
	recorded := events[0]

	replayed := replayRequest(t, recorded)
	inForce := pdp.New(testServerPolicy(t, []string{"good.example.com"}), []byte(testHMAC)).Decide(replayed)

	t.Logf("recorded : %s: %s", recorded.Data["reason"], recorded.Data["policy_version"])
	t.Logf("replayed : %s: %s", inForce.Decision, inForce.Reason)

	if inForce.Decision != pdp.Deny {
		t.Fatalf("replaying a recorded denial against the set that produced it returned %s: the record does not carry the question", inForce.Decision)
	}
	if inForce.Reason != recorded.Data["reason"] {
		t.Fatalf("reason drift:\n recorded %q\n replayed %q", recorded.Data["reason"], inForce.Reason)
	}
	if inForce.PolicyVersion != recorded.Data["policy_version"] {
		t.Fatalf("policy version drift: recorded %v, replayed %s", recorded.Data["policy_version"], inForce.PolicyVersion)
	}

	// The counterfactual an operator actually asks for: the destination is
	// added to the allow-list, and this refusal would not have happened.
	candidate := pdp.New(testServerPolicy(t, []string{"good.example.com", "payouts.evil.example"}), []byte(testHMAC)).Decide(replayed)
	t.Logf("candidate: %s: %s", candidate.Decision, candidate.Reason)
	if candidate.Decision != pdp.Allow {
		t.Fatalf("under the candidate set want %s, got %s (%s)", pdp.Allow, candidate.Decision, candidate.Reason)
	}
	if candidate.PolicyVersion == inForce.PolicyVersion {
		t.Fatal("the two sets share a PolicyVersion, so a replay could not name which one answered")
	}
}
