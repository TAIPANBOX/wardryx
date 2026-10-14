package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/replay"
)

// An agent that switches to a model its policy does not allow is refused. These
// tests drive that through the real handler with the body TokenFuse's gateway
// sends for a model call (crates/gateway/src/wardryx.rs, DecideWireRequest,
// no tool_call on the model path), and hold the record and the replay to it.

const fleetAgentID = "agent://acme.example/fleet/bot1"

const fleetPolicy = `name: fleet
target: "agent://acme.example/fleet/*"
allow_models: ["claude-sonnet-*", "claude-haiku-*"]
`

func fleetPolicies(t *testing.T, doc string) []policy.Policy {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fleet.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := policy.Load(path)
	if err != nil {
		t.Fatalf("the fleet policy did not load: %v", err)
	}
	return set.Policies()
}

// gatewayModelCall is the gateway's /v1/decide body for one model call.
func gatewayModelCall(model string) string {
	return `{"agent_id":"` + fleetAgentID + `","run_id":"run-7","on_behalf_of":[],"tool_names":["search","fetch"],"domains":[],"steps":3,"model":"` + model + `","est_cost_usd":0.012,"attestation_method":null,"approval_token":null,"chain_proven":false}`
}

func TestAnAgentThatSwitchesToAModelItsPolicyDoesNotAllowIsRefused(t *testing.T) {
	h := newSigHarness(t, false, fleetPolicies(t, fleetPolicy)...)

	before := h.decideRaw(t, gatewayModelCall("claude-sonnet-5-5"))
	if before.Decision != pdp.Allow {
		t.Fatalf("a model the list names: %s (%s), want allow", before.Decision, before.Reason)
	}
	switched := h.decideRaw(t, gatewayModelCall("claude-opus-5"))
	want := `model "claude-opus-5" is not in the allow_models of policy "fleet" (target agent://acme.example/fleet/*)`
	if switched.Decision != pdp.Deny || switched.Reason != want {
		t.Fatalf("the same agent, run and tools on another model: %s (%s), want deny %q", switched.Decision, switched.Reason, want)
	}
	back := h.decideRaw(t, gatewayModelCall("claude-haiku-5"))
	if back.Decision != pdp.Allow {
		t.Fatalf("back on a listed model: %s (%s), want allow", back.Decision, back.Reason)
	}
	// The gateway's cache is keyed by agent and tool set. All three calls share
	// both, so any of them marked cacheable would answer for the others.
	for name, r := range map[string]decideResponseDTO{"before": before, "switched": switched, "back": back} {
		if r.Cacheable {
			t.Errorf("%s: marked cacheable under allow_models", name)
		}
	}

	var deny map[string]any
	for _, ev := range h.read(t) {
		if ev.Type == "policy_deny" {
			deny = ev.Data
		}
	}
	if deny == nil || deny["model"] != "claude-opus-5" || deny["reason"] != want {
		t.Fatalf("the recorded deny does not carry the model it refused: %#v", deny)
	}
}

// A model denial is recorded with the model, so replay reaches it again, and a
// candidate policy without the list turns it back into the allow it would have
// been.
func TestAModelDenialReplaysFromTheRecord(t *testing.T) {
	h := newSigHarness(t, false, fleetPolicies(t, fleetPolicy)...)
	h.decideRaw(t, gatewayModelCall("claude-sonnet-5-5"))
	if got := h.decideRaw(t, gatewayModelCall("claude-opus-5")); got.Decision != pdp.Deny {
		t.Fatalf("setup: %s (%s)", got.Decision, got.Reason)
	}
	events := h.read(t)
	report := replay.Run(events, h.arch, nil)
	if report.Total != 2 || report.Reproduced != 2 || report.Diverged != 0 {
		t.Fatalf("the model decisions did not reproduce:\n%s", replay.Format(report, "events", ""))
	}
	without, err := policy.Compile(fleetPolicies(t, "name: fleet\ntarget: \"agent://acme.example/fleet/*\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	cf := replay.Run(events, h.arch, without)
	if cf.Changed != 1 {
		t.Fatalf("a candidate without allow_models did not change exactly the recorded denial:\n%s", replay.Format(cf, "events", "without"))
	}
}

// The policy API reads allow_models like a policy file: the list is stored,
// returned and enforced, and a blank entry is a 400 that stores nothing.
func TestAPutWithAllowModelsIsStoredAndEnforced(t *testing.T) {
	srv := newTestServer(t)
	const path = "/v1/policies/fleet"
	blank := `{"name":"fleet","target":"agent://acme.example/fleet/*","allow_models":["claude-sonnet-*",""]}`
	if rec := doRaw(t, srv.Handler(), http.MethodPut, path, adminKey, blank); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "allow_models") {
		t.Fatalf("PUT with a blank allow_models entry: %d %s, want a 400 naming allow_models", rec.Code, rec.Body.String())
	}
	if got := doRequest(t, srv.Handler(), http.MethodGet, path, adminKey, nil).Code; got != http.StatusNotFound {
		t.Fatalf("GET after the refused PUT = %d, want 404", got)
	}
	ok := `{"name":"fleet","target":"agent://acme.example/fleet/*","allow_models":["claude-sonnet-*"]}`
	if rec := doRaw(t, srv.Handler(), http.MethodPut, path, adminKey, ok); rec.Code != http.StatusOK {
		t.Fatalf("PUT with allow_models: %d %s", rec.Code, rec.Body.String())
	}
	var stored struct {
		AllowModels []string `json:"allow_models"`
	}
	rec := doRequest(t, srv.Handler(), http.MethodGet, path, adminKey, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &stored); err != nil || len(stored.AllowModels) != 1 || stored.AllowModels[0] != "claude-sonnet-*" {
		t.Fatalf("GET does not return the stored list (%v): %s", err, rec.Body.String())
	}
	got := decodeBody[decideResponseDTO](t, doRaw(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, gatewayModelCall("claude-opus-5")))
	if got.Decision != pdp.Deny || !strings.Contains(got.Reason, "allow_models") {
		t.Fatalf("after the PUT a refused model is %s (%s), want the model deny", got.Decision, got.Reason)
	}
}

// modelName is a model as a decide body carries it: present, possibly empty.
func modelName(m string) *string { return &m }

// The three callers, each with the body it sends. TokenFuse's model path sends
// the body's model as it is, so a body with "model": "" arrives as an empty
// model, a model call naming none: refused. scopyx's egress check sends agent,
// run and domains and no model key: not a model call, not judged. TokenFuse's
// MCP broker sends an empty model beside the tool_call: a tool decision, not
// judged.
func TestOnlyAModelCallIsJudgedOverTheWire(t *testing.T) {
	h := newSigHarness(t, false, fleetPolicies(t, fleetPolicy)...)
	if got := h.decideRaw(t, gatewayModelCall("")); got.Decision != pdp.Deny || !strings.Contains(got.Reason, `model "" is not in the allow_models`) {
		t.Fatalf("the gateway's body with an empty model: %s (%s), want the model deny", got.Decision, got.Reason)
	}
	scopyx := `{"agent_id":"` + fleetAgentID + `","run_id":"run-7","domains":["api.example.com"]}`
	if got := h.decideRaw(t, scopyx); got.Decision != pdp.Allow {
		t.Fatalf("scopyx's egress body, no model key: %s (%s), want allow", got.Decision, got.Reason)
	}
	broker := `{"agent_id":"` + fleetAgentID + `","run_id":"mcp:` + fleetAgentID + `","on_behalf_of":[],"tool_names":["search"],"domains":[],"steps":0,"model":"","est_cost_usd":0.0,"attestation_method":null,"approval_token":null,"chain_proven":false,"tool_call":{"name":"search","arguments":{"q":"x"},"target":"search-mcp"}}`
	if got := h.decideRaw(t, broker); got.Decision != pdp.Allow {
		t.Fatalf("the broker's tool-call body: %s (%s), want allow", got.Decision, got.Reason)
	}
	// The record says which decision sent no model, so replay judges the same
	// requests the live decision did.
	events := h.read(t)
	absent := 0
	for _, ev := range events {
		if ev.Data["model_absent"] == true {
			absent++
		}
	}
	if absent != 1 {
		t.Fatalf("%d decisions recorded model_absent, want 1 (scopyx's)", absent)
	}
	if report := replay.Run(events, h.arch, nil); report.Reproduced != 3 || report.Diverged != 0 {
		t.Fatalf("the three decisions did not reproduce:\n%s", replay.Format(report, "events", ""))
	}
}
