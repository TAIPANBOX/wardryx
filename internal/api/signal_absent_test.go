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

// A tool call whose arguments are over the enforcement point's cap reaches
// /v1/decide without them, marked arguments_truncated, and the proxy that
// classifies calls does not classify one it cannot read. So it arrives with no
// signal, and a hold_if_signal rule had nothing to read: padding a call past the
// cap made it one that no signal rule could hold. These tests drive that call,
// byte for byte as the broker sends it, through the real handler.

const brokerAgent = "agent://lab.example/agents/worker-1"

// brokerBodyOverTheCap is the body TokenFuse's MCP broker sends for a tools/call
// whose arguments are over its 12 KiB cap (crates/gateway/src/wardryx.rs,
// DecideWireRequest serialised by serde in field order): the tool_call carries
// the name, the flag and the upstream target, and no arguments.
func brokerBodyOverTheCap(token string) string {
	tok := "null"
	if token != "" {
		tok = `"` + token + `"`
	}
	return `{"agent_id":"` + brokerAgent + `","run_id":"mcp:` + brokerAgent + `","on_behalf_of":[],"tool_names":["ask"],"domains":[],"steps":0,"model":"","est_cost_usd":0.0,"attestation_method":null,"approval_token":` + tok + `,"chain_proven":false,"tool_call":{"name":"ask","arguments_truncated":true,"target":"typryx"}}`
}

// labPolicy is the policy an operator writes for the lab agents, read from a
// file the way serve reads one.
const labPolicy = `name: lab-risk
target: "agent://lab.example/agents/*"
hold_if_signal:
  name: action.risk_class
  values: [destructive]
  min_probability: 0.5
`

func loadLabPolicy(t *testing.T, doc string) []policy.Policy {
	t.Helper()
	path := filepath.Join(t.TempDir(), "lab.yaml")
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := policy.Load(path)
	if err != nil {
		t.Fatalf("the lab policy did not load: %v", err)
	}
	return set.Policies()
}

func (h *sigHarness) decideRaw(t *testing.T, body string) decideResponseDTO {
	t.Helper()
	rec := doRaw(t, h.srv.Handler(), http.MethodPost, "/v1/decide", adminKey, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("decide answered %d: %s", rec.Code, rec.Body.String())
	}
	return decodeBody[decideResponseDTO](t, rec)
}

func TestATruncatedToolCallWithNoSignalHoldsWhenTheRuleHoldsOnAbsence(t *testing.T) {
	// The bypass, as it stands with the rule written the way it always was.
	open := newSigHarness(t, true, loadLabPolicy(t, labPolicy)...)
	if got := open.decideRaw(t, brokerBodyOverTheCap("")); got.Decision != pdp.Allow {
		t.Fatalf("control: without when_absent the padded call is %s (%s), want allow, the default", got.Decision, got.Reason)
	}

	h := newSigHarness(t, true, loadLabPolicy(t, labPolicy+"  when_absent: hold\n")...)
	held := h.decideRaw(t, brokerBodyOverTheCap(""))
	if held.Decision != pdp.Hold || held.ApprovalID == "" || !held.ApprovalTokenRequired {
		t.Fatalf("the padded call under when_absent: hold is %s (%s) approval %q, want a hold a person can approve", held.Decision, held.Reason, held.ApprovalID)
	}
	if held.Cacheable {
		t.Error("the absent-signal hold was marked cacheable")
	}
	for _, want := range []string{`"action.risk_class"`, `tool call "ask"`, "arguments_truncated", "when_absent: hold"} {
		if !strings.Contains(held.Reason, want) {
			t.Errorf("the reason %q does not say %q", held.Reason, want)
		}
	}

	// The person deciding sees which call it is.
	var list []approvalDTO
	if err := json.Unmarshal(doRequest(t, h.srv.Handler(), http.MethodGet, "/v1/approvals", adminKey, nil).Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	var shown map[string]any
	for _, a := range list {
		if a.ApprovalID == held.ApprovalID {
			shown, _ = a.Context["tool_call"].(map[string]any)
		}
	}
	if shown["name"] != "ask" || shown["target"] != "typryx" || shown["arguments_truncated"] != true {
		t.Fatalf("the approval shows %#v, want the tool, the target and that its arguments were not sent", shown)
	}

	// Granted, the same call goes through once.
	token := h.grant(t, held.ApprovalID)
	if got := h.decideRaw(t, brokerBodyOverTheCap(token)); got.Decision != pdp.Allow {
		t.Fatalf("the granted call is %s (%s), want allow", got.Decision, got.Reason)
	}
	if got := h.decideRaw(t, brokerBodyOverTheCap(token)); got.Decision != pdp.Hold || got.Reason != pdp.ReasonApprovalSpent {
		t.Fatalf("the second presentation is %s (%s), want the spent-token hold", got.Decision, got.Reason)
	}
}

// A hold on an absent signal is recorded with the tool call it was about, and
// replay puts that call back: the hold reproduces from the record, and a
// candidate policy that drops when_absent turns it into the allow it used to be.
func TestAReplayReproducesAnAbsentSignalHold(t *testing.T) {
	h := newSigHarness(t, false, loadLabPolicy(t, labPolicy+"  when_absent: hold\n")...)
	if got := h.decideRaw(t, brokerBodyOverTheCap("")); got.Decision != pdp.Hold {
		t.Fatalf("setup: %s (%s)", got.Decision, got.Reason)
	}
	events := h.read(t)
	report := replay.Run(events, h.arch, nil)
	if report.Total != 1 || report.Reproduced != 1 || report.Diverged != 0 || report.Unreadable != 0 {
		t.Fatalf("the absent-signal hold did not reproduce:\n%s", replay.Format(report, "events", ""))
	}
	without, err := policy.Compile(loadLabPolicy(t, labPolicy))
	if err != nil {
		t.Fatal(err)
	}
	cf := replay.Run(events, h.arch, without)
	if cf.Changed != 1 || cf.Rows[0].Candidate.Decision != pdp.Allow {
		t.Fatalf("a candidate without when_absent did not turn the recorded hold into an allow:\n%s", replay.Format(cf, "events", "without"))
	}
}

// The policy API reads when_absent like a policy file: hold is stored and holds,
// deny is a 400 that stores nothing.
func TestWhenAbsentOverThePolicyAPI(t *testing.T) {
	srv := newTestServer(t)
	const path = "/v1/policies/lab-risk"
	rule := func(v string) string {
		return `{"name":"lab-risk","target":"agent://lab.example/agents/*","hold_if_signal":{"name":"action.risk_class","values":["destructive"],"min_probability":0.5,"when_absent":"` + v + `"}}`
	}
	rec := doRaw(t, srv.Handler(), http.MethodPut, path, adminKey, rule("deny"))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "a signal can only hold") {
		t.Fatalf("PUT with when_absent deny: %d %s, want a 400 saying a signal can only hold", rec.Code, rec.Body.String())
	}
	if got := doRequest(t, srv.Handler(), http.MethodGet, path, adminKey, nil).Code; got != http.StatusNotFound {
		t.Fatalf("GET after the refused PUT = %d, want 404", got)
	}
	if rec := doRaw(t, srv.Handler(), http.MethodPut, path, adminKey, rule("hold")); rec.Code != http.StatusOK {
		t.Fatalf("PUT with when_absent hold: %d %s", rec.Code, rec.Body.String())
	}
	got := decodeBody[decideResponseDTO](t, doRaw(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, brokerBodyOverTheCap("")))
	if got.Decision != pdp.Hold {
		t.Fatalf("after the PUT the padded call is %s (%s), want hold", got.Decision, got.Reason)
	}
}

// A named limit, pinned so it cannot change unseen. A call whose arguments were
// not sent has none in its digest, so every padded call to the same tool and
// target in one run is, on the wire, the same call: the agent's arguments
// differ and the broker sends neither. A person who approves one approves it
// without seeing what it does, and the token fits the next padded call too.
// Single-use, the default, lets exactly one of them through; with single-use
// off the token lets every one through for its lifetime.
func TestAnApprovalOfOnePaddedCallCoversTheNextPaddedCallToTheSameTool(t *testing.T) {
	first := pdp.ToolCall{Name: "ask", Target: "typryx", ArgumentsTruncated: true}
	second := first
	if first.Digest() != second.Digest() {
		t.Fatal("two padded calls to one tool and target have different digests: the limit this test pins is gone, update the docs")
	}
	whole := pdp.ToolCall{Name: "ask", Target: "typryx", Arguments: json.RawMessage(`{"q":"a"}`)}
	if whole.Digest() == first.Digest() {
		t.Fatal("control: a call with its arguments has the padded call's digest")
	}

	for _, c := range []struct {
		singleUse  bool
		wantSecond string
	}{
		{singleUse: false, wantSecond: pdp.Allow},
		{singleUse: true, wantSecond: pdp.Hold},
	} {
		h := newSigHarness(t, c.singleUse, loadLabPolicy(t, labPolicy+"  when_absent: hold\n")...)
		held := h.decideRaw(t, brokerBodyOverTheCap(""))
		if held.Decision != pdp.Hold {
			t.Fatalf("setup: %s (%s)", held.Decision, held.Reason)
		}
		token := h.grant(t, held.ApprovalID)
		if got := h.decideRaw(t, brokerBodyOverTheCap(token)); got.Decision != pdp.Allow {
			t.Fatalf("single-use %v: the approved padded call is %s (%s), want allow", c.singleUse, got.Decision, got.Reason)
		}
		got := h.decideRaw(t, brokerBodyOverTheCap(token))
		if got.Decision != c.wantSecond {
			t.Fatalf("single-use %v: the next padded call with the same token is %s (%s), want %s", c.singleUse, got.Decision, got.Reason, c.wantSecond)
		}
		if c.singleUse && got.Reason != pdp.ReasonApprovalSpent {
			t.Fatalf("single-use: the next padded call is held for %q, want the spent-token reason", got.Reason)
		}
	}
}
