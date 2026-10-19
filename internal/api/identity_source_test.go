package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// identity_source is how the enforcement point knew the agent. It is sent by the
// enforcement point and read by a policy's require_identity_source; wardryx
// verifies nothing and believes what it is told (CLAUDE.md invariant 13). These
// tests hold what the request, the decision, its event and the policy do with it.

// needSource is one policy for bot1's support agents that accepts only a source
// the enforcement point verified at its own door.
const needSource = `{"name":"need-token","target":"agent://acme.example/support/*","require_identity_source":["agent-token"]}`

// identitySourcePolicies loads policy documents the way a deployment does, so the
// rule under test is read by the same loader, not by a struct literal.
func identitySourcePolicies(t *testing.T, docs ...string) []policy.Policy {
	t.Helper()
	var out []policy.Policy
	for i, doc := range docs {
		path := filepath.Join(t.TempDir(), "policy"+string(rune('a'+i))+".json")
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		set, err := policy.Load(path)
		if err != nil {
			t.Fatalf("policy.Load %s: %v", doc, err)
		}
		out = append(out, set.Policies()...)
	}
	return out
}

// recordedSource reads the identity_source a record holds. A record from before
// the field existed holds none, which reads as none.
func recordedSource(v any) string {
	s, _ := v.(string)
	return policy.IdentitySourceOf(s)
}

func decideWithSource(t *testing.T, h *orgHarness, key, source string) decideResponseDTO {
	t.Helper()
	body := `{"agent_id":"` + bot1 + `","run_id":"r1","tool_names":["lookup"]`
	if source != "" {
		body += `,"identity_source":"` + source + `"`
	}
	body += `}`
	return decodeBody[decideResponseDTO](t, h.raw(t, http.MethodPost, "/v1/decide", key, body))
}

func TestARequireIdentitySourceAdmitsARequestThatCameWithTheListedSource(t *testing.T) {
	h := newOrgHarness(t, "gw:acme:pep", false, identitySourcePolicies(t, needSource)...)
	got := decideWithSource(t, h, "gw", "agent-token")
	if got.Decision != pdp.Allow {
		t.Fatalf("a request with the listed source got %s (%s), want allow", got.Decision, got.Reason)
	}
	allows := h.eventsOfType(t, "policy_allow")
	if len(allows) != 1 || allows[0]["identity_source"] != "agent-token" {
		t.Fatalf("the allow does not record its source: %v", allows)
	}
}

func TestARequireIdentitySourceDeniesARequestThatSentNoSource(t *testing.T) {
	h := newOrgHarness(t, "gw:acme:pep", false, identitySourcePolicies(t, needSource)...)
	got := decideWithSource(t, h, "gw", "")
	if got.Decision != pdp.Deny || !strings.Contains(got.Reason, "identity source") {
		t.Fatalf("a request with no source got %s (%s), want a deny that names the identity source", got.Decision, got.Reason)
	}
	denies := h.eventsOfType(t, "policy_deny")
	if len(denies) != 1 || denies[0]["identity_source"] != "none" {
		t.Fatalf("an absent source is recorded as %v, want none", denies)
	}
}

func TestARequireIdentitySourceDeniesTheWeakerClientKey(t *testing.T) {
	h := newOrgHarness(t, "gw:acme:pep", false, identitySourcePolicies(t, needSource)...)
	got := decideWithSource(t, h, "gw", "client-key")
	if got.Decision != pdp.Deny {
		t.Fatalf("a client-key request under a policy that lists only agent-token got %s (%s), want deny", got.Decision, got.Reason)
	}
}

func TestAnOldEnforcementPointThatSendsNoSourceIsDecidedAsBefore(t *testing.T) {
	h := newOrgHarness(t, "gw:acme:pep", false, identitySourcePolicies(t, `{"name":"plain","target":"agent://acme.example/support/*"}`)...)
	got := decideWithSource(t, h, "gw", "")
	if got.Decision != pdp.Allow {
		t.Fatalf("an old enforcement point with no policy asking for a source got %s (%s), want allow", got.Decision, got.Reason)
	}
	allows := h.eventsOfType(t, "policy_allow")
	if len(allows) != 1 || allows[0]["identity_source"] != "none" {
		t.Fatalf("the allow of a request that sent no source does not record none: %v", allows)
	}
}

func TestAnUnknownIdentitySourceCountsAsNone(t *testing.T) {
	h := newOrgHarness(t, "gw:acme:pep", false, identitySourcePolicies(t, needSource)...)
	got := decideWithSource(t, h, "gw", "AGENT-TOKEN")
	if got.Decision != pdp.Deny {
		t.Fatalf("a source in the wrong case got %s (%s), want deny: only the exact value is a source", got.Decision, got.Reason)
	}
	denies := h.eventsOfType(t, "policy_deny")
	if len(denies) != 1 || denies[0]["identity_source"] != "none" {
		t.Fatalf("an unknown source is recorded as %v, want none", denies)
	}
}

func TestEveryMatchedPolicyMustListTheSource(t *testing.T) {
	both := `{"name":"either","target":"agent://acme.example/support/*","require_identity_source":["agent-token","client-key"]}`
	tokenOnly := `{"name":"token-only","target":"agent://acme.example/support/*","require_identity_source":["agent-token"]}`
	h := newOrgHarness(t, "gw:acme:pep", false, identitySourcePolicies(t, both, tokenOnly)...)
	got := decideWithSource(t, h, "gw", "client-key")
	if got.Decision != pdp.Deny || !strings.Contains(got.Reason, "token-only") {
		t.Fatalf("a client-key request matched by two lists got %s (%s), want the deny of token-only: two lists intersect", got.Decision, got.Reason)
	}
	if got := decideWithSource(t, h, "gw", "agent-token"); got.Decision != pdp.Allow {
		t.Fatalf("an agent-token request both lists accept got %s (%s), want allow", got.Decision, got.Reason)
	}
}

func TestAPolicyThatReadsTheSourceIsNeverCacheable(t *testing.T) {
	h := newOrgHarness(t, "gw:acme:pep", false, identitySourcePolicies(t, needSource)...)
	got := decideWithSource(t, h, "gw", "agent-token")
	if got.Decision != pdp.Allow {
		t.Fatalf("setup: got %s (%s), want allow", got.Decision, got.Reason)
	}
	if got.Cacheable {
		t.Fatal("an allow that depended on the source is cacheable: a later call from another source would be served it")
	}
}

func TestTheSourceRuleComesAfterDenyIfUnattested(t *testing.T) {
	doc := `{"name":"attested-and-token","target":"agent://acme.example/support/*","deny_if_unattested":true,"require_identity_source":["agent-token"]}`
	h := newOrgHarness(t, "gw:acme:pep", false, identitySourcePolicies(t, doc)...)
	body := `{"agent_id":"` + bot1 + `","run_id":"r1","attestation_method":"none","identity_source":"client-key"}`
	got := decodeBody[decideResponseDTO](t, h.raw(t, http.MethodPost, "/v1/decide", "gw", body))
	if got.Decision != pdp.Deny || !strings.Contains(got.Reason, "live attestation") {
		t.Fatalf("a request both unattested and from a weaker source got %s (%s), want the earlier unattested reason", got.Decision, got.Reason)
	}
}

// The decision's event is what replay reads back. A recorded allow under the
// listed source must replay to that allow against the policy that was in force,
// which only holds if the source was recorded and is fed back.
func TestARecordedIdentitySourceReplaysToTheSameVerdict(t *testing.T) {
	pols := identitySourcePolicies(t, needSource)
	h := newOrgHarness(t, "gw:acme:pep", false, pols...)
	body := `{"agent_id":"` + bot1 + `","run_id":"r1","tool_names":["lookup"],"domains":["example.com"],"identity_source":"agent-token"}`
	if got := decodeBody[decideResponseDTO](t, h.raw(t, http.MethodPost, "/v1/decide", "gw", body)); got.Decision != pdp.Allow {
		t.Fatalf("setup: got %s (%s), want allow", got.Decision, got.Reason)
	}
	events, err := event.ReadFile(h.events)
	if err != nil {
		t.Fatalf("event.ReadFile: %v", err)
	}
	var recorded *event.Event
	for i, e := range events {
		if e.Type == "policy_allow" {
			recorded = &events[i]
		}
	}
	if recorded == nil {
		t.Fatal("no policy_allow was recorded")
	}
	set, err := policy.Compile(pols)
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	replayed := replayRequest(t, *recorded)
	if got := pdp.New(set, []byte(testHMAC)).Decide(replayed); got.Decision != pdp.Allow {
		t.Fatalf("replaying a recorded allow under the listed source gave %s (%s): the record does not carry the source", got.Decision, got.Reason)
	}
}
