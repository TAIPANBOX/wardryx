package pdp

import (
	"strings"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// The engine's own reading of require_identity_source, without the HTTP layer:
// a source the list names is admitted, any other source is denied, an absent or
// unknown source is none, and a decision that read the rule is not cacheable.
func TestRequireIdentitySourceDecidesOnTheSourceAlone(t *testing.T) {
	set, err := policy.Compile([]policy.Policy{{
		Name:                  "need-token",
		Target:                "agent://acme.example/support/*",
		RequireIdentitySource: []string{policy.IdentitySourceAgentToken},
	}})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	e := New(set, []byte(testSecret))
	base := DecideRequest{AgentID: "agent://acme.example/support/bot1", RunID: "r1"}

	cases := []struct {
		source string
		want   string
	}{
		{policy.IdentitySourceAgentToken, Allow},
		{policy.IdentitySourceClientKey, Deny},
		{policy.IdentitySourceNone, Deny},
		{"", Deny},
		{"AGENT-TOKEN", Deny},
	}
	for _, c := range cases {
		req := base
		req.IdentitySource = c.source
		got := e.Decide(req)
		if got.Decision != c.want {
			t.Fatalf("source %q: got %s (%s), want %s", c.source, got.Decision, got.Reason, c.want)
		}
		if c.want == Deny && !strings.Contains(got.Reason, "identity source") {
			t.Fatalf("source %q: the deny does not name the identity source: %s", c.source, got.Reason)
		}
		if got.Cacheable {
			t.Fatalf("source %q: a decision that read the source is marked cacheable", c.source)
		}
	}
}

// A policy that does not ask for a source decides every source alike, and its
// decisions stay cacheable as they always were.
func TestAPolicyWithoutTheSourceRuleIgnoresTheSource(t *testing.T) {
	set, err := policy.Compile([]policy.Policy{{Name: "plain", Target: "agent://acme.example/support/*"}})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	e := New(set, []byte(testSecret))
	for _, source := range []string{"", policy.IdentitySourceClientKey, policy.IdentitySourceAgentToken} {
		got := e.Decide(DecideRequest{AgentID: "agent://acme.example/support/bot1", RunID: "r1", IdentitySource: source})
		if got.Decision != Allow {
			t.Fatalf("source %q under a policy without the rule: got %s (%s), want allow", source, got.Decision, got.Reason)
		}
		if !got.Cacheable {
			t.Fatalf("source %q: a decision that could not read the source became uncacheable", source)
		}
	}
}
