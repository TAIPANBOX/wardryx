package pdp

import (
	"strings"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// Block A4: rules that read a chain the enforcement point already verified.
//
// The PDP does NOT verify the proof and must not: verification is a library
// call at the enforcement point (agent-stack-go/delegation), because wardryx
// decides at a 3.2 ms p50 and audits every decision, and a signature check per
// decision taxes the whole estate. What arrives here is a FACT somebody else
// established, exactly like `AttestationMethod` already is.

func decide(t *testing.T, policies []policy.Policy, req DecideRequest) DecideResponse {
	t.Helper()
	set, err := policy.Compile(policies)
	if err != nil {
		t.Fatalf("compiling policy: %v", err)
	}
	return New(set, []byte("test-secret")).Decide(req)
}

func proven() []policy.Policy {
	return []policy.Policy{{
		Name:                "delegation-must-be-proved",
		Target:              "agent://acme/*",
		DenyIfChainUnproven: true,
	}}
}

func TestAChainNobodyProvedIsRefusedWhenThePolicySaysSo(t *testing.T) {
	// The rule this block exists for. Today a chain is a list of names an
	// agent typed into a header: wardryx validates its SHAPE and believes its
	// contents. With vouchryx issuing proofs and the enforcement points
	// verifying them, a policy can finally require the difference.
	got := decide(t, proven(), DecideRequest{
		AgentID:    "agent://acme/support/bot",
		OnBehalfOf: []string{"user://acme/alice", "agent://acme/support/bot"},
	})
	if got.Decision != Deny {
		t.Fatalf("an unproven chain was allowed under deny_if_chain_unproven: %+v", got)
	}
	if !strings.Contains(got.Reason, "unproven") {
		t.Fatalf("the reason does not say what was wrong: %q", got.Reason)
	}
}

func TestTheSameChainProvedIsAllowed(t *testing.T) {
	// The other half. A rule that denied both would be a rule nobody can
	// satisfy, which an operator removes rather than fixes.
	got := decide(t, proven(), DecideRequest{
		AgentID:     "agent://acme/support/bot",
		OnBehalfOf:  []string{"user://acme/alice", "agent://acme/support/bot"},
		ChainProven: true,
	})
	if got.Decision != Allow {
		t.Fatalf("a proven chain was refused: %+v", got)
	}
}

func TestAnAgentWithNoChainIsNotThisRulesBusiness(t *testing.T) {
	// `deny_if_chain_unproven` is about a chain that IS present. An agent
	// acting autonomously is not delegating and has nothing to prove, and a
	// rule that denied it would be answering a question nobody asked. The
	// rule for "must be acting for somebody" is require_root_principal, and
	// the two are separate precisely so an operator can say either.
	got := decide(t, proven(), DecideRequest{AgentID: "agent://acme/support/bot"})
	if got.Decision != Allow {
		t.Fatalf("an autonomous agent was denied by a chain rule: %+v", got)
	}
}

func TestAPolicyMayCapTheChainShorterThanTheSpecDoes(t *testing.T) {
	// SPEC 5.1 caps every chain at 32. A policy may want two: a support bot
	// three delegations deep is a fan-out somebody should have to justify.
	capped := []policy.Policy{{
		Name:          "two-hops-is-plenty",
		Target:        "agent://acme/*",
		MaxChainDepth: 2,
	}}
	deep := DecideRequest{
		AgentID: "agent://acme/support/bot",
		OnBehalfOf: []string{
			"user://acme/alice", "agent://acme/orchestrator", "agent://acme/support/bot",
		},
	}
	got := decide(t, capped, deep)
	if got.Decision != Deny {
		t.Fatalf("a chain of 3 passed max_chain_depth 2: %+v", got)
	}
	if !strings.Contains(got.Reason, "max_chain_depth") {
		t.Fatalf("the reason does not name the rule: %q", got.Reason)
	}

	shallow := deep
	shallow.OnBehalfOf = []string{"user://acme/alice", "agent://acme/support/bot"}
	if got := decide(t, capped, shallow); got.Decision != Allow {
		t.Fatalf("a chain of exactly max_chain_depth was denied: %+v", got)
	}
}

func TestTheRootMustBeWhoThePolicySaysItIs(t *testing.T) {
	// The rule for "this agent only ever acts for a person". Matched as a
	// glob, like Target, so an operator writes one line instead of a list of
	// every employee.
	onlyPeople := []policy.Policy{{
		Name:                 "only-for-people",
		Target:               "agent://acme/*",
		RequireRootPrincipal: "user://acme/*",
	}}
	forPerson := DecideRequest{
		AgentID:    "agent://acme/support/bot",
		OnBehalfOf: []string{"user://acme/alice", "agent://acme/support/bot"},
	}
	if got := decide(t, onlyPeople, forPerson); got.Decision != Allow {
		t.Fatalf("acting for a person was denied: %+v", got)
	}

	forAgent := forPerson
	forAgent.OnBehalfOf = []string{"agent://acme/cron", "agent://acme/support/bot"}
	got := decide(t, onlyPeople, forAgent)
	if got.Decision != Deny {
		t.Fatalf("a chain rooted at an agent passed a user:// requirement: %+v", got)
	}
	if !strings.Contains(got.Reason, "require_root_principal") {
		t.Fatalf("the reason does not name the rule: %q", got.Reason)
	}
}

func TestRequireRootPrincipalDeniesAnAgentActingForNobody(t *testing.T) {
	// The half that makes the pair complete, and the opposite reading from
	// `deny_if_chain_unproven`: an empty chain has no root, so a policy that
	// requires a root is a policy that requires a delegation. Without this an
	// agent drops its chain and satisfies the rule by having nothing to check.
	onlyPeople := []policy.Policy{{
		Name:                 "only-for-people",
		Target:               "agent://acme/*",
		RequireRootPrincipal: "user://acme/*",
	}}
	got := decide(t, onlyPeople, DecideRequest{AgentID: "agent://acme/support/bot"})
	if got.Decision != Deny {
		t.Fatalf("an agent with no chain satisfied require_root_principal: %+v", got)
	}
}

func TestAChainDecisionIsNeverCached(t *testing.T) {
	// `OnBehalfOf` is a per-request value like Steps and Domains, not a stable
	// per-agent fact. A cached chain deny would be reused for a later call
	// presenting a different chain, and a cached chain ALLOW is worse: it
	// would let an unproven chain through on the strength of a proven one.
	got := decide(t, proven(), DecideRequest{
		AgentID:     "agent://acme/support/bot",
		OnBehalfOf:  []string{"user://acme/alice", "agent://acme/support/bot"},
		ChainProven: true,
	})
	if got.Cacheable {
		t.Fatal("a decision that read the chain was marked cacheable")
	}
}

func TestAnInvalidChainIsStillRefusedBeforeAnyOfThisRuns(t *testing.T) {
	// The existing defence, held so these rules cannot be read as replacing
	// it: a cyclic or overlong chain is refused independent of any policy,
	// and a proof does not make a malformed chain well-formed.
	got := decide(t, proven(), DecideRequest{
		AgentID:     "agent://acme/support/bot",
		OnBehalfOf:  []string{"agent://acme/a", "agent://acme/a"},
		ChainProven: true,
	})
	if got.Decision != Deny {
		t.Fatalf("a cyclic chain passed because it was proven: %+v", got)
	}
	if !strings.Contains(got.Reason, "invalid on_behalf_of") {
		t.Fatalf("the wrong rule fired: %q", got.Reason)
	}
}
