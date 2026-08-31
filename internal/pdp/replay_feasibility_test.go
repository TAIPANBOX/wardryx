package pdp

import (
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// Phase-0 feasibility probe for policy replay (2026-08-31).
//
// Replay means: take a decision that already happened, and ask what a
// different policy version would have answered to the SAME question. This
// probe answers the three questions that decide whether that is worth
// building, and it answers them by running the real Decide, not by reading
// struct fields.
//
//  A. Is replay meaningful at all? Same request, two policy versions, two
//     verdicts, two distinct PolicyVersions.
//  B. Can a decision be replayed from what Wardryx records TODAY? No, and the
//     failure is silent: internal/api's emit writes only {reason, tool_names}
//     plus the identity triple, and a request rebuilt from that ALLOWS what
//     really was DENIED.
//  C. Would recording the full decision input be sufficient? Yes: a request
//     rebuilt from all eleven DecideRequest fields reproduces the original
//     verdict and reason exactly.
//
// This is a characterization probe, not a regression test: it asserts what is
// true now, including the defect in B. When B is fixed (Wardryx starts
// emitting the full input) the B assertion goes red on purpose, and that is
// the signal that this probe has done its job and should be replaced.

// probeAgent and probeRun stand in for one recorded decision.
const (
	probeAgent = "agent://acme.example/finance/invoice-bot"
	probeRun   = "run-8842"
)

// liveRequest is the question that was really asked: a tool call reaching a
// destination outside the allow-list, three steps into the run, at $12.40.
func liveRequest() DecideRequest {
	return DecideRequest{
		AgentID:           probeAgent,
		RunID:             probeRun,
		ToolNames:         []string{"http_get"},
		Domains:           []string{"payouts.evil.example"},
		Steps:             3,
		Model:             "claude-sonnet-5",
		EstCostUSD:        12.40,
		AttestationMethod: "tpm",
		ChainProven:       false,
	}
}

// policyV1 is the set in force when the decision was taken.
func policyV1(t *testing.T) *policy.Set {
	t.Helper()
	return compile(t, []string{"reports.acme.example"})
}

// policyV2 is the candidate change an operator is considering: the blocked
// destination added to the allow-list.
func policyV2(t *testing.T) *policy.Set {
	t.Helper()
	return compile(t, []string{"reports.acme.example", "payouts.evil.example"})
}

func compile(t *testing.T, allowDomains []string) *policy.Set {
	t.Helper()
	set, err := policy.Compile([]policy.Policy{{
		Name:                 "finance-egress",
		Target:               "agent://acme.example/finance/*",
		AllowDomains:         allowDomains,
		MaxSteps:             10,
		RequireHumanAboveUSD: 500,
	}})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	return set
}

// TestReplayIsMeaningful is question A: the same recorded question, put to two
// policy versions, comes back with two different answers. Without this, replay
// would be an expensive way to reprint what the record already says.
func TestReplayIsMeaningful(t *testing.T) {
	req := liveRequest()

	v1 := New(policyV1(t), []byte(testSecret))
	v2 := New(policyV2(t), []byte(testSecret))

	before := v1.Decide(req)
	after := v2.Decide(req)

	t.Logf("policy %s -> %s: %s", before.PolicyVersion, before.Decision, before.Reason)
	t.Logf("policy %s -> %s: %s", after.PolicyVersion, after.Decision, after.Reason)

	if before.Decision != Deny {
		t.Fatalf("under v1 want %s, got %s (%s)", Deny, before.Decision, before.Reason)
	}
	if after.Decision != Allow {
		t.Fatalf("under v2 want %s, got %s (%s)", Allow, after.Decision, after.Reason)
	}
	if before.PolicyVersion == after.PolicyVersion {
		t.Fatalf("two different policy sets share PolicyVersion %s: a replay could not name which set it ran", before.PolicyVersion)
	}
}

// rebuiltFromTodaysEvent is the best DecideRequest recoverable from what
// internal/api emits for a policy_deny today:
//
//	s.emit(evPolicyDeny, SeverityHigh, req.AgentID, req.RunID, req.OnBehalfOf,
//	    map[string]any{"reason": resp.Reason, "tool_names": req.ToolNames})
//
// Four of the eleven inputs survive. The rest are not recorded anywhere.
func rebuiltFromTodaysEvent() DecideRequest {
	return DecideRequest{
		AgentID:   probeAgent,
		RunID:     probeRun,
		ToolNames: []string{"http_get"},
		// Domains, Steps, EstCostUSD, Model, AttestationMethod,
		// ChainProven, ApprovalToken: not emitted, so not recoverable.
	}
}

// TestTodaysRecordCannotBeReplayed is question B, and it is the finding that
// decides the work. Replaying a recorded DENIAL against the very policy that
// produced it returns ALLOW, because the field the denial turned on was never
// written down. An operator running this over last month's refusals would be
// told the new policy changes nothing, when in truth the old policy was never
// re-evaluated at all.
func TestTodaysRecordCannotBeReplayed(t *testing.T) {
	engine := New(policyV1(t), []byte(testSecret))

	truth := engine.Decide(liveRequest())
	replayed := engine.Decide(rebuiltFromTodaysEvent())

	t.Logf("what really happened : %s: %s", truth.Decision, truth.Reason)
	t.Logf("replayed from record : %s: %s", replayed.Decision, replayed.Reason)

	if truth.Decision != Deny {
		t.Fatalf("probe setup broken: the live request should deny, got %s", truth.Decision)
	}
	if replayed.Decision == truth.Decision {
		t.Fatalf("the recording gap has closed: a request rebuilt from today's event now reproduces %s. "+
			"Replace this probe with a real replay test.", truth.Decision)
	}
	if replayed.Decision != Allow {
		t.Fatalf("want the silent failure to be %s (worse than a wrong deny), got %s", Allow, replayed.Decision)
	}
}

// rebuiltFromFullEvent is what the same event would yield if Wardryx emitted
// the whole decision input, which is the one-day change phase 1 proposes.
func rebuiltFromFullEvent() DecideRequest {
	return DecideRequest{
		AgentID:           probeAgent,
		RunID:             probeRun,
		ToolNames:         []string{"http_get"},
		Domains:           []string{"payouts.evil.example"},
		Steps:             3,
		Model:             "claude-sonnet-5",
		EstCostUSD:        12.40,
		AttestationMethod: "tpm",
		ChainProven:       false,
	}
}

// TestFullInputReplaysFaithfully is question C: recording the input is not
// merely necessary, it is sufficient. Verdict and reason both come back
// identical, so a replay could be trusted to say "this is what really
// happened" before it says what would have happened instead.
func TestFullInputReplaysFaithfully(t *testing.T) {
	engine := New(policyV1(t), []byte(testSecret))

	truth := engine.Decide(liveRequest())
	replayed := engine.Decide(rebuiltFromFullEvent())

	t.Logf("what really happened : %s: %s", truth.Decision, truth.Reason)
	t.Logf("replayed from record : %s: %s", replayed.Decision, replayed.Reason)

	if replayed.Decision != truth.Decision {
		t.Fatalf("verdict drift: want %s, got %s", truth.Decision, replayed.Decision)
	}
	if replayed.Reason != truth.Reason {
		t.Fatalf("reason drift:\n want %q\n  got %q", truth.Reason, replayed.Reason)
	}
	if replayed.PolicyVersion != truth.PolicyVersion {
		t.Fatalf("policy version drift: want %s, got %s", truth.PolicyVersion, replayed.PolicyVersion)
	}

	// The counterfactual the operator actually wants, now trustworthy.
	candidate := New(policyV2(t), []byte(testSecret)).Decide(rebuiltFromFullEvent())
	t.Logf("under candidate v2   : %s: %s", candidate.Decision, candidate.Reason)
	if candidate.Decision != Allow {
		t.Fatalf("candidate policy should allow, got %s", candidate.Decision)
	}
}
