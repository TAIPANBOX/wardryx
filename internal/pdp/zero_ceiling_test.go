package pdp

import (
	"strings"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// Measured 2026-09-27: a PUT /v1/policies/n4-deny-beta with
// {"deny_above_usd":0} answered 200, the stored policy echoed back without a
// deny_above_usd field, and the next call through the enforcement point was
// allowed. deny_above_usd's zero value was defined to mean "no hard
// ceiling" (see internal/policy/policy.go's field comment before this fix),
// which made an explicit zero indistinguishable from the field never having
// been set at all: a policy that says "deny everything above zero" silently
// became "deny nothing".
//
// The fix (@decided 2026-09-27, see CLAUDE.md) makes zero a real ceiling and
// threshold once the operator writes it explicitly, distinguished from an
// unset field by internal/policy.Policy switching both fields to *float64.
// These tests are written and were first run against the pre-fix code (a
// plain float64, no way to represent "explicitly zero"); on that code every
// one of the "denies/holds any priced call" assertions below failed
// (allowed instead), which is the exact shape of the measured defect.

// usd returns a pointer to v, for constructing a Policy with an explicit
// RequireHumanAboveUSD or DenyAboveUSD (including an explicit zero, which a
// bare float64 field could not represent as distinct from "unset").
func usd(v float64) *float64 { return &v }

// zeroUSD is usd(0), named so a reader sees "an explicit zero" rather than
// wondering whether 0 is a typo.
func zeroUSD() *float64 { return usd(0) }

// TestDecideZeroDenyAboveUSDCeilingDeniesAnyPricedCall covers the measured
// PUT case at the decision layer: a policy that explicitly sets
// deny_above_usd to zero must deny any action whose cost is more than zero,
// not fall through as if no ceiling were configured.
func TestDecideZeroDenyAboveUSDCeilingDeniesAnyPricedCall(t *testing.T) {
	set, err := policy.Compile([]policy.Policy{
		{Name: "n4-deny-beta", Target: "agent://taipanbox.dev/hermes/beta", DenyAboveUSD: zeroUSD()},
	})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	engine := New(set, nil)

	t.Run("any positive cost denies", func(t *testing.T) {
		resp := engine.Decide(DecideRequest{AgentID: "agent://taipanbox.dev/hermes/beta", EstCostUSD: 0.01})
		if resp.Decision != Deny {
			t.Fatalf("Decision = %q (reason: %s), want %q: an explicit deny_above_usd of zero must deny any priced call", resp.Decision, resp.Reason, Deny)
		}
		if !strings.Contains(resp.Reason, "deny_above_usd") {
			t.Errorf("Reason = %q, want it to name deny_above_usd", resp.Reason)
		}
	})

	t.Run("exactly zero cost is not denied by this rule (boundary, not the bug)", func(t *testing.T) {
		resp := engine.Decide(DecideRequest{AgentID: "agent://taipanbox.dev/hermes/beta", EstCostUSD: 0})
		if resp.Decision != Allow {
			t.Fatalf("Decision = %q (reason: %s), want %q: cost 0 does not exceed a ceiling of 0", resp.Decision, resp.Reason, Allow)
		}
	})
}

// TestDecideZeroRequireHumanAboveUSDThresholdHoldsAnyPricedCall is
// deny_above_usd's twin for the approvable gate: an explicit
// require_human_above_usd of zero must hold (or allow via a valid token) any
// priced call, not fall through as unconfigured.
func TestDecideZeroRequireHumanAboveUSDThresholdHoldsAnyPricedCall(t *testing.T) {
	set, err := policy.Compile([]policy.Policy{
		{Name: "n4-hold-beta", Target: "agent://taipanbox.dev/hermes/beta", RequireHumanAboveUSD: zeroUSD()},
	})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	engine := New(set, nil)

	t.Run("any positive cost holds", func(t *testing.T) {
		resp := engine.Decide(DecideRequest{AgentID: "agent://taipanbox.dev/hermes/beta", EstCostUSD: 0.01})
		if resp.Decision != Hold {
			t.Fatalf("Decision = %q (reason: %s), want %q: an explicit require_human_above_usd of zero must hold any priced call", resp.Decision, resp.Reason, Hold)
		}
		if !resp.ApprovalTokenRequired {
			t.Error("ApprovalTokenRequired = false, want true")
		}
	})

	t.Run("exactly zero cost is not held by this rule (boundary, not the bug)", func(t *testing.T) {
		resp := engine.Decide(DecideRequest{AgentID: "agent://taipanbox.dev/hermes/beta", EstCostUSD: 0})
		if resp.Decision != Allow {
			t.Fatalf("Decision = %q (reason: %s), want %q: cost 0 does not exceed a threshold of 0", resp.Decision, resp.Reason, Allow)
		}
	})
}

// TestSubCentDenyAboveUSDReasonIsNotMisleading covers the second, smaller
// defect measured 2026-09-27: a deny_above_usd of $0.000001 printed its
// refusal reason as "$0.00", which reads as "the ceiling is zero" (a
// different, and false, statement from "the ceiling is a millionth of a
// cent").
func TestSubCentDenyAboveUSDReasonIsNotMisleading(t *testing.T) {
	set, err := policy.Compile([]policy.Policy{
		{Name: "freeze", Target: "agent://x/*", DenyAboveUSD: usd(0.000001)},
	})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	engine := New(set, nil)
	resp := engine.Decide(DecideRequest{AgentID: "agent://x/bot", EstCostUSD: 0.000033})
	if resp.Decision != Deny {
		t.Fatalf("Decision = %q (reason: %s), want %q", resp.Decision, resp.Reason, Deny)
	}
	if strings.Contains(resp.Reason, "$0.00 ") || strings.HasSuffix(resp.Reason, "$0.00") {
		t.Errorf("Reason = %q, a sub-cent ceiling must not print as $0.00", resp.Reason)
	}
	if !strings.Contains(resp.Reason, "0.000001") {
		t.Errorf("Reason = %q, want it to print the ceiling as 0.000001, not rounded away", resp.Reason)
	}
}

// TestSubCentRequireHumanAboveUSDReasonIsNotMisleading covers the measured
// "$0.01" case: a hold threshold of $0.005 must not print as if it were
// $0.01, a different number one cent higher.
func TestSubCentRequireHumanAboveUSDReasonIsNotMisleading(t *testing.T) {
	set, err := policy.Compile([]policy.Policy{
		{Name: "penny-gate", Target: "agent://x/*", RequireHumanAboveUSD: usd(0.005)},
	})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	engine := New(set, nil)
	resp := engine.Decide(DecideRequest{AgentID: "agent://x/bot", EstCostUSD: 0.006})
	if resp.Decision != Hold {
		t.Fatalf("Decision = %q (reason: %s), want %q", resp.Decision, resp.Reason, Hold)
	}
	if strings.Contains(resp.Reason, "$0.01") {
		t.Errorf("Reason = %q, a $0.005 threshold must not print as $0.01", resp.Reason)
	}
	if !strings.Contains(resp.Reason, "0.005") {
		t.Errorf("Reason = %q, want it to print the threshold as 0.005", resp.Reason)
	}
}
