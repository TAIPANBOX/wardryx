package pdp

import (
	"errors"
	"strings"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/approval"
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

// TestSubCentApprovalTokenCostExceededReasonIsNotMisleading is the third
// case in the same family, on the operator-visible /v1/decide Reason rather
// than internal/approval's error text directly: a presented approval_token
// whose verification fails with ErrTokenCostExceeded has its error embedded
// via "%v" into resp.Reason (see the deny branch of Decide, "; %s (%v)"
// after ReasonApprovalRefused). Before internal/approval's formatUSD fix, a
// sub-cent MaxCostUSD and a sub-cent presented cost both printed as "$0.00"
// in that embedded text too, so the reason an operator actually reads off
// /v1/decide said "presented approval_token is invalid (approval: ...
// approved ceiling $0.00 exceeded by requested $0.00)", indistinguishable
// from an actual zero ceiling.
func TestSubCentApprovalTokenCostExceededReasonIsNotMisleading(t *testing.T) {
	set, err := policy.Compile([]policy.Policy{
		{Name: "penny-gate", Target: "agent://x/*", RequireHumanAboveUSD: usd(0.001)},
	})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	engine := New(set, []byte(testSecret))

	token, _, err := approval.MintApprovalToken([]byte(testSecret), "agent://x/bot", "run-1", nil, 0.0005, approval.DefaultTTL)
	if err != nil {
		t.Fatalf("MintApprovalToken: %v", err)
	}

	resp := engine.Decide(DecideRequest{
		AgentID:       "agent://x/bot",
		RunID:         "run-1",
		EstCostUSD:    0.0016,
		ApprovalToken: token,
	})
	if resp.Decision != Deny {
		t.Fatalf("Decision = %q (reason: %s), want %q: a token approved for $0.0005 must not authorize $0.0016", resp.Decision, resp.Reason, Deny)
	}
	if strings.Contains(resp.Reason, "$0.00 exceeded by requested $0.00") {
		t.Errorf("Reason = %q, ceiling and requested cost both rounded away to $0.00, not distinguishable from an actual zero ceiling", resp.Reason)
	}
	if !strings.Contains(resp.Reason, "$0.0005") {
		t.Errorf("Reason = %q, want it to name the token's exact ceiling $0.0005", resp.Reason)
	}
	if !strings.Contains(resp.Reason, "$0.0016") {
		t.Errorf("Reason = %q, want it to name the exact requested cost $0.0016", resp.Reason)
	}
}

// TestTheTwoFormatUSDCopiesAgree holds internal/approval's copy of formatUSD
// to this package's: it exists because importing internal/pdp from
// internal/approval would cycle (invariant 22), and two copies of one money
// formatter drift silently. It reads approval's copy through the one place it
// is used, the cost-exceeded error, over a sweep of whole, cent and sub-cent
// amounts.
func TestTheTwoFormatUSDCopiesAgree(t *testing.T) {
	secret := []byte("test-secret")
	for _, ceiling := range []float64{0.0005, 0.001, 0.0016, 0.01, 0.05, 0.1, 0.125, 1, 1.5, 12.34, 100, 0.000001} {
		token, _, err := approval.MintApprovalToken(secret, "agent://x/bot", "run-1", []string{"tool"}, ceiling, approval.DefaultTTL)
		if err != nil {
			t.Fatalf("MintApprovalToken(%v): %v", ceiling, err)
		}
		requested := ceiling*3 + 0.0007
		err = approval.VerifyApprovalToken(secret, token, "agent://x/bot", "run-1", []string{"tool"}, requested)
		if !errors.Is(err, approval.ErrTokenCostExceeded) {
			t.Fatalf("ceiling %v: got %v, want ErrTokenCostExceeded", ceiling, err)
		}
		want := "approved ceiling " + formatUSD(ceiling) + " exceeded by requested " + formatUSD(requested)
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ceiling %v: approval says %q, this package formats %q", ceiling, err.Error(), want)
		}
	}
}
