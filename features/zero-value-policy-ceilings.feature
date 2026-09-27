# Provenance: @claude, 2026-09-27. Written from the defect measured that day:
# PUT /v1/policies/n4-deny-beta with {"deny_above_usd":0} answered 200, the
# stored policy echoed back without a deny_above_usd field at all, and the
# agent's next call through the enforcement point was allowed. A policy
# meaning "deny everything above zero" had silently become "deny nothing".
#
# @decided 2026-09-27: an explicit zero on require_human_above_usd or
# deny_above_usd is now a real threshold or ceiling, distinct from the field
# being left out of the policy altogether, which still means no restriction.
# See CLAUDE.md's numbered invariant for the reasoning; the short version is
# that refusing an explicit zero was rejected, since every existing policy
# file that simply never mentions one of these fields also decodes to the
# same zero value, so "refuse zero" is only expressible once presence is
# tracked, and once it is, there is no reason left to forbid the one value
# operators actually asked for over "no restriction".
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: An explicit zero on a cost field is a real threshold, not "unset"

  Scenario: an explicit deny_above_usd of zero denies any priced call
    Given a policy sets deny_above_usd to exactly 0
    When an agent's action has any estimated cost above zero
    Then the decision is deny, naming deny_above_usd
    # -> internal/pdp:TestDecideZeroDenyAboveUSDCeilingDeniesAnyPricedCall

  Scenario: an explicit require_human_above_usd of zero holds any priced call
    Given a policy sets require_human_above_usd to exactly 0
    When an agent's action has any estimated cost above zero
    Then the decision is hold, and approval is required
    # -> internal/pdp:TestDecideZeroRequireHumanAboveUSDThresholdHoldsAnyPricedCall

  Scenario: a policy file that writes deny_above_usd as 0 is not the same policy as one that omits it
    Given one policy file never mentions deny_above_usd and another writes it as 0
    When both are loaded and compiled
    Then their PolicyVersion digests differ
    # -> internal/policy:TestExplicitZeroDenyAboveUSDInAYAMLFileIsDistinctFromOmitted

  Scenario: the same holds for require_human_above_usd over the JSON decoder
    Given one policy file never mentions require_human_above_usd and another writes it as 0
    When both are loaded and compiled
    Then their PolicyVersion digests differ
    # -> internal/policy:TestExplicitZeroRequireHumanAboveUSDInAJSONFileIsDistinctFromOmitted

  Scenario: a PUT with an explicit zero ceiling is not silently dropped, and takes effect
    Given an admin PUTs a policy body containing "deny_above_usd":0 for one agent
    When the same PUT response and a later GET of that policy are read back
    Then both echo deny_above_usd as 0, never omitting the field
    And the agent's very next priced call through POST /v1/decide is denied
    # -> internal/api:TestPutPolicyWithExplicitZeroDenyAboveUSDIsNotSilentlyDropped
    # -> internal/api:TestPutPolicyWithExplicitZeroDenyAboveUSDActuallyDeniesTheNextCall

  Scenario: a sub-cent ceiling prints as itself, not as a rounded-away zero
    Given a policy sets deny_above_usd to $0.000001
    When a call estimated at $0.000033 is denied
    Then the reason names the ceiling as 0.000001, never as $0.00
    # -> internal/pdp:TestSubCentDenyAboveUSDReasonIsNotMisleading

  Scenario: a sub-cent threshold prints as itself, not as the next cent up
    Given a policy sets require_human_above_usd to $0.005
    When a call estimated at $0.006 is held
    Then the reason names the threshold as 0.005, never as $0.01
    # -> internal/pdp:TestSubCentRequireHumanAboveUSDReasonIsNotMisleading
