# Provenance: @claude 2026-10-14, a fix for a hold bypass measured on the
# 2026-10-14 range runs: a tool call padded past the enforcement point's argument
# cap reached the decision with no risk signal, and every hold_if_signal rule let
# it through. The scenarios describe the option that closes it in the
# repository's own words; they quote no person.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: A tool call whose risk signal never arrived can be held for a person

  Scenario: A call padded past the argument cap is held when the rule holds on absence
    Given a policy that holds on a destructive action.risk_class from 0.5 and holds when that signal is absent
    And the enforcement point sends a tool call whose arguments were over its cap, with no arguments and no signal
    When the call is decided
    Then it is held for a person, and the reason names the missing signal, the call and that its arguments were not sent
    And the person deciding sees the tool and its target, and a grant lets that call through once
    # -> internal/api:TestATruncatedToolCallWithNoSignalHoldsWhenTheRuleHoldsOnAbsence
    # -> internal/pdp:TestAToolCallWithNoSignalHoldsWhenTheRuleHoldsOnAbsence

  Scenario: Without the option a missing signal lets the call through as it always did
    Given the same rule written without when_absent, or with when_absent allow
    When the same call is decided
    Then it is allowed, and the policy keeps the version it had before the option existed
    # -> internal/pdp:TestAToolCallWithNoSignalHoldsWhenTheRuleHoldsOnAbsence
    # -> internal/policy:TestAPolicyWithoutWhenAbsentKeepsItsPolicyVersion
    # -> internal/policy:TestCompileChecksWhenAbsentOnARuleBuiltInGo

  Scenario: A model call is never held for a missing signal
    Given a rule that holds when its signal is absent
    When a request that carries no tool call is decided
    Then it is allowed: no call was chosen, so there was nothing to classify
    # -> internal/pdp:TestAModelCallWithNoToolCallIsNeverHeldForAMissingSignal

  Scenario: A signal that arrived with another answer is present, not absent
    Given a rule that holds when its signal is absent
    When the call carries that signal with a value the rule does not list, or under the threshold
    Then the call is allowed, and a destructive answer holds it with the reason that names the answer
    # -> internal/pdp:TestASignalWithAnUnlistedValueIsPresentNotAbsent

  Scenario: A missing signal can only hold
    Given a call a deny rule refuses, a call a cost threshold holds, and a call held because its signal is absent
    When the rule that holds on absence is added, or a token that does not verify is presented
    Then the refusal is the same refusal, the cost hold keeps its reason, and the bad token holds again
    And a policy that asks for a deny when the signal is absent is refused where it is loaded or written
    And over two hundred random policies the rule never changes a deny or another rule's hold
    # -> internal/pdp:TestAnAbsentSignalOnlyEverHolds
    # -> internal/pdp:TestSignalsNeverChangeADenyOrRemoveAHoldOverRandomPolicies
    # -> internal/policy:TestWhenAbsentTakesOnlyAllowOrHold
    # -> internal/api:TestWhenAbsentOverThePolicyAPI

  Scenario: Only an approval of the call itself lifts the hold
    Given a call held because its signal is absent
    When it comes back with a token granted for that call, for another call, or for no call at all
    Then only the token granted for that call lets it through
    # -> internal/pdp:TestAnAbsentSignalHoldIsLiftedByATokenBoundToTheCall
    # -> internal/pdp:TestAnUnboundTokenDoesNotLiftAnAbsentSignalHold
    # -> internal/approval:TestATokenThatBindsNoCallIsRefusedWhereTheCallMustBeBound

  Scenario: An approval of one padded call also fits the next padded call to the same tool
    Given a padded call held because its signal is absent, and a person who grants it without seeing its arguments
    When a second padded call to the same tool and target, in the same run, comes with the same token
    Then the two calls have the same digest, so the token fits both
    And under single-use, the default, only the first goes through, and with single-use off both do
    # -> internal/api:TestAnApprovalOfOnePaddedCallCoversTheNextPaddedCallToTheSameTool

  Scenario: Nothing decided under the rule is offered for reuse
    Given a rule that holds when its signal is absent
    When its holds and its allows are asked whether they may be cached
    Then none may be, since whether a signal arrived is a fact about one call
    # -> internal/pdp:TestAnAbsentSignalHoldIsNeverCacheable

  Scenario: The hold replays from the record with nothing asked
    Given a call held because its signal is absent, recorded with its tool call and no signal
    When the history is replayed
    Then the hold reproduces from the recorded call, a record without the call diverges, and a policy without the option turns it back into an allow
    # -> internal/api:TestAReplayReproducesAnAbsentSignalHold
    # -> internal/replay:TestARecordedAbsentSignalHoldReproducesFromTheRecordedToolCall
