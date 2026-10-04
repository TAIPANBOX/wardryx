# Provenance: @decided 2026-10-04, the wardryx half of the plan for a typed
# risk signal: a signal may turn a call into a hold, never into a deny, and the
# signal is recorded so a replay reproduces the decision. This file paraphrases
# that plan in the repository's own words; it quotes no person.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: A typed risk signal can hold a call for a person, and can do nothing else

  Scenario: A call a classifier calls destructive waits for a person
    Given a policy that holds on an action.risk_class of destructive, external_send or financial from 0.8
    And a tool call that is allowed when no signal is present
    When the same call carries a destructive signal at probability 0.95
    Then the call is held, where it was allowed before
    # -> internal/pdp:TestADestructiveSignalHoldsACallThatWasAllowed

  Scenario: A signal below the threshold or outside the listed values does nothing
    Given the same policy
    When the signal is destructive at 0.79, or read_only at 0.99, or named for another question
    Then the call is still allowed
    And a signal at exactly the threshold does hold
    # -> internal/pdp:TestASignalAtTheThresholdHoldsAndBelowItDoesNot
    # -> internal/pdp:TestAValueTheRuleDoesNotListChangesNothing
    # -> internal/pdp:TestASignalWithAnotherNameChangesNothing

  Scenario: A signal never changes a refusal and never removes another rule's hold
    Given a call that a deny rule refuses, and a call that a cost threshold holds
    When a signal is added to each, harmless or firing
    Then the refusal is the same refusal, and the cost hold keeps its own reason
    And over two hundred random policies a signal never changes a deny or a hold
    # -> internal/pdp:TestASignalNeverChangesADeny
    # -> internal/pdp:TestASignalNeverRemovesACostHold
    # -> internal/pdp:TestSignalsNeverChangeADenyOrRemoveAHoldOverRandomPolicies

  Scenario: A granted approval lifts a signal hold, and a bad token never denies
    Given a call held because of a signal, and a person who grants it
    When the call comes back with the granted token, and again with a token that does not verify
    Then it is allowed once under single-use, and the bad token holds again
    # -> internal/pdp:TestASignalHoldIsLiftedByAValidApprovalTokenAndNeverTurnsIntoADeny
    # -> internal/api:TestAGrantedApprovalLiftsASignalHoldOnceAndABadTokenNeverDenies

  Scenario: A decision that could read a signal is never reused for another call
    Given a policy with a hold_if_signal rule
    When a decision under it is asked whether it may be cached
    Then it may not, because the next call's arguments may carry a signal
    # -> internal/pdp:TestADecisionThatCanReadASignalIsNeverCacheable

  Scenario: A policy that tries to make a signal deny is refused where it is loaded
    Given a policy file that spells a deny on a signal in any way it can
    When the policy is loaded or put through the API
    Then it is refused with a message saying a signal can only hold
    # -> internal/policy:TestAPolicyThatTriesToMakeASignalDenyIsRefusedAtLoad
    # -> internal/policy:TestTheSameRefusalHoldsInJSONAndInsideAList
    # -> internal/policy:TestCompileRefusesADenyIfSignalThatArrivedThroughALaxDecoder

  Scenario: A policy with no signal rule is exactly what it was
    Given a policy that never mentions a signal
    When it is compiled
    Then its version is the one it had before signals existed
    # -> internal/policy:TestAPolicyWithoutASignalRuleKeepsItsPolicyVersion

  Scenario: Nothing a signal touched is ever offered for reuse
    Given a hold from a signal, an approved allow, an allow after a signal that did not fire, an allow after typryx failed, and a deny under a signal policy
    When each is asked whether it may be cached by an enforcement point that keys on the agent and tool set
    Then none may be, over the wire as well as in the engine
    # -> internal/pdp:TestEverySignalDependentDecisionIsMarkedNotCacheable
    # -> internal/api:TestTheCacheableHintIsFalseForEverySignalDependentDecisionOverTheWire

  Scenario: Hostile signals and tool calls are refused at the API
    Given signals with a missing, impossible or non-numeric probability, too many signals, and tool calls with oversized or malformed parts
    When they are sent to decide
    Then each is refused as the caller's mistake, never a server error, and nothing is echoed back
    # -> internal/pdp:TestSignalValidationRefusesTheMalformed
    # -> internal/pdp:TestToolCallValidationCapsWhatCanBeSent
    # -> internal/api:TestHostileSignalAndToolCallInputIsRefusedAtTheAPI

  Scenario: A signal supplied by a caller is believed and recorded
    Given a caller that sends its own destructive signal
    When the decision is made
    Then the call is held, and the event and the approval context carry the signal in full
    # -> internal/api:TestACallerSuppliedDestructiveSignalHoldsACallThatWasAllowed
    # -> internal/api:TestEverySignalUsedIsRecordedInTheEventAndTheApprovalContext

  Scenario: Typryx saying destructive holds the call
    Given typryx is configured and answers that the call is destructive
    When a tool call is decided
    Then it is asked only for the tool, the arguments and the target
    And the call is held and the typryx signal is recorded with its answer id
    # -> internal/api:TestTyprxSayingDestructiveHoldsTheCallAndTheSignalIsRecorded
    # -> internal/enrich:TestItAsksTheRiskClassTemplateWithOnlyTheThreeFieldsAndTheKey

  Scenario: Typryx failing leaves the decision exactly as it was
    Given typryx times out, answers 500, answers unanswered, answers garbage, or is unreachable
    When a tool call is decided
    Then the call is decided as if typryx were absent, nothing is recorded as a signal, and the failure is counted
    # -> internal/api:TestATyprxThatFailsLeavesTheOriginalDecisionAndNoSignal
    # -> internal/api:TestAnUnreachableTyprxLeavesTheOriginalDecision
    # -> internal/enrich:TestAnythingButACleanAnswerIsNoSignalAndIsCountedByReason
    # -> internal/enrich:TestATyprxThatTimesOutIsNoSignalWithinTheBudget

  Scenario: Typryx is asked only when its answer could change the verdict
    Given a deny, a cost hold, a caller signal that already holds, no tool call, or no policy reading the signal
    When the call is decided
    Then typryx is not asked
    # -> internal/api:TestTyprxIsAskedOnlyWhenTheAnswerCouldChangeTheVerdict
    # -> internal/api:TestWithNoEnrichmentConfiguredATyprxIsNeverAsked

  Scenario: The tool call's arguments never reach the record
    Given a tool call whose arguments hold a marker
    When it is decided and held
    Then the marker is in neither the event file nor the approval context
    # -> internal/api:TestToolArgumentsNeverReachTheRecord

  Scenario: A signal hold replays to the same hold with typryx gone
    Given a call held because typryx said destructive
    When typryx is stopped and the history is replayed
    Then the hold reproduces from the recorded signal, typryx is not asked, and a policy without the rule changes it
    # -> internal/api:TestAReplayReproducesASignalHoldWithTyprxUnreachable
    # -> internal/replay:TestARecordedSignalIsFedBackAndTheHoldReproduces
    # -> internal/replay:TestAHoldWhoseSignalWasNotRecordedIsADivergenceNotAReproduction
    # -> internal/replay:TestACandidateWithoutTheRuleChangesTheRecordedHold

  Scenario: Neither the decision nor its replay can reach the enrichment
    Given the packages the decision and its replay stand on
    When their imports are followed all the way down
    Then none of them reaches the enrichment
    # -> internal/api:TestTheDecisionPathAndReplayCannotReachTheEnrichment

  Scenario: An unusable typryx setting stops the service naming the variable
    Given a typryx URL that is not a URL, a key file that cannot be read, or a timeout that is not a number
    When the service starts
    Then it refuses to start and names the variable, and the key appears in no message
    # -> cmd/wardryx:TestAnUnusableTyprxConfigurationRefusesToStartNamingTheVariable
    # -> cmd/wardryx:TestTheKeyNeverAppearsInARefusal
    # -> internal/manifest:TestATyprxURLThatCannotBeUsedRefusesToStartNamingIt

  Scenario: Enrichment is off unless an operator names a typryx
    Given no typryx URL
    When the service is configured
    Then nothing is asked of anyone and no setting changes a decision
    # -> cmd/wardryx:TestTyprxEnrichmentIsOffByDefault

  Scenario: The tool call a signal came from is recorded without its arguments
    Given a call held because of a signal derived from its arguments
    When the decision is recorded
    Then the record holds the tool name, the target and a hash of the arguments, and the arguments themselves are nowhere
    # -> internal/api:TestTheToolCallIsRecordedAsNameTargetAndAHashOfItsArguments

  Scenario: A call whose arguments were cut off is not classified from its name
    Given an enforcement point that marks the arguments truncated and sends none
    When the call is decided
    Then typryx is not asked, the call is decided as if no signal existed, and the record says the arguments were truncated
    # -> internal/api:TestTruncatedArgumentsAreNeverAskedAboutAndAreRecordedAsTruncated
    # -> internal/enrich:TestACallWhoseArgumentsWereTruncatedIsNotAskedAbout
    # -> internal/pdp:TestATruncatedToolCallIsConsistentOrRefused
