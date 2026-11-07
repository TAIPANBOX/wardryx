# Provenance: @decided 2026-11-07 (paraphrased): a tool call of an agent that nothing
# grants is held for a person; a model call still passes; only an explicit grant
# lifts the hold, and a restriction never does. The scenarios are that decision in
# the repository's own words, with the design review's cases.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: A tool call of an agent nothing grants is held for a person

  Scenario: a tool call of an agent no policy grants is held for a person
    Given a policy file with when_no_grant: hold on every agent
    When an agent makes a tool call and no policy grants the tool
    Then the call is held for a person, the reason names the floor, the tool and the agent
    And the person is shown the tool and its target, and the row says a grant is what ends this for good
    # -> internal/pdp:TestAToolCallNothingGrantsIsHeldForAPerson
    # -> internal/api:TestAToolCallNothingGrantsIsHeldOverTheWire

  Scenario: a model call of the same agent passes
    Given the same floor
    When the gateway asks about a model call that offers the same tools
    Then it is allowed: what a model was offered is not a call
    # -> internal/pdp:TestAModelCallOfTheSameAgentPasses
    # -> internal/api:TestAModelCallOfTheSameAgentPassesOverTheWire

  Scenario: an egress question with no tool call is not held
    Given the same floor
    When the egress plane asks about a domain with no tool call and no model
    Then it is allowed
    # -> internal/pdp:TestAnEgressQuestionWithNoToolCallIsNotHeld
    # -> internal/api:TestAnEgressQuestionIsNotHeldOverTheWire

  Scenario: an agent id without the agent scheme is held and cannot be granted
    Given a floor on every agent and a grant of every tool to a trust domain
    When a tool call arrives under an id with no agent:// scheme
    Then it is held, and the reason says the id cannot be granted and what to give the agent
    And an id with a line break written into it is held the same way
    # -> internal/pdp:TestAnAgentIDWithoutTheSchemeIsHeldAndCannotBeGranted
    # -> internal/pdp:TestAnAgentIDWithALineBreakDoesNotEscapeTheFloor
    # -> cmd/wardryx:TestTheExampleFloorHoldsAnIDWithoutTheScheme

  Scenario: a restriction on every agent does not end the hold
    Given the floor and a deny_tool, a max_steps or any other restriction on agent://*
    When a tool call nothing grants arrives
    Then it is held: hardening a fleet does not switch the control off
    # -> internal/pdp:TestARestrictionOnEveryAgentDoesNotEndTheHold
    # -> internal/pdp:TestRestrictingRulesNeverLiftTheHoldOverRandomPolicies

  Scenario: a restriction on a trust domain does not end the hold
    Given the floor and a restriction on the agent's own domain, or on the agent itself
    When a tool call nothing grants arrives
    Then it is held: a rule that narrows is not a rule that gives
    # -> internal/pdp:TestARestrictionOnATrustDomainDoesNotEndTheHold
    # -> internal/pdp:TestRestrictingRulesNeverLiftTheHoldOverRandomPolicies

  Scenario: a signal rule on the agent does not end the hold
    Given the floor and a hold_if_signal rule on the agent that does not fire
    When a tool call nothing grants arrives
    Then it is held by the floor
    # -> internal/pdp:TestASignalRuleOnTheAgentDoesNotEndTheHold

  Scenario: a grant for one tool leaves the next tool held
    Given the floor and a grant of one tool to the agent
    When the agent calls that tool, then another, then names another in the same request
    Then the first passes, and the others are held by name
    # -> internal/pdp:TestAGrantForOneToolLeavesTheNextToolHeld
    # -> internal/pdp:TestEveryRequestedToolMustBeGranted
    # -> internal/pdp:TestAGrantLiftsTheHoldForTheToolItNames

  Scenario: a grant in one org does not reach another org
    Given a grant that belongs to one org
    When the same call is decided in another org, or in none
    Then it is held
    # -> internal/pdp:TestAGrantInOneOrgDoesNotReachAnotherOrg

  Scenario: a grant lifts the floor and nothing else
    Given a grant of every tool to the agent
    When a deny_tool names the tool, an allow-list leaves it out, a cost gate holds or a signal holds
    Then that rule answers as it would with no grant
    # -> internal/pdp:TestAGrantNeverLiftsADenyOrAnAllowListDenial
    # -> internal/pdp:TestAGrantLiftsNoOtherHold

  Scenario: a grant on a target with no trust domain is refused at load
    Given a policy with grant_tool on *, agent://*, agent://*/x or agent://ac*/x
    When the file is loaded, or the policy is written through the API
    Then it is refused, in a sentence saying how to write the target
    And an allow_tool on such a target grants nothing
    # -> internal/policy:TestAGrantOnATargetWithNoTrustDomainIsRefusedAtLoad
    # -> internal/api:TestAGrantOnATargetWithNoTrustDomainIsRefusedOnPut
    # -> internal/pdp:TestATargetThatPinsNoDomainGrantsNothing

  Scenario: a malformed floor or grant is refused at load in a sentence that says what to write
    Given when_no_grant written as deny, with no value, as null, or beside grant_tool, or a blank or glob grant_tool entry
    When the file is loaded
    Then it is refused, and a blank never reads as a choice
    # -> internal/policy:TestWhenNoGrantTakesOnlyHoldOrAllow
    # -> internal/policy:TestAFloorAndAGrantInOnePolicyAreRefused
    # -> internal/policy:TestAMalformedGrantToolEntryIsRefusedWithWhatToWrite

  Scenario: a file with neither field is the file it was
    Given a policy file that names neither when_no_grant nor grant_tool
    When it is loaded and decided against
    Then its policy version is the one it had before the fields, and every sentence and queue behaves as it did
    # -> internal/policy:TestAFileWithNeitherFieldKeepsItsPolicyVersion
    # -> internal/pdp:TestWithoutAFloorAGrantAndAnAllowListHoldNothing
    # -> internal/api:TestWithNoFloorTheQueueIsWhatItWas

  Scenario: the floor cannot be written or removed through the policy API
    Given a floor in the policy file
    When an admin key writes when_no_grant through PUT, whatever its value, or deletes the floor
    Then the write is a 400 that stores nothing, the delete a 404, and the floor stands
    # -> internal/api:TestTheFloorCannotBeWrittenThroughThePolicyAPI
    # -> internal/api:TestTheRefusalOfAFloorSaysWhatToDoInstead
    # -> internal/api:TestTheFloorCannotBeRemovedThroughThePolicyAPI

  Scenario: a token bound to the call lifts the hold once
    Given a hold of the floor a person granted
    When the same call is sent with the token, and then again
    Then the first is allowed and the second is a fresh hold that says the token was spent
    # -> internal/pdp:TestATokenBoundToTheCallLiftsTheHold
    # -> internal/api:TestAGrantedHoldLiftsTheCallOnce

  Scenario: a token that binds no call does not lift the hold
    Given a token granted for a request that carried no call
    When it is presented on a call the floor would hold
    Then the call is held, and neither the cost gate nor a signal hold lets it through first
    # -> internal/pdp:TestATokenThatBindsNoCallDoesNotLiftTheHold
    # -> internal/pdp:TestAnUnboundTokenDoesNotPassTheCostGateOnACallTheFloorWouldHold
    # -> internal/pdp:TestAnUnboundTokenDoesNotPassASignalHoldOnACallTheFloorWouldHold

  Scenario: an approval of one call does not open the tool for other arguments
    Given a token granted for a call
    When the same tool is called with other arguments
    Then it is held, and the token still fits the call it was granted for
    # -> internal/pdp:TestATokenForAnotherCallDoesNotLiftTheHold
    # -> internal/api:TestAnApprovalOfOneCallDoesNotOpenTheToolForOtherArguments

  Scenario: a presented token that does not verify holds and never denies
    Given a forged, expired or foreign token
    When it is presented on a call the floor holds
    Then the answer is the same hold with the same reason, never a deny
    # -> internal/pdp:TestAPresentedTokenThatDoesNotVerifyHoldsAndNeverDenies
    # -> internal/api:TestAPresentedTokenThatDoesNotVerifyHoldsOverTheWire
    # -> internal/api:TestAnInvalidTokenUnderTheFloorReplaysAsTheSameHold

  Scenario: a decision under the floor is never cacheable
    Given a floor or a grant over an agent
    When any of its decisions is made, a model call included
    Then cacheable is false, because the gateway's cache key has no call digest
    # -> internal/pdp:TestADecisionUnderTheFloorIsNeverCacheable
    # -> internal/pdp:TestADecisionUnderAGrantIsNeverCacheable

  Scenario: a recorded allow from before the floor replays unchanged
    Given an allow recorded with the reason that no policy targets the agent
    When it is replayed against the version it names
    Then it reproduces word for word, and every frozen sentence stands
    # -> internal/api:TestARecordedAllowFromBeforeTheFloorReplaysUnchanged
    # -> internal/replay:TestAnOldAllowStaysReproducedUnderItsOwnVersion
    # -> internal/pdp:TestTheFrozenReasonSentencesDoNotChange

  Scenario: a granted hold replays as approval-decided
    Given a hold of the floor, granted and redeemed
    When the record is replayed
    Then the allow is approval-decided, a spent token approval-spent, and the hold reproduces with the file of arguments gone
    # -> internal/api:TestAGrantedNoGrantHoldReplaysAsApprovalDecided
    # -> internal/api:TestASpentNoGrantTokenReplaysAsApprovalSpent
    # -> internal/api:TestAReplayReproducesANoGrantHoldFromTheRecordAlone
    # -> internal/replay:TestARecordedNoGrantHoldReproducesFromTheRecordedToolCall

  Scenario: the same call held twice is one row in the queue
    Given a floor and an agent repeating one call
    When the call is held twice
    Then both answers name one approval and both decisions are on the record
    And another argument, run, agent or org is a row of its own, and so is the call after a person answered
    # -> internal/api:TestTheSameCallHeldTwiceIsOneRow
    # -> internal/api:TestDifferentArgumentsARunOrAnAgentAreTheirOwnRow
    # -> internal/api:TestTheSameCallInAnotherOrgIsItsOwnRow
    # -> internal/api:TestAfterADecisionTheSameCallHoldsInANewRow
    # -> internal/store:TestPgOneCallIsOneRowAcrossConnections

  Scenario: past the pending cap the verdict stays and no row is added
    Given an agent at its pending cap
    When another call is held
    Then the verdict and the reason are the same, the event is written, no row is added
    And approval_queue_full fires once for that agent
    # -> internal/api:TestOverThePendingCapTheVerdictStaysAndNoRowIsAdded
    # -> internal/api:TestTheQueueFullEventFiresOncePerAgentPerProcess
    # -> internal/api:TestThePendingCapIsPerAgent

  Scenario: a candidate floor reports what it would hold before anything is enabled
    Given a history of decisions and a candidate policy with the floor and some grants
    When wardryx replay is run against it
    Then the report names each agent and tool that would wait for a person, how often and when last
    And a grant in the candidate takes a call out of the report, and the JSON form says how much could not be examined
    # -> internal/replay:TestACandidateFloorReportsWhatItWouldHold
    # -> internal/replay:TestACandidateGrantTakesACallOutOfTheReport
    # -> internal/replay:TestTheJSONFormCarriesWhatCouldNotBeExamined
    # -> cmd/wardryx:TestReplayJSONIsWhatAnInstallerReads

  Scenario: an operator gives an agent a tool on a running box and the hold ends with no restart
    Given a running wardryx with a floor in its file
    When an admin writes a policy with grant_tool through the API
    Then the next call of that tool passes, the next tool stays held, and removing the grant puts the hold back
    # -> internal/api:TestAGrantWrittenThroughTheAPIEndsTheHoldWithNoRestart
    # -> internal/manifest:TestTheBuiltBinaryHoldsAToolCallNothingGrants

  Scenario: the check says what the floor does to each agent
    Given a directory of passports and a policy with a floor and a grant
    When wardryx check is run
    Then each agent's row says which tools are granted and that any other is held
    # -> cmd/wardryx:TestCheckSaysWhatTheFloorDoesToEachAgent

  Scenario: an edit of the policy file leaves a trace
    Given a process that starts with an events file
    When it comes up
    Then a policy_loaded event names the version its first decision will name
    # -> internal/api:TestPolicyLoadedRecordsTheVersionADecisionWillName

  Scenario: an id written to be read by a person arrives as quoted data
    Given an agent id with a line break and an instruction in it
    When its tool call is held
    Then the reason on the record and in the approvals list carries it quoted and bounded
    # -> internal/pdp:TestTheHoldReasonQuotesAndBoundsWhatTheCallerWrote
    # -> internal/api:TestAHostileAgentIDReachesThePersonQuotedAndBounded
