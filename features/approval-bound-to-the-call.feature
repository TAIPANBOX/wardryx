# Provenance: @decided 2026-10-04, the owner approved this change: an approval
# for a call that a signal held is bound to that call's arguments, so a person
# who approved one call has not approved another of the same tool. This file
# states that decision in the repository's own words; it quotes no person.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: An approval is for the call a person read, not for the tool

  Scenario: An approval for one call does not approve another call of the same tool
    Given a call that a policy held, and a person who granted it
    When the token comes back on a call with the same tool but other arguments
    Then the call is not allowed, and under a signal hold it waits for its own approval
    And under a cost threshold it is refused as an invalid token
    # -> internal/api:TestAnApprovalForOneCallIsRefusedForAnotherCallOfTheSameTool
    # -> internal/api:TestACostHoldIsBoundToTheCallAndARefusedCallDenies
    # -> internal/pdp:TestASignalHoldIsLiftedOnlyForTheCallThatWasApproved
    # -> internal/pdp:TestACostGateTokenForOneCallDeniesAnotherAndNamesNeitherDigest
    # -> internal/approval:TestATokenBoundToACallVerifiesForThatCallOnly

  Scenario: The call that was approved is allowed, and once when tokens are single-use
    Given a granted approval for a held call
    When the same call is presented with its token
    Then it is allowed, and under single-use a second presentation holds again
    And a refused attempt on another call does not spend the token
    # -> internal/api:TestTheSameCallPresentedWithItsTokenIsAllowed
    # -> internal/api:TestSingleUseStillHoldsForABoundTokenAndARefusedCallDoesNotSpendIt

  Scenario: Another target, another tool name, another truncation or other bytes are another call
    Given the digest an approval is bound to
    When only the target, the tool name, the truncated flag, the argument bytes, or the split between name and target changes
    Then the digest changes
    And arguments re-spaced on the wire are another call and are refused
    # -> internal/approval:TestTheDigestSeparatesEveryPartOfTheCall
    # -> internal/approval:TestTheDigestCannotBeForgedByMovingBytesBetweenNameAndTarget
    # -> internal/approval:TestTheDigestIsOverTheArgumentBytesAsReceived
    # -> internal/api:TestArgumentsWrittenWithOtherWhitespaceAreAnotherCall

  Scenario: A token bound to a call is refused on a request that carries no call
    Given a granted approval for a held call
    When the token is presented on a request with no tool call
    Then it is not allowed, under a signal hold and under a cost threshold alike
    # -> internal/api:TestATokenBoundToACallIsRefusedOnARequestThatCarriesNone

  Scenario: A hold that carried no call, and every token minted before, work exactly as they did
    Given a hold created for a request with no tool call, and a token in the pre-change format
    When the token is presented on a request with no tool call
    Then it is allowed, and it carries neither a version nor a digest
    And presented on a request that now carries a call it still binds only what it always did
    # -> internal/api:TestATokenGrantedForARequestWithNoCallIsTheTokenItAlwaysWas
    # -> internal/approval:TestALegacyTokenOnARequestWithNoToolCallIsAcceptedAsBefore
    # -> internal/approval:TestALegacyTokenOnARequestThatNowCarriesACallBindsWhatItAlwaysDid
    # -> internal/approval:TestATokenInTheExactPreChangeFormatStillVerifies
    # -> internal/approval:TestGrantingAHoldThatCarriedNoCallMintsTheOldFormat

  Scenario: The person deciding sees the tool and target, never the arguments, and everything agrees
    Given a hold for a tool call
    When the approval list, the decision event and the granted token are read
    Then the list shows the tool name and target and no argument bytes
    And the approval, the event and the token carry the same digest
    And the approvals command names the call as tool and target
    # -> internal/api:TestTheApprovalShowsTheCallAndTheTokenEventAndContextAgree
    # -> internal/api:TestTheToolCallIsRecordedAsNameTargetAndAHashOfItsArguments
    # -> cmd/wardryx:TestTheApprovalsListNamesTheCallBeingApproved

  Scenario: A hostile token is refused and never panics
    Given a token with a tampered digest, a wrong or missing version, a malformed digest, or cut short
    When it is presented
    Then it is refused with its own reason
    And a token in the original version that carries a digest is refused, not read as unbound
    # -> internal/approval:TestHostileTokensAreRefusedWithoutPanic
    # -> internal/approval:TestALegacyVersionTokenCarryingADigestIsRefusedNotTreatedAsUnbound
    # -> internal/approval:TestEveryPrefixOfATokenAndRandomBytesAreRefusedWithoutPanic
    # -> internal/approval:TestTheRefusalNeverCarriesADigest

  Scenario: A hold whose call digest was damaged is never granted as an approval that binds nothing
    Given a pending hold whose recorded tool call has no usable digest
    When a person grants it
    Then the grant is refused and the approval stays pending
    # -> internal/approval:TestAHoldWithADamagedCallDigestIsNotGrantedUnboundAndStaysPending
    # -> internal/api:TestAHoldWhoseCallDigestIsDamagedCannotBeGrantedUnbound

  Scenario: The digest is compared in constant time and the decision path always hands over the call
    Given the source of the verifier and of every caller
    When it is read
    Then the signature and the digest are compared with hmac.Equal, never == or !=
    And no production code outside the approval package asks the question without the call
    # -> internal/approval:TestTheSignatureAndTheDigestAreComparedInConstantTime
    # -> internal/approval:TestNoProductionCodeOutsideThisPackageUsesTheUnboundEntryPoints
