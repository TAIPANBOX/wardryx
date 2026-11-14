# Provenance: @decided 2026-11-14 (paraphrased): a hold gets a lifetime after
# which wardryx closes it, the held agent may withdraw its own hold, and an admin
# key gets no way to cancel a hold. Neither closure is a person's decision.
# @claude 2026-11-14, the shape, fixed in this change: WARDRYX_HOLD_TTL (24h by
# default, 1h to 168h) closes a pending hold as expired, checked at start and once
# a minute; POST /v1/approvals/{id}/withdraw closes it as withdrawn for the agent,
# run and org the hold names; the decide route keeps taking only grant and deny.
# This file quotes no person.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: A hold is closed by a person, by its lifetime, or by its own agent

  Scenario: A hold nobody decided is closed once it has waited its lifetime
    Given a hold that nobody has decided
    When it has waited WARDRYX_HOLD_TTL
    Then it is closed as expired by wardryx, approval_expired is recorded at medium with how long it waited, no token exists for it, a person can no longer grant it, and the agent's next call is a new hold
    # -> internal/api:TestAHoldPastItsTTLIsClosedAsExpiredWithNoToken

  Scenario: The lifetime is exact
    Given a hold and a lifetime of two hours
    When a check runs one second before the two hours and then at the two hours
    Then the first check leaves it pending and the second closes it
    # -> internal/api:TestAHoldIsExpiredAtItsTTLAndNotASecondBefore

  Scenario: A hold a person decided is never closed by its lifetime
    Given a hold a person denied
    When a check runs a month later
    Then the hold stays denied and nothing is recorded as expired
    # -> internal/api:TestAHoldAPersonDecidedIsNeverExpired

  Scenario: Two instances on one store record each closed hold once
    Given twenty holds past their lifetime and two wardryx instances on one store
    When both check at the same moment, several times
    Then each hold is recorded as expired exactly once, by one of them
    # -> internal/api:TestTwoInstancesRecordEachExpiredHoldOnce

  Scenario: Holds already waiting when wardryx starts are closed by the first check
    Given holds written before this build, past their lifetime
    When wardryx starts
    Then the check at start closes them, without waiting a minute
    # -> internal/api:TestHoldsAlreadyWaitingAreClosedByTheFirstCheckAtStart

  Scenario: An expired hold frees its place under the pending cap
    Given an agent at a pending cap of one
    When its pending hold expires
    Then its next call writes a row again
    # -> internal/api:TestAnExpiredHoldFreesItsPlaceUnderThePendingCap

  Scenario: The lifetime is bounded and cannot be switched off
    Given WARDRYX_HOLD_TTL unset, set inside 1h to 168h, and set outside it or to something that is not a duration
    When serve reads it
    Then unset is 24 hours, inside is accepted, and anything else refuses to start
    # -> internal/api:TestHoldTTLIsBounded

  Scenario: The held agent withdraws its own hold
    Given a hold, and the enforcement point that speaks for the held agent
    When it withdraws the hold for that agent and run
    Then the hold is withdrawn by the agent, approval_withdrawn is recorded at info, no token is minted, a second withdraw is 409, and a person can no longer grant it
    # -> internal/api:TestTheHeldAgentWithdrawsItsHold

  Scenario: An admin key cannot cancel a hold
    Given a hold
    When an org's admin key or a cross-org admin key asks to withdraw it
    Then each is refused with 403 and the hold stays pending
    # -> internal/api:TestAnAdminKeyCannotWithdrawAHold

  Scenario: The decide route does not close a hold any other way
    Given a hold
    When an admin key sends the decision expired or withdrawn, in any spelling
    Then each is a 400 and the hold stays pending
    # -> internal/api:TestTheDecideRouteDoesNotTakeExpiredOrWithdrawn

  Scenario: Another agent or another run cannot withdraw a hold, and learns nothing about it
    Given a hold of one agent and run, and a key that speaks for that agent and another
    When it asks to withdraw the hold for the other agent, or for another run
    Then each answer is the same 404 as an id that does not exist, and the hold stays pending until its own agent withdraws it
    # -> internal/api:TestAnotherAgentOrRunCannotWithdrawAndLearnsNothing

  Scenario: Another org cannot withdraw a hold, and learns nothing about it
    Given a hold of one org, and another org's key that names the same agent
    When it asks to withdraw the hold
    Then the answer is the same 404 as an id that does not exist
    # -> internal/api:TestAKeyOfAnotherOrgCannotWithdrawAndLearnsNothing

  Scenario: A key that does not speak for the agent is refused and recorded
    Given a viewer key that speaks for no agent
    When it asks to withdraw a hold
    Then it is refused with 403 that echoes nothing, and agent_assertion_refused names the withdraw route
    # -> internal/api:TestAKeyThatDoesNotSpeakForTheAgentIsRefusedAndRecorded

  Scenario: Where wardryx verifies agent tokens, only the agent with its token and proof withdraws
    Given wardryx verifying agent tokens with DPoP proofs
    When a withdraw comes with no token, a token with no proof, a token of another agent, or a proof of another token
    Then each is refused with 403 as on the decide path, and the agent with its token and proof withdraws the hold
    # -> internal/api:TestWithAgentTokensAWithdrawNeedsTheAgentsTokenAndProof

  Scenario: The token is checked before the hold is read
    Given wardryx verifying agent tokens
    When a withdraw with no token names a hold that exists and one that does not
    Then both refusals are the same
    # -> internal/api:TestWithAgentTokensTheTokenIsCheckedBeforeTheHoldIsRead

  Scenario: Neither closure is recorded as a person's decision
    Given one hold withdrawn and one expired
    When the record is read
    Then it carries no approval_granted and no approval_denied for them
    # -> internal/api:TestAWithdrawnOrExpiredHoldIsNotADecisionByAPerson

  Scenario: Each store closes only pending holds past the cutoff, with their previews
    Given holds before, at and after the cutoff, one with a sealed preview, and one a person decided
    When the store is asked to expire them
    Then the ones at or before the cutoff close, the preview goes with its hold, the decided one is untouched, and a second call closes nothing
    # -> internal/store:TestMemoryExpiresOnlyPendingHoldsPastTheCutoff
    # -> internal/store:TestPgExpiresOnlyPendingHoldsPastTheCutoff

  Scenario: A person and the lifetime racing close each hold once
    Given sixty holds, a person denying half of them, and several checks running at once, on Postgres from two instances
    When they all run together
    Then every hold ends closed exactly once, and no check reports a hold a person or another check closed
    # -> internal/store:TestMemoryExpiryAndADecisionCloseEachHoldOnce
    # -> internal/store:TestPgTwoInstancesAndAPersonCloseEachHoldOnce
