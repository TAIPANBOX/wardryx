# Provenance: @claude, 2026-08-31. These scenarios come from the design
# conversation that asked what a recorded decision is worth, not from a quote,
# and they are written in the words that conversation used. The defect the
# first one names is @measured, not argued: the phase-0 probe
# (internal/pdp/replay_feasibility_test.go) put a recorded denial back to the
# policy set that produced it and got "allow", because the emitter wrote the
# verdict and not the question.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: A recorded decision carries the question it answered

  Scenario: an operator asks what a policy change would have done to a refusal
    Given a decision the policy point refused and recorded
    When the same recorded question is put to the set that refused it
    Then the answer is the same refusal, with the same reason and policy version
    And putting it to a candidate set that allows the destination answers allow
    # -> internal/api:TestARecordedDenialReplaysToTheSameVerdict

  Scenario: no input to the decision can go unrecorded by accident
    Given the fields the policy point reads to decide
    Then each one is recorded in the envelope, recorded in the event data,
      or excluded by name with a reason
    # -> internal/api:TestDecisionInputCoversEveryDecideRequestField

  Scenario: a live credential never enters a record that outlives it
    Given a decision made against a presented approval token
    Then the recorded event carries no approval token, under any key
    # -> internal/api:TestDecisionInputNeverCarriesTheApprovalToken

  Scenario: one fact is never written in two planes at once
    Given the envelope already carries the agent, the run and the chain
    Then the event data repeats none of them
    # -> internal/api:TestDecisionInputDoesNotRepeatTypedEnvelopeMembers

  Scenario: a hold is a verdict and records its question like the other two
    Given a decision that allows, one that refuses, and one that holds
    Then all three record the tools, domains, steps, model, estimated cost,
      attestation, chain proof, policy version and reason
    # -> internal/api:TestEveryDecisionOutcomeRecordsTheQuestion
