# Provenance: @decided 2026-10-13, paraphrased: a PUT body that writes one policy
# holds one policy. Data after that policy is refused with a 400 and nothing is
# stored; it is never read as a second policy and dropped. Whitespace after the
# policy is not data. This file quotes no person.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: A policy PUT body is one policy

  Scenario: Data after the policy in a PUT body is refused, and nothing is stored
    Given a PUT body that is one policy followed by a second policy, bytes that are not JSON, or a truncated policy
    When the body is sent to write the policy named by the URL
    Then the response is 400, the response does not echo the refused data, and the policy is not stored
    # -> internal/api:TestAPutBodyWithDataAfterThePolicyIsRefused

  Scenario: Whitespace after the policy in a PUT body is not data
    Given a PUT body that is one policy followed by newlines and tabs
    When the body is sent to write the policy named by the URL
    Then the response is 200 and the policy is accepted
    # -> internal/api:TestAPutBodyWithTrailingWhitespaceIsStillAccepted
