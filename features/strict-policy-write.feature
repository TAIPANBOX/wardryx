# Provenance: @decided 2026-10-13, paraphrased: a policy write refuses a field the
# policy does not declare, because a rule spelled wrong would be stored without
# the rule and the write would answer 200. The fields a GET of a policy returns
# beyond the policy itself (id and updated_at) are accepted on input and ignored,
# so a body copied from a GET can be written back unchanged. The other JSON
# request bodies are not part of this decision. This file quotes no person.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: A policy write refuses a field it does not know

  Scenario: A PUT with a misspelled rule is refused, and the rule is not silently dropped
    Given a PUT body for a policy whose rule name is misspelled, beside a valid target
    When the body is sent to write the policy named by the URL
    Then the response is 400, the response names the unknown field and does not echo its value, and the policy is not stored
    # -> internal/api:TestAPutWithAMisspelledRuleIsRefusedAndNothingIsStored

  Scenario: A policy read by GET can be written back unchanged
    Given a policy that was written, then read by GET, whose body carries an id and an updated_at
    When that body is sent back as a PUT to the same URL
    Then the response is 200 and the policy stored afterwards has the same rules as the one read
    # -> internal/api:TestAGetBodyWrittenBackUnchangedIsAccepted

  Scenario: The read-only fields of a PUT body do not choose what is stored
    Given a PUT body whose id names another policy and whose updated_at names an earlier time
    When the body is sent to write the policy named by the URL
    Then the policy is stored under the URL's id with the time of the write, and nothing is stored under the body's id
    # -> internal/api:TestTheReadOnlyFieldsOfAPutBodyAreIgnored

  Scenario: An unknown key inside a hold rule is refused on a PUT too
    Given a PUT body whose hold rule carries a key the rule does not have
    When the body is sent to write the policy named by the URL
    Then the response is 400 that names the key, and the policy is not stored
    # -> internal/api:TestAnUnknownKeyInsideAHoldRuleIsRefusedOnPut
