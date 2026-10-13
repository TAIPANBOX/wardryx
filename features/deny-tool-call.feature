# Provenance: @decided 2026-10-13, paraphrased: the deny-list reads every tool
# name a request carries, the tool list and the name of its tool call alike,
# as the allow-list already does. The change ships in the same release as
# allow_tool. This file quotes no person.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: The deny-list refuses a tool that a request names only in its tool call

  Scenario: A denied tool named only by the tool call is denied
    Given a policy for one agent that denies one tool
    When that agent's tool list names a benign tool and its tool call names the denied tool
    Then the request is denied, and the reason names the denied tool
    # -> internal/pdp:TestADeniedToolNamedOnlyByTheToolCallIsDenied

  Scenario: A decision that reads a tool call is never served from a cache
    Given a policy for one agent that denies one tool
    When that agent's request carries a tool call, whether the call is refused or allowed
    Then the decision is marked not cacheable, because the tool call's name is a per-call value
    # -> internal/pdp:TestADenyToolDecisionForACallIsNeverCacheable

  Scenario: A request with no tool call keeps its cacheability
    Given a policy for one agent that denies one tool
    When that agent's request names no tool call, and is allowed or refused by the tool list
    Then the decision is still marked cacheable, as it was before the tool call was read
    # -> internal/pdp:TestWithoutAToolCallADenyToolDecisionIsStillCacheable

  Scenario: A recorded allow whose tool call is now denied replays as a divergence
    Given a recorded allow for a tool list that names a benign tool, whose tool call names a tool the deny-list refuses
    When the record is replayed against the policy version it names
    Then replay reports a divergence, because the recorded allow was a call the deny-list refuses
    # -> internal/replay:TestARecordedAllowWhoseToolCallIsNowDeniedDiverges
