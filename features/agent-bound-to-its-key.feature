# Provenance: @decided 2026-10-17 (paraphrased): close the agent-security
# findings of the 2026-10-17 review, starting with the defaults and the small
# fixes. Finding F-001: the agent a decision is about was whatever the caller
# wrote in agent_id, checked only for being non-empty.
# @claude 2026-10-17, the shape, fixed in this change from the review's brief:
# a key carries the agents it may speak for; the enforcement point's key, which
# authenticates the agent before it asks, speaks for any agent of its own org;
# a request outside the key's allowance is a 403 with no decision and an event.
# This file quotes no person.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: The agent a decision is about is bound to the key that asks

  Scenario: A key that lists its agents cannot ask for another agent
    Given a key whose entry in WARDRYX_KEYS lists agent://acme.example/support/bot1
    When it asks /v1/decide for agent://acme.example/finance/bot9
    Then the answer is 403, no decision is made and nothing is held
    # -> internal/api:TestAKeyThatListsItsAgentsCannotAskForAnother

  Scenario: A key that lists its agents asks for a listed agent as before
    Given a key whose entry lists agent://acme.example/support/bot1
    When it asks /v1/decide for agent://acme.example/support/bot1
    Then the decision is the one the policy gives
    # -> internal/api:TestAKeyThatListsItsAgentsAsksForThemAsBefore

  Scenario: A pattern covers the agents under it and no agent outside it
    Given a key whose entry lists agent://acme.example/*
    When it asks for agent://acme.example/a/b, agent://acme.example.evil/x and agent://acme.exampl/x
    Then only the first is answered and the other two are 403
    # -> internal/api:TestAnAgentPatternCoversOnlyTheAgentsUnderIt

  Scenario: A viewer key that lists no agent speaks for none
    Given a viewer key with no agents listed
    When it asks /v1/decide for any agent
    Then the answer is 403, and serve says at start that this key speaks for no agent
    # -> internal/api:TestAViewerKeyWithNoListSpeaksForNoAgent
    # -> internal/api:TestKeyPostureNamesEveryKeyThatSpeaksForNoAgent

  Scenario: The enforcement point's key speaks for any agent when there is one org
    Given every key in WARDRYX_KEYS belongs to one org, and the gateway's key has the pep role and lists no agent
    When it asks /v1/decide for any agent
    Then the decision is the one the policy gives
    # -> internal/api:TestAPepKeySpeaksForAnyAgentWhenThereIsOneOrg

  Scenario: With more than one org a key must list the agents it speaks for
    Given WARDRYX_KEYS names two orgs and their pep and admin keys list no agent
    When either key asks /v1/decide for any agent
    Then the answer is 403, because wardryx cannot tell which agents belong to which org, and serve says so at start
    # -> internal/api:TestWithTwoOrgsAnUnlistedKeySpeaksForNoAgent
    # -> internal/api:TestKeyPostureNamesEveryKeyThatSpeaksForNoAgent

  Scenario: A cross-org admin key speaks for any agent
    Given WARDRYX_KEYS names two orgs and a key with the cross-org-admin role
    When it asks /v1/decide for an agent of either org
    Then the decision is the one the policy gives
    # -> internal/api:TestACrossOrgAdminKeySpeaksForAnyAgent

  Scenario: A refused request decides nothing, holds nothing and spends no approval token
    Given a granted single-use approval token for agent bot1
    When a key that may not speak for bot1 presents it for bot1
    Then the answer is 403 and the token still allows bot1's call once afterwards
    # -> internal/api:TestARefusedRequestSpendsNoApprovalToken

  Scenario: The refusal is recorded, names the key by fingerprint and never holds the key
    Given events are enabled
    When a key asks for an agent outside its allowance
    Then one agent_assertion_refused event names the asserted agent, the org and the key's fingerprint, and no decision event is written
    # -> internal/api:TestARefusalIsRecordedAndNamesTheKeyByFingerprint

  Scenario: Filtering tools is bound the same way
    Given a key that lists agent://acme.example/support/bot1
    When it asks /v1/filter-tools for agent://acme.example/finance/bot9
    Then the answer is 403 and the policy partition of that agent is not shown
    # -> internal/api:TestFilterToolsIsBoundToTheKeyLikeDecide

  Scenario: A key entry keeps its old form and gains a list of agents
    Given the entries key:org, key:org:viewer and key:org:pep:agent://a.example/x|agent://b.example/*
    When WARDRYX_KEYS is parsed
    Then the first two parse exactly as before and the third carries both patterns
    # -> internal/api:TestParseKeysReadsAnAgentListAfterTheRole

  Scenario: The local devkey speaks for any agent
    Given serve runs with WARDRYX_ALLOW_DEVKEY and no keys
    When the devkey asks /v1/decide for any agent
    Then the decision is the one the policy gives
    # -> internal/api:TestTheDevkeySpeaksForAnyAgent
