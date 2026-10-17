# Provenance: @decided 2026-10-17 (paraphrased): close the agent-security
# findings of the 2026-10-17 review, starting with the defaults and the small
# fixes. Finding F-012, its policy half: a policy carried no org, so the admin
# of one org could write a rule that changed the decisions of another org's
# agents.
# @claude 2026-10-17, the shape, fixed in this change: a policy may carry an
# org; a policy with an org applies only to the decisions that org's keys ask
# for; a policy with no org applies across orgs and only a principal allowed
# across orgs may write one. This file quotes no person.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: A policy written by an org's admin governs that org's decisions only

  Scenario: One org's admin cannot change another org's decisions
    Given two orgs, each with an admin key that lists its own agents
    When the first org's admin writes a deny for the second org's agents
    Then the second org's decision for that agent is unchanged, and the policy is stored with the first org
    # -> internal/api:TestOneOrgsAdminCannotChangeAnotherOrgsDecisions

  Scenario: A policy with an org applies only to decisions asked in that org
    Given a policy with org acme that denies a tool
    When a key of acme and a key of globex ask for the same agent and tool
    Then acme's answer is deny and globex's is allow
    # -> internal/pdp:TestAPolicyWithAnOrgAppliesOnlyToThatOrgsDecisions

  Scenario: Filtering tools reads the same org rule as deciding
    Given policies with and without an org over random requests
    When every tool is offered alone to Filter and to Decide under random orgs
    Then Filter lists a tool exactly when Decide denies it by deny_tool or allow_tool
    # -> internal/pdp:TestFilterAgreesWithDecideOnEveryToolAlone

  Scenario: An org admin cannot write a policy for another org or across orgs
    Given two orgs
    When an admin of one org writes a policy naming the other org, and then one naming no org over an existing cross-org policy
    Then both are 403 and nothing is stored
    # -> internal/api:TestAnOrgAdminCannotWriteForAnotherOrgOrAcrossOrgs

  Scenario: An org admin neither sees nor removes another org's policy
    Given a policy of the second org
    When an admin of the first org lists policies, reads it and deletes it
    Then it is not listed, the read and the delete are 404, and it is still in force
    # -> internal/api:TestAnOrgAdminNeitherSeesNorRemovesAnotherOrgsPolicy

  Scenario: A cross-org admin writes a policy that applies across orgs
    Given two orgs and a cross-org admin key
    When it writes a policy that names no org
    Then the policy is stored with no org and changes the decisions of both orgs
    # -> internal/api:TestACrossOrgAdminWritesAPolicyThatAppliesAcrossOrgs

  Scenario: With one org its admin writes and edits policies as before
    Given every key belongs to one org and a policy stored before this change, with no org
    When that org's admin replaces it and writes a new one
    Then both writes are accepted and both policies are stored with no org, as before
    # -> internal/api:TestWithOneOrgItsAdminWritesPoliciesAsBefore

  Scenario: A policy without an org keeps its policy version
    Given the policy sets the version golden values were measured on
    When they are compiled
    Then their PolicyVersion is byte for byte what it was before the org field existed
    # -> internal/policy:TestAPolicyWithoutAnOrgKeepsItsPolicyVersion

  Scenario: An org that is blank or padded is refused at load
    Given a policy whose org is "  " or " acme"
    When it is compiled
    Then it is refused, because a padded org would match no key and a blank one would read as across orgs
    # -> internal/policy:TestABlankOrPaddedOrgIsRefusedAtLoad

  Scenario: A recorded decision carries its org and replays to the same verdict
    Given a decision a policy with an org denied
    When the decision is replayed from the record alone
    Then it reproduces, because the record carries the org it was asked in
    # -> internal/api:TestAnOrgScopedDenialReplaysFromTheRecord
    # -> internal/replay:TestARecordedOrgIsFedBackToThePDP
