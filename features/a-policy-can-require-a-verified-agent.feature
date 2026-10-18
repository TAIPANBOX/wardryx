# Provenance: @decided 2026-10-18 (paraphrased): wardryx keeps trusting its
# enforcement point and learns how the enforcement point knew the agent. The
# decision lists an identity source with each request, records it, and lets a
# policy name the sources it accepts. wardryx verifies no token itself.
# @claude 2026-10-18, the shape: identity_source is one of agent-token,
# client-key and none; an absent or unknown value is none; a policy's
# require_identity_source is a list of accepted sources, and a request whose
# source is not in it is denied.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: A policy can require a verified agent, and the decision records how the agent was known

  Scenario: A policy that requires a verified source admits a request that came with one
    Given a policy that accepts only agent-token, and an enforcement point that reports agent-token
    When it asks /v1/decide for a listed agent
    Then the decision is allow, and the allow records agent-token as its source
    # -> internal/api:TestARequireIdentitySourceAdmitsARequestThatCameWithTheListedSource

  Scenario: A request that sends no source is refused by a policy that requires one
    Given a policy that accepts only agent-token
    When the request carries no identity_source
    Then the decision is deny, the reason names the identity source, and the deny records none
    # -> internal/api:TestARequireIdentitySourceDeniesARequestThatSentNoSource

  Scenario: A static client key does not satisfy a policy that requires a verified token
    Given a policy that accepts only agent-token
    When the request reports client-key
    Then the decision is deny
    # -> internal/api:TestARequireIdentitySourceDeniesTheWeakerClientKey

  Scenario: An enforcement point that predates the field is decided as it always was
    Given a policy that asks for no source, and an enforcement point that sends none
    When it asks /v1/decide
    Then the decision is the one the policy gives, and the allow records none
    # -> internal/api:TestAnOldEnforcementPointThatSendsNoSourceIsDecidedAsBefore

  Scenario: A source that is not one of the three counts as none
    Given a policy that accepts only agent-token
    When the request reports a source in another case
    Then the decision is deny, and the deny records none
    # -> internal/api:TestAnUnknownIdentitySourceCountsAsNone

  Scenario: Every matched policy must accept the source
    Given two policies matching the same agent, one accepting agent-token and client-key, one accepting only agent-token
    When the request reports client-key
    Then the decision is deny, and the reason names the policy that refused it
    # -> internal/api:TestEveryMatchedPolicyMustListTheSource

  Scenario: A decision that depended on the source is never served from a cache
    Given a policy that requires a source, and a request that meets it
    When it is decided
    Then the decision is marked not cacheable
    # -> internal/api:TestAPolicyThatReadsTheSourceIsNeverCacheable

  Scenario: The source rule comes after the attestation rule
    Given a policy that denies unattested agents and also requires agent-token, and a request that is both unattested and from client-key
    When it is decided
    Then the reason is the attestation one, which is the earlier rule
    # -> internal/api:TestTheSourceRuleComesAfterDenyIfUnattested

  Scenario: A recorded decision replays to the same verdict from its record
    Given a decision allowed on agent-token under a policy that requires it
    When its record is replayed against the policy in force
    Then the replay allows, because the record carries the source
    # -> internal/api:TestARecordedIdentitySourceReplaysToTheSameVerdict
    # -> internal/replay:TestARecordedSourceIsReadBack

  Scenario: A record from before the field replays as having no source, not as unreadable
    Given a decision record that carries no identity_source
    When replay reads it
    Then it reads as none and is not refused as unreadable
    # -> internal/replay:TestAnOldRecordWithoutASourceIsReadAsNone

  Scenario: A policy names only the three sources, and a typo is refused at load
    Given a policy whose require_identity_source names agnet-token
    When the policy is loaded
    Then the load refuses it and names the value
    # -> internal/policy:TestAnUnlistedIdentitySourceIsRefusedAtLoad

  Scenario: The order of a source list does not change the policy version
    Given two policies that accept the same two sources, listed in different orders
    When both are loaded
    Then they have the same policy version
    # -> internal/policy:TestTheOrderOfTheSourceListDoesNotChangeThePolicyVersion
