# Provenance: @decided 2026-10-19 (paraphrased): the policy decision point
# verifies the agent's own token itself, instead of trusting the enforcement
# point's word for who the agent is.
# @claude 2026-10-19, the shape: an enforcement point may send the agent's
# access token in the decide request; when wardryx is configured to verify it,
# wardryx checks the token against a key set and a revocation list it holds, and
# sets the identity source itself. The enforcement point can still skip wardryx.
# This file quotes no person.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: wardryx verifies the agent's own token before it trusts who the agent is

  Scenario: A verified agent token sets the identity source to agent-token
    Given wardryx is configured to verify agent tokens, and a policy requires the agent-token source
    When the enforcement point sends a valid token for the agent it names
    Then the decision is made with the verified source and the policy allows it
    # -> internal/api:TestAVerifiedAgentTokenSetsTheIdentitySource

  Scenario: A token that names another agent is refused and the mismatch is put on the bus
    Given wardryx is configured to verify agent tokens
    When a request names one agent and the valid token it sends is for another
    Then the answer is 403 agent_contradicts_token, no decision is made, and an identity_mismatch event is written
    # -> internal/api:TestATokenNamingAnotherAgentIsRefusedAndPutOnTheBus

  Scenario: An expired token is refused with 403 agent_token_invalid
    Given wardryx is configured to verify agent tokens
    When the enforcement point sends a token that expired more than the leeway ago
    Then the answer is 403 agent_token_invalid and nothing is decided
    # -> internal/api:TestAnExpiredAgentTokenIsRefusedWith403

  Scenario: A revoked token is refused, even after it verified once
    Given a token that verified, and the revocation list then names its jti
    When the same token is presented again
    Then it is refused
    # -> internal/agenttoken:TestARevokedTokenIsRefusedEvenAfterItVerified

  Scenario: A claim of agent-token without a token is refused when verification is configured
    Given wardryx is configured to verify agent tokens
    When a request claims identity_source agent-token and carries no token
    Then the answer is 403 agent_token_required
    # -> internal/api:TestAClaimOfAgentTokenWithNoTokenIsRefused

  Scenario: Without configuration the token is ignored and the request decides as before
    Given wardryx is not configured to verify agent tokens
    When a request carries an agent_token field
    Then the field is ignored and the request is decided as it was before
    # -> internal/api:TestWithoutVerificationTheTokenIsIgnoredAndTheRequestDecidesAsBefore

  Scenario: A token is accepted only for a configured audience
    Given the configured audiences name one resource
    When a valid token names another resource as its audience
    Then it is refused, and a token for the configured resource verifies
    # -> internal/agenttoken:TestAnAgentTokenForAnotherAudienceIsRefused

  Scenario: An expired token is refused, and one inside the leeway is accepted
    Given a token that expired a minute ago and one that expired ten seconds ago
    When each is verified
    Then the first is refused and the second verifies
    # -> internal/agenttoken:TestAnExpiredAgentTokenIsRefusedAndOneInTheLeewayAccepted

  Scenario: Only an ES256 token signed by a key the set holds verifies
    Given a token under a key the set holds, and tokens under an unknown kid or another algorithm
    When each is verified
    Then only the first verifies
    # -> internal/agenttoken:TestOnlyAnES256TokenFromAKnownKeyVerifies

  Scenario: A forged signature, another issuer or a future not-before is refused
    Given a token whose payload was changed after signing, one from another issuer, and one not valid yet
    When each is verified
    Then all three are refused, and a token from the configured issuer verifies
    # -> internal/agenttoken:TestAForgedSignatureOrOtherIssuerOrFutureNotBeforeIsRefused

  Scenario: A failed key-set refresh keeps the set it held
    Given a key set that loaded, and a later refresh that returns a malformed set
    When a token under the loaded key is verified
    Then it still verifies
    # -> internal/agenttoken:TestAFailedKeySetRefreshKeepsTheSetItHeld

  Scenario: The verified-token cache is keyed by the token, never by its jti
    Given a valid token has verified and is cached
    When a different token carries the same jti and is forged
    Then the forged token is refused
    # -> internal/agenttoken:TestTheCacheIsKeyedByTheTokenNotItsJTI

  Scenario: An incomplete configuration refuses to start
    Given an issuer without audiences, or audiences without a key source
    When the verifier is built
    Then it refuses, and says which setting is missing
    # -> internal/agenttoken:TestAnIncompleteConfigurationIsRefused

  Scenario: A partial configuration refuses to start the process
    Given WARDRYX_AGENT_TOKEN_AUDIENCES is set and WARDRYX_AGENT_TOKEN_ISSUER is not
    When the process starts
    Then it refuses to start and names the setting
    # -> cmd/wardryx:TestAPartialAgentTokenConfigurationRefusesToStart

  Scenario: The decide body ignores an unknown field, as it did before
    Given a decide body with a field the server does not declare
    When it is decided
    Then the field is ignored and the decision is made
    # -> internal/api:TestTheDecideBodyIgnoresAnUnknownFieldAsBefore

  Scenario: The agent-token settings are read once from the environment
    Given the WARDRYX_AGENT_TOKEN_* variables are set
    When the configuration is read
    Then each value reaches its setting
    # -> internal/config:TestAgentTokenSettingsAreReadFromTheEnvironment

  Scenario: The key set is fetched from its URL, and a refused poll keeps the set held
    Given WARDRYX_AGENT_TOKEN_JWKS_URL names a key set that loaded
    When the URL answers with an error on a later poll
    Then a token that verified under the held set still verifies
    # -> internal/agenttoken:TestTheKeySetIsFetchedFromItsURLAndAFailedRefreshKeepsIt

  Scenario: The sources are polled on their interval
    Given a running verifier with a key set URL
    When time passes
    Then the URL is asked again and again, not once
    # -> internal/agenttoken:TestTheSourcesArePolledOnTheInterval
