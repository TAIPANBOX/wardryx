# Provenance: @claude, 2026-09-06. These scenarios come from the security
# reviewer's spec for this hardening wave (findings W1-W4), written in the
# operator language the spec itself used (a bearer key, an org, a store that
# is down, a request body). Not a quote from Yurii: no such quote exists for
# this session, so every scenario is @claude rather than @yurii.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: A bare `wardryx serve` does not become an admin key on every interface

  Scenario: no keys and no opt-in authenticates nobody
    Given WARDRYX_KEYS is unset or every entry in it is malformed
    And WARDRYX_ALLOW_DEVKEY is not set
    When the bearer-key spec is parsed
    Then the resulting key map is empty, not the built-in devkey admin credential
    # -> internal/api:TestNoKeysAndNoOptInAuthenticatesNobody

  Scenario: serve refuses to start with no keys and no opt-in
    Given no valid WARDRYX_KEYS and no WARDRYX_ALLOW_DEVKEY
    When serve decides whether to start
    Then it refuses, naming both WARDRYX_KEYS and WARDRYX_ALLOW_DEVKEY as ways out
    # -> cmd/wardryx:TestServeRefusesToStartWithNoKeysAndNoOptIn

  Scenario: the real binary exits rather than listens with an empty environment
    Given the built wardryx binary run with no environment variables at all
    When it is started with `serve`
    Then the process exits instead of opening its listening port
    And the exit output names both WARDRYX_KEYS and WARDRYX_ALLOW_DEVKEY
    # -> internal/manifest:TestARefusingServiceExitsRatherThanListens

  Scenario: the devkey fallback on a non-loopback bind is refused outright
    Given WARDRYX_ALLOW_DEVKEY is set and no real keys are configured
    And -addr binds every interface or another routable address
    When serve decides whether to start
    Then it refuses, this being the exact pairing behind stack-k8s GOTCHAS 20
    # -> cmd/wardryx:TestDevkeyOnARoutableBindIsRefused

  Scenario: the devkey fallback on loopback starts with a loud warning
    Given WARDRYX_ALLOW_DEVKEY is set and no real keys are configured
    And -addr binds loopback only
    When serve decides whether to start
    Then it starts, warning that the insecure devkey credential is active
    # -> cmd/wardryx:TestDevkeyOnLoopbackStartsWithAWarning

  Scenario: an operator-supplied key spec makes WARDRYX_ALLOW_DEVKEY a no-op
    Given WARDRYX_KEYS already has at least one valid entry
    And WARDRYX_ALLOW_DEVKEY is also set
    When serve decides whether to start
    Then it starts normally and warns that the flag had no effect
    # -> cmd/wardryx:TestAllowDevkeySetButKeysAlreadyValidWarnsTheFlagIsUnused

  Scenario: a wide bind with real keys is only warned about, never refused
    Given WARDRYX_KEYS has real entries
    And -addr binds every interface
    When serve decides whether to start
    Then it starts, merely warning about the bind, since k8s binds 0.0.0.0 on purpose
    # -> cmd/wardryx:TestARealKeySpecOnANonLoopbackBindOnlyWarns

Feature: An error from the store never reaches an HTTP response, even folded into a message

  Scenario: a failing store on a fresh hold does not leak the database password
    Given a policy that requires human approval above its cost threshold
    And the approval store is down
    When an agent's action crosses that threshold
    Then the response is a 500 naming the operation, with no database credential in it
    # -> internal/api:TestAStoreErrorWhileRecordingAnApprovalHoldDoesNotLeakTheDatabasePassword

  Scenario: a failing store during single-use redemption does not leak the database password
    Given WARDRYX_APPROVAL_SINGLE_USE is on and a validly signed approval token is presented
    And the approval store is down
    When the token's redemption is recorded
    Then the response is a 500 naming the operation, with no database credential in it
    # -> internal/api:TestAStoreErrorDuringApprovalTokenRedemptionDoesNotLeakTheDatabasePassword

Feature: An admin of one org cannot decide another org's approval

  Scenario: a cross-org decide is refused as though the approval did not exist
    Given an approval hold recorded under one organization
    When an admin key belonging to a different organization tries to decide it
    Then the response is 404, identical to a decide on an unknown id
    And the approval is still pending afterwards
    # -> internal/api:TestAnAdminOfAnotherOrgCannotDecideAnApproval

  Scenario: an approval with no organization on it is decided as before
    Given an approval whose recorded context carries no organization at all
    When any admin key tries to decide it
    Then the decide succeeds, since org scoping only narrows what was already open
    # -> internal/api:TestAnApprovalWithNoOrgInItsContextIsDecidedAsBefore

Feature: A request body has a size an operator can name

  Scenario: an oversized body is refused rather than fully read
    Given a request body larger than the one-megabyte cap
    When it is sent to a route that decodes JSON
    Then the response is 413, and the request is never allowed through on its contents
    # -> internal/api:TestAnOversizedBodyIsRefusedWithoutBeingRead

  Scenario: an ordinary body is unaffected by the cap
    Given a request body well under the one-megabyte cap
    When it is sent to a route that decodes JSON
    Then it is processed normally
    # -> internal/api:TestABodyAtOrUnderTheCapIsUnaffected
