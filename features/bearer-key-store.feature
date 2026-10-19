# Provenance: @decided 2026-10-17 (paraphrased): close the agent-security
# findings of the 2026-10-17 review, starting with the small fixes. Finding
# F-023: a bearer key was compared by a lookup keyed by its raw value, which is
# not a constant-time comparison.
# @claude 2026-10-19, the shape, fixed in this change from the review's brief:
# the key store is keyed by the SHA-256 of each configured key, a presented
# bearer is digested and compared with every configured digest in constant
# time (no lookup of the store), and the MAC comparisons stay in constant
# time. This file quotes no person.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: A bearer key is stored and looked up by its digest, never by its value

  Scenario: The key store holds no raw bearer secret
    Given WARDRYX_KEYS names four keys, one for each role
    When the server is built from that key spec
    Then no key the store holds equals one of the configured secrets
    # -> internal/api:TestTheKeyStoreHoldsNoRawSecret

  Scenario: Every role still authenticates with its own key
    Given WARDRYX_KEYS names an admin, a viewer, an enforcement point and a cross-org admin
    When each presents its own key to a route its role may use
    Then none is refused as unauthenticated, and a role outside an admin route is refused as not admin
    # -> internal/api:TestEveryRoleStillAuthenticatesWithItsKey

  Scenario: A key that is almost right is refused with 401
    Given the admin key of WARDRYX_KEYS
    When a caller presents that key with one byte changed, shortened, lengthened, in upper case, or cut to a prefix
    Then the answer is 401 for each of them
    # -> internal/api:TestANearMissKeyIsRefusedWith401

  Scenario: A presented bearer is compared with every configured key, with no early exit
    Given WARDRYX_KEYS names several keys
    When a request presents a bearer
    Then its digest is compared with every configured digest in constant time, and that comparison alone decides the match
    # -> internal/api:TestTheBearerIsComparedInConstantTime

  Scenario: An approval token's MAC is compared in constant time
    Given an approval token whose signature and tool-call digest are checked
    When the verifier compares each with the value it computed
    Then both comparisons use hmac.Equal and neither uses == or !=
    # -> internal/approval:TestTheSignatureAndTheDigestAreComparedInConstantTime
