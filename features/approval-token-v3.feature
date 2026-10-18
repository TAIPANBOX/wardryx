# Provenance: @decided 2026-10-18 (paraphrased): wardryx's approval tokens move
# from an HMAC under a secret the service holds to an ES256 signature made by
# the key custody service, Keyryx, which the service verifies from a cached key
# set. The v2 HMAC tokens of earlier grants stay accepted only until a deadline
# the operator sets. The scenarios below are the decision in behaviour; each
# names the test that holds it. @claude 2026-10-18: the bindings and the cases
# that a planted fault must turn red are this repository's own reading.
Feature: An approval token signed by Keyryx, verified from a key set wardryx holds

  Scenario: A grant with Keyryx mints an ES256 token that names its key and its approval
    Given wardryx signs approval tokens through Keyryx
    When a person grants a hold for a call
    Then the token is a three-part JWS whose header names the kid that signed it
    And its claims name the approval, the agent, the run, the tools and the cost
    # -> internal/approval:TestAGrantMintsAnES256TokenNamingItsKidAndTheApproval
    # -> internal/api:TestAGrantWithKeyryxMintsAV3TokenThatDecideAccepts

  Scenario: A token under a kid the verifier does not hold is refused
    Given a token signed under kid k1
    When the verifier holds a key set without k1, even one whose key would verify it
    Then the token is refused as an unknown kid, and the decision does not allow
    # -> internal/approval:TestAnUnknownKidIsRefused
    # -> internal/api:TestAnUnknownKidHoldsAgainOnDecide

  Scenario: A signature that does not verify under its kid is refused
    Given a token whose signature was altered, or made by another key under the same kid
    When the token is verified
    Then it is refused as a bad signature
    # -> internal/approval:TestAForgedOrAlteredSignatureIsRefused

  Scenario: The header pins ES256 and carries no key of its own
    Given a token whose header names another algorithm, a key, a jku, or another type
    When the token is verified
    Then it is refused as malformed before any claim is read
    # -> internal/approval:TestTheHeaderMustPinES256AndCarryNoKey

  Scenario: A v3 token binds the agent, run, tools, cost, call and expiry as a v2 token does
    Given a token granted for one call of one agent
    When the same token is presented for another agent, run, tool set, call, or a higher cost
    Then each is refused, and the same call at a lower cost is allowed
    And a token granted with no call verifies on a request with no call but never lifts a bound hold
    # -> internal/approval:TestV3BindsWhatV2Binds
    # -> internal/approval:TestAV3TokenWithNoCallIsRefusedWhereACallMustBeBound

  Scenario: Keyryx unreachable at grant: nothing is decided and the hold stays pending
    Given Keyryx cannot sign
    When a person grants the hold
    Then the grant answers 503, no token is issued and the approval is not decided
    And a later grant, with Keyryx reachable, succeeds
    # -> internal/approval:TestAGrantWithTheSignerDownLeavesTheHoldPending
    # -> internal/api:TestAGrantWithKeyryxDownAnswers503AndLeavesTheHoldPending

  Scenario: Keyryx unreachable after the key set was fetched: tokens still verify
    Given the verifier fetched Keyryx's key set and Keyryx is now unreachable
    When a token signed under a key in that set is presented
    Then it verifies, and a failed refresh keeps the set the verifier had
    # -> internal/api:TestCachedKeysVerifyWhileKeyryxIsDown
    # -> internal/approval:TestAV3TokenVerifiesWithNoSignerCall
    # -> internal/keyryx:TestAPollThatFailsKeepsTheSetItHad

  Scenario: A v2 HMAC token verifies only until its deadline
    Given a v2 token granted before Keyryx signing was switched on
    When it is presented before the deadline, after it, or with no deadline and a signer set
    Then it verifies before the deadline and is refused after it
    # -> internal/approval:TestAV2TokenVerifiesOnlyBeforeTheDeadline
    # -> internal/api:TestAV2TokenAfterTheDeadlineHoldsAgain

  Scenario: With no signer a grant still mints the v2 token it always did
    Given no signer is configured
    When a person grants a hold
    Then the token is the v2 payload and signature, with no kid and no approval id
    And a grant with neither a signer nor a secret is still refused
    # -> internal/approval:TestWithoutASignerTheGrantMintsTheV2TokenItAlwaysDid
    # -> internal/approval:TestNoSecretAndNoSignerStillRefuses

  Scenario: A kid that moves during a grant is followed once, and a second move fails the grant
    Given the signing key rotates between the header and the signature
    When a grant is made
    Then one move is followed and the token names the kid that signed it
    And two moves in one grant fail it with nothing decided
    # -> internal/approval:TestAKidThatMovesOnceDuringAGrantIsFollowed
    # -> internal/approval:TestAKidThatMovesTwiceFailsTheGrant

  Scenario: Keyryx's published key set is taken whole or not at all
    Given a published key set with an off-curve key, a kid that is not the key's thumbprint, or a revoked kid
    When the verifier fetches it
    Then a malformed set is refused and the cache kept, and a revoked kid leaves at the next fetch
    # -> internal/keyryx:TestAMalformedSetIsRefusedWholeAndTheCacheKept
    # -> internal/keyryx:TestAKidThatIsNotTheKeysThumbprintIsRefused
    # -> internal/keyryx:TestARevokedKidLeavesTheSetAtOnce
