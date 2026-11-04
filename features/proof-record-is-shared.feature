# Provenance: @decided 2026-11-04 (paraphrased): with a database configured, the
# record of accepted DPoP proofs is shared the way approval redemption is, so a
# restart or a second instance does not accept a proof a first one accepted, and
# without a database the record stays in the process, with that limit written
# where an operator reads it.
# @claude 2026-11-04, a decision taken under delegated authority, open to
# reversal: a record that cannot be asked refuses the proof, with 503 for a store
# that is gone and 500 for a store that answered with a failure of its own,
# because a proof nobody could check for replay is a proof that may be a replay.
# This file quotes no person.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: A DPoP proof is accepted once by every wardryx on one database

  Scenario: a proof one instance accepted is refused by another
    Given two wardryx instances on one database
    When the same proof is presented to the first and then to the second
    Then the first accepts it and the second answers 403 agent_token_proof_invalid
    # -> internal/manifest:TestTheBuiltBinaryRefusesAProofAcrossTwoInstancesAndARestart
    # -> internal/api:TestAProofAcceptedByOneInstanceIsRefusedByAnother
    # -> internal/agenttoken:TestAProofAcceptedByOneVerifierIsRefusedByAnotherOnTheSameRecord

  Scenario: a proof accepted before a restart is refused after it
    Given a wardryx on a database that accepted a proof
    When the process is stopped, started again, and shown the same proof inside its window
    Then the answer is 403 agent_token_proof_invalid, and a fresh proof is accepted
    # -> internal/manifest:TestTheBuiltBinaryRefusesAProofAcrossTwoInstancesAndARestart
    # -> internal/agenttoken:TestAVerifierBuiltAfterARestartRefusesAProofTheRecordHolds

  Scenario: one proof presented at once to two instances is accepted once
    Given two verifiers on one real database
    When the same proof is presented many times at once to both
    Then exactly one presentation is accepted
    # -> internal/agenttoken:TestTwoVerifiersOnOneDatabaseAcceptAProofOnceUnderConcurrentPresentation
    # -> internal/store:TestPgTryRecordProofIsAtomicAcrossConnections

  Scenario: a store that is gone refuses the proof rather than passing it
    Given a wardryx whose database has gone away
    When an agent presents a fresh proof that is good in every other way
    Then the answer is 503 agent_token_proof_unrecorded and no decision is made
    And the store's own error text does not leave the process
    # -> internal/api:TestAProofIsRefusedWith503WhenTheRecordIsUnreachable
    # -> internal/manifest:TestTheBuiltBinaryRefusesAProofWhileItsDatabaseIsGone
    # -> internal/agenttoken:TestARecordThatCannotBeAskedRefusesTheProof

  Scenario: a store that hangs refuses the proof within the deadline
    Given a database that accepts a connection and never answers
    When an agent presents a proof
    Then the answer is 503 within the store deadline, never a hang
    # -> internal/api:TestAProofOnAHangingRecordIsRefusedWithinTheDeadline
    # -> internal/manifest:TestTheBuiltBinaryRefusesAProofOnAHangingDatabaseWithinTheDeadline

  Scenario: a caller that hangs up does not cut the claim short
    Given a database that hangs and a caller that gives up before the store deadline
    When the caller goes away
    Then the claim runs to its own deadline, and the outage is logged once as an outage
    # -> internal/api:TestACallerThatHangsUpDoesNotCutTheClaimShort

  Scenario: a store that answers with a failure of its own refuses the proof too
    Given a database that answers the write with an error that is not an outage
    When an agent presents a proof
    Then the answer is 500, no decision is made, and the error text is only in the log
    # -> internal/api:TestARecordFailureThatIsNotAnOutageIsRefusedWith500

  Scenario: a request that carries no proof still decides while the store is down
    Given a wardryx whose database has gone away
    When a request carries no token, or a token where proofs are optional
    Then it is decided from the policy set in memory, as before
    # -> internal/api:TestARequestWithNoProofStillDecidesWhileTheRecordIsDown
    # -> internal/manifest:TestTheBuiltBinaryRefusesAProofWhileItsDatabaseIsGone

  Scenario: a proof refused because nothing could be written is not spent
    Given a proof refused because the database could not be reached at all
    When the database is back and the same proof is presented inside its window
    Then it is accepted once, and a proof accepted before the outage stays refused
    # -> internal/manifest:TestTheBuiltBinaryRefusesAProofWhileItsDatabaseIsGone

  Scenario: an outage of the record is logged when it starts and when it ends
    Given proofs keep arriving while the database is gone and after it returns
    When each is answered
    Then the log carries one line for the outage and one for its end
    # -> internal/api:TestARecordOutageIsLoggedOncePerOutage
    # -> internal/api:TestARequestWithNoProofSaysNothingAboutTheRecord

  Scenario: a proof is kept past the longest window, and rows past that are removed
    Given a proof accepted at a known time, on an instance with any window set
    When the record is written and the purge runs
    Then the row lasts until the longest window closes, and the longest window again
    And a row past both is removed, and no other
    # -> internal/agenttoken:TestTheRecordIsAskedToKeepAProofUntilTheLongestWindowCloses
    # -> internal/agenttoken:TestExpiredProofsArePurgedAtStartAndOnTheInterval
    # -> internal/store:TestPgPurgeProofsRemovesOnlyRowsPastTheirWindowAndTheGrace

  Scenario: a purge that fails costs nothing but the row count
    Given a record that fails a purge
    When the interval comes round
    Then the failure is reported, the next purge still runs, and no proof is refused by it
    # -> internal/agenttoken:TestAFailedPurgeIsReportedAndTheLoopGoesOn

  Scenario: what a client put in a jti reaches the database only as a digest
    Given a holder's proof whose jti carries a NUL, quotes or 256 bytes
    When it is recorded
    Then the key is 64 hex characters and carries none of those bytes
    # -> internal/agenttoken:TestTheRecordKeyIsAFixedSizeDigestWhateverTheJTIHolds
    # -> internal/agenttoken:TestAHostileJTIIsHeldByARealDatabase

  Scenario: two holders do not share a jti
    Given two holders of two keys
    When each sends a proof with the same jti
    Then both are accepted, and a second presentation of either is refused
    # -> internal/agenttoken:TestTwoHoldersMayUseOneJTIAndOneHolderMayNotUseItTwice

  Scenario: a proof refused for any other reason writes nothing
    Given a shared record
    When a proof is stale, names another token, goes to a foreign door or is forged
    Then the record is never asked
    # -> internal/agenttoken:TestAProofRefusedForAnythingElseWritesNothingToTheRecord

  Scenario: without a database the record is per process, and the start says so
    Given wardryx verifies agent tokens and no database is configured
    When two instances are started and shown one proof
    Then each accepts it, and each said at start that the record is per process
    # -> internal/manifest:TestWithoutADatabaseTheRecordIsPerProcessAndTheStartSaysSo
    # -> cmd/wardryx:TestThePerProcessProofRecordIsWarnedAtStartup
