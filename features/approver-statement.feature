# Provenance: @decided 2026-10-19 (paraphrased): an approval names the person who
# gave it, and the decision is recorded against that person when a verified
# statement from the console says who it was. Decisions that carry no statement
# are recorded as the key that made them, as before.
# @claude 2026-10-19, the shape: wave3/approval-statement-proposal.md (compact JWS,
# ES256, signed by the console device key after the passkey assertion, verified
# against a static JWK set named by WARDRYX_APPROVER_JWKS).
# This file quotes no person.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: An approval names the person who gave it, when a verified statement says who

  Scenario: A grant with a verified statement records the approver and the passkey credential
    Given an approval held for a call, and a console key set in WARDRYX_APPROVER_JWKS
    When the decision carries a statement the console signed for that approval and grant
    Then the approval records decided_by as approver:<id>, approver_kind as person, and the event names the approver and the credential
    # -> internal/api:TestAGrantWithAVerifiedStatementRecordsThePersonNotTheKey

  Scenario: A decision with no statement is recorded as the key that made it
    Given an approval held for a call
    When a grant arrives with no statement
    Then the approval records decided_by as the key and approver_kind as key
    # -> internal/api:TestAGrantWithoutAStatementIsRecordedAsAKey

  Scenario: A statement the console did not sign leaves the hold pending
    Given a console key set, and a statement signed by another key for the same approval
    When the decision carries that statement
    Then the answer is 403 approver_statement_invalid, the hold stays pending, and the statement is not echoed
    # -> internal/api:TestAStatementThatDoesNotVerifyLeavesTheHoldPending

  Scenario: A statement for another approval is refused
    Given a statement the console signed for one approval
    When it is presented on the decision of a different approval
    Then the answer is 403
    # -> internal/api:TestAStatementForAnotherApprovalIsRefused

  Scenario: A server with no console key set refuses every statement
    Given WARDRYX_APPROVER_JWKS is unset
    When a decision carries a statement
    Then the answer is 403 approver_statement_invalid
    # -> internal/api:TestAStatementWithNoApproverKeySetIsRefused

  Scenario: A statement signed by another key under the console's kid is refused
    Given a console key set
    When a statement is signed by another key and names the console's kid
    Then the statement is refused
    # -> internal/approverstmt:TestAStatementSignedByAnotherKeyIsRefused

  Scenario: A statement cannot carry its own key or a key location in its header
    Given a console key set
    When a statement's header names alg none, another typ, or carries a jwk, x5c or jku
    Then each is refused
    # -> internal/approverstmt:TestTheHeaderIsPinnedAndCarriesNoKey

  Scenario: A statement outside its validity window is refused
    Given a console key set
    When a statement has expired past the leeway, is issued in the future, or lives longer than five minutes
    Then each is refused, and one that expired inside the leeway is accepted
    # -> internal/approverstmt:TestAStatementOutsideItsWindowIsRefused

  Scenario: A hostile approver name or credential id is refused
    Given a console key set
    When a statement's sub, cred or jti is empty, oversize, or carries a control character or a bidirectional override
    Then the statement is refused
    # -> internal/approverstmt:TestAHostileApproverOrCredentialOrJTIIsRefused

  Scenario: A key set that does not read refuses to load, and a valid one is read from its file
    Given the file named by WARDRYX_APPROVER_JWKS
    When the file is not a JWK set, holds a key that is not EC P-256, or holds two keys with one thumbprint
    Then it is refused whole, and a valid set in the file verifies the console's statements
    # -> internal/approverstmt:TestAnUnreadableKeySetIsRefusedWhole
    # -> internal/approverstmt:TestTheKeyFileIsReadAsAJWKSet
