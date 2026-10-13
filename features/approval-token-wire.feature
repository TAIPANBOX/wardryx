# Provenance: @measured 2026-10-13 by `grep -rn x-fuse-approval-token` over this
# repository and over tokenfuse. The README's decision table told a reader to
# redeem a hold by resubmitting the call "with header x-fuse-approval-token", and
# docs/decisions.svg and docs/architecture.svg drew the same thing. Wardryx reads
# one header, Authorization; handleDecide takes the token from the approval_token
# field of the /v1/decide body. The header belongs to TokenFuse, the enforcement
# point, which reads it from the agent's request and forwards its value in that
# field (tokenfuse crates/gateway/src/proxy.rs, held there by
# approval_token_header_is_forwarded_to_decide_call). So the code on both sides
# was right and the README described the gateway's surface as this service's.
# This file quotes no person.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: An approval token reaches wardryx in the request body, and the README says so

  Scenario: A granted token sent in a header is not read and is not spent
    Given a call held for a human, and a token granted for that hold, with single-use on
    When the same call is sent to /v1/decide with the token in the x-fuse-approval-token header and an empty approval_token field
    Then the call is held again, as it is for any header a caller might guess
    And the same token in the approval_token field of the body is then allowed, so no header attempt spent it
    # -> internal/api:TestAnApprovalTokenSentAsAHeaderIsNotRead

  Scenario: Every header the README and its diagrams name is one wardryx reads, or is said to be TokenFuse's
    Given the README, its code blocks, and the text of every diagram under docs and assets
    When a sentence, a table cell, a code line or a diagram text names an x- header
    Then that header is one the code of this repository reads, or the same sentence names TokenFuse
    # -> cmd/wardryx:TestReadmeNamesNoHeaderWardryxDoesNotRead

  Scenario: The check catches the sentence that drifted, and passes a true one
    Given a copy of the README carrying the decision table row as it read before 2026-10-13, or a copy of the decisions diagram carrying its old hold card
    When the header check reads the copy
    Then it reports x-fuse-approval-token as a header wardryx does not read
    And a sentence that attributes the header to TokenFuse, or a header the code reads, is reported as nothing
    # -> cmd/wardryx:TestReadmeHeaderCheckCatchesPlantedFaults
