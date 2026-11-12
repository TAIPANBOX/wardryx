# Provenance: @decided 2026-11-12, the owner approved this change: a person
# approving a tool call is shown its arguments, taken from the enforcement point
# and never from what a model wrote; secrets and personal data are hidden by
# fixed rules; what is kept is sealed to the console and lives at most a day; a
# decision made without seeing the arguments is allowed and marked. This file
# states that decision in the repository's own words; it quotes no person.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: A person deciding a held call is shown its arguments

  Scenario: A person sees the arguments of a call that waits for them
    Given a policy that holds a tool call
    When an agent calls the tool with a repository and an action
    Then the preview of the hold shows the repository and the action
    And the preview is built from the same bytes the grant is bound to
    # -> internal/preview:TestAPersonSeesTheArgumentsOfAHeldCall
    # -> internal/api:TestAHeldCallKeepsASealedPreviewThatOnlyTheConsoleKeyOpens
    # -> internal/api:TestThePreviewIsBuiltFromTheBytesTheGrantIsBoundTo

  Scenario: A password in the arguments cannot be read
    Given arguments with a user and a password
    When the preview is built
    Then the user is shown and the password is hidden by the rule on its key name
    And the password's value appears nowhere in the preview
    # -> internal/preview:TestAMemberWhoseKeyNamesACredentialIsHiddenWhole
    # -> internal/preview:TestPlantedSecretsNeverAppearInTheDocument

  Scenario: A secret or a piece of personal data inside a text is hidden and the rest of the text shows
    Given a note that carries an API key, an email address, a card number or an IBAN
    When the preview is built
    Then that part of the note is hidden by its kind and the words around it are shown
    And a long random token is hidden while a commit id stays visible
    # -> internal/preview:TestEverySecretKindInsideAStringIsHiddenAndTheRestShows
    # -> internal/preview:TestTheSecretKindsAreTheBrokersKinds
    # -> internal/preview:TestPersonalDataInsideAStringIsHiddenAndTheRestShows
    # -> internal/preview:TestAHighEntropyRunIsHiddenAndAHexDigestIsNot

  Scenario: A secret from the broker's vault is shown by its name and has no value to show
    Given arguments that refer to a vault secret by its handle
    When the preview is built
    Then the handle's name is shown and no value is
    # -> internal/preview:TestAVaultHandleShowsItsNameAndNoValue

  Scenario: An image sent as base64 is shown as its type, size and hash
    Given arguments that carry an encoded picture
    When the preview is built
    Then the picture is shown as its type, its size and its hash, never decoded
    And a long name made of words is still shown as text
    # -> internal/preview:TestABase64ImageIsShownAsTypeSizeAndHashAndNeverDecoded
    # -> internal/preview:TestALongIdentifierIsTextAndNotABlob

  Scenario: A long text is cut, with how long it was and a hash of the whole
    Given a text longer than the preview shows
    When the preview is built
    Then its beginning is shown, cut between characters, with its length and its hash
    And deep, wide or large arguments are cut with a count of what was left out
    # -> internal/preview:TestALongStringIsCutOnARuneBoundaryWithItsCountAndHash
    # -> internal/preview:TestDepthArrayAndObjectLimits
    # -> internal/preview:TestTheDocumentIsBoundedInSize

  Scenario: Text that does not read as it looks is marked
    Given a text with a character that reverses the direction of what follows, or a lookalike letter
    When the preview is built
    Then the text carries a mark that names what is wrong with it
    And a repeated key is shown twice and marked, and numbers are shown as written
    # -> internal/preview:TestCharactersThatDoNotReadAsTheyLookAreFlagged
    # -> internal/preview:TestDuplicateKeysAreShownBothAndMemberOrderIsTheOrderOfTheBytes
    # -> internal/preview:TestANumberIsShownAsWritten

  Scenario: The same arguments always give the same preview and the same digest
    Given the same argument bytes built twice
    When their previews are compared
    Then they are identical and their digest is the pinned one
    And arguments that are not JSON are refused
    # -> internal/preview:TestBuildIsDeterministicAndTheDigestIsPinned
    # -> internal/preview:TestTheDigestSeparatesDocumentsAndHasTheShapeItChecks
    # -> internal/preview:TestArgumentsThatAreNotOneJSONValueAreRefused

  Scenario: Only the console's key opens what wardryx keeps
    Given a sealed preview of a hold
    When an admin key fetches it, or another org's admin, or the enforcement point
    Then the admin gets ciphertext only the console's key opens, the other org gets not found, and the enforcement point is refused
    And a ciphertext moved to another hold or changed by one bit does not open
    # -> internal/previewseal:TestASealedPreviewOpensOnlyUnderTheConsoleKeyAndItsBinding
    # -> internal/previewseal:TestAPreviewDigestThatIsNotTheDocumentsIsRefusedBothWays
    # -> internal/previewseal:TestTheInfoCannotBeForgedByMovingBytesBetweenFields
    # -> internal/previewseal:TestOnlyTheTwoAllowedKEMsAreAccepted
    # -> internal/previewseal:TestHostileCiphertextsAreRefusedWithoutPanic
    # -> internal/api:TestAPreviewIsReadOnlyByAnAdminOfTheHoldsOrg

  Scenario: The record, the hold and the list never carry the arguments
    Given a held call
    When the event record, the hold's context and the approvals list are read
    Then none of them carries the arguments, and the record carries the preview's state and digest
    # -> internal/api:TestNothingOfTheArgumentsReachesTheRecordTheContextOrTheList

  Scenario: A person who saw the preview grants, and the record says so
    Given a sealed preview of a hold
    When a person's statement names the call and the preview and grants
    Then the grant is recorded as seen, with both digests, and the preview is deleted
    # -> internal/api:TestAPersonWhoSawThePreviewGrantsAndTheRecordSaysSeen
    # -> internal/approverstmt:TestAVersion2StatementNamesTheCallAndThePreviewThePersonWasShown

  Scenario: A decision signed for another preview or another call is refused and nothing is written
    Given a sealed preview of a hold
    When a statement names another preview, another call, no preview, or is of the old version
    Then it is refused, the hold stays pending, and the preview stays
    # -> internal/api:TestAStatementForAnotherPreviewOrCallIsRefusedAndNothingIsDecided
    # -> internal/approverstmt:TestAVersion2StatementWithAMalformedDigestIsRefused
    # -> internal/approverstmt:TestAVersion1StatementCannotCarryTheVersion2ClaimsAndOtherVersionsAreRefused

  Scenario: A person may refuse a call without reading its arguments
    Given a sealed preview of a hold
    When a person denies it with a statement that names no preview
    Then the denial is made and recorded as unseen, while a grant named the same way is refused
    # -> internal/api:TestAPersonMayDenyASealedHoldWithoutOpeningItAndTheRecordSaysUnseen

  Scenario: A decision without a preview is allowed and marked
    Given a hold whose arguments could not be shown
    When a person decides it
    Then the decision is made and the record marks it as unseen, with the reason
    # -> internal/api:TestADecisionWithoutAPreviewIsAllowedAndMarkedUnseen
    # -> internal/api:TestTruncatedArgumentsRecordNoPreview
    # -> internal/api:TestAHoldWithNoCallRecordsNoPreviewAndIsDecidedAsBefore

  Scenario: A policy can require that a person saw the arguments before a grant
    Given a policy in the policy file that requires a preview
    When a grant comes from a person who saw none, or from a key
    Then the grant is refused and a denial is still allowed
    And the requirement cannot be written through the policy API
    # -> internal/api:TestRequirePreviewRefusesAGrantNobodySawAndAllowsADeny
    # -> internal/api:TestRequirePreviewCannotBeWrittenThroughThePolicyAPI
    # -> internal/api:TestACallWithNoArgumentsHasNothingToShowAndAPersonMayGrantItUnderRequirePreview

  Scenario: What is kept lives until the decision or a day, whichever comes first
    Given a sealed preview nobody answered
    When its time passes
    Then it is no longer served and is purged, and the hold stays
    And both stores delete a preview with the decision of its hold
    # -> internal/api:TestAPreviewPastItsTimeIsNotServedAndIsPurged
    # -> internal/api:TestPreviewTTLIsBounded
    # -> internal/api:TestARepeatedHeldCallKeepsOnePreview
    # -> internal/api:TestWatchPreviewsPurgesUntilItsContextEnds
    # -> internal/store:TestTheMemoryStoreKeepsAPreviewUntilItIsDecidedOrExpires
    # -> internal/store:TestPgKeepsAPreviewUntilItIsDecidedOrExpires

  Scenario: The console's preview key is made by the operator and a bad one refuses the start
    Given an operator who generates a preview key
    When the key is written and the recipient is given to wardryx
    Then the private key is a file only its owner reads, and a recipient that does not parse refuses the start
    # -> cmd/wardryx:TestPreviewKeyWritesAPrivateFileAndPrintsTheRecipient
    # -> cmd/wardryx:TestAPreviewRecipientOrTTLThatDoesNotParseRefusesTheStart
