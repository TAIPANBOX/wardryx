# Provenance: @decided 2026-10-13, paraphrased: every document in a YAML policy
# file, and every value in a JSON policy file, is loaded, in order. A document
# or value that fails to decode fails the whole file and is named by its
# position. Data after a JSON value is refused, never ignored. A single-document
# file keeps its PolicyVersion. The defect this closes: a file with several
# documents or values loaded only the first, with no error, so a rule after it
# was silently not in force. This file quotes no person.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: Wardryx loads every document or value of a multi-document policy file

  Scenario: A rule in the second document is enforced
    Given a policy file whose first document denies one tool and whose second document denies another
    When the agent asks for the tool the second document denies
    Then the request is denied, and the reason names the second document's policy
    # -> internal/pdp:TestARuleInTheSecondDocumentIsEnforced

  Scenario: Every document loads, in order
    Given a policy file of three documents: one policy, a list of two policies, and one policy
    When the file is loaded
    Then all four policies are in force, and each one matches the agents it targets
    # -> internal/policy:TestEveryDocumentOfAFileLoads

  Scenario: An empty document is skipped and is not a policy
    Given a policy file with two empty documents between real ones and a separator at the end
    When the file is loaded
    Then only the real policies load, and no error is reported
    # -> internal/policy:TestAnEmptyDocumentIsSkippedNotCountedAsAPolicy

  Scenario: A malformed document fails the whole file, naming the document
    Given a policy file whose first document is valid and whose second is not a policy
    When the file is loaded
    Then the load fails, the error names the second document, and no set is returned
    # -> internal/policy:TestAMalformedDocumentFailsTheWholeFileNamingIt

  Scenario: A misspelled field in a later document is refused
    Given a policy file whose second document misspells a field name
    When the file is loaded
    Then the load fails, and the error names the second document and the field
    # -> internal/policy:TestAMisspelledFieldInALaterDocumentIsRefused

  Scenario: A single-document file keeps its PolicyVersion
    Given a policy file with one document, the same file with a leading separator, and the same file with a trailing separator
    When each one is loaded
    Then each reports the PolicyVersion the single-document file reported before this change
    # -> internal/policy:TestASingleDocumentFileKeepsItsPolicyVersion

  Scenario: The version of a multi-document file covers every policy in it
    Given a policy file with two documents
    When the rule in the second document changes
    Then the PolicyVersion changes, and equals the version of the same policies compiled together
    # -> internal/policy:TestTheVersionOfAMultiDocumentFileCoversEveryPolicy

  Scenario: Every document of every file in a directory loads
    Given a directory holding one file of two documents and one file holding a list of two policies
    When the directory is loaded
    Then all four policies are in force
    # -> internal/policy:TestADirectoryLoadsEveryDocumentOfEveryFile

  Scenario: Every value of a JSON policy file loads, in order
    Given a JSON policy file of four values: one policy, a list of two policies, a null, and one policy
    When the file is loaded
    Then the four policies are in force, each one matches the agents it targets, and the null holds no policy
    # -> internal/policy:TestEveryValueOfAJSONFileLoads

  Scenario: Data after a JSON value is refused, not ignored
    Given a JSON policy file whose first value is a valid policy and whose second is bytes that are not a whole value
    When the file is loaded
    Then the load fails, the error names the second value, and no set is returned
    # -> internal/policy:TestDataAfterAJSONValueIsRefusedNotIgnored

  Scenario: A JSON value that fails strict decoding fails the whole file, naming the value
    Given a JSON policy file whose second value misspells a field or gives a value of the wrong type
    When the file is loaded
    Then the load fails, and the error names the second value and, for a misspelled field, the field
    # -> internal/policy:TestAJSONValueThatFailsStrictDecodingFailsTheFileNamingIt

  Scenario: An empty JSON file is refused, as before
    Given a JSON policy file with no value in it
    When the file is loaded
    Then the load fails with the decoder's end-of-input error, as it did before this change
    # -> internal/policy:TestAnEmptyJSONFileIsRefusedAsBefore

  Scenario: A single-value JSON file keeps its PolicyVersion
    Given a JSON policy file with one value, and the same value padded with whitespace
    When each one is loaded
    Then each reports the PolicyVersion the single-value file reported before this change
    # -> internal/policy:TestASingleValueJSONFileKeepsItsPolicyVersion
