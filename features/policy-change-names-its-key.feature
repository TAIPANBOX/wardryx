# Provenance: @claude 2026-10-15, a design fixed by the supervisor session of this
# audit (paraphrased). A policy_updated event names the key that made the change,
# as a fingerprint of the key's bytes; the organisation stays in decided_by, which
# current readers already use. The raw key is never written anywhere.
# This file quotes no person.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: A policy change names the key that made it

  Scenario: A PUT of a policy records the fingerprint of the key that made the write
    Given two bearer keys that both belong to one organisation
    When one of them writes a policy with PUT
    Then the policy_updated event carries key_fp, the first 16 hex characters of SHA-256 of that key
    # -> internal/api:TestAPolicyPutRecordsTheFingerprintOfTheKeyThatMadeIt

  Scenario: A DELETE of a policy records the fingerprint of the key that made the delete
    Given a policy written by one key and removed by the other key of the same organisation
    When the policy is removed with DELETE
    Then the second policy_updated event carries the fingerprint of the key that deleted it
    # -> internal/api:TestAPolicyDeleteRecordsTheFingerprintOfTheKeyThatMadeIt

  Scenario: The raw key never reaches the event file
    Given a policy written and removed under two bearer keys with events enabled
    When the event file is read in full
    Then neither bearer key appears anywhere in it
    # -> internal/api:TestTheRawKeyNeverReachesTheEventFile

  Scenario: A recorded fingerprint is sixteen lower-case hex characters and never the fingerprint of an empty key
    Given a policy written and removed under two bearer keys with events enabled
    When each policy_updated event is read
    Then its key_fp is sixteen lower-case hex characters, and is not the fingerprint of the empty string
    # -> internal/api:TestTheRecordedFingerprintIsSixteenLowerCaseHexAndNotTheEmptyKeys

  Scenario: Two keys of one organisation can be told apart in the record
    Given a policy written by one key and removed by the other key of the same organisation
    When the two policy_updated events are compared
    Then their key_fp values differ
    # -> internal/api:TestTwoKeysOfOneOrganisationAreToldApart

  Scenario: decided_by still names the organisation
    Given a policy written and removed under two bearer keys of one organisation
    When each policy_updated event is read
    Then its decided_by is the organisation, unchanged by the addition of key_fp
    # -> internal/api:TestTheDecidedByFieldStillNamesTheOrganisation
