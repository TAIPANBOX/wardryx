# Provenance: @decided 2026-10-18 (paraphrased): a decision whose record cannot
# be written is not returned as an allow or a hold under the closed record fail
# mode, which is the default. Open is an explicit choice, and it is visible.
# Finding F-011 of the 2026-10-17 agent-security review.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: A decision is not returned when the record of it could not be written

  Scenario: an allow is refused when its record cannot be written
    Given wardryx is in its default closed record fail mode and its record writer refuses every write
    When a governed agent asks /v1/decide for a call the policy allows
    Then the answer is 503 record_unavailable and no allow is returned
    # -> internal/api:TestAnAllowIsRefusedWhenItsRecordCannotBeWritten

  Scenario: a hold is refused when its record cannot be written
    Given wardryx is in its default closed record fail mode and its record writer refuses every write
    When a governed agent asks /v1/decide for a call that needs a person to approve it
    Then the answer is 503 record_unavailable and no hold is returned
    # -> internal/api:TestAHoldIsRefusedWhenItsRecordCannotBeWritten

  Scenario: a deny is still returned when its record cannot be written
    Given wardryx is in its default closed record fail mode and its record writer refuses every write
    When a governed agent asks /v1/decide for a call the policy denies
    Then the answer is the deny, because a refusal is the safe direction
    # -> internal/api:TestADenyIsStillReturnedWhenItsRecordCannotBeWritten

  Scenario: the record of an allow is attempted before the allow is returned
    Given wardryx is in its default closed record fail mode
    When a governed agent asks /v1/decide for a call the policy allows
    Then exactly one record write is attempted before the answer leaves
    # -> internal/api:TestTheAllowRecordIsAttemptedBeforeItIsReturned

  Scenario: open mode returns the allow and says so on the readiness probe
    Given wardryx is in the open record fail mode and its record writer refuses every write
    When a governed agent asks /v1/decide for a call the policy allows, and a launcher asks GET /readyz
    Then the allow is returned, and /readyz answers 503 with the record named as failing
    # -> internal/api:TestOpenModeReturnsTheAllowAndRaisesTheHealthFlag

  Scenario: readiness clears once a record write succeeds again
    Given wardryx refused an allow because its record writer refused every write
    When the record writer accepts writes again and the next allow is recorded
    Then the allow is returned and /readyz answers 200 again
    # -> internal/api:TestReadyzClearsWhenARecordWriteSucceedsAgain

  Scenario: with no record configured, closed mode refuses nothing
    Given wardryx has no record writer, so no record can fail to be written
    When a governed agent asks /v1/decide for a call the policy allows
    Then the allow is returned
    # -> internal/api:TestWithNoRecordWriterNothingIsRefused

  Scenario: the record fail mode is closed when the variable is not set
    Given WARDRYX_RECORD_FAILMODE is not set
    When wardryx reads its configuration
    Then the record fail mode is closed
    # -> internal/config:TestTheRecordFailModeDefaultsToClosed

  Scenario: only an explicit open selects the open mode
    Given WARDRYX_RECORD_FAILMODE is set to a value other than open
    When wardryx reads its configuration
    Then the record fail mode is closed
    # -> internal/config:TestRecordFailModeIsOpenOnlyWhenAskedFor

  Scenario: serve warns at startup when the open mode is chosen
    Given WARDRYX_RECORD_FAILMODE is open
    When serve starts
    Then the startup warning names the variable and the readiness signal
    # -> cmd/wardryx:TestTheOpenFailModeIsWarnedAtStartup
