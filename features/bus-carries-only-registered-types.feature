# Provenance: @decided 2026-11-07 (paraphrased): where wardryx and the shared event
# registry (agent-passport SPEC.md section 6.2) disagree, wardryx changes and the
# registry does not. The two types 2.6.0 added outside the registry come off the bus,
# and the facts they carried are kept. The scenarios are that decision in the
# repository's own words (invariant 50, and invariants 48 and 49 for the two facts).
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: The shared bus carries only the types the registry lists for wardryx

  Scenario: everything the server writes onto the bus is in the registry row at its severity
    Given the copy of SPEC 6.2's wardryx row
    When a server starts, allows, denies, holds past the pending cap, has holds granted and denied, takes a policy write and sweeps an unanswered hold
    Then every event it wrote is a type the row lists, at the severity the row gives it
    # -> internal/api:TestEveryEventTheServerWritesIsInTheSpecRowAtItsSeverity
    # -> internal/manifest:TestTheBuiltBinaryHoldsAToolCallNothingGrants

  Scenario: an agent past the pending cap puts no new type on the bus
    Given a floor and an agent at its pending cap
    When the agent's calls go on being held
    Then each hold is recorded as approval_requested with queue_full, and nothing else is written for it
    And one warning line in the log names the agent, its run and the limit, once per process
    # -> internal/api:TestAnAgentPastTheCapPutsNoNewTypeOnTheBus
    # -> internal/api:TestAnAgentPastTheCapIsLoggedOncePerProcess

  Scenario: an agent id written to break the log stays inside its line
    Given an agent id with a line break and a forged log line in it
    When that agent reaches the pending cap
    Then the log line carries the id quoted, and no line of the caller's making appears
    # -> internal/api:TestAnAgentIDWithALineBreakStaysOneLogLine

  Scenario: a start writes nothing onto the bus and says what it decides under
    Given a process with a policy file and a policy archive
    When it comes up
    Then no event is written, and one log line names the version, the counts, the floors and the archived file of that set
    # -> internal/api:TestTheStartPutsNothingOnTheBus
    # -> internal/api:TestTheStartIsLoggedWithTheVersionTheFirstDecisionNames
    # -> internal/archive:TestFileNamesWhereAKeptVersionLives
