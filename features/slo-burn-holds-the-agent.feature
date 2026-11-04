# Provenance: @decided 2026-11-04 (paraphrased): an agent whose error budget is
# spent has its actions put to a person, with no change to how the budget is
# measured. @claude 2026-11-04, the shape: the decision point reads the quality
# plane's own event file and adds one standing signal to a decision; the policy,
# not the file, decides whether that signal holds anything. The scenarios
# describe the option in the repository's own words; they quote no person.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: An agent whose error budget is spent has its actions put to a person

  Scenario: A spent budget holds the agent's tool calls when the policy says so
    Given the quality plane's event file says the budget of an agent is exhausted
    And a policy that holds on the slo_burn signal when it is exhausted or a fast burn
    When that agent proposes a tool call
    Then the call is held for a person, and the reason names the signal and its value
    And a person who grants the hold lets that one call through
    # -> internal/api:TestAnExhaustedAgentsToolCallIsHeldWhenThePolicyHoldsOnTheSignal
    # -> internal/api:TestAGrantedApprovalLiftsTheBudgetHoldForThatCall

  Scenario: The policy the documentation shows is the one that works
    Given the example policy in docs/examples, copied as an operator would copy it
    When an agent with a spent budget proposes a tool call, and an agent with no event does
    Then the first is held and the second is allowed
    # -> internal/api:TestTheExamplePolicyHoldsAnAgentWhoseBudgetIsSpent

  Scenario: Without a rule that reads the signal, nothing changes
    Given the event file says a budget is exhausted, and the policy has no rule on slo_burn
    When the agent proposes a call
    Then the answer is the one it would have been with the option off, and the policy keeps its version
    # -> internal/api:TestWithoutARuleThatReadsTheSignalTheDecisionIsUnchanged

  Scenario: Another agent is not held for this agent's budget
    Given an exhausted budget for one agent
    When a different agent, or an agent whose id only shares a prefix with it, proposes a call
    Then it is not held
    # -> internal/api:TestAnotherAgentIsNotHeldForThisAgentsBudget
    # -> internal/sloburn:TestOnlyTheExactAgentIsSignalled

  Scenario: The caller cannot remove or fake the signal
    Given an agent with an exhausted budget, and a caller that sends its own slo_burn signal saying none
    When the call is decided
    Then the caller's signal is dropped and the call is held
    And the same holds for the name written in another case or with spaces around it
    And while the file cannot be read, a caller's own slo_burn signal does not stand in for the missing one
    # -> internal/api:TestACallerCannotRemoveTheSignalByDeclaringItsOwn
    # -> internal/api:TestACallerCannotHideTheMissingSignalByDeclaringItsOwn

  Scenario: Room is kept for the standing signal
    Given the option is on
    When a request carries sixteen signals of its own
    Then it is refused with a sentence saying fifteen is the most, and fifteen are accepted
    # -> internal/api:TestWithTheOptionOnARequestMayCarryFifteenSignalsOfItsOwn

  Scenario: A signal can only hold, never refuse
    Given two hundred random policy sets, random agents and random states of the event file
    When every decision is compared with the same decision with the option off
    Then each is the same, or an allow that became a hold, or a hold for a missing signal that the signal now answers, and never a deny
    # -> internal/api:TestTheBudgetSignalOnlyEverTurnsAnAllowIntoAHoldOverRandomPolicies

  Scenario: A healthy file gives every agent an answer, so holding on absence holds nobody healthy
    Given a readable file with no live burn event for an agent
    And a policy that also holds when the signal is absent
    When that agent proposes a tool call
    Then it carries the signal with the value none, which says there is no live event and not that the agent is healthy, and it is allowed
    # -> internal/api:TestAReadableFileGivesAnAgentWithNoEventTheValueNoneSoHoldOnAbsenceHoldsNobodyHealthy
    # -> internal/sloburn:TestAnAgentWithNoEventGetsTheValueNoneAndTheHeadOfTheFile

  Scenario: A file that cannot be read leaves the signal absent, and the policy decides
    Given the event file is missing, or its chain is broken
    When an agent proposes a tool call
    Then the signal is absent: the default policy allows it as before, a policy that holds on absence holds it, and a call that is not a tool call is never held for it
    # -> internal/api:TestAnUnreadableFileLeavesTheSignalAbsentAndWhenAbsentDecides

  Scenario: A rate nobody measured is not taken as proof of health
    Given a fast burn event whose burn_events_seen is missing, zero, negative, fractional or not a number
    When the signal is read
    Then its value is unmeasured and never none, and it holds only where the policy lists unmeasured
    And an exhausted event stands on the budget whatever its burn_events_seen says
    # -> internal/sloburn:TestAFastBurnWithoutAMeasuredRateIsUnmeasuredAndNeverNone
    # -> internal/sloburn:TestAnExhaustedEventStandsOnTheBudgetWhateverItsRateSays
    # -> internal/sloburn:TestAnEventThePlaneCannotReadIsUnmeasured
    # -> internal/api:TestAnUnmeasuredRateHoldsOnlyWhereThePolicyListsIt

  Scenario: The signal ends when the event is too old
    Given an exhausted event older than the longest age the operator allows
    When the agent proposes a call
    Then it is not held, and an event inside the age still holds
    # -> internal/sloburn:TestAnEventPastItsMaxAgeNoLongerSignals
    # -> internal/api:TestAnExpiredEventReleasesTheAgent

  Scenario: A newer event for the same indicator replaces the older one
    Given an exhausted event, then a later event for the same indicator that is only a fast burn
    When the signal is read
    Then it is the fast burn, since the budget came back; and the most severe live indicator of an agent is the one reported
    # -> internal/sloburn:TestTheNewestEventOfAnIndicatorReplacesTheOlderOne
    # -> internal/sloburn:TestTheMostSevereLiveIndicatorIsReported

  Scenario: Only the quality plane's own slo_burn lines count
    Given a file that also holds other event types and an slo_burn line from another source
    When the signal is read
    Then the other lines change nothing, and the chain is still checked across them
    # -> internal/sloburn:TestOnlyVerdryxSloBurnEventsCount

  Scenario: A file whose chain does not hold is not believed
    Given a file where a line was edited, a line is malformed, the chain restarts, it opens mid-chain, an event is dated in the future, an event has no usable time, or the file is over the size cap
    When the file is read
    Then the state is broken, no agent is signalled, and the log says why once
    And a torn last line, which is an append in progress, is not an error
    # -> internal/sloburn:TestAFileWhoseChainDoesNotHoldIsBroken
    # -> internal/sloburn:TestAFileWithALineTooLongToReadIsBroken
    # -> internal/sloburn:TestHostileBytesNeverPanicAndAFlippedByteInTheMiddleIsNeverBelieved
    # -> internal/sloburn:TestAnEventDatedInTheFutureMakesTheFileBroken
    # -> internal/sloburn:TestAnEventWithNoUsableTimeMakesTheFileBroken
    # -> internal/sloburn:TestAFileOverTheSizeCapIsBroken
    # -> internal/sloburn:TestATornLastLineIsAnAppendInProgressNotAnError

  Scenario: A file written by the quality plane itself passes the check
    Given a file written by verdryx, in Python, on a real run
    When the chain is verified by the shared library
    Then it holds, and the exhausted event it carries is read as exhausted
    # -> internal/sloburn:TestAFileWrittenByVerdryxItselfVerifiesAndIsRead

  Scenario: A missing file is reported, and recovers when it appears
    Given the path is set and no file is there yet
    When the state is asked for, and again after the file appears
    Then it is unreadable, then ok; and a directory or other thing that is not a plain file is unreadable without blocking
    # -> internal/sloburn:TestAMissingFileIsUnreadableAndRecoversWhenItAppears
    # -> internal/sloburn:TestSomethingThatIsNotAPlainFileIsUnreadableAndNeverBlocks

  Scenario: The file is read again only when it changed
    Given a file already read and not touched since
    When the next poll runs, and again after a line is appended
    Then the first poll does not parse it again and the second does, and the new line is seen
    # -> internal/sloburn:TestAnUnchangedFileIsNotParsedAgainAndAChangedOneIs

  Scenario: The file is watched while the service runs, and a change of state is said once
    Given the service is running with the option on
    When a line is appended, and when the file breaks and then comes back
    Then the line is seen without a restart, the log says each change of state once, naming the file and the line, and says when it is readable again
    # -> internal/sloburn:TestRunPollsTheFileUntilTheContextEnds
    # -> internal/sloburn:TestAChangeOfStateIsLoggedOnceAndTheDetailNamesTheLine

  Scenario: The signal names the event it stands on
    Given an exhausted event on the file
    When the signal is read
    Then its answer id is the chain hash of that line, the one the next line carries as prev_hash
    # -> internal/sloburn:TestTheSignalNamesTheLineItStandsOn

  Scenario: Readiness says what the file is doing and never why
    Given the option is off, then on with a good file, a missing file and a broken one
    When readiness is asked for
    Then the member is absent, ok, unreadable and broken, the status stays 200, and no path or error text is in the body
    # -> internal/api:TestReadyzSaysWhatTheBudgetFileIsDoingAndNeverWhy
    # -> internal/api:TestReadyzLeavesTheBodyAloneWhenTheOptionIsOff

  Scenario: The decision records the signal, and a replay needs no file
    Given a call held for an exhausted budget
    When the history is replayed with the event file deleted
    Then the hold reproduces from the recorded signal, and a policy without the rule turns it back into an allow
    # -> internal/api:TestAHoldForAnExhaustedBudgetReplaysFromTheRecordAlone

  Scenario: The settings are checked where the service starts
    Given the maximum age set without the file, set to nothing usable, or set outside one minute to thirty days
    When the service starts
    Then it refuses to start and names the setting, and with neither set the option is off
    # -> cmd/wardryx:TestTheSignalMaxAgeNeedsTheFileAndAUsableValue
    # -> cmd/wardryx:TestTheSignalFileIsNamedAtStartWhenItCannotBeRead

  Scenario: The built service serves the option end to end
    Given the binary started with the option on and a good file
    When readiness is asked for
    Then it says ok for the file
    # -> internal/manifest:TestTheBuiltBinaryReadsTheBudgetFileAndSaysSoOnReadyz

  Scenario: The reader stays outside the decision
    Given the packages the decision and a replay stand on
    When their imports are listed
    Then none reaches the reader, and the reader reaches no network, no process and no database
    # -> internal/api:TestTheDecisionPathKnowsNothingOfTheBudgetFile
