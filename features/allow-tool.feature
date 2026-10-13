# Provenance: @decided 2026-10-13, paraphrased: a policy may name the only
# tools that the agents it matches may use. Any other requested tool is
# denied, and an empty or absent list restricts nothing. The decision is
# recorded here in this repository's own words and quotes no person.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: A policy can name the only tools its agents may use

  Scenario: A tool on the allow-list is allowed
    Given a policy for one agent whose allow-list names one tool
    When that agent asks for that tool
    Then the request is allowed
    # -> internal/pdp:TestAToolOnTheAllowListIsAllowed

  Scenario: A renamed tool is denied
    Given a policy for one agent whose allow-list names a tool written with underscores
    When that agent asks for the same tool written with hyphens
    Then the request is denied, because the renamed tool is not the one listed
    # -> internal/api:TestARenamedToolIsDeniedByAnAllowList

  Scenario: A tool the list leaves out is denied, and the reason names the rule and the tool
    Given a policy for one agent whose allow-list names two tools
    When that agent asks for a third tool
    Then the request is denied, and the reason names the allow-list rule and the tool
    # -> internal/pdp:TestAToolTheListLeavesOutIsDeniedByName

  Scenario: No allow-list means no restriction
    Given a policy for one agent with no allow-list, and another with an empty allow-list
    When that agent asks for any tool
    Then the request is allowed under either policy
    # -> internal/pdp:TestNoAllowListMeansNoRestriction

  Scenario: Two policies narrow each other
    Given two policies matching one agent, each with its own allow-list, and a third matching policy with none
    When that agent asks for a tool that only one of the allow-lists names
    Then the request is denied, because the tool must be allowed by every allow-list that applies
    # -> internal/pdp:TestTwoAllowListsNarrowEachOther

  Scenario: The tool named in the broker's call is checked too
    Given a policy for one agent whose allow-list names one tool
    When that agent's tool list names the listed tool but its tool call names a tool the list leaves out
    Then the request is denied, because the tool call names a tool the list does not allow
    # -> internal/pdp:TestToolCallNameIsCheckedAgainstTheAllowList

  Scenario: Matching follows the case rule the deny-list already uses
    Given a policy for one agent whose allow-list names a tool in lower case
    When that agent asks for the same tool in upper case, and for a tool whose name differs only by a separator
    Then the upper-case request is allowed, and the separator variant is denied
    # -> internal/pdp:TestAllowToolFoldsCaseLikeDenyTool

  Scenario: The filter reports a tool outside the list
    Given a policy for one agent whose allow-list names one tool
    When the filter is asked about that tool and about a tool the list leaves out
    Then the tool the list leaves out is reported as denied by the allow-list rule, and the listed tool is allowed
    # -> internal/api:TestFilterToolsReportsAToolOutsideTheAllowList

  Scenario: A valid approval does not lift an allow-list denial
    Given a policy for one agent whose allow-list does not name a tool, and a valid approval for that call
    When that agent asks for the tool with the approval presented
    Then the request is still denied
    # -> internal/pdp:TestAnApprovalDoesNotLiftAnAllowListDenial

  Scenario: A tool that both lists deny is denied by the deny-list
    Given a policy for one agent that denies one tool and allows only that same tool
    When that agent asks for the tool
    Then the request is denied by the deny-list rule
    # -> internal/pdp:TestDenyToolWinsOverAllowTool

  Scenario: A blank entry in an allow-list is refused at load
    Given a policy whose allow-list holds only a blank entry
    When the policy is loaded
    Then loading refuses it, because a blank entry would otherwise be read as no restriction at all
    # -> internal/policy:TestABlankAllowToolEntryIsRefusedAtLoad

  Scenario: A decision that reads the tool call's name is never cacheable
    Given a policy for one agent with an allow-list
    When that agent is decided for a call
    Then the decision is marked not cacheable, because the tool call's name is a per-call value
    # -> internal/pdp:TestAnAllowToolDecisionIsNeverCacheable

  Scenario: A recorded allow-list denial replays to the same verdict
    Given a recorded denial by an allow-list, which named a tool the list leaves out in its tool call
    When the record is replayed against the policy version it names
    Then the replay reaches the same denial, and is not reported as a divergence
    # -> internal/replay:TestAnAllowToolDenialReplaysFromTheRecord

  Scenario: A policy without an allow-list keeps its policy version
    Given a policy set that uses no allow-list
    When it is compiled
    Then its policy version is the one it had before the allow-list existed
    # -> internal/policy:TestAPolicyWithoutAllowToolKeepsItsPolicyVersion
