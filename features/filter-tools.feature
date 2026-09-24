# Provenance: @decided 2026-09-24, the wardryx half of the W2a plan
# (tokenfuse shadow tool-schema measurement): a pure Filter beside Decide,
# and a route so an enforcement point can ask which offered tools a policy's
# deny_tool would refuse, before anything removes them. No quote of any
# person: this file paraphrases the plan in the repository's own words.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: A caller can ask which offered tools a policy would refuse, without asking whether the action itself may happen

  Scenario: Every denied tool is named, not only the first
    Given a policy for one agent denying two of the tools it might offer
    When that agent offers a tool list naming both denied tools plus one allowed tool
    Then every denied tool is reported, not only the first one found
    # -> internal/pdp:TestFilterNamesEveryDeniedToolNotOnlyTheFirst

  Scenario: A rule about the action does not remove a tool
    Given a policy for one agent that sets a step cap, a cost ceiling, an approval threshold, an attestation requirement and an allowed-domain list, and no denied tool
    When that agent offers one ordinary tool
    Then the tool is allowed, because none of those rules is a rule about a tool
    # -> internal/pdp:TestFilterAppliesNoRuleThatIsNotAboutATool

  Scenario: The filter and the decision agree on every tool alone
    Given a randomly generated set of policies, drawn from a fixed seed so the case reproduces
    When each tool in a fixed pool is offered by itself, once through the filter and once through the full decision
    Then the filter denies a tool exactly when the decision would deny that same lone offer for the same reason
    # -> internal/pdp:TestFilterAgreesWithDecideOnEveryToolAlone

  Scenario: The route answers only a caller holding a key
    Given no bearer token on the request
    When the filter-tools route is called
    Then the call is refused before any policy is consulted
    # -> internal/api:TestFilterToolsRequiresAuth
