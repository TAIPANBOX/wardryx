# Provenance: @decided 2026-10-14 (paraphrased): an operator may bound which
# models an agent uses, per policy. The shape (a list of model ids and globs,
# exact matching, a request with no model left alone) is @claude 2026-10-14.
# These scenarios describe it in the repository's own words; they quote no
# person.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: A policy can name the models its agents may use

  Scenario: An agent that switches to a model its policy does not allow is refused
    Given a policy that allows claude-sonnet and claude-haiku models for a fleet of agents
    And an agent of that fleet whose call on a listed model is allowed
    When the same agent, in the same run with the same tools, calls a model the list does not name
    Then that call is denied, the reason names the model and the policy, and the record carries the model
    And when it switches back to a listed model it is allowed again
    # -> internal/api:TestAnAgentThatSwitchesToAModelItsPolicyDoesNotAllowIsRefused
    # -> internal/pdp:TestAModelTheListDoesNotNameIsDenied

  Scenario: A model is matched exactly, by name or glob, and nothing looser
    Given a list with a glob and a plain model name
    When a call names the model in other capitals, with a leading space, as a longer name, with a control character, or as unknown
    Then each of them is denied
    # -> internal/pdp:TestAModelTheListDoesNotNameIsDenied

  Scenario: No list means no restriction
    Given a policy with no list, or an empty one
    When any model is called
    Then it is allowed, and the policy keeps the version it had before the list existed
    # -> internal/pdp:TestNoAllowModelsMeansNoRestriction
    # -> internal/policy:TestAPolicyWithoutAllowModelsKeepsItsPolicyVersion

  Scenario: A decision that names no model is not a model decision
    Given a policy with a list
    When an egress check or a tool call that names no model is decided for the same agent
    Then it is not refused for its model
    # -> internal/pdp:TestARequestThatNamesNoModelIsNotRestrictedByAllowModels

  Scenario: Two lists narrow each other
    Given two policies that both match an agent, each with its own list
    When a model only one of them names is called
    Then it is denied by the other
    # -> internal/pdp:TestTwoModelListsNarrowEachOther

  Scenario: An approval does not lift a model denial
    Given a costly call on a model the list does not name, with a valid approval for its cost
    When it is decided
    Then it is denied for its model, and the same approval still lifts the cost hold on a listed model
    # -> internal/pdp:TestAnApprovalDoesNotLiftAModelDenial

  Scenario: Nothing decided under a model list is offered for reuse
    Given a policy with a list, and an enforcement point whose cache is keyed by agent and tool set
    When its allows and denials are asked whether they may be cached
    Then none may be, since the next call of the same agent and tools may name another model
    And over two hundred random policies the list denies exactly the unlisted models and changes nothing else
    # -> internal/pdp:TestAnAllowModelsDecisionIsNeverCacheable
    # -> internal/pdp:TestAllowModelsDeniesExactlyTheUnlistedModelsOverRandomPolicies

  Scenario: The list is read the same way wherever a policy comes from
    Given a list written in YAML, in JSON, or through the policy API
    When it is loaded or written
    Then it is stored sorted and once per entry, its order does not change the version, and a blank entry is refused
    # -> internal/policy:TestAllowModelsLoadsFromYAMLAndJSONAndThroughTheLaxDecoder
    # -> internal/policy:TestABlankAllowModelsEntryIsRefusedAtLoad
    # -> internal/policy:TestAnAllowModelsListIsPartOfThePolicyVersionAndItsOrderIsNot
    # -> internal/api:TestAPutWithAllowModelsIsStoredAndEnforced

  Scenario: A model denial replays from the record
    Given a run whose calls were allowed and denied for their models, recorded
    When the history is replayed
    Then each decision reproduces from the recorded model, and a policy without the list changes only the denial
    # -> internal/api:TestAModelDenialReplaysFromTheRecord
    # -> internal/replay:TestARecordedModelDenialReproducesFromTheRecordedModel

  Scenario: The tool filter does not apply the model list
    Given a policy with a model list and rules about the action as a whole
    When the tools offered to the agent are filtered
    Then no tool is removed for the model list
    # -> internal/pdp:TestFilterAppliesNoRuleThatIsNotAboutATool
