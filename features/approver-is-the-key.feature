# Provenance: @decided 2026-10-17 (paraphrased): close the agent-security
# findings of the 2026-10-17 review, starting with the defaults and the small
# fixes. Finding F-012, its approval half: the approver an approval recorded
# was the free text the request sent in decided_by, and an approval with no
# org could be decided by an admin of any org.
# @claude 2026-10-17, the shape, fixed in this change: the approver is the key
# that authenticated the decision, by fingerprint; the text is kept as a
# display label beside it; an approval with no org needs a principal allowed
# across orgs. This file quotes no person.
#
# Each scenario names the test that holds it. scripts/scenarios-bind-to-tests.sh
# checks that binding in both directions.

Feature: The approver an approval records is the key that decided it

  Scenario: The approver is the key, whatever text the request sends
    Given a hold, and an admin who grants it with decided_by "someone-who-is-not-a-person-42"
    When the approval is read back from the list and from the approval_granted event
    Then decided_by is key: and the fingerprint of the admin's key, in both
    # -> internal/api:TestTheApproverRecordedIsTheKeyNotTheText

  Scenario: The text the request sent is kept as a display label
    Given an admin who denies a hold with decided_by "alice"
    When the approval is read back
    Then decided_by_label is "alice" in the list and in the approval_denied event
    # -> internal/api:TestTheTextSentIsKeptAsALabelBesideTheApprover

  Scenario: A decision with no label is accepted
    Given an admin who grants a hold and sends no decided_by
    When the grant is made
    Then it is accepted, the approver is the key, and no label is recorded
    # -> internal/api:TestAnApprovalDecisionNeedsNoLabel

  Scenario: A label that could rewrite a terminal or overflow a table is refused
    Given a label holding a control character, a label holding a bidirectional override, and a label over 256 bytes
    When each is sent with a grant
    Then each is a 400 that does not echo it, and the approval stays pending
    # -> internal/api:TestAHostileLabelIsRefusedAndTheApprovalStaysPending

  Scenario: With more than one org an approval with no org needs a cross-org admin
    Given two orgs and an approval whose context names no org
    When an admin of one org decides it, and then a cross-org admin decides it
    Then the first is answered as though the approval did not exist, and the second is accepted
    # -> internal/api:TestAnApprovalWithNoOrgNeedsAPrincipalAllowedAcrossOrgs

  Scenario: With one org its admin decides an approval with no org as before
    Given every key belongs to one org and an approval whose context names no org
    When that org's admin decides it
    Then it is accepted, as it was before this change
    # -> internal/api:TestWithOneOrgItsAdminDecidesAnApprovalWithNoOrg

  Scenario: A cross-org admin sees the approvals of every org
    Given holds made by two orgs and one with no org
    When a cross-org admin lists approvals, and an admin of one org lists them
    Then the cross-org admin sees all three and the org admin sees its own one
    # -> internal/api:TestACrossOrgAdminListsTheApprovalsOfEveryOrg

  Scenario: The approvals command shows the approver and the label
    Given an approval decided by a key with the label "alice"
    When wardryx approvals prints it
    Then the DECIDED BY column shows the key and the label
    # -> cmd/wardryx:TestTheApprovalsListShowsTheApproverAndTheLabel
