# CLAUDE.md, working instructions for wardryx

These instructions apply to any model working in this repo. Read this file
before writing code. It holds process and invariants only: **no status.**
Status goes stale, and a stale instruction file is worse than none. For where
the code actually is, read the git tags, `VALIDATION.md`, and the README.

## Read before you change anything

1. `README.md`, the "Where this fits in the stack" section. Wardryx is the
   policy decision point (PDP). TokenFuse is the policy enforcement point (PEP)
   and calls this service before an LLM or tool call.
2. `internal/pdp/pdp.go` and `internal/policy/policy.go` package comments.
   They state the determinism contract in prose, and the invariants below are
   that contract made explicit.
3. `SPEC.md` in the sibling repo `TAIPANBOX/agent-passport` for the identity and
   event-envelope rules this service consumes.
4. `VALIDATION.md` for what has been measured versus asserted.

## What this service is

A deterministic policy decision point. It answers allow, deny, or hold for a
proposed agent action. A hold is stateless human-in-the-loop: the decision is
resolved out of band and comes back as a signed approval token.

**It decides, it never acts.** Wardryx performs no action on the caller's
behalf, and the decision path never reaches the network.

This service is defensive: it exists so an organization can govern its own
agents. Never describe it, in code, docs, or commit messages, as tooling for
acting against anyone else.

## Blast radius

Wardryx sits in front of every governed LLM and tool call in the stack. A
wrong allow ships silently and is only visible later in an audit; a wrong deny
breaks a caller in production. There is no such thing as a cosmetic change to
`internal/pdp` or `internal/policy`.

This repo also pins `github.com/TAIPANBOX/agent-stack-go` **by tag**. Bumping
that tag is a contract change, not a dependency refresh.

## The working loop

1. Branch off `main`, one logical increment per branch.
2. Run every gate below. All must pass locally before the push.
3. Commit with Conventional Commits. End the message with the standard
   co-author trailer naming the model that actually did the work.
4. Push the branch, open a PR with `gh`.
5. Wait for all CI checks to go green. Fix forward, do not force-push over red.
6. **Ask the user before merging.** Do not self-merge.

Use `git worktree add` when working in parallel with another session.

## Gates

```sh
test -z "$(gofmt -l .)"
go vet ./...
staticcheck ./...
go test -race ./...
go build ./...
./scripts/decision-path-purity.sh
./scripts/no-raw-error-in-response.sh
./scripts/store-hands-out-copies.sh
./scripts/decide-order-is-documented.sh
./scripts/readme-numbers.sh
./scripts/scenarios-bind-to-tests.sh
./scripts/gates-have-teeth.sh   # invariant 12; needs a clean tree
```

`readme-numbers.sh` was missing from this list until 2026-08-09 while CI ran
it, so this instruction was strictly smaller than CI's.

CI additionally runs `govulncheck ./...`, `gosec ./...` (the `security` job in
`.github/workflows/ci.yml`), and a Postgres-backed store test (`go test -tags
integration ./internal/store/`). The integration test needs a live database
and is skipped locally by the build tag, so a green local run proves less
than a green CI run. Do not treat the two as equivalent.

## Hard invariants

Each one carries how it is held today. Use `(gate: ...)`, `(test: ...)`,
`(partly gated: ...)` or `(not enforced)`, and use the weakest one that is
true. An invariant with no check, written as though it had one, is worse than
an absent invariant.

1. **The decision-path packages reach for no clock, randomness, network or
   database in their own code.** `internal/pdp` and `internal/policy` import
   none of those directly. The same request against the same policy set yields
   the same decision and the same reported violation, which is what makes a
   decision auditable after the fact.
   *(gate: `scripts/decision-path-purity.sh`, test:
   `TestLoadIsDeterministicAcrossRepeatedLoads`)*

   **Read the limit of this guarantee before relying on it.** There is a
   transitive path by design: `internal/pdp` imports `internal/approval`, which
   imports `internal/store`, which imports pgx. Approval tokens are single-use
   (invariant 5) and redemption state has to persist, so the approval branch
   reaches a database on purpose. The gate therefore checks direct imports, not
   the transitive closure, and the honest claim is "the PDP's own code is
   deterministic", not "no decision ever touches a database". Do not restate
   this as the stronger claim in a README.

   The gate is deliberately not transitive for a second reason: `gopkg.in/yaml.v3`
   imports `time` to parse timestamps, which does not make policy loading
   clock-dependent. A check that fails on that is wrong in the strict direction
   and gets disabled, which is worse than no check.
2. **Wardryx never performs the action it is asked about.** It returns a
   verdict. Any code here that would call out and do the thing belongs in the
   PEP, not the PDP. The purity gate makes the crude version of this violation
   (an http client in the PDP) impossible, but it cannot tell a verdict from an
   action in general. *(partly gated: `scripts/decision-path-purity.sh`)*
3. **Policy compilation produces a deterministic order**, sorted by target then
   name, so two loads of one policy set are byte-comparable and a diff between
   deployments means something. *(test:
   `TestLoadIsDeterministicAcrossRepeatedLoads`)*
4. **An approval token is always HMAC-signed and never falls back to unsigned.**
   The key is `WARDRYX_APPROVAL_SECRET`. If the secret is absent the service
   must refuse to mint a token, not mint an unsigned one. An unsigned approval
   is an approval anyone can forge.
   *(test: `TestMintAndVerifyFailClosedWithNoSecret`,
   `TestDecideGrantFailsClosedWithNoSecretAndLeavesApprovalPending`)*
5. **An approval token is single-use.** A redeemed token allows exactly one
   `/v1/decide` call for the approval it was minted for; a second presentation
   of the same token is rejected. Replay of an approval is the whole attack.
   *(test: `TestSingleUseOnSecondDecideWithSameTokenHolds`,
   `TestApprovalDecideTwiceReturns409`, and `TryRedeem`'s own atomicity and
   race-safety suites in `internal/store` for both backends)*
6. **`POST /v1/approvals/{id}/decide` is admin-only.** Granting an approval is
   the privileged operation in this service; every widening of who may call it
   is a security decision, not a routing change.
   *(test: `TestApprovalDecideRequiresAdminRole`, and
   `TestListPoliciesRequiresAdmin` for the other admin-only route)*
7. **A hold is stateless.** Do not add server-side session state to carry a
   hold between the decision and its resolution. The signed token is the state,
   which is what lets any instance resolve a hold minted by any other.
   *(partly gated: `TestFullHoldGrantThenDecideAllowsWithToken` proves the
   round trip works through the token, but nothing asserts the ABSENCE of
   session state, which is the part that would decay)*
8. **`agent-stack-go` is pinned by tag and is the only source of the wire
   types.** Never hand-roll a local copy of a passport, event, or chain type.
   If the shared type is wrong, widen it there. *(not enforced)*

9. **This plane reports what it observes and decides only what a policy says.**
   The unanswered-approval sweep raises `approval_unanswered` for a hold nobody
   has decided, and leaves the hold exactly as it was. It must never grant,
   deny or expire one on a timer.

   The distinction is the whole reason a human-in-the-loop gate exists: a
   timeout that silently becomes a denial is a decision made by a clock, and
   one that silently becomes an allow is worse. Either would be a behaviour
   change hiding inside an observability feature, which is the shape nobody
   reviews.

   The sweep is also why this is a background loop rather than a check on the
   request path: the condition is defined by the ABSENCE of requests, so a
   check that runs when one arrives cannot see the case it exists for.
   *(test: `TestTheSweepNeverDecidesTheHoldItReports`,
   `TestAHoldNobodyDecidedIsReportedOncePerHold` (verified by removing the
   marker, which reports three times), `TestAFreshHoldIsNotReported`,
   `TestZeroDisablesTheSweep`, `TestMarkersForDecidedHoldsAreDropped`)*

10. **An error from outside this package never reaches an HTTP response.**
    Every internal-error path in `internal/api` wrote `err.Error()` into the
    body until 2026-08-20, and six of them were reachable by any admin-keyed
    request against a store that was down.

    **What actually leaked, said precisely rather than dramatically.** pgx
    keeps the password out of its own error text and puts the host, user and
    database in, so what a client could read was internal topology and SQL,
    not a credential. It is a defect anyway, and the reason is the one worth
    remembering: the guarantee was being held by a third-party library's
    formatting choices, which are revisited on every upgrade and are nobody's
    promise to wardryx.

    The operator loses nothing, since `writeInternalError` logs the detail.
    The client gains an operation name wardryx wrote itself, so a 500 is
    reportable instead of anonymous.

    **What the gate cannot do**: it reads source text. A message built by hand
    out of the same error, or one interpolated through a helper it does not
    know about, walks past it. That stays a matter for review.
    *(gate: `scripts/no-raw-error-in-response.sh`, with 3 cases in
    `gates-have-teeth.sh`; and
    `TestAStoreErrorDoesNotCarryTheDatabasePasswordIntoTheResponse`, which
    fails on the unfixed code across all six store-backed routes)*

11. **What the store hands out is never the store's own memory.** A struct
    copy is not a copy of what the struct points at. `Approval.Context` is a
    map and `Policy`'s `DenyTool` and `AllowDomains` are slices, so returning a
    stored value by value hands the caller a live reference into a governance
    record. An edit they make for their own reasons rewrites it, and nothing
    anywhere sees a write.

    The disarm case is the one worth naming: a reader editing the deny list
    they were handed changes the deny list the engine consults.

    **The write path had this from the start and the read path did not**, which
    also made the two backends disagree. Postgres reconstructs from rows on
    every read and cannot alias, so the same code against the same data behaved
    differently depending on which store was configured. That is exactly what
    `deepCopyContext`'s own comment says it exists to prevent, one direction
    down from where it was written.

    Five read methods were affected: `GetApproval`, `ListApprovals`,
    `GetPolicy`, `DecideApproval` and `ListPolicies`. The last two were found
    by the gate, while the gate was still wrong about four correct helpers.

    **What the gate is for is the sixth**, a read method added later that never
    copied. Its absence produces no symptom: it compiles, returns the right
    values, and passes any test that reads them. No test would be missing,
    because nobody would have written one.
    *(gate: `scripts/store-hands-out-copies.sh`, which reads each read method's
    BODY rather than the shape of its returns, with 4 cases in
    `gates-have-teeth.sh`; plus six behavioural tests in
    `internal/store/isolation_test.go`, each verified against the unfixed code)*

12. **A check must be able to tell "did not fail" from "did not run", and both
    gates here have been made to fail on purpose to prove they can.**
    `readme-numbers.sh` already refuses in two distinct ways when its subject
    is absent. Both sentences were true, were established by hand once in the
    session that wrote it, and nothing re-ran them.

    `decision-path-purity.sh` is the one with the sharper edge. It reads `go
    list` output and matches each import against two lists. A list that stops
    being consulted, or a `go list` that returns nothing, produces exactly the
    same output as a clean tree: silence, then OK. The decision path is where
    this plane answers allow or deny, so a purity check that has quietly
    stopped looking is worse here than almost anywhere in the estate: invariant
    1 exists so a verdict can be reproduced from the same input, and a verdict
    that cannot be reproduced is not evidence.
    *(gate: `scripts/gates-have-teeth.sh`, 6 cases: four real faults, one
    non-fault, and one subject taken away. The non-fault is the one worth
    keeping: the decision path may still use the standard library for pure
    work, and a gate that flagged that would be flagging the code it protects.)*

    **What it does not cover.** It cannot test itself. It proves each gate
    catches the faults named in it, not every fault of that kind. It found no
    hole in either.

13. **The PDP reads a proof it did not verify, and that is the design.**
   `DecideRequest.ChainProven` is a FACT the enforcement point established with
   `agent-stack-go/delegation` before calling. This service must not verify it
   itself: it decides at a 3.2 ms p50 and audits every decision, and a signature
   check per decision taxes every decision in the estate. The trust boundary is
   exactly the one `AttestationMethod` already has, and a caller that lies is
   believed. That is where the boundary IS, not a weakness of the field.

   **Absent means not verified, never "verified and unsaid".** A default of
   true would make every enforcement point that has not been upgraded look like
   one that verifies, which is a fleet mid-upgrade silently satisfying a rule
   none of it implements. *(test:
   `TestAnAbsentChainProvenMeansNotVerified`,
   `TestTheWireCarriesWhetherAnybodyVerifiedTheProof`, both of which exist
   because a planted mutant hardcoding `ChainProven: true` in the HTTP layer
   survived the entire suite: every other API test either sends no chain or
   uses a policy with no chain rule, so nothing observed the field at all. That
   is the failure that looks exactly like the feature working.)*

   **`deny_if_chain_unproven` and `require_root_principal` are two rules on
   purpose.** The first is about a chain that IS present: an agent acting
   autonomously is not delegating and has nothing to prove. The second denies an
   EMPTY chain, because a rule saying "this agent only ever acts for a person"
   is not satisfied by an agent acting for nobody. Fold them into one and an
   operator loses the ability to say either without the other; read the first
   the second way and an agent satisfies it by dropping its chain.

   **A decision that read the chain is never cacheable.** `OnBehalfOf` and
   `ChainProven` are per-REQUEST values like `Steps` and `Domains`. A cached
   chain deny would be reused for a call presenting a different chain, and a
   cached chain ALLOW is worse: it would let an unproven chain through on the
   strength of a proven one. *(test: `TestAChainDecisionIsNeverCached`)*

   **`max_chain_depth` above the stack-wide cap is refused at load.** SPEC 5.1
   caps every chain at 32 and this service already refuses a longer one
   independent of policy, so a higher number is a rule that can never fire,
   which reads as a control and is not.

## Decisions that have no gate yet

This list is debt, and it is here to stay visible rather than to be tidy.

**Held by this file alone: invariant 8. Invariant 7 is half held.**

**A correction worth keeping, because it is the mirror of the usual mistake.**
This section previously said invariants 4, 5 and 6 were held by prose alone and
were "the strongest candidates for a test that must fail first". That was wrong:
all three are among the best-tested things in this repository. Invariant 5 alone
has five tests, including atomicity and race safety against both store backends.

The cause is worth naming. The invariants were derived by reading the code and
its comments, and the test suite was never opened. A marker set from assumption
is wrong in whichever direction the assumption ran, and the harm of the direction
that ran here is quieter: an invariant labelled weaker than reality hides real
coverage and sends the next person to write a test that already exists.

**Set a marker from evidence, both ways.** Before writing `(not enforced)`, grep
the suite for the property. Before writing `(test: ...)`, open the test and
check it asserts what the invariant claims.

Invariant 8 is mechanically checkable, by asserting no local type duplicates a
shared one, but there are no duplicates today and the check is only worth
writing if one ever appears.

## Standing rule

An approved architecture decision is **not finished** until it is two things: a
numbered invariant in this file, and a gate in a script if it can be checked
structurally. Until then it is a document, and documents do not stop code.

When the user approves a decision, add it here in the same session.

## Escalate, do not push through

Stop and tell the user, then wait, when a task hits any of these:

- Anything on the decision path that changes an allow or deny outcome.
- Anything touching approval minting, signing, redemption, or the admin check.
- Bumping the `agent-stack-go` tag.
- Cutting a tag or release, or any outward-facing action.
- Adding a dependency to `go.mod`.

Routine work: tests, doc comments, report formatting, refactors that leave the
decision outcome and every exported signature identical.

## Conventions

- **No long dashes** anywhere: not in code comments, docs, commit messages, or
  PR bodies. Use a comma, a colon, parentheses, or a short hyphen.
- Nothing paid or metered gets enabled without telling the user first and
  getting agreement. This includes anything that would start metering CI.
- Do not delete or revoke keys, tokens, or certificates on your own initiative.

14. **The order `Decide` documents is the order `Decide` runs.** A caller reads
    that order to know which `reason` it gets when two rules would both deny,
    and `reason` is what an operator sees first, what a dashboard groups by,
    and what somebody debugging a refusal reads before anything else.

    `deny_if_chain_unproven`, `max_chain_depth` and `require_root_principal`
    landed on 2026-08-26 in the code and in this file, and in neither the
    README nor `Decide`'s own doc comment. The comment did not merely omit
    them: it went on NUMBERING, so it said "3. deny_if_unattested" while three
    chain rules ran between rule 2 and it. Every number after the second was
    wrong, each by exactly the count of the rules nobody had mentioned.

    That is worse than an omission, and it is why the gate reads the ORDER
    rather than the membership. A missing entry is visible to anybody looking
    for it. A renumbered list looks complete.
    *(gate: `scripts/decide-order-is-documented.sh`, which reads the numbered
    items out of the doc comment and the deny predicates out of the function
    and compares them position by position. Its limit is in the script: it
    knows the `if ... ok {` shape those checks have always had, so a rule
    added by some other shape is invisible to it.)*

15. **A recorded decision carries the question it answered, not only the
    answer.** Every input `Decide` reads reaches the emitted event, or is
    excluded by name with a reason. Two exclusions stand: `agent_id`, `run_id`
    and `on_behalf_of` are typed members of the shared envelope and are read
    from there, so repeating them in `data` would put one fact in a typed
    field and in the erasable payload plane at once; and `approval_token` is a
    live credential, and this record is append-only, replicated, and outlives
    any token's TTL.

    This was measured, not argued. Until 2026-08-31 the emitter wrote
    `{reason, tool_names}` plus the identity triple, four of eleven inputs,
    and `internal/pdp/replay_feasibility_test.go` put a recorded DENIAL back
    to the very policy set that produced it and got ALLOW: the field the
    refusal turned on, `domains`, was nowhere in the record. Nothing was
    corrupt and nothing logged an error. An operator re-examining a month of
    refusals would have been told the policy changed nothing, having never
    re-evaluated the real question.

    The loss is also one-way. Replay works forward from the day the input is
    recorded and can never be applied to records that never carried it, so a
    decision emitted without its question is unexaminable for as long as it is
    kept.
    *(test: `TestDecisionInputCoversEveryDecideRequestField` in
    `internal/api/decision_input_test.go`, which reflects over
    `pdp.DecideRequest` so the set of fields to account for is read from the
    code rather than restated, and fails on a field with no home. The loop is
    closed end to end by `TestARecordedDenialReplaysToTheSameVerdict`, which
    drives a real refusal over HTTP, reads the event back off disk, and
    rebuilds the request from that record alone.)*

16. **A scenario names a test that exists, and a test-binding names a real
    test.** Both directions, because both failures are quiet: a scenario with
    no test is prose describing software nobody checks, and a binding naming a
    test since renamed reads as coverage and cannot be told from the real
    thing without opening the file.
    *(gate: `scripts/scenarios-bind-to-tests.sh`, which refuses with exit 2
    rather than reporting success when it parses no feature files, no
    scenarios, or no bindings. Its limit: it checks that a named test exists,
    not that the test asserts what the scenario says.)*

17. **A policy set is archived before it is allowed to decide anything.** A
    recorded decision names a `PolicyVersion`, and the store behind that name
    is a live control surface: `PutPolicy` overwrites and `DeletePolicy`
    removes. Without a separate append-only copy, the rules a decision was
    taken under are gone by the next edit, and invariant 15 buys nothing: the
    record would carry a faithful question and no rules to put it to.

    The ordering is the invariant, not merely the archiving. Keeping happens
    BEFORE the store write and before `SetPolicies`, because a set that is
    stored and not archived becomes effective again on the next restart, so a
    failure between the two would put rules into force that no recorded
    decision can ever be replayed against. A set archived and then not stored
    is the harmless direction: a spare copy under a name nothing references.

    Attaching an archive keeps the set already in force, since that set
    decides from the first request. Archiving is opt-in
    (`WARDRYX_POLICY_ARCHIVE`); a deployment without one keeps a working PDP
    and loses replay, and the process says so on startup rather than leaving
    it to be discovered.
    *(tests: `TestAPolicySetDecidesOnlyAfterItIsArchived` and
    `TestEveryRecordedPolicyVersionCanBeFetchedBack` in
    `internal/api/policy_archive_test.go`, the second stated the way an
    auditor would ask it: take the events this server actually wrote, and
    require every version any of them names to come back and to recompile to
    that same version. Its limit: it proves the archive holds what THIS
    process made effective, not that a directory carried across a migration
    still holds what an older process did.)*
