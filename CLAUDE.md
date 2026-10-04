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
./scripts/compat-surface.sh      # invariant 19; compat/1.0.json against the code, COMPATIBILITY.md rendered
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
   of the same token returns a fresh hold. Replay of an approval is the whole
   attack. The default since 1.0: `WARDRYX_APPROVAL_SINGLE_USE` unset, or set
   to anything that does not parse as a bool, is single-use, the closed side;
   only an explicit false restores the pre-1.0 behaviour of a token redeemed
   repeatedly for its TTL against the same agent, run and tool set at or
   below the approved cost. `@decided 2026-09-13`: the default flips to
   single-use for 1.0, with the variable kept as the switch; the open question
   of 2026-09-06 is closed by that. Durable, cross-instance single-use needs
   `-db`/`WARDRYX_DB`; without it the redemption set lives in one process and
   `serve` says so at start.
   *(tests: `TestFromEnvApprovalSingleUseDefaultsOn` and the parsing table in
   `internal/config` (unset and unparsable read as true, explicit false as
   false; red on the pre-flip code first), `TestSingleUseOnSecondDecideWithSameTokenHolds`,
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

18. **A counterfactual is offered only for a decision that reproduced, and
    everything else is counted by name.** `wardryx replay` exists to answer
    what a candidate policy would have done to decisions already taken, and
    the answer is worthless unless the run first proves it can reproduce what
    DID happen. `Decide` is deterministic, so a recorded question put back to
    the version it names must return the same verdict and the same reason.

    Six rows are not a plain reproduction and each is reported rather than
    folded in: `not-archived` (invariant 17 was not honoured for it),
    `unreadable` (recorded before invariant 15), `diverged` (the record and
    this build disagree about the past, which fails the command),
    `approval-decided`, which is not a failure at all: the approval token is
    deliberately never recorded, so replay reaches the hold a human then
    answered, and the counterfactual is measured against that hold rather
    than against the person's answer; and `approval-spent` (since 1.0.1,
    wardryx#57), its twin under the single-use default: the second
    presentation of a token records a hold whose reason only that token
    explains, `pdp.ReasonApprovalSpent`, the one sentence `internal/api`
    writes and `internal/replay` reads back, so the row is excused by that
    exact sentence and no other; a hold with any other reason the replay does
    not reproduce is still a divergence. And `approval-refused` (since 1.0.2,
    wardryx#59), the third and last token-dependent outcome: a presented
    token that does not verify records a deny carrying the verifier's reason
    after the phrase `pdp.ReasonApprovalRefused`, matched in that position
    and no other; replay presents nothing and reaches the hold. A token is
    only ever inspected past the threshold, so these three are every way a
    credential the record does not carry can move a verdict.

    The counting rule is the invariant's teeth: a change tally never appears
    without the tally of decisions the run could not examine. "2 of 4 change"
    beside a silent four that were skipped reads as coverage it does not have,
    which is the same silent shape as the defect that started this work.
    *(tests: `TestAnUnarchivedVersionIsCountedNotSkipped`,
    `TestADivergentReplayIsReportedLoudly`,
    `TestAnAllowGrantedByAHumanIsNotADivergence`,
    `TestASpentTokenHoldIsNotADivergence`,
    `TestAHoldWithAReasonTheTokenDoesNotExplainStaysDiverged`,
    `TestARefusedTokenDenyIsNotADivergence`,
    `TestADenyWithAReasonTheTokenDoesNotExplainStaysDiverged` and
    `TestTheReportNamesWhatItCouldNotExamine` in `internal/replay`;
    `TestASpentTokenHoldReplaysAsApprovalSpent` and
    `TestARefusedTokenDenyReplaysAsApprovalRefused` in `internal/api`, the
    seams that keep the sentences the handler writes and the ones replay
    reads the same. Its limit:
    reproduction proves the PDP answers the same way, not that the recorded
    question was the one the enforcement point actually asked.)*

19. **The surface `compat/1.0.json` promises is present in the code, and
    `COMPATIBILITY.md` is rendered from it, never typed.** SemVer's item 5:
    version 1.0.0 defines the public API, so a 1.0 is a promise about a
    surface, and a promise nobody can point at is a mood. The estate's first
    1.0 tags (agent-passport, agent-stack-go, 2026-09-12) each came with the
    surface written down and a gate that fails when it moves; trailryx, idryx
    and qryx followed in wave 1 of the 1.0 plan. This repository's manifest was
    written on 2026-09-13, ahead of its own 1.0, so the tag freezes something
    already held.

    Frozen, in eight kinds: the nine `METHOD /path` routes the router
    registers (`internal/api/api.go`), the eleven request and six response
    fields of `/v1/decide` as their struct tags spell them, the three decision
    words `allow`, `deny`, `hold` (`internal/pdp/pdp.go`), the eleven policy
    fields (`internal/policy/policy.go`), the five subcommands
    (`cmd/wardryx/main.go`), the eleven `WARDRYX_*` names the one config reader
    reads (`internal/config/config.go`), and the eight event types this service
    emits under `source: wardryx`. Additive: new event types, new policy
    fields whose zero value means no restriction, new routes and optional
    request fields, and the approval token's DEFAULT (single-use or reusable
    for its TTL), which is configuration and not wire: it may flip by decision
    and `WARDRYX_APPROVAL_SINGLE_USE` stays the switch either way (invariant
    5). Experimental: the OTLP span attribute names and replay's
    candidate-policy report shape.

    The check is textual by design and says so: a plain name must appear as a
    quoted literal (`"name"`, `'name'` or `` `name` ``) in a file the manifest
    says holds it, so a comment mentioning it does not count as the code
    carrying it. This repository's wire fields live in Go struct tags spelled
    `json:"name,omitempty"`, so the check also accepts a comma where the
    closing quote would be; a field named in more than one literal (an
    `approval_id` is also a JSON key inside an event's data) leaves the file
    only when every occurrence does, which the teeth case for the tag form
    respects by renaming a field that appears exactly once. estate-gates C19
    asks whether the manifest and the gate exist and whether the newest tag is
    1.0 or above; this gate asks whether the promise still holds.
    *(gate: `scripts/compat-surface.sh`; six cases in `gates-have-teeth.sh`: a
    frozen route gone from the router, a wire field renamed in its struct tag,
    an env name gone from the config reader, `COMPATIBILITY.md` edited by hand,
    an additive name added (must pass), the manifest gone (measured nothing).)*

20. **Liveness never reads the store, readiness does, and a policy write never
    hangs on it.** Issue #62, measured on the appliance proving run of
    2026-09-17 with the policy store stopped: `/healthz` answered 200 (right:
    decisions continued from memory, and a liveness check that restarted the
    process for its store would trade a working PDP for a crash loop), a
    `PUT /v1/policies/{id}` had no answer after eight seconds, the log had no
    line about the store, and a launcher reading `/healthz` could not tell
    "deciding from memory" from "healthy".

    Three parts, each held on its own. `GET /readyz`, unauthenticated like
    `/healthz` and reading nothing from the request, pings the store under
    `api.DefaultStoreTimeout` (three seconds) and answers 200
    `{"store":"ok"}` or 503 `{"store":"unreachable"}`: a launcher check reads
    the status, so the signal is the code and not a field inside a 200. Every
    store call a `PUT` or `DELETE /v1/policies/{id}` makes shares that
    deadline, and a store that is gone (`store.IsUnavailable`: the deadline
    passed, or the network said no) answers 503 with a sentence wardryx
    composed, while a store that answered with a failure of its own stays the
    500 of invariant 10. And an outage is logged once when it starts and once
    when it ends, never once per request in between.

    The deadline is proven on the driver and not only on a double: pgx against
    a listener that accepts and never speaks returns at the deadline on every
    bounded call. Its limit: "the change is not in force" is a statement about
    this process's engine; a write the store applied after the process stopped
    waiting is restored on the next start, and until then the store and the
    live set differ. Reads under `/v1/policies`, `/v1/approvals` and
    `/v1/status`, the approval paths on `/v1/decide`, the unanswered-approval
    sweep and `OpenPostgres` at startup are not bounded by this deadline.
    `components.json` declares the ready path as a `checked` claim, proven by
    starting the binary.
    *(tests: `TestReadyzAnswers503WhenTheStoreRefuses`,
    `TestReadyzAnswers503WithinTheDeadlineWhenTheStoreHangs`,
    `TestReadyzAnswers200WhenTheStoreAnswers`,
    `TestHealthzAndDecisionsStayUpWhileTheStoreIsDown` (red on a planted
    `/healthz` that pings the store), `TestReadyzIgnoresHostileInput`,
    `TestAPolicyWriteOnAHangingStoreAnswers503InsteadOfHanging` (red on the
    unfixed handler: no answer after three seconds),
    `TestAPolicyWriteOnARefusingStoreAnswers503WithAReason`,
    `TestAWriteThatFailsAfterTheListAnswers503AndLeavesTheLiveSetAlone` (the
    issue's "nothing half-written", held on a store that lists and then loses
    the write),
    `TestAStoreOutageIsLoggedOncePerOutageNotPerRequest`,
    `TestAStoreFailureThatIsNotAnOutageIsStillA500` in `internal/api`;
    `TestPostgresCallsReturnWithinTheDeadlineAgainstAListenerThatNeverAnswers`,
    `TestARefusedConnectionIsUnavailable`, `TestMemoryPingAlwaysAnswers`,
    `TestAnOrdinaryStoreErrorIsNotUnavailable` in `internal/store`; and the
    ready-path half of `TestItStartsAndRefusesUnauthenticatedCalls` in
    `internal/manifest`. Scenarios in `features/store-outage.feature`.)*

21. **`Filter` is Decide's rule 2 applied to each offered tool alone, through
    the same matcher, and it is unrecorded while no enforcement point acts on
    its answer.** `POST /v1/filter-tools` exists to answer a narrower
    question than `/v1/decide`: not "may this action happen" but "which of
    these offered tools would `deny_tool` refuse". It reads the Engine's
    policy set exactly the way `Decide` reads it (one load, `Set.Match` on
    `AgentID`), and denies a tool through the same `containsFold` `Decide`
    uses, called rather than copied, so the two can never quietly diverge on
    what "denied" means for one tool.

    It is pure in the same sense `Decide` is pure (invariant 1): no clock,
    randomness, network or database in `internal/pdp`'s own code. And it
    applies no rule that is not about one tool: no chain rule, no
    attestation, no `max_steps`, no `allow_domains`, no cost rule, no
    approval token. Those are rules about the action as a whole, and `Filter`
    was asked a question about tools offered, not an action taken.

    **Unrecorded is a decision, not an oversight, and it is temporary.** No
    event is emitted for a `filter-tools` call. Recording it would describe a
    decision nothing yet enforces: emitting `policy_deny`-shaped events for
    tools an agent never attempted to use would double the event volume for a
    verdict with no consequence, and would need its own name so a reader
    could tell "the agent tried this and was refused" from "the agent asked
    what it could try, once, in a plane that only measures shadow pruning."
    The named limitation is TokenFuse's shadow-measurement wave (W2a): this
    route exists so an enforcement point can measure how many tool
    definitions a policy would remove, before anything prunes them. If a
    later wave enforces on this answer, that wave adds the event and this
    line stops being true.
    *(gate: `scripts/decision-path-purity.sh` for the purity half; the "no
    event" half is not enforced, there is nothing to grep for an absence, and
    a later wave changing this is expected, not a regression; test:
    `TestFilterNamesEveryDeniedToolNotOnlyTheFirst`,
    `TestFilterAppliesNoRuleThatIsNotAboutATool`,
    `TestFilterMatchesToolsTheWayDecideDoes`,
    `TestFilterIgnoresPoliciesForOtherAgents`, `TestFilterDropsLaterDuplicates`,
    `TestFilterAgreesWithDecideOnEveryToolAlone` (a 200-seed sweep: for every
    tool offered alone, `Decide` denies by `deny_tool` if and only if `Filter`
    lists it in `Denied`) in `internal/pdp`; `TestFilterToolsRequiresAuth`,
    `TestFilterToolsAnswersThePartition`, `TestFilterToolsRefusesABodyOverTheCap`,
    `TestFilterToolsRefusesAMissingAgentID`, `TestFilterToolsSurvivesHostileInput`
    in `internal/api`)*

22. **An explicit zero on `require_human_above_usd` or `deny_above_usd` is a
    real threshold or ceiling, never silently the same as the field being
    left out.** Measured 2026-09-27: `PUT /v1/policies/n4-deny-beta` with
    `{"deny_above_usd":0}` answered 200, the stored policy echoed back with
    no `deny_above_usd` field at all, and the agent's next call through the
    enforcement point was allowed. Both fields were a plain `float64` with
    `omitempty`, so an explicit `0` and the field never being mentioned
    decoded to the identical Go value: a policy meaning "deny everything
    above zero" silently became "deny nothing".

    `@decided 2026-09-27`: both fields are `*float64`. `nil` (the field
    absent from the file or the PUT body) still means no restriction, exactly
    as before; a non-nil zero now denies (or holds) any action whose cost is
    more than zero, which is what the field's own long-standing contract
    ("denies any action whose estimated cost exceeds it") already says a
    threshold of zero should do. Refusing an explicit zero at load and at PUT
    instead was considered and rejected: every already-valid policy that
    simply never mentions one of these fields also decodes to the Go zero
    value, so "refuse an explicit zero" is only expressible at all once
    presence is tracked, at which point there is no reason left to forbid
    the one value an operator actually asked for over "no restriction". This
    also matches how the sibling field on an `approval_token`, `MaxCostUSD`,
    already treats zero (README's approval-token section: zero is
    deliberately never read as "no ceiling").

    A pointer field changes nothing for a policy file that never mentions
    either field: JSON and YAML both leave the pointer `nil` on an absent
    key, `omitempty` still drops a `nil` pointer the same way it dropped a
    zero `float64`, and `PolicyVersion` (a digest of the normalized,
    marshaled set) is unchanged for every policy in the estate today, since
    none of them writes either field as a literal `0`. Only a policy that
    does write an explicit `0` gets a new, and now correctly distinguished,
    `PolicyVersion`.

    The formatting half of the same measurement: a `deny_above_usd` of
    `$0.000001` printed its refusal reason as `$0.00` (rounded away by a
    fixed two-decimal format), and a `require_human_above_usd` of `$0.005`
    printed as `$0.01` (rounded up to a different cent). Both read as a
    different number than the one configured. Fixed by printing the
    ordinary two-decimal form only when it round-trips back to the exact
    value, and the shortest exact decimal otherwise, so `$100.00` still
    prints as `$100.00` and a sub-cent figure prints as itself.
    *(test: `TestDecideZeroDenyAboveUSDCeilingDeniesAnyPricedCall`,
    `TestDecideZeroRequireHumanAboveUSDThresholdHoldsAnyPricedCall` in
    `internal/pdp`; `TestExplicitZeroDenyAboveUSDInAYAMLFileIsDistinctFromOmitted`,
    `TestExplicitZeroRequireHumanAboveUSDInAJSONFileIsDistinctFromOmitted`,
    `TestRequiresHumanApprovalIsTrueExactlyWhenAHoldCanHappen` in
    `internal/policy`; `TestPutPolicyWithExplicitZeroDenyAboveUSDIsNotSilentlyDropped`,
    `TestPutPolicyWithExplicitZeroDenyAboveUSDActuallyDeniesTheNextCall` in
    `internal/api`; and the formatting fix by
    `TestSubCentDenyAboveUSDReasonIsNotMisleading`,
    `TestSubCentRequireHumanAboveUSDReasonIsNotMisleading`, plus the existing
    `TestDecideDenyAboveUSDHardCeiling`'s "exactly at the ceiling" case for
    the boundary the zero fix must not move. Scenarios in
    `features/zero-value-policy-ceilings.feature`.)*

    **The same defect, found in a third refusal reason on 2026-09-27, after
    this invariant's first two fixes shipped.** `internal/approval`'s
    `ErrTokenCostExceeded` (`VerifyApprovalToken`, returned when a presented
    `est_cost_usd` exceeds an approval_token's `MaxCostUSD`) still built its
    message with a plain `"%.2f"`: a token minted for a `MaxCostUSD` of
    $0.0005, presented for $0.0016, read "approved ceiling $0.00 exceeded by
    requested $0.00", both amounts rounded away and indistinguishable from an
    actual zero ceiling. This error reaches an operator two ways: directly
    from `internal/approval`, and embedded via `Decide`'s `"; %s (%v)"` after
    `ReasonApprovalRefused` into the `Reason` a `/v1/decide` caller actually
    reads (`internal/pdp/pdp.go`, the deny branch of `overThreshold`).

    Fixed the same way as the first two: `internal/approval` gained its own
    unexported `formatUSD`, byte-for-byte the same algorithm as
    `internal/pdp`'s (duplicated rather than imported, since `internal/pdp`
    already imports `internal/approval` on the documented transitive path of
    invariant 1, so the reverse import would be a cycle). Cent-and-above
    output is unchanged: `formatUSD` prints the ordinary two-decimal form
    whenever it round-trips back to the exact value, so `TestVerifyCostCeiling`'s
    existing "a cent over the ceiling" and "exactly at the ceiling" cases
    still hold.
    *(test: `TestSubCentTokenCostExceededReasonIsNotMisleading` in
    `internal/approval`, and `TestSubCentApprovalTokenCostExceededReasonIsNotMisleading`
    in `internal/pdp`, and `TestTheTwoFormatUSDCopiesAgree` in `internal/pdp`; `TestFormatUSDPrintsNoFloatNoise` in both packages, which requires a computed amount to print rounded to the micro-dollar ("$0.0055", not "$0.0055000000000000005") and a nonzero amount below a micro-dollar never to print as zero, red first on the shortest-representation form, which holds the two copies of `formatUSD` to each other over a sweep of amounts (a drifted copy re-planted and caught); the second of the two named above drives a full `Decide` call with a presented,
    over-ceiling approval_token and asserts the operator-visible `Reason`
    itself, not only the internal error text; both red-first against the
    unfixed `"%.2f"` call. Scenarios in
    `features/zero-value-policy-ceilings.feature`.)*

23. **The README's environment table states the default the code uses, for
    every variable the code reads, and for no other.** The table's Default
    column is the only place an operator reads what an unset variable means.
    From 1.0 (#53) until #78 its `WARDRYX_APPROVAL_SINGLE_USE` row said the
    default was `false`, the pre-1.0 reusable token, while `parseBoolClosed`
    had made it single-use: the README told an operator that the replay-safe
    setting was one they had to opt into, and nothing compared the two.

    Three sets are held equal: the `WARDRYX_*` names any non-test Go file
    reads with `os.Getenv`/`os.LookupEnv` and a literal name, the table's
    rows, and the derivations in the test's `codeDefaults`. Each derivation
    reads the code `serve` runs (`config.FromEnv`, `api.DefaultUnansweredAfter`,
    and the `-addr` fallback literal read out of `main.go` exactly as
    `internal/manifest` reads it) rather than restating a value, so a
    default that moves in code turns the table red until the cell moves too.
    A Default cell is `(empty)` or one backticked value; durations compare
    as durations. The Meaning column does not restate defaults, so the
    column is the one copy.
    *(test: `TestReadmeEnvTableStatesTheDefaultsTheCodeUses`, red first on
    the pre-#78 `false` cell and on seven more planted faults; its teeth are
    `TestReadmeEnvCheckCatchesPlantedFaults`, four planted faults and one
    non-fault, itself red when the comparison is neutered. Its limits: prose
    outside the table is invariant 24's subject, not this test's; and the
    unanswered sweep's derivation mirrors `runServe`'s unset branch rather
    than calling it.)*

24. **README prose outside the environment table never contradicts a
    default the code uses.** The single-use default drifted in prose, not
    only in the table: until #78, three sentences told an operator to set
    `WARDRYX_APPROVAL_SINGLE_USE=true` to get what was already the default,
    and the status list called it "optional". Prose cannot be parsed as a
    table, so the test reads three claim shapes that need no understanding
    of English, against the same `codeDefaults` invariant 23 uses:
    `WARDRYX_X=V` where V is already X's default (an operator is never told
    to set a variable to the value it has, so this describes an old default
    as an opt-in); "`WARDRYX_X`, default V" within a short span of the name
    with nothing backticked between, where V must be the code's default
    ("15 minutes" reads as `15m`); and a switch that is on by default called
    "optional" or "opt-in" in a sentence naming it. Code blocks are read
    too, the environment table's rows are not.
    *(test: `TestReadmeProseNeverContradictsTheCodeDefaults`, red first on
    the real pre-#78 README, where it names all four drifted sentences, and
    on a flipped `parseBoolClosed` and a changed `api.DefaultUnansweredAfter`
    with the README unchanged; its teeth are
    `TestReadmeProseCheckCatchesPlantedFaults`, six planted faults, three of
    them verbatim pre-#78 sentences, and two non-faults, itself red when
    `sameSetting` is neutered. Its limits: a default restated in words that
    name no variable ("tokens are reusable by default") and paraphrase in
    general are not read; those stay with review.)*

25. **A typed risk signal can add a hold and nothing else.** `@decided
    2026-10-04`: a signal may turn a call into a hold and never into a deny, and
    the signal is recorded so a replay reproduces the decision. A signal is a
    probability about the world ("this tool call is destructive, 0.95"), and a
    probability must never refuse an action by itself. `hold_if_signal` is the
    only rule that reads one. It is evaluated after every deny rule and after
    the cost gate, so it can turn an allow into a hold and can change no other
    verdict: a deny stays the same deny, a cost hold keeps its own reason, and
    nothing a signal says ever produces an allow. A granted `approval_token`
    lifts a signal hold exactly as it lifts a cost hold (single-use under the
    default), and a token that does not verify HOLDS again here where it denies
    at the cost gate, because without the signal the same call was allowed and
    a signal must not be able to turn an allow into a refusal. A policy that
    tries to make a signal deny is refused at load and at PUT with a sentence
    saying a signal can only hold: `deny_if_signal` in any value, and any key
    inside `hold_if_signal` beyond `name`, `values` and `min_probability`
    (`decision`, `action`, `on_match`, anything else), in the strict decoder
    of a policy file and in the lax one the policy API uses alike. `name`,
    `values` and `min_probability` are required, the last because a rule with
    no threshold would hold on any probability. A decision under a policy that
    carries the rule is never `cacheable`: a signal belongs to one call's
    arguments, not to the agent and tool set an enforcement point's cache keys
    on, and that holds for the signal-driven hold, an approved allow, an allow
    reached while the rule could have fired on other arguments, and a deny
    under such a policy alike. A policy without the rule keeps its `PolicyVersion` byte for byte.
    *(test: `TestADestructiveSignalHoldsACallThatWasAllowed`,
    `TestASignalAtTheThresholdHoldsAndBelowItDoesNot`,
    `TestAValueTheRuleDoesNotListChangesNothing`,
    `TestASignalNeverChangesADeny`, `TestASignalNeverRemovesACostHold`,
    `TestASignalHoldIsLiftedByAValidApprovalTokenAndNeverTurnsIntoADeny`,
    `TestSignalsNeverChangeADenyOrRemoveAHoldOverRandomPolicies` (200 seeds),
    `TestADecisionThatCanReadASignalIsNeverCacheable`,
    `TestEverySignalDependentDecisionIsMarkedNotCacheable` in `internal/pdp`,
    `TestTheCacheableHintIsFalseForEverySignalDependentDecisionOverTheWire` in
    `internal/api`;
    `TestAPolicyThatTriesToMakeASignalDenyIsRefusedAtLoad`,
    `TestTheSameRefusalHoldsInJSONAndInsideAList`,
    `TestCompileRefusesADenyIfSignalThatArrivedThroughALaxDecoder`,
    `TestAPolicyWithoutASignalRuleKeepsItsPolicyVersion` in `internal/policy`;
    mutants named in the PR that added it, each caught: hold to deny, the
    threshold comparison flipped two ways, the rule evaluated before the deny
    rules with a token lifting it to allow, an invalid token denying, the rule
    missing from the cacheability check)*

26. **A signal is an input to the decision, supplied by the caller, and
    nothing the decision stands on can fetch one.** `@claude 2026-10-04,
    delegated by the owner`: the core does not change for an optional add-on,
    which joins it by configuration only. So `/v1/decide` takes `signals` and
    `tool_call` as fields of the request, and whatever produces them (a
    classifier behind a proxy placed in front of this service) is deployment
    configuration this repository neither names nor calls: it holds no client,
    no URL and no variable for one, so a deployment without a producer runs the
    identical service, and the policy plane is not an egress path that sends a
    call's arguments to anyone. `pdp.Decide` reads `DecideRequest.Signals` the
    way it reads `EstCostUSD`. Nothing in `internal/pdp`, `internal/policy`,
    `internal/replay`, `internal/approval` or `internal/archive`, or any package
    of this module in their import closure, imports `net/http` or `os/exec`:
    a decision cannot make an outbound call, and a replay cannot ask anybody.
    A signal's `source` is the caller's claim, recorded and never branched on,
    and a lying caller is believed, which costs a delay for a person and
    nothing else because of invariant 25. Caps: 16 signals, 128 bytes a text
    field, 12 KiB of tool arguments. A tool call the enforcement point marked
    `arguments_truncated` carries no arguments, and one that says both is a 400.
    *(gate: `scripts/decision-path-purity.sh`, three cases in
    `gates-have-teeth.sh`; test: `TestTheDecisionPathAndReplayCannotMakeAnOutboundCall`,
    `TestHostileSignalAndToolCallInputIsRefusedAtTheAPI`,
    `TestAnySourceTheCallerNamesIsRecordedAsClaimed`,
    `TestTruncatedArgumentsAreAcceptedWithNoArgumentsAndRecordedAsTruncated`,
    `TestTruncatedArgumentsBesideArgumentsAreRefused` in `internal/api`;
    `TestSignalValidationRefusesTheMalformed`,
    `TestToolCallValidationCapsWhatCanBeSent`,
    `TestATruncatedToolCallIsConsistentOrRefused` in `internal/pdp`)*

27. **A decision records every signal it read, and a replay feeds them back
    and asks nobody.** The decision event and the approval context carry each
    signal in full (`name`, `value`, `probability`, `source`, `answer_id`) and
    carry the key only when the decision used any, so a decision that used none
    is recorded as it always was. The tool call a request carried is recorded
    as `tool_call` (`name`, `target`, `arguments_sha256`, the sha-256 of the
    arguments exactly as received, `arguments_truncated`, and, since
    invariant 28, `digest`, the value an approval of the call is bound to),
    never the arguments themselves: they can carry customer data. The hash
    ties a signal to the call it was about. `Decide` does not read `tool_call`; the signals
    are what replay feeds back. `wardryx replay` puts the recorded signals to
    the PDP with the rest of the question, so a hold caused by a signal
    reproduces with whatever produced it unreachable; a record whose signals
    are not the shape the emitter writes is `unreadable`, by name, never
    guessed. A hold a person granted replays as `approval-decided`, as a cost
    hold does.
    *(test: `TestEverySignalUsedIsRecordedInTheEventAndTheApprovalContext`,
    `TestADecisionWithNoSignalsCarriesNoSignalsKey`,
    `TestToolArgumentsNeverReachTheRecord`,
    `TestTheToolCallIsRecordedAsNameTargetAndAHashOfItsArguments`,
    `TestADecisionWithNoToolCallRecordsNoToolCallKey`,
    `TestAReplayReproducesASignalHoldFromTheRecordAlone`,
    `TestAReplayOfACallerSuppliedSignalHoldAlsoReproduces`,
    `TestAGrantedSignalHoldReplaysAsApprovalDecided` in `internal/api`;
    `TestARecordedSignalIsFedBackAndTheHoldReproduces`,
    `TestAHoldWhoseSignalWasNotRecordedIsADivergenceNotAReproduction`,
    `TestACandidateWithoutTheRuleChangesTheRecordedHold`,
    `TestMalformedRecordedSignalsAreUnreadableNotGuessed` in
    `internal/replay`; `TestDecisionInputCoversEveryDecideRequestField`)*

28. **An approval is for the call a person read, not for the tool.** `@decided
    2026-10-04`: an approval for a call that a policy held is bound to that
    call's arguments. Before this, a token bound agent, run, tool set and cost,
    so a person who approved "delete repo X" had also approved "delete repo Y"
    with the same tool for the token's lifetime; single-use limited it to one
    use but not to the call that was read. Now, when a hold is created for a
    request that carries a `tool_call`, the approval's context records the
    call's `name`, `target`, `arguments_truncated` and `digest` (never the
    arguments), the approvals list and `wardryx approvals` show the tool and
    target, and the granted token carries the same digest in a signed, versioned
    claim. The digest is `approval.ToolCallDigest`: a sha-256 over a fixed
    domain tag, then name and target each with an 8-byte length prefix, then the
    sha-256 of the arguments exactly as received (the same value the event
    records as `arguments_sha256`), then the truncated flag. Verification
    (`approval.VerifyApprovalTokenForCall`, which `Decide` and the timeout check
    call with the presented call's digest) refuses a token whose digest differs
    from the presented call's, and refuses a digest-bound token on a request
    with no `tool_call`. Under a cost threshold that refusal is the same deny as
    any invalid token; under a signal hold it holds again with an approval of
    its own, as invariant 25 requires. A refused attempt does not redeem the
    token (redemption happens only after an allow), so single-use still allows
    the approved call once. The digest is compared with `hmac.Equal`, as the
    signature is. A grant refuses (`ErrToolCallContext`) before writing anything
    when a hold's context names a tool call but holds no well-formed digest, so
    a damaged hold can never become a token that binds nothing.

    **Format and back-compat.** A token minted for a hold whose request carried
    no `tool_call` is minted exactly as before (no `v`, no `tcd`), verifies on a
    request with no `tool_call` exactly as before, and every token minted before
    this change verifies as it did. A token with a digest is claims version 2
    (`v: 2`, `tcd`); a version other than absent or 2 is refused
    (`ErrTokenVersion`), as is a version-absent token that carries a digest and a
    version-2 token without a well-formed one. Limits, named: a token with no
    digest also verifies on a request that carries a call (it was granted with
    no call in view, so nobody was shown one, and it binds what it always did);
    a call whose arguments were truncated binds only name, target and the flag;
    the digest is over the argument bytes as received, so the same JSON
    re-spaced is another call and is refused; the caller is believed to describe
    the call it will make, the same boundary as a signal (invariant 26); and a
    build from before this change verifies a bound token without checking the
    digest (it ignores unknown claims), which is the old behaviour and never
    wider, so a rollback loses the binding for tokens still inside their TTL.
    *(test: `TestAnApprovalForOneCallIsRefusedForAnotherCallOfTheSameTool`,
    `TestACostHoldIsBoundToTheCallAndARefusedCallDenies`,
    `TestTheSameCallPresentedWithItsTokenIsAllowed`,
    `TestSingleUseStillHoldsForABoundTokenAndARefusedCallDoesNotSpendIt`,
    `TestATokenBoundToACallIsRefusedOnARequestThatCarriesNone`,
    `TestATokenGrantedForARequestWithNoCallIsTheTokenItAlwaysWas`,
    `TestTheApprovalShowsTheCallAndTheTokenEventAndContextAgree`,
    `TestArgumentsWrittenWithOtherWhitespaceAreAnotherCall`,
    `TestAHoldWhoseCallDigestIsDamagedCannotBeGrantedUnbound` in
    `internal/api`; `TestASignalHoldIsLiftedOnlyForTheCallThatWasApproved`,
    `TestACostGateTokenForOneCallDeniesAnotherAndNamesNeitherDigest` in
    `internal/pdp`; `TestTheDigestSeparatesEveryPartOfTheCall`,
    `TestTheDigestCannotBeForgedByMovingBytesBetweenNameAndTarget`,
    `TestATokenBoundToACallVerifiesForThatCallOnly`,
    `TestALegacyTokenOnARequestWithNoToolCallIsAcceptedAsBefore`,
    `TestATokenInTheExactPreChangeFormatStillVerifies`,
    `TestHostileTokensAreRefusedWithoutPanic`,
    `TestALegacyVersionTokenCarryingADigestIsRefusedNotTreatedAsUnbound`,
    `TestEveryPrefixOfATokenAndRandomBytesAreRefusedWithoutPanic`,
    `TestAHoldWithADamagedCallDigestIsNotGrantedUnboundAndStaysPending`,
    `TestTheSignatureAndTheDigestAreComparedInConstantTime` (reads the verifier's
    source: the compare is not behaviourally observable),
    `TestNoProductionCodeOutsideThisPackageUsesTheUnboundEntryPoints` in
    `internal/approval`; `TestTheApprovalsListNamesTheCallBeingApproved` in
    `cmd/wardryx`; scenarios in `features/approval-bound-to-the-call.feature`;
    mutants named in the PR that added it, each caught: digest ignored at
    verify, digest over the name only, target left out of the digest, the
    constant-time compare replaced, the legacy path accepting a digest-bound
    token without the digest)*
