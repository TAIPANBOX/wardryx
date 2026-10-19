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
./scripts/agent-is-bound-to-its-key.sh  # invariants 36 to 38
./scripts/decision-record-is-checked.sh  # invariant 40
./scripts/approval-verifier-trusts-its-keys.sh  # invariant 41
./scripts/no-raw-secret-lookup.sh  # invariant 42
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
4. **An approval token is always signed and never falls back to unsigned.**
   The v2 form is HMAC-signed with `WARDRYX_APPROVAL_SECRET`; the v3 form
   (invariant 41) is ES256-signed by Keyryx. With neither a signer nor a secret
   the service must refuse to mint a token, not mint an unsigned one. An
   unsigned approval is an approval anyone can forge.
   *(test: `TestMintAndVerifyFailClosedWithNoSecret`,
   `TestDecideGrantFailsClosedWithNoSecretAndLeavesApprovalPending`,
   `TestNoSecretAndNoSignerStillRefuses` in `internal/approval`)*
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
   is a security decision, not a routing change. The admin roles are `admin`,
   confined to its own org when there is more than one, and `cross-org-admin`
   (invariant 37).
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
   none of it implements.

   **identity_source extends this in words, and changes none of it.**
   `@decided 2026-10-18` (paraphrased): the enforcement point reports how it
   knew the agent, as `agent-token` (it verified an agent token at its own
   door), `client-key` (a static key) or `none`, and a policy may require one
   of them (invariant 39). wardryx still does not verify a token: it holds no
   verifier, no JWKS and no key for the agent, and it never sees the agent's
   request, so what arrives is the enforcement point's FACT, believed the way
   `chain_proven` is believed. A lying enforcement point can claim a stronger
   source than it had, and that is the same residual as a lying
   `chain_proven`, named rather than closed. What the source adds is a bound
   a policy can state, not a check wardryx performs. Absent or unknown is none,
   never the strongest value. *(test:
   `TestARequireIdentitySourceDeniesARequestThatSentNoSource` and
   `TestAnUnknownIdentitySourceCountsAsNone` in `internal/api`, which hold the
   absent and unknown cases as none)*

   *(test:
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

21. **`Filter` is Decide's rules 2 and 3 (deny_tool, allow_tool) applied to each
    offered tool alone, through
    the same matcher, and it is unrecorded while no enforcement point acts on
    its answer.** `POST /v1/filter-tools` exists to answer a narrower
    question than `/v1/decide`: not "may this action happen" but "which of
    these offered tools would `deny_tool` or `allow_tool` refuse". It reads the Engine's
    policy set exactly the way `Decide` reads it (one load, `Set.Match` on
    `AgentID`), and denies a tool through the same `containsFold` `Decide`
    uses, called rather than copied, so the two can never quietly diverge on
    what "denied" means for one tool.

    It is pure in the same sense `Decide` is pure (invariant 1): no clock,
    randomness, network or database in `internal/pdp`'s own code. And it
    applies no rule that is not about one tool: no chain rule, no
    attestation, no `max_steps`, no `allow_domains`, no `allow_models`, no
    cost rule, no approval token. Those are rules about the action as a whole, and `Filter`
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
    tool offered alone, `Decide` denies by `deny_tool` or `allow_tool` if and only if `Filter`
    lists it in `Denied`) in `internal/pdp`; `TestFilterToolsRequiresAuth`,
    `TestFilterToolsAnswersThePartition`, `TestFilterToolsRefusesABodyOverTheCap`,
    `TestFilterToolsRefusesAMissingAgentID`, `TestFilterToolsSurvivesHostileInput`
    in `internal/api`)*

    Since 2026-10-17 the route is bound like `/v1/decide` (invariant 36): a
    request naming an agent outside the key's allowance is a 403 and is
    recorded as an `agent_assertion_refused` event. That event records a
    refusal, not a filter answer, so "no event records a filter answer" still
    holds. `Filter` reads policies through the same org rule as `Decide`
    (invariant 38), and the 200-seed agreement sweep draws orgs.

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

    The diagrams the README shows are read the same way, one `<text>` of
    `docs/*.svg` or `assets/*.svg` at a time. Until 2026-10-13
    `docs/modes.svg` still said approval tokens are reusable for the full TTL
    by default and that `WARDRYX_APPROVAL_SINGLE_USE=true` makes each redeem
    once: written true on 2026-07-10, false since #53 flipped the default on
    2026-09-13, and left behind by #78, which fixed the README's own
    sentences, because the check read only the README.
    *(test: `TestReadmeProseNeverContradictsTheCodeDefaults`, red first on
    the real pre-#78 README, where it names all four drifted sentences, and
    on a flipped `parseBoolClosed` and a changed `api.DefaultUnansweredAfter`
    with the README unchanged, and red first on the unfixed `modes.svg`; its
    teeth are `TestReadmeProseCheckCatchesPlantedFaults`, eight planted
    faults, four of them verbatim pre-fix sentences (three from the README,
    one from `modes.svg`), and three non-faults, itself red when
    `sameSetting` is neutered and, on both diagram faults, when the diagrams
    are not read. Its limits: a default restated in words that name no
    variable ("tokens are reusable by default") and paraphrase in general are
    not read; those stay with review. The PNG renders are not read either, so
    a PNG regenerated from a stale SVG passes.)*

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
    inside `hold_if_signal` beyond `name`, `values`, `min_probability` and
    the optional `when_absent` (`decision`, `action`, `on_match`, anything
    else), in the strict decoder of a policy file and in the lax one the
    policy API uses alike. `name`, `values` and `min_probability` are
    required, the last because a rule with no threshold would hold on any
    probability. A signal that never arrived reaches the same rule and the
    same limit: under `when_absent: hold` it can hold a tool call, never deny
    one (invariant 33). A decision under a policy that
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
    ties a signal to the call it was about. Replay feeds back the signals and
    the tool call's `name`, `target` and `arguments_truncated`: `Decide` reads
    the name (invariant 29) and whether a call was there at all (invariant 33). `wardryx replay` puts the recorded signals to
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

29. **A policy can name the only tools its agents may use, and any other tool is
    denied.** `@decided 2026-10-13`: a policy may carry `allow_tool`, the list of
    the only tools that the agents it matches may use. A requested tool that the
    list does not name is denied, and no approval lifts that denial, because the
    rule sits before the cost gate, as deny_tool does. Matching uses the same
    case and surrounding-space folding as deny_tool and nothing looser, so a
    renamed tool is a different tool. Every matched list applies, so the lists
    intersect, and a matched policy with no list adds no restriction. An empty
    or absent list restricts nothing, so every policy written before the field
    decides exactly as it did. Both places a tool name reaches the PDP are
    checked: the tool list and the `tool_call` name on `/v1/decide`, and the tool
    list on `/v1/filter-tools`, which reports the refusal under the `allow_tool`
    rule. A blank entry is refused at load, since normalization would drop it and
    leave an empty list, which reads as no restriction. A decision that reads a
    tool call's name is never cacheable. Replay puts the recorded tool call name
    back to the PDP, so a recorded denial reproduces.
    The deny-list reads the same names. `@decided 2026-10-13`: deny_tool refuses a
    tool that a request names only in its tool call, as it refuses one that the
    tool list names. Rule 2 of `Decide` reads the tool list and the tool call's
    name, the same set rule 3 reads. The tool call sits outside the (agent, tool
    set) key a decision cache uses, so a request that carries a tool call is never
    cacheable under a matched deny_tool. A request with no tool call is read as it
    was before, and stays cacheable. `Filter` judges one offered tool at a time
    and carries no tool call, so it is unchanged. Replay reads the same name, so a
    recorded allow whose tool call is now denied replays as a divergence.
    Named limit: a request with no tool call is still cacheable under a deny_tool,
    so a cache keyed on agent and tool set alone can serve that allow to a later
    call whose tool call names a denied tool. A caller that caches must key on
    whether a tool call is present, or leave deny-list decisions uncached.
    *(test: `TestADeniedToolNamedOnlyByTheToolCallIsDenied`,
    `TestADenyToolDecisionForACallIsNeverCacheable`,
    `TestWithoutAToolCallADenyToolDecisionIsStillCacheable` (the golden for a
    request with no tool call) and `TestARecordedAllowWhoseToolCallIsNowDeniedDiverges`
    in `internal/replay`; scenarios in `features/deny-tool-call.feature`;
    `TestAToolOnTheAllowListIsAllowed`,
    `TestARenamedToolIsDeniedByAnAllowList`, `TestAToolTheListLeavesOutIsDeniedByName`,
    `TestNoAllowListMeansNoRestriction`, `TestTwoAllowListsNarrowEachOther`,
    `TestToolCallNameIsCheckedAgainstTheAllowList`,
    `TestAllowToolFoldsCaseLikeDenyTool`, `TestDenyToolWinsOverAllowTool`,
    `TestAnApprovalDoesNotLiftAnAllowListDenial`,
    `TestAnAllowToolDecisionIsNeverCacheable`,
    `TestFilterReportsAToolOutsideTheAllowList`,
    `TestFilterAgreesWithDecideOnEveryToolAlone` (its generator now draws
    allow-lists) in `internal/pdp`; `TestFilterToolsReportsAToolOutsideTheAllowList`
    in `internal/api`; `TestABlankAllowToolEntryIsRefusedAtLoad`,
    `TestAnAllowListIsPartOfThePolicyVersionAndItsOrderIsNot`,
    `TestAPolicyWithoutAllowToolKeepsItsPolicyVersion` (a golden value measured on
    the tree before the field) in `internal/policy`;
    `TestAnAllowToolDenialReplaysFromTheRecord` and
    `TestAMalformedRecordedToolCallIsUnreadableNotGuessed` in `internal/replay`.
    Scenarios in `features/allow-tool.feature`.)*

30. **Every document and every value in a policy file is loaded, or the file does not load.**
    `@decided 2026-10-13`: a YAML policy file may hold several documents
    separated by `---`, and a JSON policy file several values. Each document or
    value is read as one policy or as a list of policies, in order, and every
    one of them is in force. A YAML document with nothing in it holds no policy;
    a JSON file with no value at all is refused, as it always was. A document or
    value that fails to decode, including one with a field the Policy struct does
    not declare, fails the whole file, and the error names it by its position, so
    a file never loads smaller than it reads. Data after a JSON value is refused,
    not ignored. Before this decision the loader read the first document or value
    and stopped, and a rule in any later one was dropped with no error: a dropped
    deny is a silent allow. A file with one document or value keeps its
    `PolicyVersion` byte for byte, and a file with several has a version that
    covers every policy it loaded. The directory loader and the `replay`
    candidate both go through the same decode.
    A PUT /v1/policies/{id} body is one policy: data after it is refused with a
    400, does not echo it, and stores nothing; whitespace after it is not data.
    The other JSON request bodies (decide, filter-tools, approval decide) are
    read as before.
    *(test: `TestEveryDocumentOfAFileLoads`,
    `TestAnEmptyDocumentIsSkippedNotCountedAsAPolicy`,
    `TestAMalformedDocumentFailsTheWholeFileNamingIt`,
    `TestAMisspelledFieldInALaterDocumentIsRefused`,
    `TestASingleDocumentFileKeepsItsPolicyVersion` (golden values measured on
    the tree before the change), `TestTheVersionOfAMultiDocumentFileCoversEveryPolicy`,
    `TestADirectoryLoadsEveryDocumentOfEveryFile`,
    `TestEveryValueOfAJSONFileLoads`, `TestDataAfterAJSONValueIsRefusedNotIgnored`,
    `TestAJSONValueThatFailsStrictDecodingFailsTheFileNamingIt`,
    `TestAnEmptyJSONFileIsRefusedAsBefore`,
    `TestASingleValueJSONFileKeepsItsPolicyVersion` (golden measured before the
    change) in `internal/policy`; `TestARuleInTheSecondDocumentIsEnforced` in
    `internal/pdp`; `TestAPutBodyWithDataAfterThePolicyIsRefused` and
    `TestAPutBodyWithTrailingWhitespaceIsStillAccepted` in `internal/api`;
    scenarios in `features/multi-document-policy-file.feature` and
    `features/policy-put-body.feature`)*

31. **A policy write refuses a field the policy does not declare, and accepts
    the read-only fields a GET returns.** `@decided 2026-10-13`: a
    `PUT /v1/policies/{id}` body is decoded with unknown fields refused. A key
    the policy does not declare is a 400 that names it, echoes no value, and
    stores nothing. Before this decision the decoder dropped such a key, so a
    rule spelled wrong was stored without the rule and the write answered 200,
    and the call the rule meant to deny was allowed. The two fields a GET of a
    policy returns beyond the policy's own, `id` and `updated_at`, are accepted
    on input and ignored: the URL names the policy and the server stamps the
    write, so a body copied from a GET can be written back unchanged. A key
    inside `hold_if_signal` that the rule does not have is refused on this path
    as well, by the rule's own decoder. The other JSON request bodies (decide,
    filter-tools, approval decide) are not covered by this invariant and are
    read as before.
    *(test: `TestAPutWithAMisspelledRuleIsRefusedAndNothingIsStored`,
    `TestAGetBodyWrittenBackUnchangedIsAccepted`,
    `TestTheReadOnlyFieldsOfAPutBodyAreIgnored`,
    `TestAnUnknownKeyInsideAHoldRuleIsRefusedOnPut` in `internal/api`;
    scenarios in `features/strict-policy-write.feature`)*

32. **An approval token reaches `/v1/decide` in the `approval_token` field of
    the body, and a header the README names is one this service reads or is
    said to be the enforcement point's.** Measured 2026-10-13: the README's
    decision table told a reader to redeem a hold by resubmitting "with header
    `x-fuse-approval-token`", in the column that describes this service's own
    response, and `docs/decisions.svg` and `docs/architecture.svg` drew the
    same thing. Wardryx reads one header, `Authorization`. The header is
    TokenFuse's: the gateway reads it from the agent's request and forwards
    its value in the body field (held on that side by tokenfuse's
    `approval_token_header_is_forwarded_to_decide_call`). The code of both
    repositories was right; a caller of `/v1/decide` that followed the README
    sent the token where nothing reads it and was held again.

    Two halves, held apart. The code half: a granted token sent in
    `x-fuse-approval-token`, or in two other spellings a caller might guess,
    with the body field empty, is a hold, and does not spend a single-use
    token. The prose half: every `x-` header named in a README sentence, a
    table cell, a code line or a `<text>` of `docs/*.svg` or `assets/*.svg`
    is one a non-test Go file reads with `r.Header.Get`, or the same unit
    names TokenFuse. Its limits: naming TokenFuse is taken as attribution,
    the grammar is not read; a header with one part after `x-` is not seen;
    the PNG renders are not read, so a PNG regenerated from a stale SVG passes.
    *(test: `TestAnApprovalTokenSentAsAHeaderIsNotRead` in `internal/api`,
    red on a planted header fallback in `handleDecide`;
    `TestReadmeNamesNoHeaderWardryxDoesNotRead` in `cmd/wardryx`, red first on
    the unfixed README and both diagrams, three findings; its teeth are
    `TestReadmeHeaderCheckCatchesPlantedFaults`, five planted faults, the
    pre-fix row and hold card among them, and three non-faults, itself red
    when the attribution test is neutered. Scenarios in
    `features/approval-token-wire.feature`.)*

33. **A tool call whose risk signal never arrived can be held, and only an
    approval of that call lifts the hold.** `@claude 2026-10-14`: on the
    2026-10-14 range runs a tool call padded past the enforcement point's
    12 KiB argument cap reached `/v1/decide` marked `arguments_truncated` and
    carrying no signal, because the classifying proxy does not ask about a call
    it cannot read, and every `hold_if_signal` rule let it through: the rule
    had nothing to read and the signal rule fell through to allow. The same "no signal,
    so allow" follows when the producer's own budget is spent, when it times
    out, and when it is down, and the first of these is the caller's choice.

    `hold_if_signal` takes an optional `when_absent`. `allow`, the default, is
    what the rule always did, and a policy that leaves the key out or writes
    `allow` keeps its `PolicyVersion` byte for byte (Compile stores `allow` as
    the default). `hold` holds a request that carries a `tool_call` and no
    signal of the rule's name, of any value. A signal of that name with a value
    the rule does not list, or under the threshold, is present: it is an
    answer, and it holds nothing. A request with no `tool_call` (a model call,
    where no call has been chosen to classify) is never held for a missing
    signal. The hold is the signal rule's (rule 13 since allow_models), after
    every deny rule and the cost gate, so
    invariant 25 stands as it was: it turns an allow into a hold and nothing
    else. `when_absent: deny` is refused at load and at PUT with the sentence
    that a signal can only hold; any value but `allow` or `hold` is refused,
    and so is the key written with no value, as null or as anything but text,
    so that a blank never reads as a choice.

    Only an approval token bound to the call lifts a hold that an absent signal
    caused (`approval.VerifyApprovalTokenBoundToCall`): the hold exists because
    nobody could say what the call does. A token that binds no call, which
    invariant 28 still accepts on a hold a present signal caused, holds again
    here, and so does every token that is not bound to this call when any
    matched rule held on absence, whichever rule the reason names. The hold
    always records its call, so the token granted for it is always bound. The
    reason names the rule's policy and signal, the tool call, and, when it was,
    that its arguments were not sent. The record carries the tool call
    (invariant 27) and replay feeds its name, target and truncated flag back,
    so the hold reproduces with the producer unreachable. A decision under such
    a rule is never cacheable (invariant 25).

    Named limits. The default is `allow`, so a deployment is covered only where
    its policy sets `hold`; this repository ships no policy, and a launcher
    that writes one decides. With `hold`, every tool call the producer does not
    answer waits for a person, so a producer outage holds every governed tool
    call until it is back. The caller is believed about whether a call exists
    (invariant 26): a request that leaves `tool_call` out is decided as a model
    call. A padded call carries no arguments, so its digest binds only name,
    target and the flag (invariant 28's limit for truncated arguments): every
    padded call to the same tool and target in one run has the same digest, the
    person who approves one approves it without seeing what it does, and the
    token fits the next padded call too. Under the single-use default
    (invariant 5) it lets exactly one of them through; with
    `WARDRYX_APPROVAL_SINGLE_USE=false` it lets every one through for the
    token's lifetime. A deployment that sets `when_absent: hold` must leave
    single-use on. `TestAnApprovalOfOnePaddedCallCoversTheNextPaddedCallToTheSameTool`
    pins this limit in both modes, so a change to it is seen.
    *(test: `TestAToolCallWithNoSignalHoldsWhenTheRuleHoldsOnAbsence`,
    `TestAModelCallWithNoToolCallIsNeverHeldForAMissingSignal`,
    `TestAnAbsentSignalOnlyEverHolds`,
    `TestASignalWithAnUnlistedValueIsPresentNotAbsent`,
    `TestAnAbsentSignalHoldIsLiftedByATokenBoundToTheCall`,
    `TestAnUnboundTokenDoesNotLiftAnAbsentSignalHold`,
    `TestAnAbsentSignalHoldIsNeverCacheable`,
    `TestSignalsNeverChangeADenyOrRemoveAHoldOverRandomPolicies` (200 seeds,
    `when_absent` drawn at random, every decision compared with the same policy
    without the rule) in `internal/pdp`;
    `TestWhenAbsentTakesOnlyAllowOrHold`,
    `TestAPolicyWithoutWhenAbsentKeepsItsPolicyVersion`,
    `TestCompileChecksWhenAbsentOnARuleBuiltInGo` in `internal/policy`;
    `TestATokenThatBindsNoCallIsRefusedWhereTheCallMustBeBound` in
    `internal/approval`;
    `TestATruncatedToolCallWithNoSignalHoldsWhenTheRuleHoldsOnAbsence` (the
    broker's body over the cap, byte for byte),
    `TestAReplayReproducesAnAbsentSignalHold`, `TestWhenAbsentOverThePolicyAPI`,
    `TestAnApprovalOfOnePaddedCallCoversTheNextPaddedCallToTheSameTool` in
    `internal/api`;
    `TestARecordedAbsentSignalHoldReproducesFromTheRecordedToolCall` in
    `internal/replay`; scenarios in `features/hold-when-signal-absent.feature`;
    mutants named in the PR that added it, each caught: `when_absent` ignored,
    a hold with no tool call, absence turned into a deny, an unlisted value read
    as absent, a token that does not lift the hold, the absence check before the
    deny rules, an unbound token lifting it, only the first holding rule
    deciding the binding, the rule left out of the cache check, replay dropping
    the tool call, `deny` accepted at load, `allow` not stored as the default,
    the bound verifier accepting an unbound token, a blank value read as the
    default)*

34. **A policy can name the models its agents may use, and a call naming any
    other model is denied.** `@decided 2026-10-14` (paraphrased): an operator
    may bound which models an agent uses, per policy and so per agent or unit.
    Until this change no plane bounded it: wardryx received `model` and did not
    branch on it, TokenFuse has no model rule, and the Passport's `models` is a
    declaration, not a control. `@claude 2026-10-14`, the shape, chosen in this
    change: `allow_models` is a list of model ids and globs in `target`'s
    syntax; a request whose `model` matches no entry of a matched non-empty list
    on a model call is denied by rule 8 of `Decide`, after `deny_if_unattested` and before
    `max_steps`, so no approval token lifts it. Every matched list applies, so
    two lists narrow each other. Matching is exact (`policy.MatchesGlob`, no
    case or space folding, which would widen an allow-list), and a model holding
    a control character or invalid UTF-8 matches nothing. An empty or absent
    list restricts nothing and keeps the policy's `PolicyVersion` byte for byte;
    the list is sorted and deduplicated, so its order is not part of the
    version; a blank entry is refused at load and at PUT. Only a model call is
    judged: a request with no `tool_call` that sends a `model` key
    (`DecideRequest.ModelAbsent` false; the API sets it from whether the key
    was sent, and the record carries `model_absent` only when it is true, so
    replay judges what the live decision judged). A model call whose model is
    empty or blank is refused: TokenFuse sends the body's `model` as it is, so
    `"model": ""` arrives empty, and an upstream that fills in a default would
    otherwise serve any model. A request with a `tool_call` is a tool decision
    (TokenFuse's MCP broker sends the call and an empty model) and a request
    with no `model` key is not about a model call (scopyx's egress checks send
    agent, run and domains only): neither is judged, the way `allow_domains`
    does not judge a request that declares no domain, and refusing them would
    refuse every tool and egress decision of a governed agent. The offline
    `wardryx check` sends no model. TokenFuse sends `unknown` for a model call
    whose body names none, and that is matched like any other name. A decision under a matched policy that sets the list is never
    `cacheable`, whatever it decided: the model is per call, and the gateway's
    decision cache is keyed by agent, tool set, attestation and chain, so a
    cached allow for a listed model would answer a call naming a refused one.
    The model is already recorded with every decision (invariant 15), and replay
    puts it back, so a model denial reproduces. `Filter` does not apply the rule
    (invariant 21): a model is not a tool.

    Named limits. The enforcement point is believed about the model (invariant
    26): a caller that leaves the `model` key out, or sends a `tool_call`, is
    not judged, and the rule bounds the
    model a call names, not the one a provider serves; TokenFuse settles by the
    requested id and never reads the response's model. A rollback to a build
    before this one refuses a policy file that uses the key, which is loud, and
    reads a policy stored in Postgres with a decoder that drops it, so remove
    `allow_models` from stored policies first.
    *(test: `TestAModelTheListDoesNotNameIsDenied`,
    `TestNoAllowModelsMeansNoRestriction`,
    `TestAModelCallThatNamesNoModelIsRefused`,
    `TestOnlyAModelCallIsJudgedByAllowModels`,
    `TestTwoModelListsNarrowEachOther`, `TestAnApprovalDoesNotLiftAModelDenial`,
    `TestAnAllowModelsDecisionIsNeverCacheable`,
    `TestAllowModelsDeniesExactlyTheUnlistedModelsOverRandomPolicies` (200
    seeds, every decision compared with the same policies without the lists,
    the match recomputed by the test's own glob reader),
    `TestFilterAppliesNoRuleThatIsNotAboutATool` in `internal/pdp`;
    `TestAllowModelsLoadsFromYAMLAndJSONAndThroughTheLaxDecoder`,
    `TestABlankAllowModelsEntryIsRefusedAtLoad`,
    `TestAPolicyWithoutAllowModelsKeepsItsPolicyVersion`,
    `TestAnAllowModelsListIsPartOfThePolicyVersionAndItsOrderIsNot` in
    `internal/policy`;
    `TestAnAgentThatSwitchesToAModelItsPolicyDoesNotAllowIsRefused` (the
    gateway's body), `TestAModelDenialReplaysFromTheRecord`,
    `TestAPutWithAllowModelsIsStoredAndEnforced`,
    `TestOnlyAModelCallIsJudgedOverTheWire` (the gateway's, scopyx's and the
    broker's bodies), `TestDecisionInputCoversEveryDecideRequestField` in
    `internal/api`; `TestCheckDoesNotJudgeAModelItWasNotShown` in
    `cmd/wardryx`;
    `TestARecordedModelDenialReproducesFromTheRecordedModel` in
    `internal/replay`; the order is held by `scripts/decide-order-is-documented.sh`;
    scenarios in `features/allow-models.feature`; mutants named in the PR that
    added it, each caught: the match inverted, the empty-list short-circuit
    dropped, a decision under the list marked cacheable, case folded, the rule
    after the cost gate, only the first matched list read, a control character
    allowed, an entry matched as a prefix, replay dropping the model, a blank
    entry accepted, the list not normalised, the early return for a blank model
    restored, a request that sent no model judged, a tool call judged, a model
    sent empty read as none sent, replay dropping `model_absent`, the record
    leaving it out, the offline check judged as a model call)*

35. **A policy change names the key that made it, as a fingerprint, and never holds the key.** `@claude 2026-10-15`, a design fixed by the supervisor session of this audit. A `policy_updated` event from a `PUT` or a `DELETE` of `/v1/policies/{id}` carries `key_fp`: the first 16 hex characters of SHA-256 over the bearer key that authenticated the write, computed at authentication from the presented key and held on the `Principal`. `decided_by` stays the organisation, unchanged for current readers. The raw key is never stored, logged or emitted, and the field is added only to those two emits; the emit stays fail-open and writes only when an events file is configured. An operator matches a fingerprint to a key with `printf %s "$KEY" | shasum -a 256 | cut -c1-16`. Named limits: the fingerprint identifies the key, not the person holding it, and it is a 64-bit truncation of the hash.
   *(test: `TestAPolicyPutRecordsTheFingerprintOfTheKeyThatMadeIt`, `TestAPolicyDeleteRecordsTheFingerprintOfTheKeyThatMadeIt`, `TestTheRawKeyNeverReachesTheEventFile`, `TestTheRecordedFingerprintIsSixteenLowerCaseHexAndNotTheEmptyKeys`, `TestTwoKeysOfOneOrganisationAreToldApart`, `TestTheDecidedByFieldStillNamesTheOrganisation` in `internal/api`; scenarios in `features/policy-change-names-its-key.feature`; the mutants named in the report, each caught by one of these)*

36. **The agent a decision is about is bound to the key that asks.**
    `@decided 2026-10-17` (paraphrased): close the agent-security findings of
    the 2026-10-17 review, starting with the defaults and the small fixes.
    Finding F-001: `/v1/decide` took `agent_id` from the body and checked only
    that it was not empty, so any key could ask in any agent's name and get
    that agent's decisions and approvals (live run L3, P2). `@claude
    2026-10-17`, the shape, from the review's brief: a `WARDRYX_KEYS` entry
    may list, after the role, the agents the key speaks for
    (`key:org:role:pattern|pattern`, each a glob in a policy target's syntax,
    compiled once by `api.New`). `speaksFor` is the rule: a listed key speaks
    for exactly its patterns; an unlisted `cross-org-admin` for any agent; an
    unlisted `pep` (the enforcement point, which authenticated the agent first)
    or `admin` (which can rewrite the rules that decide) for any agent of its
    own org, which wardryx can tell only when every key belongs to one org,
    so with more than one org they speak for none until listed; an unlisted
    `viewer`, or a role this service does not know, for none. The check runs
    in `handleDecide` and `handleFilterTools` before anything else in the body
    is read: a refused request is a 403 that echoes nothing, reaches no rule,
    holds nothing and reads no approval token, so it cannot spend one, and
    emits one `agent_assertion_refused` event whose `agent_id` is wardryx's
    own (`agent://wardryx.internal/auth/agent-binding`) and whose data names
    the route, the asserted agent and run, and the key's org, role and
    fingerprint, never the key. `serve` prints at start every key that speaks
    for no agent, by fingerprint (`KeyPosture`). Named limits: wardryx does not
    know which trust domains an org owns, so an unlisted `pep` key of a
    one-org deployment speaks for any agent id; `chain_proven` and
    `attestation_method` stay the enforcement point's word, believed as
    before (invariant 13), and nothing here widens them; and an existing
    gateway key with the `viewer` role must become `pep`.
    *(gate: `scripts/agent-is-bound-to-its-key.sh`, six cases in
    `gates-have-teeth.sh`; test: `TestAKeyThatListsItsAgentsCannotAskForAnother`,
    `TestAKeyThatListsItsAgentsAsksForThemAsBefore`,
    `TestAnAgentPatternCoversOnlyTheAgentsUnderIt`,
    `TestAViewerKeyWithNoListSpeaksForNoAgent`,
    `TestAPepKeySpeaksForAnyAgentWhenThereIsOneOrg`,
    `TestWithTwoOrgsAnUnlistedKeySpeaksForNoAgent`,
    `TestACrossOrgAdminKeySpeaksForAnyAgent`,
    `TestARefusedRequestSpendsNoApprovalToken`,
    `TestARefusalIsRecordedAndNamesTheKeyByFingerprint`,
    `TestFilterToolsIsBoundToTheKeyLikeDecide`,
    `TestParseKeysReadsAnAgentListAfterTheRole`,
    `TestKeyPostureNamesEveryKeyThatSpeaksForNoAgent`,
    `TestTheDevkeySpeaksForAnyAgent` in `internal/api`; scenarios in
    `features/agent-bound-to-its-key.feature`)*

37. **The approver an approval records is the key that decided it, and an
    approval with no org needs a principal allowed across orgs.** Finding
    F-012, its approval half (live run L3, P3): `decided_by` was the free text
    the request sent, recorded as who decided. `@claude 2026-10-17`, the
    shape: the approval's `decided_by` is `approverID`, `key:` and the
    fingerprint of the bearer key (invariant 35's `key_fp`), in the store, in
    `GET /v1/approvals`, in `wardryx approvals` and in the `approval_granted`
    and `approval_denied` events, which also carry `key_fp`. The text a
    request sends in `decided_by` is optional and is kept beside it as
    `decided_by_label` (a column added with `ADD COLUMN IF NOT EXISTS`, NULL
    when none was sent), at most 256 bytes with no control character and no
    bidirectional override, refused with a 400 that does not echo it. A
    principal is allowed across orgs when it has the `cross-org-admin` role,
    or is an `admin` and every key belongs to one org (a `cross-org-admin` is
    not counted as an org): only such a principal decides an approval with no
    org, or of another org, and lists the approvals of every org. Named
    limits: rows decided before this change hold the text as `decided_by`; a
    fingerprint names a key, not the person holding it.
    *(gate: `scripts/agent-is-bound-to-its-key.sh`; test:
    `TestTheApproverRecordedIsTheKeyNotTheText`,
    `TestTheTextSentIsKeptAsALabelBesideTheApprover`,
    `TestAnApprovalDecisionNeedsNoLabel`,
    `TestAHostileLabelIsRefusedAndTheApprovalStaysPending`,
    `TestAnApprovalWithNoOrgNeedsAPrincipalAllowedAcrossOrgs`,
    `TestWithOneOrgItsAdminDecidesAnApprovalWithNoOrg`,
    `TestACrossOrgAdminListsTheApprovalsOfEveryOrg` in `internal/api`;
    `TestMemoryDecideApprovalKeepsTheLabelApartFromTheApprover` and, in CI's
    integration job, `TestPgDecideApprovalKeepsTheLabelApartFromTheApprover`
    in `internal/store`; `TestTheApprovalsListShowsTheApproverAndTheLabel` in
    `cmd/wardryx`; scenarios in `features/approver-is-the-key.feature`)*

38. **A policy written by an org's admin governs that org's decisions only.**
    Finding F-012, its policy half (live run L3, P6): a policy had no org, so
    the admin of one org wrote a deny that changed another org's decisions.
    `@claude 2026-10-17`, the shape: `policy.Policy` has `org` (omitted when
    empty, so a policy without it keeps its `PolicyVersion` byte for byte).
    `Decide` and `Filter` read `policy.Set.MatchIn(agent, org)`: a policy with
    an org governs only a decision asked in that org, the org of the key that
    asked (`DecideRequest.Org`, set from the principal, never the body); one
    without applies across orgs, as every policy did before. An org admin's
    `PUT` stamps its own org, refuses a body naming another (403), and may not
    replace or delete a policy across orgs or of another org (403, and another
    org's policy reads as 404 on GET, list and DELETE); a principal allowed
    across orgs (invariant 37) writes any. `/v1/status` counts the policies
    that govern the caller. Every decision event records `org`, and replay
    feeds it back; a record from before the field asks in no org, where only
    policies across orgs apply, which is every policy that then existed. An
    org with surrounding space or a control character is refused at load.
    Named limits: `wardryx check` asks in no org, so it applies only policies
    across orgs; a policy id is one namespace across orgs, so a refused `PUT`
    tells a caller that an id is taken; a rollback to a build before this one
    reads a stored `org` with a decoder that drops it, which widens that
    policy to every org, so remove org-scoped policies first.
    *(gate: `scripts/agent-is-bound-to-its-key.sh`; test:
    `TestOneOrgsAdminCannotChangeAnotherOrgsDecisions`,
    `TestAnOrgAdminCannotWriteForAnotherOrgOrAcrossOrgs`,
    `TestAnOrgAdminNeitherSeesNorRemovesAnotherOrgsPolicy`,
    `TestACrossOrgAdminWritesAPolicyThatAppliesAcrossOrgs`,
    `TestWithOneOrgItsAdminWritesPoliciesAsBefore`,
    `TestAnOrgScopedDenialReplaysFromTheRecord`,
    `TestDecisionInputCoversEveryDecideRequestField` in `internal/api`;
    `TestAPolicyWithAnOrgAppliesOnlyToThatOrgsDecisions`,
    `TestFilterAgreesWithDecideOnEveryToolAlone` in `internal/pdp`;
    `TestAPolicyWithoutAnOrgKeepsItsPolicyVersion` (golden values measured on
    the tree before the field), `TestABlankOrPaddedOrgIsRefusedAtLoad` in
    `internal/policy`; `TestARecordedOrgIsFedBackToThePDP` in
    `internal/replay`; scenarios in `features/policy-belongs-to-an-org.feature`)*

39. **A policy can require the identity source the enforcement point reports,
    and a request without a known source is refused by such a policy.**
    `@decided 2026-10-18` (paraphrased): the decision names how the enforcement
    point knew the agent, and a policy may list the sources it accepts.
    `require_identity_source` takes `agent-token`, `client-key` and `none`; a
    value that is none of those is refused at load, naming it. Every matched
    policy's list must name the request's source, so two lists intersect. An
    absent `identity_source`, and any value that is not one of the three, is
    `none`, which no list naming a real source accepts. The rule is rule 8 of
    `Decide`, after `deny_if_unattested` and before the model rule, and a
    decision under a policy that carries it is never cacheable. A policy that
    does not set the field keeps its `PolicyVersion` byte for byte, and each
    decision event records the normalized source. Replay reads a record that
    lacks one as `none`, never as unreadable. Named limits: wardryx trusts the
    reported source, as invariant 13 says; `wardryx check` has no enforcement
    point and so judges such a rule as `none`; the rule denies and never holds.
    *(gate: `scripts/decide-order-is-documented.sh`, which reads the rule's
    place in the order; test: `TestTheSourceRuleComesAfterDenyIfUnattested`,
    `TestEveryMatchedPolicyMustListTheSource`,
    `TestAPolicyThatReadsTheSourceIsNeverCacheable`,
    `TestARecordedIdentitySourceReplaysToTheSameVerdict`,
    `TestDecisionInputCoversEveryDecideRequestField` in `internal/api`;
    `TestAnUnlistedIdentitySourceIsRefusedAtLoad`,
    `TestTheOrderOfTheSourceListDoesNotChangeThePolicyVersion`,
    `TestAPolicyWithoutTheRequirementKeepsItsVersion` in `internal/policy`;
    `TestARecordedSourceIsReadBack`,
    `TestAnOldRecordWithoutASourceIsReadAsNone` in `internal/replay`; scenarios
    in `features/a-policy-can-require-a-verified-agent.feature`; mutants: an
    absent source read as agent-token, the rule inverted, the source not
    recorded, the cache marker dropped, replay reading the field strictly,
    replay ignoring it, the load check skipped, and only the first matched
    policy checked, each caught)*

40. **An allow or a hold is not returned when its record could not be written,
    under the closed record fail mode.** `@decided 2026-10-18` (paraphrased):
    wardryx does not answer a caller with an allow or a hold that no record
    holds, because that answer is the one an audit later has nothing to say
    about. Finding F-011 of the 2026-10-17 review: `emit` logged the write error
    and the handler answered anyway, so a full volume or an unwritable stream
    gave decisions with no record, and only a log line said so.

    `WARDRYX_RECORD_FAILMODE` picks the mode. `closed`, the default, answers
    `503 record_unavailable` in place of an allow or a hold whose record was not
    written. `open` returns it anyway and makes `/readyz` answer 503 with
    `"record": "failing"` until a write succeeds; `serve` warns at startup when
    `open` is chosen. Any value other than `open` is closed. A deny is returned
    either way: it starts no action, so refusing it would trade a known refusal
    for an unknown one, and it stays fail-open through `emit`. Only an allow or
    a hold goes through `recordDecision`.

    Named limits. With no event file (`WARDRYX_EVENTS_PATH` unset) there is no
    record to fail, and nothing is refused. The record of an approval grant or
    denial and of a policy write stays fail-open, as before: the approval's row
    in the store is the durable record of a grant, and an allow that uses its
    token is refused under closed if its own record fails. A single-use token
    redeemed for an allow that was then refused stays spent, and a refused hold
    stays pending in the approval queue. The gate reads the handler's shape; it
    does not judge whether a given refusal is right.

    *(gate: `scripts/decision-record-is-checked.sh`, six cases in
    `scripts/gates-have-teeth.sh`; test: `TestAnAllowIsRefusedWhenItsRecordCannotBeWritten`,
    `TestAHoldIsRefusedWhenItsRecordCannotBeWritten`,
    `TestADenyIsStillReturnedWhenItsRecordCannotBeWritten`,
    `TestTheAllowRecordIsAttemptedBeforeItIsReturned`,
    `TestOpenModeReturnsTheAllowAndRaisesTheHealthFlag`,
    `TestReadyzClearsWhenARecordWriteSucceedsAgain`,
    `TestWithNoRecordWriterNothingIsRefused` in `internal/api`;
    `TestTheRecordFailModeDefaultsToClosed` and
    `TestRecordFailModeIsOpenOnlyWhenAskedFor` in `internal/config`;
    `TestTheOpenFailModeIsWarnedAtStartup` in `cmd/wardryx`; scenarios in
    `features/record-failmode.feature`)*

41. **An approval token signed by Keyryx is verified by its signature under the
    kid it names, from a key set the verifier holds, and by nothing else.**
    `@decided 2026-10-18` (paraphrased): the approval key is held by the custody
    service, Keyryx, so the record can show what a person approved and an auditor
    can check a token without the service that issued it. The HMAC tokens of
    earlier grants are accepted only until a deadline the operator sets.
    `@claude 2026-10-18`, the shape: with `WARDRYX_APPROVAL_SIGNER=keyryx` a grant
    mints a v3 token, a compact JWS whose header is `alg` ES256, `kid`, and
    `typ` `wardryx-approval+jwt`, and whose claims are `v` 3, `aid` (the
    approval), the agent, run, tools, `max_cost_usd`, `tcd` when the hold named a
    call, `exp` and `nonce`. Keyryx signs at grant time and before the approval
    is written, so a grant that cannot be signed leaves the hold pending and
    answers 503. Verification reads only the set wardryx holds: each key is a
    P-256 point on the curve whose kid is its RFC 7638 thumbprint, a kid the set
    does not hold is refused, a key or key location in the header is refused as
    malformed, the HMAC is never used for v3, and a failed fetch keeps the set
    it had. Everything after the signature is what invariants 5 to 29 state for
    v2. A v2 token verifies before `WARDRYX_APPROVAL_V2_UNTIL` and not after, and
    with a signer and no deadline it is refused. Named limits: a token is trusted
    as far as Keyryx's key and its use log are; the cached set has no age bound
    while Keyryx is unreachable, so a revoked kid verifies until the next
    successful fetch; a verifier that never fetched the set refuses every v3
    token; a fingerprint names a key, not a person. *(gate:
    `scripts/approval-verifier-trusts-its-keys.sh`, five cases in
    `gates-have-teeth.sh`; test: `TestAGrantMintsAnES256TokenNamingItsKidAndTheApproval`,
    `TestAnUnknownKidIsRefused`, `TestAForgedOrAlteredSignatureIsRefused`,
    `TestTheHeaderMustPinES256AndCarryNoKey`, `TestV3BindsWhatV2Binds`,
    `TestAGrantWithTheSignerDownLeavesTheHoldPending`,
    `TestAV2TokenVerifiesOnlyBeforeTheDeadline`,
    `TestAKidThatMovesTwiceFailsTheGrant` in `internal/approval`;
    `TestAGrantWithKeyryxMintsAV3TokenThatDecideAccepts`,
    `TestAnUnknownKidHoldsAgainOnDecide`,
    `TestAGrantWithKeyryxDownAnswers503AndLeavesTheHoldPending`,
    `TestCachedKeysVerifyWhileKeyryxIsDown` in `internal/api`;
    `TestAMalformedSetIsRefusedWholeAndTheCacheKept`,
    `TestAKidThatIsNotTheKeysThumbprintIsRefused`,
    `TestARevokedKidLeavesTheSetAtOnce`,
    `TestAPollThatFailsKeepsTheSetItHad`,
    `TestTheThumbprintIsTheOneAgentStackGoComputes` in `internal/keyryx`; scenarios in
    `features/approval-token-v3.feature`.)*

42. **No map in `internal/` is indexed by a bearer key a request presented, and every configured bearer is stored under its SHA-256 digest.**
    `@decided 2026-10-17` (paraphrased): close finding F-023 of the 2026-10-17 review, bearer keys compared by a lookup on the raw value rather than in constant time.
    `@claude 2026-10-19`, the shape: `ParseKeys` keys each entry by `keyDigest`, the lowercase hex SHA-256 of the key; `authenticate` digests the presented bearer and looks that digest up; `keyFingerprint` takes the digest, so the `key_fp` every audit record carries (invariant 35) is unchanged. The MAC comparisons already used `hmac.Equal` (the v2 signature and the tool-call digest in `internal/approval`), so they stay as they are and a source-reading test holds them.
    Named limits: the comparison is between one-way digests, not between the secret and the presented bytes. The gate follows one assignment from the Authorization header, not a chain of them, and a lookup inside a helper that takes the bearer is not seen.
    *(gate: `scripts/no-raw-secret-lookup.sh`, four cases in `scripts/gates-have-teeth.sh`; test: `TestTheKeyStoreHoldsNoRawSecret`, `TestEveryRoleStillAuthenticatesWithItsKey` and `TestANearMissKeyIsRefusedWith401` in `internal/api`, `TestTheSignatureAndTheDigestAreComparedInConstantTime` in `internal/approval`; scenarios in `features/bearer-key-store.feature`)*
