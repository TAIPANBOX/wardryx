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
```

CI additionally runs `govulncheck ./...` and a Postgres-backed store test
(`go test -tags integration ./internal/store/`). The integration test needs a
live database and is skipped locally by the build tag, so a green local run
proves less than a green CI run. Do not treat the two as equivalent.

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
   is an approval anyone can forge. *(not enforced)*
5. **An approval token is single-use.** A redeemed token allows exactly one
   `/v1/decide` call for the approval it was minted for; a second presentation
   of the same token is rejected. Replay of an approval is the whole attack.
   *(not enforced)*
6. **`POST /v1/approvals/{id}/decide` is admin-only.** Granting an approval is
   the privileged operation in this service; every widening of who may call it
   is a security decision, not a routing change. *(not enforced)*
7. **A hold is stateless.** Do not add server-side session state to carry a
   hold between the decision and its resolution. The signed token is the state,
   which is what lets any instance resolve a hold minted by any other.
   *(not enforced)*
8. **`agent-stack-go` is pinned by tag and is the only source of the wire
   types.** Never hand-roll a local copy of a passport, event, or chain type.
   If the shared type is wrong, widen it there. *(not enforced)*

## Decisions that have no gate yet

This list is debt, and it is here to stay visible rather than to be tidy.

**Held by this file alone: invariants 4, 5, 6, 7 and 8.**

Invariants 4, 5 and 6 are security properties and are the strongest candidates
for a test that must fail first: mint without a secret, present a token twice,
call the decide route as a non-admin. Each should assert the refusal, and each
should be written by breaking the code first to confirm the test can see it.
Until then they are prose.

Invariant 7 is judgement about design shape. Invariant 8 is mechanically
checkable in principle, by asserting no local type duplicates a shared one, but
the check is only worth writing if a duplicate ever appears.

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
