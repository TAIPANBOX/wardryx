# Live infrastructure validation

Wardryx was run as a live policy decision point in front of a real Claude-backed gateway, TokenFuse (the
PEP, the enforcement point that calls Wardryx's `/v1/decide`), on disposable Hetzner infrastructure before
any public launch, including under real concurrent multi-agent load - the first time TokenFuse had ever
faced simultaneous, adversarial-shaped traffic rather than sequential test cases.

## Policy decisions under real, concurrent load

An enriched multi-agent campaign produced **176 real PEP decisions** with differentiated per-agent
rights: an `analyst` agent denied a `wire_transfer` (403), a `treasury` agent allowed the same action,
an unattested `scraper` denied on `call_unattested` but allowed once attested, and `shell_exec` denied
for every agent regardless of identity.

Under a **34-request concurrent burst** (different agents, credentials, and policies fired at once), the
PEP filtered exactly the right ones: permission-oversteppers **6/6 denied (403)**, unattested calls
**403 / attested calls 200**, with differentiated rights holding correctly under concurrency, not just
sequential requests.

## Real bugs live testing found (and fixed)

Both were enforcement gaps invisible on sequential test traffic - only real concurrent load surfaced
them. Both fixed, covered by a regression test, and re-verified live before the numbers above were taken
as final.

**Both bugs were entirely on the PEP's side, not Wardryx's.** The PEP in this run was TokenFuse's
gateway (`crates/gateway/src/wardryx.rs`), which calls Wardryx's `/v1/decide` and then acts on the
verdict. Wardryx returned a correct decision and a correct `cacheable` hint throughout; the defect in
each case was in how TokenFuse's own code built its request and cached the result, not in anything
Wardryx computed. This live testing genuinely found and fixed both, in TokenFuse - see that repository's
`PROGRESS.md` (the Wardryx policy hook entry) for the fixes attributed to that file, and this repository's
own [README](README.md#the-v1decide-contract) ("Wardryx never caches anything itself") for the same point
made in the ongoing documentation rather than a point-in-time report.

1. **Declared-but-not-invoked tool bypass** - TokenFuse's gateway built its deny/allow decision from
   *invoked* tools only, so a request that merely *declared* a forbidden tool without ever calling it
   reached the model, bypassing a `deny_tool` policy. Fixed in TokenFuse by unioning
   `taint::declared_tool_names_in` into the decision path, with a unit test for the exact bypass case
   plus an end-to-end regression.
2. **Decision-cache attestation gap** - TokenFuse's decision cache was keyed on `(agent_id, tool-set
   hash)` but not `attestation_method`, so within the cache TTL an unattested agent could inherit a
   recently attested `allow` (or vice versa), silently defeating `deny_if_unattested` in an
   order-dependent way. Found by the 34-agent concurrency test specifically - it never showed up under
   sequential load. Fixed in TokenFuse by adding attestation to the cache key; re-verified live
   (unattested → 403 in both cache orderings and under the full concurrent test).

## What this proves

- Per-agent differentiated policy (`deny_tool`, `deny_if_unattested`, `require_human_above_usd`) is
  deterministic and correct under real concurrent load, not just in isolation.
- Both enforcement gaps found here needed genuinely concurrent, adversarial-shaped traffic to surface -
  neither would have shown up in a sequential test suite, which is exactly the kind of gap real-world
  testing exists to close before anyone else finds it.

---

# At cluster scale, on three clouds

The run above proves the decisions are right. It says nothing about how many of
them a pod can make, what they cost, or what they leave behind. Between 25 and
27 July 2026 the whole stack came up as a five-node k3s cluster on Hetzner, AWS
and GCP, six clusters in all, and that is what got measured. Everything below
is from a live cluster; the command output is public in
[stack-k8s](https://github.com/TAIPANBOX/stack-k8s) under `cloud/*/evidence/`,
and the full sheet is that repository's `PORTABILITY.md`.

All three clouds ran AMD EPYC Milan, 8 vCPU / 16 GiB, so the comparison is
between clouds rather than between chip generations.

| | Hetzner CPX42 (shared cores) | AWS `c6a.2xlarge` | GCP `c2d-highcpu-8` |
|---|---|---|---|
| peak decisions/s, one pod | 2,344 | **2,449** | **2,479** |
| p50 at 8 concurrent | 3.9 ms | **3.21 ms** | **3.22 ms** |
| throughput at 256 concurrent | not measured | **2,331** | **2,353** |
| audit bytes per decision | 393 | **427.6** | **426.4** |
| a freeze reaching live traffic | 5 ms | **9.2 ms** | **5.0 ms** |
| cost per million governed decisions | **EUR 0.024** | **USD 0.208** | **USD 0.229** |

The last row is the cost of the infrastructure under the control plane at full
load. It is not a price for anything, and it is not what governing a fleet
costs you: a fleet of 200 agents each taking 500 actions a day uses about 0.05%
of one of these clusters.

## What binds first is the evidence, not the processor

Every decision is audited, not a sample of them: 23,700 decisions produced
23,700 hash-linked records. At about 426 bytes each that is **614 MB a day at a
thousand calls a minute**, and a 5 GiB volume fills in nine days. Under the same
load the PDP itself sat at 1m CPU and 9 MiB.

This is the rare capacity line that can be forecast exactly, because it is
linear in a number you already know. Multiply expected decisions by 426 bytes,
add whatever retention your compliance function requires, and size the volume
once. When it fills, what you lose is not disk, it is the ability to prove why
each action was permitted.

## A published conclusion we withdrew

After the first cluster we wrote down that throughput collapses past 64
concurrent callers (2,344/s at 64 falling to 1,059/s at 128) and that a fleet
should be designed against that line.

**That was wrong.** On both dedicated-core clouds there is no cliff at all out
to 256 concurrent, on two chip generations: throughput holds within 6% and only
latency grows, the way a queue should. The collapse was a property of a
shared-vCPU instance whose hypervisor hands the tick to a neighbour under load.

It is left here rather than quietly corrected, because a benchmark run on
shared cores measures the neighbours, and that is worth more to a reader than
the number it replaces.

## Deployment facts, since they are the same PDP

- Enforcement never lapsed across a node loss, but a StatefulSet on an RWO
  volume does not self-heal: the pod hangs in Terminating until an operator
  confirms the node is dead.
- A freeze issued from the console survives a restart of the policy plane's own
  pod, verified on all three clouds.
- The decisions are `cacheable: false` while a freeze is in effect, which is why
  a freeze reaches live traffic in one PDP round trip rather than at cache
  expiry.

## On a box behind a home router, with two clouds asking (2026-09-17)

- A single-machine launcher (stack-single v1.1.3) pinned this service at v1.0.2 on a Debian 13 mini
  PC behind a home router, the gateway published only on the box's tailnet address, with that TokenFuse
  gateway as the enforcement point (`TOKENFUSE_WARDRYX_MODE: enforce`, `TOKENFUSE_WARDRYX_FAILMODE: closed`)
  and two customer agents, one in AWS and one in GCP, calling through it over that tailnet.
- Both agents' calls carried this service's decision on the wire: the gateway's own
  `x-fuse-wardryx` response header read `allow` on every `200`, 17 calls each for the AWS and the
  GCP agent at USD 0.000033 per call, and every decision this service made reached the bus in
  `wardryx.ndjson`.
- A `PUT /v1/policies/freeze-gcp` (`deny_above_usd 0.000001`, target
  `agent://customer.example/gcp/*`) denied the GCP agent from its first call onward (`403`,
  `wardryx=deny`) while the AWS agent kept getting `200`, 17 calls in the same window; three
  `policy_deny` events at `high` severity reached the bus. `DELETE` on the same policy returned
  `204`, and the GCP agent's next call was `200` again.
- With this service stopped, the gateway itself answered every call: `403 wardryx unreachable,
  failmode=closed` in 0.3 s, one `dependency_failed` event (`dependency=policy_plane`) per call, and
  no call reached the model provider. Started again, the next call was `200`. This is the
  fail-closed half of the README's [enforcement modes](README.md#enforcement-modes-at-the-pep)
  table, measured on the shipped launcher's own setting.
- With the policy store (Postgres) stopped and this service still running, `GET /healthz` stayed
  `200` and decisions kept coming from the in-memory set (correct: liveness never reads the store),
  but a `PUT /v1/policies/{id}` against the same outage had no answer after 8 s and the write was
  never applied. That gap is issue #62; #63 closed it (`00ad4b5`) by adding `GET /readyz` (reads the
  store, `200` or `503` inside a 3 s deadline) and the same deadline on every policy write, see
  ["When the store is down"](README.md#when-the-store-is-down). The v1.0.2 this run pinned predates
  that fix.
- A delegation chain of 40 entries, carried in the request header `x-fuse-on-behalf-of`, reached
  this service's `/v1/decide` and was allowed. Nothing here had a `max_chain_depth` rule loaded, so
  this is the base policy set doing exactly what it was configured to do, not a defect in this
  service; the matching gap on the header's own cap was the gateway's, closed in tokenfuse#297 and
  tokenfuse#303.

Not exercised here: the hold and approval-token path, and this service's decision-call timeout under
real wide-area latency, since it and its enforcement point shared one compose network throughout.
Detail behind every point above is in
[estate-gates/PROVEN.md](https://github.com/TAIPANBOX/estate-gates/blob/main/PROVEN.md), the 16-case
failure matrix and the rows dated 2026-09-17.

## A DPoP proof, once, across instances and a restart (2026-11-04)

The built binary on a real Postgres 16, on one 4-core Intel N150 box. `@measured` 2026-11-04, the two runs below by hand on that box, and
the same steps as `TestTheBuiltBinaryRefusesAProofAcrossTwoInstancesAndARestart`,
`TestTheBuiltBinaryRefusesAProofWhileItsDatabaseIsGone` and
`TestTheBuiltBinaryRefusesAProofOnAHangingDatabaseWithinTheDeadline` in CI's integration job.

One proof, two instances on one database, one of them killed and started again:

| Presentation of the same proof | Record in the process (`7462673`) | Shared record |
|---|---|---|
| Instance A | `200` allow | `200` allow |
| Instance B | `200` allow | `403 agent_token_proof_invalid` |
| A, after `kill` and a fresh start | `200` allow | `403 agent_token_proof_invalid` |

With the database taken away from a running instance:

- `docker stop` of Postgres: a decide with a fresh proof answered `503 agent_token_proof_unrecorded` in
  1 ms, a decide with no proof answered `200` allow from memory, `/healthz` answered `200` and `/readyz`
  answered `503`.
- `docker pause` of Postgres: a decide with a fresh proof answered `503 agent_token_proof_unrecorded` in
  3.003 s, the store deadline.

After `docker start` the proof the outage refused was accepted once and the proof accepted before the
outage stayed refused, and the log carried one line for the outage and one for its end.

What a proof costs on `/v1/decide`. `@measured` `go test -tags 'integration latency' -run
TestDecideLatency -v ./internal/manifest/`, 2026-11-04, three rounds of 3000 decides for each row,
client, wardryx and Postgres on that one box at load average 3 to 4, `synchronous_commit` on:

| Callers | Decide | p50 | p95 | p99 | Over 50 ms |
|---|---|---|---|---|---|
| 1 | no token, memory store | 0.10 ms | 0.19 ms | 0.24 ms | 0 of 9000 |
| 1 | no token, Postgres store | 0.10 ms | 0.20 ms | 0.30 ms | 0 of 9000 |
| 1 | proof, record in the process | 0.42 ms | 0.56 ms | 0.91 ms | 0 of 9000 |
| 1 | proof, shared record | 2.3 ms | 2.8 ms | 5.1 ms | 0 of 9000 |
| 8 | no token, Postgres store | 0.29 ms | 0.85 ms | 1.7 ms | 0 of 9000 |
| 8 | proof, record in the process | 0.99 ms | 2.7 ms | 4.2 ms | 0 of 9000 |
| 8 | proof, shared record | 3.1 ms | 4.7 ms | 6.7 ms | 0 of 9000 |
| 32 | no token, Postgres store | 1.0 ms | 4.0 ms | 6.6 ms | 0 of 8928 |
| 32 | proof, record in the process | 3.1 ms | 9.8 ms | 14.9 ms | 0 of 8928 |
| 32 | proof, shared record | 6.9 ms | 13.8 ms | 29.9 ms | 63 of 8928 |

The shared record adds about 2 ms at the median to a decide with a proof for 1 or 8 callers and about
4 ms for 32, and a decide with no proof pays nothing. 50 ms is the enforcement point's default wait on a
model call, past which its fail mode applies: 0.7% of decides passed it at 32 callers and none below
that. The same run with the box at load average 15, other work taking the cores, put the shared record
at p50 2.4 ms and p99 11.9 ms for one caller and p50 24.3 ms and p99 88.8 ms for 32, where 7.6% passed
50 ms against 5.2% with the record in the process. The write is about 420 bytes of WAL per proof, and
27,386 rows held 6.6 MB, index included.

Before the pool was bounded, the same run at 32 callers opened 2241 sessions for 5952 decides and put
the p99 at 358 ms: database/sql keeps two idle connections, so every burst reconnected. `maxPoolConns`
brought that to 42 sessions for 8928 decides.

## An agent whose error budget is spent, held for a person (2026-11-04)

The built binary reading a file the quality plane (verdryx, `452ac7c`, rfc8785 0.1.4) wrote itself, on one 4-core
Intel N150 box. `@measured` 2026-11-04, by hand on that box with the documentation's own example policy
(`docs/examples/hold-while-the-budget-is-spent.yaml`), `WARDRYX_SIGNAL_EVENTS_MAX_AGE=4m`, and the same
steps as `TestTheBuiltBinaryReadsTheBudgetFileAndSaysSoOnReadyz`, which is in CI.

A trace of four agents (400, 540, 400 and 300 runs) went through `verdryx slo --input ... --events ...`. It
reported two budgets exhausted and wrote two `slo_burn` events, the second chained to the first by
`prev_hash`. A third agent, burning at 10.5 times its sustainable rate with budget left, was reported and
**not written**: verdryx puts a fast burn on the file only when the interval of the indicator sits wholly
below its target, and a measurement with budget left cannot have that, so the file as verdryx writes it
today carries `exhausted` events.

| Step | Result |
|---|---|
| `GET /readyz` | `200 {"store":"ok","signal_events":"ok"}` |
| a tool call of each of the four agents | the two with a spent budget `hold`, reason naming `slo_burn` and `exhausted`; the other two `allow` |
| a person grants one hold, the call is sent with the token | `allow`, and the same token again is a `hold` |
| the same agent sends its own signal `slo_burn: none` | still `hold` |
| a line that is not an event is appended to the file, 17 s later | `/readyz` is `200` with `signal_events: broken`, the agent's call is `allow` (the default `when_absent`), the log says which file and why |
| the line is removed, 15 s later | `/readyz` says `ok`, the agent is `hold` again, the log says the file is readable again |
| `when_absent: hold`, the file missing | `/readyz` says `unreadable`, a tool call is `hold` for the missing signal, a call with no tool call is `allow` |
| verdryx runs again over good data for the first agent | it writes nothing for that agent; with the age at 4 minutes the agent is `allow` 246 s after its event. The second agent, still exhausted, got a fresh event and stayed `hold` |
| `wardryx replay` with the quality plane's file deleted | 33 decisions, 31 reproduced, 1 approval decided, 1 approval spent, none diverged or unreadable |

The standing signal adds 171 bytes to a decision record. `@measured` `go test -bench BenchmarkDecideWith
./internal/api/`, three rounds of 20000 decides through the handler with no network and no event file, a rule
on `slo_burn`, and a file of 200 lines: 33 to 42 microseconds and 60 allocations with the option off, 44 to 49
microseconds and 72 allocations with it on, so about 8 microseconds and 12 allocations more, inside the
run-to-run spread of the off case.

## A tool call nothing grants, held for a person (2026-11-07)

The built binary on one 4-core Intel N150 box, against a real Postgres, with the documentation's own example
(`docs/examples/tool-hold.yaml`) as the floor. `@measured` 2026-11-07, by hand on that box, the same steps as
`TestTheBuiltBinaryHoldsAToolCallNothingGrants`, which is in CI. First a history with a file that has no floor
and one fleet-wide `deny_tool`, then the candidate report, then the floor on.

| Step | Result |
|---|---|
| five decisions under the file with no floor (tool calls of two agents, a denied tool, a model call) | as they always were |
| `wardryx replay -policy docs/examples/tool-hold.yaml` | 5 reproduced, none unexamined, and a table: `fetch_url` 2 calls and `exec` 1 call of the worker would wait for a person. Nothing was enabled |
| the broker's body, tool nothing grants | `hold`, `approval_token_required: true`, `cacheable: false`, reason `policy "tool-hold" when_no_grant: no policy grants tool "fetch_url" to agent "agent://acme.example/agents/worker"; human approval required` |
| the same call again | `hold`, the same `approval_id` |
| a model call of the same agent, an egress question | `allow` |
| a forged token | `hold`, not `deny` |
| a person grants; the token on a call with other arguments | `hold` |
| the token on the approved call, then again | `allow`, then `hold` with the spent sentence |
| `PUT` with `when_no_grant` | `400`, the sentence says the policy file and `grant_tool` |
| `PUT` with `grant_tool` on `agent://*`, then on the agent | `400`, then `200`, and the next call of that tool is `allow` with no restart, and the next tool `hold` |
| 31 different calls of one tool, in a loop | every one `hold` with one reason, 20 rows pending in Postgres, the answers past the cap name no approval, `approval_queue_full` written once |
| the record | two `policy_loaded` events, `9e5d23cb3d6f` with no floor and `6c5914b6007f` with `tool-hold` |
| `wardryx replay` of the whole record | 46 decisions: 44 reproduced, 1 approval decided, 1 approval spent, none diverged, the allows from before the floor word for word |

## Method

Disposable Hetzner VPS boxes (deleted after each run), Wardryx running as a PEP in front of a real
Claude-backed gateway; code delivered as a `git archive` tarball (no secrets, no `.git`, no token); every
service bound to `127.0.0.1` only, reached exclusively via SSH tunnel. Nothing from these runs was ever
exposed publicly, and no infrastructure or secret from the campaign persists today.
