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

## Method

Disposable Hetzner VPS boxes (deleted after each run), Wardryx running as a PEP in front of a real
Claude-backed gateway; code delivered as a `git archive` tarball (no secrets, no `.git`, no token); every
service bound to `127.0.0.1` only, reached exclusively via SSH tunnel. Nothing from these runs was ever
exposed publicly, and no infrastructure or secret from the campaign persists today.
