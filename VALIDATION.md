# Live infrastructure validation

Wardryx was run as a live policy decision point in front of a real Claude-backed gateway on disposable
Hetzner infrastructure before any public launch, including under real concurrent multi-agent load - the
first time its PEP had ever faced simultaneous, adversarial-shaped traffic rather than sequential test
cases.

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

1. **Declared-but-not-invoked tool bypass** - the PEP built its deny/allow decision from *invoked* tools
   only, so a request that merely *declared* a forbidden tool without ever calling it reached the model,
   bypassing a `deny_tool` policy. Fixed by unioning `taint::declared_tool_names_in` into the decision
   path, with a unit test for the exact bypass case plus an end-to-end regression.
2. **Decision-cache attestation gap** - the PEP's decision cache was keyed on `(agent_id, tool-set hash)`
   but not `attestation_method`, so within the cache TTL an unattested agent could inherit a recently
   attested `allow` (or vice versa), silently defeating `deny_if_unattested` in an order-dependent way.
   Found by the 34-agent concurrency test specifically - it never showed up under sequential load. Fixed
   by adding attestation to the cache key; re-verified live (unattested → 403 in both cache orderings and
   under the full concurrent test).

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

## Method

Disposable Hetzner VPS boxes (deleted after each run), Wardryx running as a PEP in front of a real
Claude-backed gateway; code delivered as a `git archive` tarball (no secrets, no `.git`, no token); every
service bound to `127.0.0.1` only, reached exclusively via SSH tunnel. Nothing from these runs was ever
exposed publicly, and no infrastructure or secret from the campaign persists today.
