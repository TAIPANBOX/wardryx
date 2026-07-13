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

## Method

Disposable Hetzner VPS boxes (deleted after each run), Wardryx running as a PEP in front of a real
Claude-backed gateway; code delivered as a `git archive` tarball (no secrets, no `.git`, no token); every
service bound to `127.0.0.1` only, reached exclusively via SSH tunnel. Nothing from these runs was ever
exposed publicly, and no infrastructure or secret from the campaign persists today.
