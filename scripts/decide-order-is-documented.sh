#!/usr/bin/env bash
# Enforces invariant 14 of CLAUDE.md: the order `Decide` documents is the order
# `Decide` runs.
#
# WHY THE ORDER AND NOT JUST THE LIST
#
# A caller reads this order to know which `reason` it gets when two rules would
# both deny. That is not a detail: `reason` is what an operator sees, what a
# dashboard groups by, and what somebody debugging a refusal reads first. A
# request from an unattested agent carrying an over-deep chain is denied by
# ONE of those rules, and which one is a fact about this list.
#
# WHAT WENT WRONG, on the day this was written
#
# `deny_if_chain_unproven`, `max_chain_depth` and `require_root_principal`
# landed on 2026-08-26 and were added to CLAUDE.md and to the code and to
# neither the README nor `Decide`'s own doc comment. The comment did not merely
# omit them: it went on NUMBERING, so it said "3. deny_if_unattested" while
# three chain rules ran between 2 and it. Every number after the second was
# wrong, and each was wrong by exactly the count of the rules nobody had
# mentioned.
#
# That is worse than an omission and it is why this reads the ORDER rather than
# the membership. A missing entry is visible to anybody who looks for it. A
# renumbered list looks complete.
#
# HOW IT READS THE CODE
#
# The deny checks in `Decide` are calls of the form `if ... ok {` against a
# named predicate, in source order. That is a shape rather than a contract, and
# it is the honest limit here: a rule added by some other shape is invisible.
# It is stated rather than hidden, and the shape has been stable across every
# rule this service has.
#
# It refuses when it found nothing to compare, because a check that goes green
# once its subject has vanished is worse than no check.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

python3 - "$@" <<'PY'
import pathlib
import re
import sys

src = pathlib.Path("internal/pdp/pdp.go")
if not src.exists():
    print("FAIL: internal/pdp/pdp.go is not there, so nothing was compared and")
    print("      this check measured nothing.")
    sys.exit(1)

text = src.read_text()

start = text.find("\n// Decide evaluates req against")
if start == -1:
    print("FAIL: `Decide` has no doc comment beginning `Decide evaluates req")
    print("      against`, so the documented order could not be read and this")
    print("      check measured nothing.")
    sys.exit(1)

body = text.find("\nfunc (e *Engine) Decide", start)
if body == -1:
    print("FAIL: no `func (e *Engine) Decide` follows the doc comment, so the")
    print("      order it runs could not be read and this check measured nothing.")
    sys.exit(1)

# The documented order: numbered items in the doc comment.
doc = text[start:body]
documented = re.findall(r"^//\s+(\d+)\.\s+(.*)$", doc, re.M)

# The last item is the terminal case, "otherwise, Allow", and it has no
# predicate to compare against. It stays NUMBERED in the comment, because a
# reader following a numbered list to its end should find the answer there
# rather than a list that stops. So it is dropped here rather than there.
#
# Written after this check counted it as an eleventh rule against ten
# predicates and reported a disagreement that was its own.
terminal = documented and re.match(r"otherwise\b", documented[-1][1].strip(), re.I)
if terminal:
    documented = documented[:-1]
if not terminal:
    print("FAIL: `Decide`'s doc comment does not end with an `otherwise` item, so")
    print("      a reader following the list finds no answer at the end of it, and")
    print("      this check cannot tell the terminal case from a rule.")
    sys.exit(1)


# The real order: the deny predicates, in source order, inside Decide.
end = text.find("\nfunc ", body + 10)
run = text[body : end if end != -1 else len(text)]
PREDICATES = {
    "chain.Validate": "an invalid on_behalf_of delegation chain",
    "deniedTool": "deny_tool",
    "chainDepthExceeded": "max_chain_depth",
    "rootPrincipalRefused": "require_root_principal",
    "chainUnproven": "deny_if_chain_unproven",
    "unattestedDenied": "deny_if_unattested",
    "exceededMaxSteps": "max_steps",
    "deniedDomain": "allow_domains",
    "deniedAboveCeiling": "deny_above_usd",
    "overThreshold": "require_human_above_usd",
}
# DISCOVERED, not declared. The deny checks are `if [...] ok := <fn>(...)` or
# `if err := <fn>(...)`, and every one of them is found here. `PREDICATES` then
# says which POLICY FIELD each corresponds to, because the comment speaks in
# policy fields and the code speaks in function names, and no search can bridge
# those two vocabularies.
#
# So an unknown predicate is a FINDING rather than something skipped. The first
# version iterated `PREDICATES` and looked for each one, which meant a genuinely
# new rule was invisible: exactly the defect this estate corrected three times
# on the day this was written, in C2's copy list, C4's producer list and C10's
# hardcoded path. Its own teeth case caught it here, which is the fourth.
DENY_CALL = re.compile(r"^\t{1,2}if (?:[a-zA-Z_, ]+ :?= )?([a-zA-Z][A-Za-z0-9_.]*)\(")
actual = []
unknown = []
seen = set()
for line in run.splitlines():
    m = DENY_CALL.match(line)
    if not m:
        continue
    fn = m.group(1)
    if fn in ("len", "append", "make", "errors.Is", "strings.Contains"):
        continue
    if fn not in PREDICATES:
        if fn not in seen:
            unknown.append(fn)
            seen.add(fn)
        continue
    name = PREDICATES[fn]
    if name not in actual:
        actual.append(name)

if len(actual) < 3:
    print(f"FAIL: only {len(actual)} deny check(s) were found in `Decide`, which")
    print("      cannot be right. Either the shape this reads has changed or the")
    print("      function has, and this check measured nothing.")
    sys.exit(1)

fails = []
for fn in unknown:
    fails.append(
        f"`Decide` calls `{fn}(...)` in a deny position and this check has no "
        f"policy-field name for it. A rule this gate cannot name is a rule it "
        f"cannot compare, so add it to PREDICATES and to the doc comment "
        f"together, or the comment will renumber past it the way it did on "
        f"2026-08-26"
    )

if len(documented) != len(actual):
    fails.append(
        f"the doc comment numbers {len(documented)} rule(s) and `Decide` runs "
        f"{len(actual)}"
    )

for i, name in enumerate(actual):
    if i >= len(documented):
        fails.append(f"rule {i + 1} in the code is `{name}` and the comment stops before it")
        continue
    num, said = documented[i]
    if name not in said:
        fails.append(
            f"rule {i + 1}: `Decide` runs `{name}` and the comment's item {num} "
            f"says: {said.strip()[:70]}"
        )

if fails:
    print()
    for f in fails:
        print(f"FAIL: {f}")
    print()
    print("A caller reads this order to know which `reason` it gets when two")
    print("rules would both deny, and `reason` is what an operator sees first.")
    print(f"{len(fails)} disagreement(s) between the documented order and the real one.")
    sys.exit(1)

print(f"decide order: {len(actual)} deny rule(s), documented in the order they run.")
PY
