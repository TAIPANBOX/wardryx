#!/usr/bin/env bash
# The floor that holds a tool call nothing grants comes from the policy file and
# from nowhere else, and the rule behind it stays the shape it was decided in
# (invariants 46 and 47).
#
# WHY THIS IS A GATE
#
# `when_no_grant` is the one rule in this service that a matched policy lifts by
# being there, so it is the one where a wrong answer reads as the control working.
# Every behaviour test here runs with a floor in a set built by the test, so none
# of the faults below turns a suite red on its own:
#
#   1. handlePutPolicy stops refusing the key. The store reads a policy with a
#      decoder that drops what it does not know, so a floor stored there is gone
#      after a rollback, with nothing to say so.
#   2. Something in the code sets a floor. Then the default lives in a build and
#      not in a file, and every decision recorded before it diverges on replay,
#      because the version it names no longer explains it.
#   3. requestSpecific stops reading the two fields. The gateway's cache key has no
#      call digest, so an allow a token earned opens the tool with other arguments.
#   4. The rule stops asking whether there is a tool call, and a model call is held.
#   5. Rule 15 loses the bound verifier, stops setting ApprovalTokenRequired (a
#      token stops being spent) or learns to deny.
#   6. A frozen sentence is reworded. Replay compares the reason, so every decision
#      recorded under the old words becomes a divergence.
#
# WHAT THIS CANNOT DO
#
# It reads source text. A floor set through a helper it does not know, or a refusal
# moved behind a condition, needs a reader; the tests in internal/api/no_grant_test.go
# and internal/pdp/no_grant_test.go prove the behaviour and this keeps their
# subject in place. Comment lines are skipped, so a comment naming a shape is not
# mistaken for code.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

python3 - "$@" <<'PY'
import pathlib
import re
import sys

API = pathlib.Path("internal/api/api.go")
PDP = pathlib.Path("internal/pdp/pdp.go")
RULE = pathlib.Path("internal/pdp/no_grant.go")
for f in (API, PDP, RULE):
    if not f.is_file():
        print(f"FAIL: {f} is not here, so this measured nothing.")
        sys.exit(2)


def code(path):
    """The file with its comment lines removed, for the text checks."""
    return "\n".join(l for l in path.read_text().splitlines() if not l.strip().startswith("//"))


def function(text, signature):
    """The body of the top-level function that starts with signature, or None."""
    start = text.find("\n" + signature)
    if start == -1:
        return None
    end = text.find("\n}\n", start)
    return text[start : end if end != -1 else len(text)]


problems = []

# 1. The write path refuses the key, before anything reaches the store.
put = function(code(API), "func (s *Server) handlePutPolicy(")
if put is None:
    print("FAIL: internal/api/api.go has no handlePutPolicy, so this measured nothing.")
    sys.exit(2)
refusal = re.search(r'if p\.WhenNoGrant != "" \{\s*writeError\(w, http\.StatusBadRequest,', put)
write = put.find("s.store.PutPolicy(")
if write == -1:
    print("FAIL: handlePutPolicy no longer calls s.store.PutPolicy, so this measured nothing.")
    sys.exit(2)
if refusal is None:
    problems.append("handlePutPolicy does not refuse when_no_grant with a 400: a floor written through the API is lost on a rollback")
elif refusal.start() > write:
    problems.append("handlePutPolicy refuses when_no_grant only after the store write")

# 2. No code outside the decoder sets a floor.
setters = re.compile(r'\bWhenNoGrant:\s|\.WhenNoGrant\s*=[^=]')
go_files = [
    p for root in ("internal", "cmd") for p in pathlib.Path(root).rglob("*.go")
    if not p.name.endswith("_test.go")
]
if not go_files:
    print("FAIL: no Go files under internal or cmd, so this measured nothing.")
    sys.exit(2)
for p in go_files:
    for n, line in enumerate(p.read_text().splitlines(), 1):
        if line.strip().startswith("//") or not setters.search(line):
            continue
        # normalize stores allow as the default it is, the one write there is.
        if p.as_posix() == "internal/policy/policy.go" and 'np.WhenNoGrant = ""' in line:
            continue
        problems.append(f"{p}:{n} sets a floor in code: the floor is read from a policy file and nothing else")

# 3. A decision under the floor or a grant is never cacheable.
specific = function(code(PDP), "func requestSpecific(")
if specific is None:
    print("FAIL: internal/pdp/pdp.go has no requestSpecific, so this measured nothing.")
    sys.exit(2)
for field in ("WhenNoGrant", "GrantTool"):
    if f"p.{field}" not in specific:
        problems.append(f"requestSpecific does not read {field}: a cached allow would open the tool with other arguments")

# 4. Only a request with a tool call is judged.
held = function(code(RULE), "func heldWithoutGrant(")
if held is None:
    print("FAIL: internal/pdp/no_grant.go has no heldWithoutGrant, so this measured nothing.")
    sys.exit(2)
if "req.ToolCall == nil" not in held:
    problems.append("heldWithoutGrant does not stop at a request with no tool call: model calls must pass")

# 5. The shape of rule 15.
decide = function(code(PDP), "func (e *Engine) Decide(")
if decide is None:
    print("FAIL: internal/pdp/pdp.go has no Decide, so this measured nothing.")
    sys.exit(2)
m = re.search(r"\n\tif held, ok := heldWithoutGrant\(matched, req\); ok \{\n(.*?)\n\t\}\n", decide, re.S)
if m is None:
    problems.append("Decide has no `if held, ok := heldWithoutGrant(matched, req); ok {` block: rule 15 is gone or moved out of the shape this reads")
else:
    block = m.group(1)
    if "e.approvals.VerifyBoundToCall(" not in block:
        problems.append("rule 15 does not verify with VerifyBoundToCall: a token that binds no call would lift the hold")
    if "resp.ApprovalTokenRequired = true" not in block:
        problems.append("rule 15 does not set ApprovalTokenRequired: a token would stop being single-use and a granted hold would replay as a divergence")
    if "resp.Decision = Deny" in block:
        problems.append("rule 15 can deny: a floor turns an allow into a hold and nothing else")
if "if floorHolds {" not in decide:
    problems.append("rule 13 does not read the floor: a token that binds no call would pass the cost gate on a call rule 15 holds")
if "held.callMustBeBound || floorHolds" not in decide:
    problems.append("rule 14 does not read the floor: a token that binds no call would pass a signal hold on a call rule 15 holds")

# 6. The sentences replay compares.
FROZEN = (
    "allowed: no policy targets agent %s",
    "allowed: request satisfies all matched policy rules",
)
for sentence in FROZEN:
    if f'"{sentence}"' not in decide:
        problems.append(f"the frozen sentence {sentence!r} is gone: every decision recorded under it diverges on replay")

if problems:
    print()
    for p in problems:
        print(f"PROBLEM {p}")
    print()
    print(f"{len(problems)} problem(s). See CLAUDE.md invariants 46 and 47.")
    sys.exit(1)

print(f"OK: the floor is file-only, {len(go_files)} Go file(s) set none, and rule 15 keeps its shape and the frozen sentences.")
PY
