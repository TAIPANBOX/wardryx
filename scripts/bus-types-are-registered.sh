#!/usr/bin/env bash
# wardryx writes onto the shared event bus only the types agent-passport SPEC.md
# section 6.2 lists under `wardryx`, each at the severity that row gives it, and
# every type the row lists has a site that writes it (invariant 50).
#
# WHY THIS IS A GATE
#
# 2.6.0 added two types, `approval_queue_full` and `policy_loaded`, that the row
# does not carry. Every test was green: each event was written, read back and
# asserted on. What was wrong was not in this repository at all, it was the
# distance between this code and a table in another one, and only estate-gates C4
# could see it, after the merge, on every run from then on. A consumer reads the
# row to learn what exists; a type outside it is an event nobody was told to
# expect. This keeps the push from getting that far.
#
# WHAT IT READS
#
#   - internal/api/testdata/spec-6.2-wardryx.json, the copy of the row (type to
#     severity). The spec is the original: a type joins the copy only after the
#     spec lists it, in the change that adds the emit.
#   - every non-test Go file under internal/ and cmd/, and in each, every call of
#     the three helpers that write the envelope, `s.emit(`, `s.recordDecision(` and
#     `s.writeRecord(`, with the type and the severity read from the first two
#     arguments. A type is a literal or a string constant of its own package, as
#     C4 reads it; a severity is `event.Severity<Level>`. Anything else cannot be
#     read and fails, because a type nobody can read is a hole, not an agreement.
#     The two forwarding calls inside `emit` and `recordDecision` themselves are
#     the only ones skipped.
#   - every `event.Event{` literal and `.records.Write(` call: each must sit in
#     writeRecord, so no second writer can put a type on the bus past this check.
#
# WHAT IT CANNOT DO
#
# It reads source text, so a writer this repository does not have yet (a new
# helper, another package's own writer) is invisible until the third check above
# catches the literal it would need. It does not read the spec itself: that is
# C4's job, and the copy is only as current as the change that last touched it.
# Comment lines are skipped, so a comment naming an old type is not a writer.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

python3 - "$@" <<'PY'
import json
import pathlib
import re
import sys

ROW = pathlib.Path("internal/api/testdata/spec-6.2-wardryx.json")
SEVERITIES = {"info", "low", "medium", "high", "critical"}


def nothing(why: str) -> None:
    print(f"FAIL: {why}, so this measured nothing.")
    sys.exit(2)


if not ROW.is_file():
    nothing(f"{ROW}, the copy of SPEC 6.2's wardryx row, is not here")
try:
    row = json.loads(ROW.read_text(encoding="utf-8"))
except json.JSONDecodeError as e:
    nothing(f"{ROW} is not JSON ({e})")
registered = row.get("types") or {}
if row.get("source") != "wardryx" or not registered:
    nothing(f"{ROW} names source {row.get('source')!r} and {len(registered)} type(s)")
for t, sev in registered.items():
    if sev not in SEVERITIES:
        nothing(f"{ROW} gives {t!r} the severity {sev!r}, which is not one of {sorted(SEVERITIES)}")

go_files = sorted(
    p for root in ("internal", "cmd") for p in pathlib.Path(root).rglob("*.go")
    if not p.name.endswith("_test.go")
)
if not go_files:
    nothing("there are no Go files under internal or cmd")

CONST = re.compile(r'^\s*(?:const\s+)?(\w+)\s*(?:string\s*)?=\s*"([a-z0-9_]+)"\s*$', re.M)
CALL = re.compile(r'\bs\.(emit|recordDecision|writeRecord)\(')
SEVERITY = re.compile(r'^event\.Severity(Info|Low|Medium|High|Critical)$')


def code(path: pathlib.Path) -> str:
    """The file with comment lines blanked, keeping line numbers."""
    return "\n".join("" if l.strip().startswith("//") else l for l in path.read_text().splitlines())


def first_two_args(text: str, at: int):
    """The first two arguments of the call whose `(` ends just before `at`, split at
    the commas outside brackets and string literals, so a type written as a call
    (`kind(p)`) is read as that and not skipped. None when the call has fewer."""
    args, depth, cur, i, quote = [], 0, [], at, None
    while i < len(text) and len(args) < 2:
        c = text[i]
        if quote:
            cur.append(c)
            if c == "\\" and quote != "`":
                cur.append(text[i + 1])
                i += 1
            elif c == quote:
                quote = None
        elif c in "\"'`":
            quote = c
            cur.append(c)
        elif c in "([{":
            depth += 1
            cur.append(c)
        elif c in ")]}":
            if depth == 0:
                break
            depth -= 1
            cur.append(c)
        elif c == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    return args if len(args) == 2 else None


def body(text: str, signature: str):
    """(start, end) of the top-level function that starts with signature, or None."""
    start = text.find("\n" + signature)
    if start == -1:
        return None
    end = text.find("\n}\n", start)
    return (start, end if end != -1 else len(text))


texts = {p: code(p) for p in go_files}
consts_by_dir: dict[pathlib.Path, dict[str, str]] = {}
for p, t in texts.items():
    consts_by_dir.setdefault(p.parent, {}).update(dict(CONST.findall(t)))

problems: list[str] = []
sites: dict[str, list[str]] = {}
writer_seen = False
calls = 0

for p, t in texts.items():
    consts = consts_by_dir[p.parent]
    helpers = [b for b in (body(t, "func (s *Server) emit("), body(t, "func (s *Server) recordDecision(")) if b]
    writer = body(t, "func (s *Server) writeRecord(")
    if writer:
        writer_seen = True
    for m in CALL.finditer(t):
        where = f"{p}:{t.count(chr(10), 0, m.start()) + 1}"
        args = first_two_args(t, m.end())
        if args is None:
            calls += 1
            problems.append(f"{where} calls s.{m.group(1)} with arguments this check cannot split: a type nobody can read is a hole")
            continue
        raw_type, raw_sev = args
        if raw_type == "evType" and raw_sev == "severity" and any(a <= m.start() < b for a, b in helpers):
            continue  # emit and recordDecision forwarding their own arguments
        calls += 1
        if raw_type.startswith('"') and raw_type.endswith('"'):
            typ = raw_type.strip('"')
        elif raw_type in consts:
            typ = consts[raw_type]
        else:
            problems.append(f"{where} writes a type that cannot be read ({raw_type}): a type must be a literal or a string constant of its package")
            continue
        sm = SEVERITY.match(raw_sev)
        if sm:
            sev = sm.group(1).lower()
        elif raw_sev.strip('"') in SEVERITIES and raw_sev.startswith('"'):
            sev = raw_sev.strip('"')
        else:
            problems.append(f"{where} writes {typ} at a severity that cannot be read ({raw_sev}): the severity is fixed per type, never chosen at the call site")
            continue
        sites.setdefault(typ, []).append(where)
        if typ not in registered:
            problems.append(f"{where} writes {typ} onto the bus under wardryx, and SPEC 6.2 does not list it there: log it, or carry it in a listed type's data")
        elif sev != registered[typ]:
            problems.append(f"{where} writes {typ} at {sev}, and SPEC 6.2 gives it {registered[typ]}")
    for needle in ("event.Event{", ".records.Write("):
        for m in re.finditer(re.escape(needle), t):
            if writer and writer[0] <= m.start() < writer[1]:
                continue
            problems.append(f"{p}:{t.count(chr(10), 0, m.start()) + 1} has {needle} outside writeRecord: a second writer of the envelope is one this check cannot read")

if not writer_seen:
    nothing("no file defines `func (s *Server) writeRecord(`, the one writer of the envelope")
if calls == 0:
    nothing("no s.emit, s.recordDecision or s.writeRecord call was found")

for typ in sorted(registered):
    if typ not in sites:
        problems.append(f"SPEC 6.2 lists {typ} under wardryx and no emit site writes it: the row claims an event nobody will receive")

if problems:
    print()
    for p in problems:
        print(f"PROBLEM {p}")
    print()
    print(f"{len(problems)} problem(s). See CLAUDE.md invariant 50.")
    sys.exit(1)

print(f"OK: {calls} emit site(s) in {len(go_files)} Go file(s) write {len(sites)} type(s), each one SPEC 6.2 lists under wardryx at the severity it gives, and every listed type has a writer.")
PY
