#!/usr/bin/env bash
# The compatibility surface compat/1.0.json promises is present in the code,
# and COMPATIBILITY.md is rendered from it.
#
# WHY THIS EXISTS
#
# SemVer's item 5: version 1.0.0 defines the public API. A 1.0 is a promise
# about a surface, and a promise nobody can point at is a mood. The estate's
# first two 1.0 tags (agent-passport, agent-stack-go, 2026-09-12) each came
# with the surface written down and a gate that fails when it moves; this is
# the same pair for this repository, written before its 1.0 so that the tag,
# when it comes, freezes something that has already been held for a while.
# estate-gates C19 asks whether this file and the manifest exist and CI runs
# this; this file asks whether the promise still holds.
#
# WHAT IT CHECKS
#
# For every kind under `frozen` in compat/1.0.json, every name appears in one
# of the files `where[kind]` names. A plain name must appear as a quoted string
# literal ("name", 'name' or `name`), or as the leading field of a Go struct
# tag ("name,omitempty"), so a comment mentioning it does not count as the code
# carrying it. An `lhs=rhs` entry must appear as an
# assignment `lhs = rhs`, whitespace free, which is how a Go constant such as
# an exit code is declared. Then COMPATIBILITY.md must equal the rendering of
# the manifest; `--write` regenerates it, so the human form is never typed
# twice.
#
# WHAT IT REFUSES TO PASS ON
#
# A manifest that is absent or not JSON, a `frozen` with no kinds, a kind with
# no `where`, a `where` file that is not there, a kind with no names: each is
# "measured nothing", printed as such, and exit 1. A gate that passed on an
# empty manifest would be the silence the estate's gates exist to end.
#
# WHAT IT DOES NOT CHECK
#
# That the code does what the name says: `/healthz` present in the router is
# not `/healthz` answering 200. That a name absent from the manifest is not
# part of the surface: additive things may exist unlisted, by design. The
# `additive` and `experimental` lists are documentation for a reader and are
# rendered, never checked.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

python3 - "$@" <<'PY'
import json
import pathlib
import re
import sys

MANIFEST = pathlib.Path("compat/1.0.json")
DOC = pathlib.Path("COMPATIBILITY.md")
SCHEMA = "taipanbox.dev/compat/v1"
write = "--write" in sys.argv[1:]

def nothing(why: str) -> int:
    print(f"FAIL: {why}, so this check measured nothing.")
    return 1

if not MANIFEST.is_file():
    sys.exit(nothing(f"{MANIFEST} is not there"))
try:
    m = json.loads(MANIFEST.read_text(encoding="utf-8"))
except json.JSONDecodeError as e:
    sys.exit(nothing(f"{MANIFEST} is not JSON ({e})"))
if m.get("schema") != SCHEMA:
    sys.exit(nothing(f"{MANIFEST} carries schema {m.get('schema')!r}, not {SCHEMA!r}"))
frozen = m.get("frozen") or {}
where = m.get("where") or {}
if not frozen:
    sys.exit(nothing(f"{MANIFEST} freezes nothing"))

fails: list[str] = []
checked = 0
for kind in sorted(frozen):
    names = frozen[kind]
    files = where.get(kind)
    if not names:
        sys.exit(nothing(f"kind {kind!r} lists no names"))
    if not files:
        sys.exit(nothing(f"kind {kind!r} has no `where`"))
    texts = {}
    for f in files:
        p = pathlib.Path(f)
        if not p.is_file():
            sys.exit(nothing(f"{f}, where {kind!r} is said to live, is not there"))
        texts[f] = p.read_text(encoding="utf-8", errors="replace")
    for name in names:
        checked += 1
        if "=" in name:
            lhs, rhs = name.split("=", 1)
            pat = re.compile(re.escape(lhs) + r"\s*=\s*" + re.escape(rhs) + r"\b")
            found = any(pat.search(t) for t in texts.values())
        else:
            # A quoted literal, or the leading field of a Go struct tag: the
            # `json:"agent_id,omitempty"` spelling puts a comma where the closing
            # quote would be, and this repository's wire fields live in tags.
            lit = re.compile(r"[\"'`]" + re.escape(name) + r"([\"'`]|,)")
            found = any(lit.search(t) for t in texts.values())
        if not found:
            fails.append(f"{kind}: {name!r} is promised and appears as a literal in none of {', '.join(files)}")

# The human form, rendered from the manifest and never typed twice.
lines = [f"# Compatibility", ""]
lines.append(
    f"`{m.get('repo', '?')}` promises the surface below from its 1.0 "
    f"(`compat/1.0.json`, held by `scripts/compat-surface.sh` on every push). "
    f"A frozen name is not removed or renamed within a major; an additive thing may "
    f"appear as a minor; an experimental thing may change in any release."
)
if m.get("status"):
    lines += ["", f"Status: {m['status']}"]
lines += ["", "## Frozen", ""]
for kind in sorted(frozen):
    lines.append(f"### {kind} ({len(frozen[kind])})")
    lines.append("")
    for name in frozen[kind]:
        lines.append(f"- `{name}`")
    lines.append(f"- held in: {', '.join('`' + f + '`' for f in where[kind])}")
    lines.append("")
for key, title in (("additive", "Additive within a major"), ("experimental", "Experimental")):
    items = m.get(key) or []
    lines += [f"## {title}", ""]
    lines += [f"- {i}" for i in items] or ["- nothing listed"]
    lines.append("")
lines += [
    "## Support",
    "",
    "The newest minor gets every fix; the previous minor gets security-relevant fixes for 90 days after the newer one is tagged. Before this repository's 1.0, only `main` is supported.",
    "",
]
rendered = "\n".join(lines)

if write:
    DOC.write_text(rendered, encoding="utf-8")
    print(f"wrote {DOC}")
elif not DOC.is_file():
    fails.append(f"{DOC} is not there; run ./scripts/compat-surface.sh --write")
elif DOC.read_text(encoding="utf-8") != rendered:
    fails.append(f"{DOC} is not the rendering of {MANIFEST}; run ./scripts/compat-surface.sh --write and commit the result")

if fails:
    for f in fails:
        print(f"FAIL: {f}")
    print()
    print("A frozen name that left the code is a promise broken, or a manifest")
    print("that needs a deliberate edit and a major behind it.")
    sys.exit(1)

print(f"OK: {checked} frozen name(s) across {len(frozen)} kind(s) are present in the code, and {DOC} is their rendering.")
PY
