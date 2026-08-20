#!/usr/bin/env bash
# Every read on the memory store returns a copy, not the store's own memory.
#
# WHY THIS IS A GATE AND NOT ONLY A TEST
#
# The four read methods that exist are held by behavioural tests, which are
# stronger than anything a grep can say. What a grep can do is catch the FIFTH
# one: a read method added later, returning a stored value directly, with no
# test written for a property whose absence produces no symptom.
#
# And it produces none. A struct copy compiles, returns the right values, and
# passes any test that reads them. The defect is that the caller now holds a
# live reference into a governance record, and an edit they make for their own
# reasons rewrites it with nothing anywhere seeing a write. On 2026-08-20 that
# was true of GetApproval, ListApprovals and GetPolicy, and had been since they
# were written.
#
# WHAT THIS CANNOT DO
#
# It matches on the shape of a return statement. A read method that builds its
# result some other way, or one that copies through a helper this does not
# know, needs a reader. The list of approved copy helpers is here rather than
# inferred, so adding one is a decision somebody makes on purpose.

set -euo pipefail
cd "$(dirname "$0")/.."

f="internal/store/memory.go"
if [ ! -f "$f" ]; then
	echo "FAIL: $f is not here, so this measured nothing."
	echo "      An absent subject is not a passing one."
	exit 1
fi

# Methods on *Memory that hand a stored value back to a caller.
readers=$(grep -c '^func (m \*Memory) \(Get\|List\|Decide\)' "$f" || true)
if [ "$readers" -eq 0 ]; then
	echo "FAIL: no read method found on *Memory, so this measured nothing."
	exit 1
fi

# Checked by BODY rather than by the shape of a return.
#
# The first version matched `return a, nil` and friends. It fired on the two
# copy helpers, which return their own freshly built values and are exactly
# right, and it would have gone on firing until somebody deleted it. A gate
# that is wrong about correct code is a gate that gets switched off.
#
# It also found two more real ones while being wrong about four: DecideApproval
# and ListPolicies were aliasing too.
missing=""
while IFS= read -r fn; do
	body=$(awk -v want="$fn" '
		$0 == want { inside = 1 }
		inside { print }
		inside && $0 == "}" { inside = 0 }
	' "$f")
	case "$body" in
	*copyOut*|*copyPolicyOut*) ;;
	*) missing="$missing$fn\n" ;;
	esac
done <<EOF
$(grep '^func (m \*Memory) \(Get\|List\|Decide\)' "$f")
EOF

if [ -n "$missing" ]; then
	printf "%b" "$missing"
	echo
	echo "A read on the memory store does not copy what it hands back. A struct"
	echo "copy copies a map header and a slice header, so the caller holds a"
	echo "live reference into a governance record: an edit they make for their"
	echo "own reasons rewrites it, and nothing anywhere sees a write."
	echo "Return through copyOut or copyPolicyOut. See CLAUDE.md invariant 11."
	exit 1
fi

echo "OK: $readers read method(s) on *Memory, none returning a stored value directly."
