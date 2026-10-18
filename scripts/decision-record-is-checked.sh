#!/usr/bin/env bash
# An allow or a hold is answered only after its record was written, or the
# closed record fail mode is off (invariant 40).
#
# WHY THIS IS A GATE
#
# Finding F-011 of the 2026-10-17 agent-security review: a decision was returned
# when its record could not be written, because emit logged the write error and
# handleDecide answered anyway. The fix is one checked line in handleDecide for
# each of the two answers a caller acts on. A later edit that drops the check,
# or writes an allow or a hold through the fail-open emit again, still answers
# 200 with a correct-looking decision, so no test that runs against a healthy
# record notices. This reads the source for the shape and fails when it is
# missing.
#
#   1. In handleDecide, the record of an allow and the record of a hold are each
#      written by `if !s.recordDecision(...)`, and within three lines the answer
#      is refused with writeRecordUnavailable(w).
#   2. Nothing else in internal/api writes an allow or a hold record through
#      emit, which would return the answer with no check at all.
#
# WHAT THIS CANNOT DO
#
# It reads source text, one function at a time, from the handleDecide line to
# the next closing brace. A check spelled another way, or a record written
# through a helper this does not know, is not seen; that stays with review. It
# proves the lines are there, not that the refusal is right: the tests in
# internal/api/record_failmode_test.go prove that. Comment lines are skipped, so
# a comment naming the call is not mistaken for code.

set -euo pipefail
cd "$(dirname "$0")/.."

file="internal/api/api.go"
if [ ! -f "$file" ]; then
	echo "FAIL: $file is not here, so this measured nothing."
	exit 2
fi

# The handler, read with awk. Every recordDecision call for an allow or a hold
# must be an `if !` whose refusal follows within three lines.
report=$(awk -v file="$file" '
	function fault(line, why) {
		printf "PROBLEM %s:%d: the record of an allow or a hold %s\n", file, line, why
	}
	/^func \(s \*Server\) handleDecide\(/ { inside = 1; pend = 0; next }
	inside && /^}/ {
		if (pend) fault(pendAt, "is checked, but the answer is not refused when the write fails")
		inside = 0
		next
	}
	/^[ \t]*\/\// { next }
	inside {
		if (pend) {
			if ($0 ~ /writeRecordUnavailable\(w\)/) pend = 0
			else if (FNR - pendAt > 3) {
				fault(pendAt, "is checked, but the answer is not refused when the write fails")
				pend = 0
			}
		}
		if ($0 ~ /recordDecision\(ev(PolicyAllow|ApprovalRequested),/) {
			seen++
			if ($0 ~ /if !s\.recordDecision\(ev(PolicyAllow|ApprovalRequested),/) {
				pend = 1
				pendAt = FNR
			} else {
				fault(FNR, "is written, but its result is not checked, so the answer is returned whatever the write did")
			}
		}
	}
	END { print "COUNT " seen + 0 }
' "$file")

count=$(printf '%s\n' "$report" | sed -n 's/^COUNT //p')
problems=$(printf '%s\n' "$report" | grep '^PROBLEM ' | sed 's/^PROBLEM //' || true)

# Any allow or hold record written through emit skips the check entirely.
bypass=$(grep -nE 's\.emit\(ev(PolicyAllow|ApprovalRequested),' $(find internal/api -name '*.go' ! -name '*_test.go' | sort) |
	grep -vE '^[^:]+:[0-9]+:[ \t]*//' |
	sed 's/^\([^:]*:[0-9]*\):.*/\1: an allow or a hold is written through emit, which bypasses the check/' || true)

if [ "${count:-0}" -eq 0 ]; then
	echo "FAIL: found no allow or hold record call in handleDecide under $file, so this measured nothing."
	echo "      The subject is gone or renamed; an absent subject is not a passing one."
	exit 2
fi

if [ -n "$problems$bypass" ]; then
	[ -n "$problems" ] && printf '%s\n' "$problems"
	[ -n "$bypass" ] && printf '%s\n' "$bypass" | sed 's/^/PROBLEM /'
	echo
	echo "An allow or a hold is answered before its record is known to be written."
	echo "See CLAUDE.md invariant 40."
	exit 1
fi

echo "OK: $count allow/hold record call(s) in handleDecide are checked and refuse on a failed write; no allow or hold record goes through emit."
