#!/usr/bin/env bash
# The agent a request names, the org it is asked in and the approver it
# records come from the authenticated key, never from the body alone.
#
# WHY THIS IS A GATE
#
# Finding F-001 of the 2026-10-17 agent-security review: /v1/decide took
# agent_id from the body and checked only that it was not empty, so any key
# could ask in any agent's name. Finding F-012: an approval recorded the free
# text decided_by as who decided it, and a policy had no org. The fix is three
# lines of code in internal/api, and each of them is the kind of line a later
# handler or a refactor drops without any test noticing, because a handler
# that forgets the check still answers 200 with a correct-looking decision.
# This reads the source for the three shapes and fails when one is missing.
#
#   1. Every function that reads dto.AgentID checks
#      s.allow.speaksFor(principal, dto.AgentID), before it asks the engine.
#   2. Every pdp.DecideRequest and pdp.FilterRequest the API builds sets
#      Org: principal.Org, so the org is the key's and not the body's.
#   3. Every approval.Decide call records approverID(principal) as who
#      decided, with dto.DecidedBy only as the label after it.
#
# WHAT THIS CANNOT DO
#
# It reads source text in internal/api, one function at a time, from one
# "func " line to the next. A check spelled another way, a request built
# through a helper, or a handler outside internal/api is not seen: those stay
# with review. It proves the lines are there, not that they are right; the
# tests in internal/api/agent_binding_test.go, approver_test.go and
# policy_org_test.go prove that. Comment lines are skipped, so a comment that
# names dto.AgentID is not mistaken for code.

set -euo pipefail
cd "$(dirname "$0")/.."

subject="internal/api"
if [ ! -d "$subject" ]; then
	echo "FAIL: $subject is not here, so this measured nothing."
	exit 2
fi
files=$(find "$subject" -name '*.go' ! -name '*_test.go' | sort)
if [ -z "$files" ]; then
	echo "FAIL: no non-test Go file under $subject, so this measured nothing."
	exit 2
fi

# One awk per file (see no-raw-error-in-response.sh on ENDFILE). Each prints
# "COUNT <handlers> <literals> <decides>" and one "PROBLEM ..." line per fault.
problems=""
handlers=0
literals=0
decides=0
for f in $files; do
	out=$(awk -v file="$f" '
		function close_func() {
			if (fn != "" && reads) {
				handlers++
				if (!bound) printf "PROBLEM %s: %s reads dto.AgentID and never checks the key may speak for it (s.allow.speaksFor(principal, dto.AgentID))\n", file, fn
				else if (engine && engine < bound) printf "PROBLEM %s: %s asks the engine before it checks the key may speak for the agent\n", file, fn
			}
			fn = ""; reads = 0; bound = 0; engine = 0
		}
		/^[ \t]*\/\// { next }
		/^func / { close_func(); fn = $0; sub(/\(w http.*/, "", fn) }
		{
			if ($0 ~ /dto\.AgentID/) reads = 1
			if (!bound && $0 ~ /s\.allow\.speaksFor\(principal, dto\.AgentID\)/) bound = FNR
			if (!engine && $0 ~ /s\.engine\.(Decide|Filter)\(/) engine = FNR
		}
		/pdp\.(Decide|Filter)Request\{/ && $0 !~ /Request\{\}/ { inlit = 1; litorg = 0; litline = FNR; literals++ }
		inlit && /Org:[ \t]*principal\.Org,/ { litorg = 1 }
		inlit && /^[ \t]*\}\)?$/ {
			if (!litorg) printf "PROBLEM %s:%d: a pdp request built here does not set Org: principal.Org, so the org it is asked in is not the key'"'"'s\n", file, litline
			inlit = 0
		}
		/approval\.Decide\(/ {
			decides++
			if ($0 !~ /, dto\.Decision, approverID\(principal\), dto\.DecidedBy, /) printf "PROBLEM %s:%d: approval.Decide does not record approverID(principal) as the approver, with dto.DecidedBy as the label after it\n", file, FNR
		}
		END { close_func(); printf "COUNT %d %d %d\n", handlers, literals, decides }
	' "$f")
	p=$(printf '%s\n' "$out" | grep '^PROBLEM ' | sed 's/^PROBLEM //' || true)
	[ -n "$p" ] && problems="$problems$p
"
	read -r _ h l d <<<"$(printf '%s\n' "$out" | grep '^COUNT ')"
	handlers=$((handlers + h))
	literals=$((literals + l))
	decides=$((decides + d))
done

if [ "$handlers" -eq 0 ] || [ "$literals" -eq 0 ] || [ "$decides" -eq 0 ]; then
	echo "FAIL: found $handlers handler(s) reading dto.AgentID, $literals pdp request literal(s) and $decides approval.Decide call(s) under $subject."
	echo "      One of the three subjects is gone, so this measured nothing; an absent subject is not a passing one."
	exit 2
fi

if [ -n "$problems" ]; then
	printf '%s' "$problems"
	echo
	echo "The agent, the org or the approver is taken from somewhere other than"
	echo "the authenticated key. See CLAUDE.md invariants 36 to 38."
	exit 1
fi

echo "OK: $handlers handler(s) bind the agent to the key, $literals pdp request(s) carry the key's org, $decides approval decision(s) record the key as the approver."
