#!/usr/bin/env bash
# No error from outside this package is written into an HTTP response.
#
# WHY THIS IS A GATE AND NOT A REVIEW NOTE
#
# On 2026-08-20 this was found unchecked AND broken: all
# ten internal-error paths in internal/api wrote err.Error() into the body,
# and six of them were reachable by any admin-keyed request against a store
# that was down.
#
# What leaked is worth stating exactly. pgx keeps the password out of its own
# error text and puts the host, user and database in. So the readable damage
# was internal topology and SQL. The reason it is a defect anyway is that the
# invariant was held by a third-party library's formatting choices, which are
# revisited on every upgrade and are nobody's promise to wardryx.
#
# A SECOND SHAPE OF THE SAME LEAK
#
# 2026-09-06: two 500 paths (the approval-hold write and the single-use
# redemption write in handleDecide) wrote the store's error into the body
# through fmt.Sprintf's %v verb instead of through err.Error() directly:
# `writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to
# record ...: %v", err))`. The value that reaches the client is exactly the
# same string a bare err.Error() would have produced, and the grep above
# never saw it, because there is no literal ".Error()" call on that line.
#
# The check below catches that shape too: a write(Error|JSON)( call, on the
# StatusInternalServerError path, whose Sprintf argument formats some
# err-named identifier through a %v/%s/%w verb. Deliberately scoped to
# StatusInternalServerError rather than every writeError/writeJSON call:
# invariant 10 is about "every internal-error path", and a 400 that echoes
# fmt.Sprintf("invalid request body: %v", err) back to the caller is telling
# them what was wrong with the body they just sent, which is the opposite of
# a leak. Widening past StatusInternalServerError would flag those three
# legitimate 400s as well.
#
# WHAT THIS CANNOT DO
#
# It is a source-text check. A message built by hand out of the same error, or
# an error interpolated through a helper this does not know about, walks past
# it. That is a matter for review and is written here rather than implied. The
# %v/%s/%w-plus-err check only looks at the matched line and the one after it,
# so a Sprintf call split across more than two lines is invisible to it too.

set -euo pipefail
cd "$(dirname "$0")/.."

subject="internal/api"
if [ ! -d "$subject" ]; then
	echo "FAIL: $subject is not here, so this measured nothing."
	echo "      An absent subject is not a passing one."
	exit 1
fi

files=$(find "$subject" -name '*.go' ! -name '*_test.go')
if [ -z "$files" ]; then
	echo "FAIL: no non-test Go file under $subject, so this measured nothing."
	exit 1
fi

# shellcheck disable=SC2086
hits=$(grep -n 'write\(Error\|JSON\)(.*err\.Error()' $files || true)

# One file per awk invocation, deliberately: mawk/gawk's ENDFILE would let
# this run in one pass over every file, but the "one true awk" macOS ships
# (and CI's Ubuntu runner may not) does not implement ENDFILE at all, and
# fails the whole invocation. That failure was swallowed by `|| true` the
# first time this was written, which is exactly invariant 12's shape: a
# check that cannot run reported the same silence as a check that ran and
# found nothing.
sprintf_hits=""
for f in $files; do
	out=$(awk '
		{ line[FNR] = $0; last = FNR }
		END {
			for (i = 1; i <= last; i++) {
				if (line[i] !~ /write(Error|JSON)\(/) continue
				if (line[i] !~ /StatusInternalServerError/) continue
				window = line[i]
				if ((i + 1) in line) window = window "\n" line[i + 1]
				if (window !~ /Sprintf\(/) continue
				if (window !~ /%[vsw]/) continue
				n = split(window, toks, /[^A-Za-z0-9_]+/)
				leak = 0
				for (j = 1; j <= n; j++) {
					t = tolower(toks[j])
					if (t != "" && t ~ /err[a-z0-9_]*$/) { leak = 1; break }
				}
				if (leak) printf "%d: %s\n", i, line[i]
			}
		}
	' "$f")
	if [ -n "$out" ]; then
		sprintf_hits="$sprintf_hits$(printf '%s\n' "$out" | sed "s#^#$f:#")
"
	fi
done

if [ -n "$hits" ] || [ -n "$sprintf_hits" ]; then
	[ -n "$hits" ] && echo "$hits"
	[ -n "$sprintf_hits" ] && echo "$sprintf_hits"
	echo
	echo "An error from outside this package is written into an HTTP response,"
	echo "either directly (err.Error()) or folded into a message through"
	echo "fmt.Sprintf's %v/%s/%w verb. Use writeInternalError, which logs the"
	echo "detail and answers with a message wardryx composed itself. See"
	echo "CLAUDE.md invariant 10."
	exit 1
fi

n=$(printf '%s\n' $files | wc -l | tr -d ' ')
echo "OK: $n file(s) under $subject, none writing a foreign error into a response."
