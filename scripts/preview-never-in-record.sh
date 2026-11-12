#!/usr/bin/env bash
# Enforces invariant 51 of CLAUDE.md, the half a test cannot hold: what a
# person is shown of a held call's arguments goes to one place, sealed, and
# nowhere else.
#
# WHY A GATE AS WELL AS THE TESTS
#
# The tests hold the paths that exist: a marker sent in the arguments is not in
# the event file, the hold's context or the approvals list. What they cannot
# see is the NEXT path: somebody builds a preview for a log line, a span, a
# replay report or an export, and no test was written for the leak, because a
# leak produces no symptom. This reads the code for the shapes that would be
# such a path.
#
# WHAT IT HOLDS
#
#  1. preview.Build is called in exactly one production place,
#     internal/api/preview.go, which seals what it builds.
#  2. previewseal.Open is called in no production code: wardryx seals and
#     never opens. Only the console holds the key that opens.
#  3. No package that writes a record, replays one, archives one or exports a
#     span imports internal/preview or internal/previewseal.
#  4. The sealed bytes leave internal/api/preview.go only towards the store
#     and the preview endpoint: no other file in internal/api names them.
#
# WHAT IT CANNOT DO
#
# It reads shapes. A preview smuggled out through a helper with another name
# needs a reader, and the API tests are that reader for the paths that exist.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

subject="internal/api/preview.go"
if [ ! -f "$subject" ]; then
	echo "measured nothing: $subject is not here"
	exit 2
fi

fail=0
prod() { git ls-files -- '*.go' | grep -v '_test\.go$'; }

builds=$(prod | xargs grep -ln 'preview\.Build(' 2>/dev/null | grep -v '^internal/preview/' || true)
if [ "$builds" != "$subject" ]; then
	echo "FAIL: preview.Build is called outside $subject (or not in it): ${builds:-nowhere}"
	fail=1
fi

opens=$(prod | xargs grep -ln 'previewseal\.Open(' 2>/dev/null || true)
if [ -n "$opens" ]; then
	echo "FAIL: production code opens a sealed preview: $opens"
	fail=1
fi

for pkg in internal/replay internal/archive internal/otel internal/pdp internal/policy internal/approval internal/sloburn; do
	[ -d "$pkg" ] || { echo "measured nothing: $pkg is not here"; exit 2; }
	hits=$(git ls-files -- "$pkg/*.go" | grep -v '_test\.go$' | xargs grep -ln '"github.com/TAIPANBOX/wardryx/internal/preview' 2>/dev/null || true)
	if [ -n "$hits" ]; then
		echo "FAIL: $hits imports the preview packages"
		fail=1
	fi
done

sealed=$(git ls-files -- 'internal/api/*.go' 'cmd/*.go' | grep -v '_test\.go$' | grep -v "^$subject\$" | xargs grep -ln '\.sealed\b\|\.Sealed\b' 2>/dev/null || true)
if [ -n "$sealed" ]; then
	echo "FAIL: the sealed preview is named outside $subject: $sealed"
	fail=1
fi

if [ "$fail" -ne 0 ]; then
	exit 1
fi
n=$(prod | wc -l | tr -d ' ')
echo "OK: the preview is built in $subject only, opened nowhere, and reaches no record path ($n production files read)"
