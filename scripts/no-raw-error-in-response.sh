#!/usr/bin/env bash
# No error from outside this package is written into an HTTP response.
#
# WHY THIS IS A GATE AND NOT A REVIEW NOTE
#
# CLAUDE.md has recorded for a long time that invariant 3's error-text half is
# unchecked, and on 2026-08-20 it turned out to be unchecked AND broken: all
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
# WHAT THIS CANNOT DO
#
# It is a source-text check. A message built by hand out of the same error, or
# an error interpolated through a helper this does not know about, walks past
# it. That is a matter for review and is written here rather than implied.

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
if [ -n "$hits" ]; then
	echo "$hits"
	echo
	echo "An error from outside this package is written into an HTTP response."
	echo "Use writeInternalError, which logs the detail and answers with a"
	echo "message wardryx composed itself. See CLAUDE.md invariant 3."
	exit 1
fi

n=$(printf '%s\n' $files | wc -l | tr -d ' ')
echo "OK: $n file(s) under $subject, none writing a foreign error into a response."
