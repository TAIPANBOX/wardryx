#!/usr/bin/env bash
# Every number this README states about this repository, checked against the
# repository.
#
# WHY THIS EXISTS
#
# A number on a README is a claim with no owner. It is right the day it is
# written and nothing tells anybody when it stops being right, because the
# suite grows in a commit that never opens the README.
#
# That is not hypothetical here. On 2026-08-05 the it-rat.com service pages were
# audited against the repositories they describe and FOUR OF SEVEN figures were
# stale: trailryx by 33 tests, tokenfuse by 196, engram by 42, verdryx by 75.
# None was wrong when written. The site now has a gate; this is the same idea at
# the source, where the number actually changes.
#
# WHAT "TESTS" MEANS HERE, because a number needs a definition more than it
# needs a badge
#
# `go test ./... -list '.*'` enumerates test FUNCTIONS. It does not count
# subtests created with `t.Run`, and it does not count table cases inside one
# function. So the figure is "test functions in this module", which is a real
# and checkable quantity, and it is deliberately not called "assertions" or
# "cases", both of which would be larger and neither of which anybody can
# reproduce.
#
# It also does not run them. This is a claim about how much test code exists,
# not about it passing: `go test -race ./...` in CI is what says they pass, and
# conflating the two would let a green badge mean a red suite.
#
# WHY A BROKEN BUILD IS REFUSED RATHER THAN COUNTED
#
# `go test -list` enumerates only packages that COMPILE. A package that does
# not contributes zero test functions to stdout, writes its compiler errors to
# stderr, and leaves the total quietly smaller. Nothing about that output says
# a package is missing.
#
# On 2026-08-31 a test file referenced a symbol that had been reverted out of
# the production file. internal/archive stopped building, its seven tests
# vanished from the count, the total fell from 237 to 230, and this gate said
# "the badge says 237 and counts 230" -- which reads as a stale badge and sends
# the reader to edit the README. Following that advice made the gate report
# "230 test functions, and the badge says so" and exit 0, on a tree where a
# whole package did not compile. A badge was committed from that number.
#
# So this is the THIRD way this check refuses rather than reporting success:
# no test functions at all, no badge to compare against, and now a module that
# did not build. All three are the same rule, which is invariant 12: a check
# must be able to tell "did not fail" from "did not run".

set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1

readme="README.md"
problems=0

note() {
	printf '%s\n' "$1"
	problems=$((problems + 1))
}

build_errors=$(mktemp)
trap 'rm -f "$build_errors"' EXIT

listing=$(go test ./... -list '.*' 2>"$build_errors")
list_status=$?
if [ "$list_status" -ne 0 ]; then
	note "the module did not build, so this count is missing every package that failed to compile"
	printf '\n%s\n\n' "$(head -20 "$build_errors")"
	printf 'A package that does not compile contributes ZERO test functions to\n'
	printf '`go test -list`, silently, and the total just comes out smaller. Fix the\n'
	printf 'build first: a badge agreed with here would be a number derived from a\n'
	printf 'suite that does not exist.\n'
	exit 1
fi

actual=$(printf '%s\n' "$listing" | grep -cE '^Test')
if [ "${actual:-0}" -eq 0 ]; then
	note "the module reported no test functions at all, which means this check measured nothing"
	exit 1
fi

stated=$(grep -o 'badge/tests-[0-9]*-' "$readme" | grep -o '[0-9]*' | head -1)
if [ -z "$stated" ]; then
	note "the README carries no tests badge, so this check has nothing to compare against"
	note "add: ![tests](https://img.shields.io/badge/tests-${actual}-brightgreen)"
	exit 1
fi

[ "$stated" = "$actual" ] ||
	note "the badge says $stated test functions and \`go test -list\` counts $actual"

if [ "$problems" -gt 0 ]; then
	printf '\n%d number(s) the README states that this repository does not support.\n' "$problems"
	printf 'Update the badge in the same commit as the tests. That is the whole point:\n'
	printf 'the suite changes in a commit that never opens the README, and this is what\n'
	printf 'makes that impossible.\n'
	exit 1
fi

printf '%s test functions, and the badge says so.\n' "$actual"
