#!/usr/bin/env bash
# Invariant: every Gherkin scenario names a test that exists, and every
# binding points at a real test function.
#
# WHY BOTH DIRECTIONS
#
# A scenario with no test is prose that describes software nobody checks. A
# binding that names a test which has been renamed or deleted is worse: it
# reads as coverage, and the reader has no way to tell it apart from the real
# thing without opening the file. Neither failure is loud on its own.
#
# WHY IT REFUSES RATHER THAN PASSES WHEN IT FINDS NOTHING
#
# This gate parses text. A features directory that is gone, a Feature file
# that stops matching, or a grep that returns nothing all produce the same
# output as a clean tree: silence, then OK. So an empty measurement is an
# error with its own exit code, never a pass.
set -uo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
features="$root/features"

if [ ! -d "$features" ]; then
	echo "measured nothing: no features/ directory at $features"
	exit 2
fi

shopt -s nullglob
files=("$features"/*.feature)
if [ ${#files[@]} -eq 0 ]; then
	echo "measured nothing: no .feature files in $features"
	exit 2
fi

scenarios=0
bindings=0
problems=0

for file in "${files[@]}"; do
	rel="${file#"$root"/}"
	# One pass per file: count scenarios, and require each to be followed by
	# at least one binding before the next scenario begins.
	current=""
	bound=0
	line_no=0
	while IFS= read -r line || [ -n "$line" ]; do
		line_no=$((line_no + 1))
		case "$line" in
		*Scenario:*)
			if [ -n "$current" ] && [ "$bound" -eq 0 ]; then
				echo "$rel: scenario names no test: $current"
				problems=$((problems + 1))
			fi
			current="$(printf '%s' "$line" | sed 's/^[[:space:]]*Scenario:[[:space:]]*//')"
			scenarios=$((scenarios + 1))
			bound=0
			;;
		*"# ->"*)
			target="$(printf '%s' "$line" | sed 's/.*# ->[[:space:]]*//')"
			name="${target##*:}"
			if [ -z "$name" ] || [ "$name" = "$target" ]; then
				echo "$rel:$line_no: binding is not pkg:TestName: $target"
				problems=$((problems + 1))
				continue
			fi
			if ! grep -rqE "^func ${name}\(" --include='*_test.go' "$root"; then
				echo "$rel:$line_no: binding names a test that does not exist: $name"
				problems=$((problems + 1))
				continue
			fi
			bindings=$((bindings + 1))
			bound=1
			;;
		esac
	done <"$file"
	if [ -n "$current" ] && [ "$bound" -eq 0 ]; then
		echo "$rel: scenario names no test: $current"
		problems=$((problems + 1))
	fi
done

if [ "$scenarios" -eq 0 ]; then
	echo "measured nothing: parsed no scenarios out of ${#files[@]} feature file(s)"
	exit 2
fi
if [ "$bindings" -eq 0 ]; then
	echo "measured nothing: parsed no bindings out of $scenarios scenario(s)"
	exit 2
fi

if [ "$problems" -gt 0 ]; then
	echo
	echo "$problems scenario/test binding problem(s)."
	echo "A scenario with no test describes software nobody checks; a binding"
	echo "naming a test that is gone reads as coverage and is not."
	exit 1
fi

echo "$scenarios scenario(s), $bindings binding(s), every one naming a test that exists"
