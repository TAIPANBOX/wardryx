#!/usr/bin/env bash
# The file that carries an agent's error budget is read outside the decision, and
# its signal cannot be removed by the caller (invariant 45).
#
# WHY THIS IS A GATE
#
# `WARDRYX_SIGNAL_EVENTS` makes wardryx read a file and add one signal to a
# decision. That is a new input to the answer allow, deny or hold, and the one
# promise worth keeping about it is that the decision path never learned of the
# file: the engine reads the signal as it reads any other, so a rule on it can add
# a hold and nothing else (invariant 25), and a recorded decision replays with the
# file gone (invariant 27). Each of the five checks below is a way for that to stop
# being true without one test noticing, because every behaviour test runs with the
# file present and healthy.
#
#   1. Nothing the decision or its replay stands on depends on internal/sloburn,
#      and nothing in internal/pdp or internal/policy names the setting.
#   2. internal/sloburn reaches no network, process or database package, and its
#      non-test code opens no file for writing.
#   3. handleDecide passes the signals it built through withStandingSignal, so the
#      standing signal is added in one place, after the caller's are validated.
#   4. withStandingSignal compares a caller's signal name to slo_burn the way a
#      rule compares it (EqualFold), so the caller cannot declare its own.
#   5. The reader keeps its file by a digest of its bytes, not by size and time.
#
# WHAT THIS CANNOT DO
#
# It reads source text and `go list`. A caller's signal dropped by some other
# spelling, or a write through a helper it does not know, is not seen; the tests
# in internal/api/slo_burn_test.go and internal/sloburn/sloburn_test.go prove the
# behaviour, and this keeps their subject in place. Comment lines are skipped, so
# a comment naming a refused shape is not mistaken for code.

set -euo pipefail
cd "$(dirname "$0")/.."

module="github.com/TAIPANBOX/wardryx"
reader_dir="internal/sloburn"
api_file="internal/api/api.go"
standing_file="internal/api/slo_burn.go"

for f in "$api_file" "$standing_file" "$reader_dir/sloburn.go"; do
	if [ ! -f "$f" ]; then
		echo "FAIL: $f is not here, so this measured nothing."
		exit 2
	fi
done

problems=0
say() {
	printf 'PROBLEM %s\n' "$1"
	problems=$((problems + 1))
}

# Code with its comment lines removed, for the text checks.
code() { grep -v '^[[:space:]]*//' "$1" || true; }

# has <file> <extended regex>: whether the file's code, comments removed, matches.
# The code goes through a here-string and not a pipe: under pipefail, grep -q
# closing the pipe at its first match makes the writer die of SIGPIPE, and the
# pipeline then reports failure for a match that was found.
has() { grep -Eq -- "$2" <<<"$(code "$1")"; }

# 1. The closure of the decision and its replay.
checked=0
for pkg in internal/pdp internal/policy internal/replay internal/approval internal/archive; do
	deps=$(go list -deps "$module/$pkg" 2>/dev/null) || {
		echo "FAIL: go list -deps $pkg failed, so this measured nothing."
		exit 2
	}
	checked=$((checked + $(printf '%s\n' "$deps" | grep -c "^$module/")))
	if grep -qx "$module/$reader_dir" <<<"$deps"; then
		say "$pkg depends on $reader_dir: the decision path would then know of the file"
	fi
done
if [ "$checked" -lt 5 ]; then
	echo "FAIL: go list read $checked module package(s), so this measured nothing."
	exit 2
fi
for pkg in internal/pdp internal/policy; do
	for f in "$pkg"/*.go; do
		case "$f" in *_test.go) continue ;; esac
		if has "$f" 'sloburn|WARDRYX_SIGNAL_EVENTS'; then
			say "$f names the signal file or its setting: the decision path must not know of it"
		fi
	done
done

# 2. What the reader may reach, and how it opens its file.
rdeps=$(go list -deps "$module/$reader_dir" 2>/dev/null) || {
	echo "FAIL: go list -deps $reader_dir failed, so this measured nothing."
	exit 2
}
if [ "$(printf '%s\n' "$rdeps" | wc -l)" -lt 10 ]; then
	echo "FAIL: go list read fewer than 10 dependencies of $reader_dir, so this measured nothing."
	exit 2
fi
while IFS= read -r dep; do
	case "$dep" in
	net | net/http | os/exec | database/sql | *pgx*)
		say "$reader_dir reaches $dep: it reads one local file and must reach no network, process or database"
		;;
	esac
done <<<"$rdeps"
for f in "$reader_dir"/*.go; do
	case "$f" in *_test.go) continue ;; esac
	if has "$f" 'os\.(Create|OpenFile|WriteFile|Remove|RemoveAll|Rename|Truncate|Chmod|Mkdir)|O_WRONLY|O_RDWR|O_APPEND|O_CREATE'; then
		say "$f writes, removes or changes a file: the reader may only read"
	fi
done

# 3. The standing signal enters in one place.
if ! awk '
	/^func \(s \*Server\) handleDecide\(/ { inside = 1; next }
	inside && /^}/ { inside = 0 }
	inside && /^[ \t]*\/\// { next }
	inside && /s\.withStandingSignal\(/ { found = 1 }
	END { exit found ? 0 : 1 }
' "$api_file"; then
	say "handleDecide does not pass its signals through withStandingSignal: the standing signal would never be added, or be added somewhere else"
fi

# 4. A caller's own slo_burn is dropped under the rule's own comparison.
if ! has "$standing_file" 'EqualFold\(strings\.TrimSpace\([a-z]+\.Name\), *sloburn\.SignalName\)'; then
	say "withStandingSignal does not compare a caller's signal name to slo_burn with EqualFold: a spelling the rule reads could get past it"
fi

# 5. The reader tells one version of its file from another by the bytes.
if ! has "$reader_dir/sloburn.go" 'sha256\.Sum256\('; then
	say "the reader does not tell its file's versions apart by a digest of the bytes: an edit of the same length inside one clock tick would be missed"
fi

if [ "$problems" -gt 0 ]; then
	printf 'FAIL: %d problem(s).\n' "$problems"
	exit 1
fi
printf 'OK: %d module packages read for the decision closure; %s reaches no network, process or database and only reads; the standing signal is added in one place and a caller cannot declare its own.\n' "$checked" "$reader_dir"
