#!/usr/bin/env bash
# Invariant 42: nothing under internal/ indexes a map, or a slice, with the
# bearer a request presented.
#
# WHY
#
# The bearer key store was a map keyed by the raw configured key, and
# authenticate looked the presented Authorization value up in it (finding F-023
# of the 2026-10-17 review). A lookup by the presented bytes is not a
# constant-time comparison: how far the hash-table walk and the key comparison
# get depends on those bytes. The store is now keyed by the SHA-256 of each
# configured key, and the presented bearer is digested before the lookup, so the
# bytes compared are digests, one-way over the secret.
#
# This gate keeps the lookup from coming back. It is a source-text check.
#
# WHAT IT READS
#
# The subject is the bearer: a name assigned on a code line that reads the
# Authorization header (`token, ok := strings.CutPrefix(r.Header.Get(
# "Authorization"), ...)` makes `token` the presented bearer). A code line that
# indexes with that name (`s.keys[token]`) is refused. Comment lines are prose
# and are not read. Test files are not read.
#
# WHAT IT CANNOT DO
#
# It follows one assignment, not a chain. `raw := token` and then `m[raw]` is
# not seen, and neither is a lookup inside a helper that takes the bearer as an
# argument. Both stay a matter for review. The rule the gate holds is narrower
# than the rule CLAUDE.md states, and CLAUDE.md says so.
#
# It refuses to report success when it measured nothing: no internal/ directory,
# no non-test Go file, or no code under internal/ that reads the Authorization
# header at all. The last one is the teeth case that matters: a refactor that
# stops reading the bearer from that header would otherwise leave nothing to
# check and say OK.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

subject="internal"
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

# One awk pass per file. Taint: names assigned on a code line that mentions
# Authorization. Then every code line that indexes with a tainted name is a hit.
hits=""
readers=0
for f in $files; do
	out=$(awk '
		function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
		function ident(s,   n, w) {
			n = split(s, w, /[ \t]+/)
			if (n == 0) return ""
			s = w[n]
			if (s !~ /^[A-Za-z_][A-Za-z0-9_]*$/) return ""
			if (s == "_") return ""
			return s
		}
		{ code[FNR] = $0; last = FNR }
		END {
			# Pass 1: the names the Authorization header is read into.
			for (i = 1; i <= last; i++) {
				l = code[i]
				if (l ~ /^[ \t]*\/\//) continue
				if (index(l, "Authorization") == 0) continue
				pos = index(l, ":=")
				if (pos == 0) pos = index(l, " = ")
				if (pos == 0) continue
				lhs = substr(l, 1, pos - 1)
				n = split(lhs, parts, ",")
				for (j = 1; j <= n; j++) {
					name = ident(trim(parts[j]))
					if (name != "") tainted[name] = 1
				}
			}
			for (name in tainted) readers++
			printf "READERS %d\n", readers
			# Pass 2: a code line that indexes with a tainted name.
			for (i = 1; i <= last; i++) {
				l = code[i]
				if (l ~ /^[ \t]*\/\//) continue
				for (name in tainted) {
					if (index(l, "[" name "]") > 0) {
						printf "HIT %d %s\n", i, name
					}
				}
			}
		}
	' "$f")
	n=$(printf '%s\n' "$out" | sed -n 's/^READERS //p')
	readers=$((readers + ${n:-0}))
	hit_lines=$(printf '%s\n' "$out" | grep '^HIT ' || true)
	if [ -n "$hit_lines" ]; then
		while IFS= read -r h; do
			line_no=$(printf '%s' "$h" | awk '{print $2}')
			name=$(printf '%s' "$h" | awk '{print $3}')
			src=$(sed -n "${line_no}p" "$f")
			hits="$hits$f:$line_no: indexes a map by the presented bearer ($name): $(printf '%s' "$src" | sed 's/^[[:space:]]*//')
"
		done <<<"$hit_lines"
	fi
done

if [ "$readers" -eq 0 ]; then
	echo "FAIL: no code under $subject reads the Authorization header, so this measured nothing."
	echo "      The bearer is no longer read where this gate knows to look."
	exit 1
fi

if [ -n "$hits" ]; then
	printf '%s' "$hits"
	echo
	echo "A map or slice under internal/ is indexed with the bearer a request presented."
	echo "Store keys under keyDigest(key) and look up keyDigest(presented), so that the"
	echo "bytes compared are digests. See CLAUDE.md invariant 42 (finding F-023)."
	exit 1
fi

n=$(printf '%s\n' $files | wc -l | tr -d ' ')
echo "OK: $n file(s) under $subject, none indexing a map with the presented bearer."
