#!/usr/bin/env bash
# Checks that the gates in `scripts/` still FAIL on the faults they exist to
# catch, still PASS on what they must not catch, and REFUSE to report success
# when they measured nothing at all.
#
# WHY
#
# Every gate here parses text, and a text parser does not break loudly: it
# stops matching and reports success. The mutants that proved each one existed
# as prose, in commit messages and in the `*(gate: ...)*` markers in CLAUDE.md,
# which is a record of what was true once. Nothing ran them again.
#
# A gate that has quietly stopped catching anything looks exactly like a gate
# with nothing to catch, and stays that way until the fault it guards ships.
#
# WHY THE THIRD PROPERTY IS SEPARATE FROM THE FIRST
#
# `readme-numbers.sh` already refuses in two distinct ways when its subject is
# absent: no test functions at all, and no badge to compare against. Both
# sentences were true, were established by hand once in the session that wrote
# it, and nothing re-ran them.
#
# `decision-path-purity.sh` is the one with the sharper edge. It reads `go
# list` output and matches each import against two lists. A list that stops
# being consulted, or a `go list` that returns nothing, produces exactly the
# same output as a clean tree: silence, then OK. The decision path is where
# this repository answers allow or deny, so a purity check that has quietly
# stopped looking is worse here than almost anywhere else in the estate.
#
# HOW IT MUTATES WITHOUT LEAVING A MESS
#
# It edits tracked files in place, so it refuses to start unless the tree is
# clean, restores with `git checkout` after every case, restores again from a
# trap on any exit path including a kill, and asserts the tree is clean before
# reporting success.
#
#
# A GATE THAT IS ALREADY FAILING CANNOT BE JUDGED
#
# No case proves anything if the gate was already failing before the mutation.
# So every case runs the gate on the UNMUTATED tree first and reports
# UNJUDGEABLE. Found on 2026-08-09 in it-rat, where one gate was legitimately
# red and a case against it would have been indistinguishable from a working
# one.
#
# It covered only the fail-cases at first, which left the mirror of the same
# bug: on a red gate a pass-case reports OVEREAGER, "the gate failed on
# something it must not catch", and sends the reader to look at a harmless
# mutation. The verdict was being given without the predicate it depends on.
#
# A MUTATION THAT DID NOT APPLY PROVES NOTHING
#
# Every edit asserts it changed the file. A case whose edit applied nothing is
# a failure here, not a pass. That is not hypothetical: five such mutations
# were caught across idryx and tokenfuse on 2026-08-09, and three of the five
# had been verified BY HAND against the same gate minutes earlier. The hand
# version and the harness version differ only in how many layers of quoting sit
# between the text and python, which is exactly the difference nobody sees.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

if [ -n "$(git status --porcelain)" ]; then
	printf 'this script mutates tracked files, so it needs a clean tree.\n'
	printf 'commit or stash first; it restores with `git checkout` and cannot\n'
	printf 'tell your edits from its own.\n'
	exit 1
fi

# Untracked files too: a mutation may RENAME a tracked file, and `git checkout`
# restores the original while leaving the new name behind. And the INDEX, since
# a gate may read `git ls-files` rather than the disk, so a mutation has to move
# the file in both. Safe because this
# script refuses to start unless the tree is clean, so anything untracked
# during a run was created by the run. `-x` is deliberately absent: ignored
# build output is not ours to delete.
restore() {
	git reset -q --hard HEAD 2>/dev/null
	git clean -fdq 2>/dev/null
}
baseline_dir="$(mktemp -d)"

# One trap for both, because a second `trap ... EXIT` REPLACES the first
# rather than adding to it. Writing them separately disarmed `restore` on
# every interrupt path, which would leave a mutated tree behind on Ctrl-C.
cleanup() {
	restore
	rm -rf "$baseline_dir"
}
trap cleanup EXIT INT TERM


failures=0
cases=0

# run_case <name> <expect: fail|pass> <gate> <python edit> [required output]
#
# The needle separates "it failed" from "it failed for the reason this case is
# about". Without it, a case expecting failure is satisfied by any failure,
# including one this harness caused itself.
run_case() {
	local name="$1" expect="$2" gate="$3" edit="$4" needle="${5:-}"
	cases=$((cases + 1))

	# The baseline applies to EVERY case, not only the ones expecting a failure.
	# It was `fail`-only until 2026-08-09, which left the mirror of the bug it was
	# written for: on a gate that is already red, a `pass` case reports OVEREAGER,
	# "the gate failed on something it must not catch", and sends the reader to
	# look at a harmless mutation while the gate was failing without it. Neither
	# verdict means anything on a red gate, so neither is given.
	skip_baseline=0
	if [ "$expect" = fail_env ]; then
		# `fail` with the baseline skipped, for cases whose fault IS the command
		# rather than a mutation: red before and after is the point there.
		expect=fail
		skip_baseline=1
	fi

	if [ "$skip_baseline" = 0 ]; then
		local key base_out
		key="$baseline_dir/$(printf '%s' "$gate" | cksum | tr -d ' ')"
		if [ ! -f "$key" ]; then
			if eval "$gate" >/dev/null 2>&1; then printf 'green' >"$key"; else printf 'red' >"$key"; fi
		fi
		base_out="$(cat "$key")"
		if [ "$base_out" = red ]; then
			printf 'UNJUDGEABLE  %s\n             the gate is already failing on a clean tree, so neither a\n             failure nor a pass after the mutation would prove anything\n' "$name"
			failures=$((failures + 1))
			return
		fi
	fi

	if ! python3 -c "$edit"; then
		printf 'BROKEN  %s\n        its mutation did not apply, so this case proved nothing\n' "$name"
		failures=$((failures + 1))
		restore
		return
	fi

	local out rc
	out=$(eval "$gate" 2>&1)
	rc=$?
	restore

	# Exit code first, then wording. Checking the needle before the expectation
	# turns "it did not fail at all" into "it failed for the wrong reason",
	# which sends the reader to look at prose when the gate is toothless.
	if [ "$expect" = fail ] && [ "$rc" -ne 0 ] && [ -n "$needle" ] &&
		! printf '%s' "$out" | grep -qF -- "$needle"; then
		printf 'WRONG REASON  %s\n              it failed, but not saying: %s\n' "$name" "$needle"
		failures=$((failures + 1))
		return
	fi
	if [ "$expect" = fail ] && [ "$rc" -eq 0 ]; then
		printf 'TOOTHLESS  %s\n           the gate passed on a fault it exists to catch\n' "$name"
		failures=$((failures + 1))
	elif [ "$expect" = pass ] && [ "$rc" -ne 0 ]; then
		printf 'OVEREAGER  %s\n           the gate failed on something it must not catch\n' "$name"
		failures=$((failures + 1))
		printf '%s\n' "$out" | head -4 | sed 's/^/           /'
	else
		printf 'ok  %-58s (%s)\n' "$name" "$expect"
	fi
}

py() { printf 'def edit(p, a, b):\n    s = open(p).read()\n    assert a in s, "pattern not found in " + p\n    open(p, "w").write(s.replace(a, b, 1))\n%s\n' "$1"; }

echo "=== faults each gate must catch ==="

# A clock on the decision path is the canonical impurity: the same input stops
# producing the same verdict, and a verdict that cannot be reproduced is not
# evidence.
run_case "decision-path-purity: the PDP reads the clock" fail \
	'./scripts/decision-path-purity.sh' \
	"$(py 'edit("internal/pdp/pdp.go", "import (", "import (\n\t_ \"time\"")')" \
	"imports 'time' directly"

run_case "decision-path-purity: the PDP reaches the network" fail \
	'./scripts/decision-path-purity.sh' \
	"$(py 'edit("internal/pdp/pdp.go", "import (", "import (\n\t_ \"net/http\"")')" \
	"imports 'net/http' directly"

run_case "decision-path-purity: the PDP takes randomness" fail \
	'./scripts/decision-path-purity.sh' \
	"$(py 'edit("internal/pdp/pdp.go", "import (", "import (\n\t_ \"crypto/rand\"")')" \
	"imports 'crypto/rand' directly"

run_case "no-raw-error-in-response: a driver error written into a body" fail \
	'./scripts/no-raw-error-in-response.sh' \
	"$(py 'edit("internal/api/api.go", "writeInternalError(w, \"listing policies\", err)", "writeError(w, http.StatusInternalServerError, err.Error())")')" \
	"err.Error()"

run_case "store-hands-out-copies: a read method that stops copying" fail \
	'./scripts/store-hands-out-copies.sh' \
	"$(py 'edit("internal/store/memory.go", "\treturn copyOut(a)", "\treturn a, nil")')" \
	"does not copy"

# The one the gate exists for: not a method that stopped copying, but a NEW
# one that never did. Nothing about it produces a symptom, and no test would
# be missing, because nobody wrote one.
run_case "store-hands-out-copies: a new read method that never copied" fail \
	'./scripts/store-hands-out-copies.sh' \
	"$(py 'p = "internal/store/memory.go"
s = open(p).read()
open(p, "w").write(s + """
func (m *Memory) GetSomethingNew(id string) (Approval, error) {
\tm.mu.Lock()
\tdefer m.mu.Unlock()
\treturn m.byID[id], nil
}
""")')" \
	"does not copy"

run_case "readme-numbers: a stale test badge" fail \
	'./scripts/readme-numbers.sh' \
	"$(py 'import re
s = open("README.md").read()
m = re.search(r"badge/tests-(\d+)-", s)
assert m, "no test badge in README.md"
open("README.md","w").write(s.replace(m.group(0), "badge/tests-%d-" % (int(m.group(1))+7), 1))')" \
	"badge"

echo
echo "=== and what they must NOT catch ==="

# A new read method that DOES copy must pass. The first version of this gate
# matched the shape of a return statement and fired on the two copy helpers,
# which are exactly right. A gate that is wrong about correct code is a gate
# somebody deletes.
run_case "store-hands-out-copies: a new read method that copies properly" pass \
	'./scripts/store-hands-out-copies.sh' \
	"$(py 'p = "internal/store/memory.go"
s = open(p).read()
open(p, "w").write(s + """
func (m *Memory) GetSomethingNew(id string) (Approval, error) {
\tm.mu.Lock()
\tdefer m.mu.Unlock()
\treturn copyOut(m.byID[id])
}
""")')"


# The decision path may still use the standard library for pure work. A gate
# that flagged this would be flagging the code it exists to protect.
# Logging an error is not returning one. The check is about what leaves the
# process in a RESPONSE, and a gate that also refused the log line would push
# people to stop logging, which is the opposite of what the fix did.
run_case "no-raw-error-in-response: an error logged and not returned" pass \
	'./scripts/no-raw-error-in-response.sh' \
	"$(py 'edit("internal/api/api.go", "func writeError(w http.ResponseWriter", "func loggedNotReturned(err error) { log.Printf(\"x: %v\", err.Error()) }\n\nfunc writeError(w http.ResponseWriter")')"

run_case "decision-path-purity: a pure stdlib import on the decision path" pass \
	'./scripts/decision-path-purity.sh' \
	"$(py 'edit("internal/pdp/pdp.go", "import (", "import (\n\t_ \"sort\"")')"

echo
echo "=== and the one this estate learned the hard way ==="
echo "    a gate whose subject is gone must SAY so, not report OK on nothing"

run_case "decide-order: a rule is added to the code and not to the comment" fail \
	'./scripts/decide-order-is-documented.sh' \
	"$(py 'edit("internal/pdp/pdp.go",
        "\tif pol, ok := unattestedDenied(",
        "\tif pol, ok := brandNewRule(matched); ok {\n\t\t_ = pol\n\t}\n\tif pol, ok := unattestedDenied(")')" \
	"no policy-field name for it"

run_case "decide-order: the comment loses a rule and renumbers over it" fail \
	'./scripts/decide-order-is-documented.sh' \
	"$(py 'import re
s = open("internal/pdp/pdp.go").read()
before = s
s = re.sub(r"//  4\. a matched policy.s require_root_principal, with a chain whose root is\n//     not one it names, denies;\n", "", s, count=1)
assert s != before, "the require_root_principal item is not where this expects it"
open("internal/pdp/pdp.go", "w").write(s)')" \
	"and the comment"

run_case "decide-order: the doc comment is gone" fail \
	'./scripts/decide-order-is-documented.sh' \
	"$(py 'edit("internal/pdp/pdp.go",
        "// Decide evaluates req against",
        "// Decide handles the request")')" \
	"measured nothing"

run_case "no-raw-error-in-response: no internal/api left to read" fail \
	'./scripts/no-raw-error-in-response.sh' \
	"$(py 'import shutil; shutil.rmtree("internal/api")')" \
	"measured nothing"

run_case "store-hands-out-copies: no memory store left to read" fail \
	'./scripts/store-hands-out-copies.sh' \
	"$(py 'import os; os.remove("internal/store/memory.go")')" \
	"measured nothing"

run_case "readme-numbers: no badge left to compare against" fail \
	'./scripts/readme-numbers.sh' \
	"$(py 'import re
s = open("README.md").read()
m = re.search(r"badge/tests-\d+-", s)
assert m, "no test badge in README.md"
open("README.md","w").write(s.replace(m.group(0), "badge/nothing-", 1))')" \
	"nothing to compare against"

# The two directions of the scenario/test binding, and the empty measurement.
# A scenario that names no test is prose; a binding naming a test that is gone
# reads as coverage. Both are silent, which is why both have a case here.
run_case "scenarios-bind-to-tests: a scenario that names no test" fail \
	'./scripts/scenarios-bind-to-tests.sh' \
	"$(py 'import re
s = open("features/policy-replay.feature").read()
m = re.search(r"\n    # -> [^\n]+\n", s)
assert m, "no binding comment in the feature file"
open("features/policy-replay.feature","w").write(s.replace(m.group(0), "\n", 1))')" \
	"names no test"

run_case "scenarios-bind-to-tests: a binding pointing at a test that is gone" fail \
	'./scripts/scenarios-bind-to-tests.sh' \
	"$(py 'edit("features/policy-replay.feature",
    "internal/api:TestARecordedDenialReplaysToTheSameVerdict",
    "internal/api:TestThisTestWasRenamedAwayLongAgo")')" \
	"does not exist"

run_case "scenarios-bind-to-tests: no scenarios left to bind" fail \
	'./scripts/scenarios-bind-to-tests.sh' \
	"$(py 'import os; os.remove("features/policy-replay.feature")')" \
	"measured nothing"

echo
if [ -n "$(git status --porcelain)" ]; then
	printf 'FAIL: this script left the tree dirty, so it cannot be trusted about anything above\n'
	git status --porcelain | head -5
	exit 1
fi

if [ "$failures" -gt 0 ]; then
	printf '%d of %d cases failed.\n' "$failures" "$cases"
	printf 'A gate that has quietly stopped catching anything looks exactly like a gate\n'
	printf 'with nothing to catch, and stays that way until the fault it guards ships.\n'
	exit 1
fi

printf 'OK: %d cases. Every gate fails on its own fault, passes on a non-fault,\n' "$cases"
printf '    and refuses to report success when it measured nothing.\n'
