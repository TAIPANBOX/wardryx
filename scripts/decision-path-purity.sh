#!/usr/bin/env bash
# Enforces invariant 1 of CLAUDE.md: the decision-path packages do not reach for
# the network, a clock, or a random source in their own code.
#
# This checks DIRECT imports, deliberately, and the reason is worth reading
# before you "improve" it to a transitive check:
#
#   A transitive check is wrong in the strict direction here. gopkg.in/yaml.v3
#   legitimately imports "time" to parse timestamps, which does not make policy
#   loading clock-dependent. Failing on that teaches people to disable the gate.
#
#   There is also a real transitive path by design:
#     internal/pdp -> internal/approval -> internal/store -> pgx
#   Approval tokens are single-use, and redemption state has to persist, so the
#   approval path reaches a database on purpose. The guarantee this script holds
#   is therefore narrower than "the decision path never touches a database", and
#   CLAUDE.md says so rather than implying otherwise.
#
# What this does catch is the actual regression mode: somebody adds time.Now(),
# an http client, or a model SDK to pdp.go or policy.go.
#
# This file is the ONE copy of this check. The local hook and CI both call it.
# Two copies of one check always diverge, so do not inline it anywhere.

set -euo pipefail

cd "$(dirname "$0")/.."

PURE_PKGS=(./internal/pdp ./internal/policy)

# Forbidden as a DIRECT import of a decision-path package.
FORBIDDEN=(
	"net"
	"net/http"
	"net/url"
	"database/sql"
	"math/rand"
	"crypto/rand"
	"time"
	"os/exec"
)

FORBIDDEN_PREFIX=(
	"github.com/jackc/pgx"
	"github.com/anthropics/"
	"github.com/sashabaranov/go-openai"
)

fail=0

for pkg in "${PURE_PKGS[@]}"; do
	imports="$(go list -f '{{join .Imports "\n"}}' "$pkg")"

	while IFS= read -r imp; do
		[ -n "$imp" ] || continue

		for bad in "${FORBIDDEN[@]}"; do
			if [ "$imp" = "$bad" ]; then
				echo "FAIL: $pkg imports '$imp' directly"
				fail=1
			fi
		done

		for pre in "${FORBIDDEN_PREFIX[@]}"; do
			case "$imp" in
			"$pre"*)
				echo "FAIL: $pkg imports '$imp' directly"
				fail=1
				;;
			esac
		done
	done <<<"$imports"
done

if [ "$fail" -ne 0 ]; then
	echo
	echo "A decision that reads a clock, a random source, the network or a"
	echo "database in its own code cannot be replayed during an audit, and it is"
	echo "not the same decision twice. See CLAUDE.md invariant 1."
	echo
	echo "Resolve the value at the API layer (internal/api) and pass it in."
	exit 1
fi

echo "OK: decision-path packages import no clock, randomness, network or DB directly."
