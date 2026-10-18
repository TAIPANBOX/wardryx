#!/usr/bin/env bash
# Invariant 41: a v3 approval token is checked by its ES256 signature under the
# kid its header names, from a key set the verifier holds. It is never checked
# with the HMAC secret, never with a key the token carries, and never by a
# package on the decision path that imports the Keyryx client.
#
# WHY A TEXT GATE
#
# The behaviour is tested in internal/approval and internal/keyryx. What a test
# cannot see is a shape that compiles and passes: a header member that brings
# its own key (jwk, jku, x5c, x5u), an HMAC call slipped into the v3 verifier,
# the algorithm pin removed, or the client imported by the decision path. Each
# of those is a line of text, so each is checked as text.
#
# WHY IT REFUSES RATHER THAN PASSES WHEN IT FINDS NOTHING
#
# A verifier file that is renamed away, or a client that is moved, would make
# every check below find nothing and report OK. So a missing subject is an
# error with its own exit code, never a pass.
set -uo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
verifier="$root/internal/approval/v3.go"
client="$root/internal/keyryx/keyryx.go"
for f in "$verifier" "$client"; do
	if [ ! -f "$f" ]; then
		echo "measured nothing: $f is missing"
		exit 2
	fi
done

status=0

# 1. The token's header never brings a key: no quoted jwk, jku, x5c or x5u.
if grep -nE '"(jwk|jku|x5c|x5u)"' "$verifier"; then
	echo "FAIL: the v3 verifier reads a key or a key location from the token"
	status=1
fi

# 2. The HMAC secret never checks a v3 token: no hmac call in the v3 verifier.
if grep -nE 'hmac\.' "$verifier"; then
	echo "FAIL: the v3 verifier calls the HMAC"
	status=1
fi

# 3. The algorithm is pinned in the verifier, so an ES256 check is what runs.
if ! grep -qE '"ES256"' "$verifier"; then
	echo "FAIL: the v3 verifier does not pin ES256"
	status=1
fi

# 4. Nothing on the decision path imports the Keyryx client (invariant 26's
#    closure, checked here by name as well).
for f in "$root"/internal/approval/*.go "$root"/internal/pdp/*.go "$root"/internal/policy/*.go \
	"$root"/internal/replay/*.go "$root"/internal/archive/*.go; do
	case "$f" in *_test.go) continue ;; esac
	if [ -f "$f" ] && grep -q '"github.com/TAIPANBOX/wardryx/internal/keyryx"' "$f"; then
		echo "FAIL: $f imports the Keyryx client on the decision path"
		status=1
	fi
done

if [ "$status" -eq 0 ]; then
	echo "OK: the v3 verifier pins ES256, reads no key from the token, and never calls the HMAC; the decision path does not import the Keyryx client"
fi
exit "$status"
