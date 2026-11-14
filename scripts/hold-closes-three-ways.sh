#!/usr/bin/env bash
# A hold is closed in three ways and no others (invariant 52): a person decides
# it (grant or deny), wardryx closes it as expired once it has waited
# WARDRYX_HOLD_TTL, or the held agent withdraws it. An admin key closes nothing
# that is not a decision.
#
# WHY THIS IS A GATE
#
# Each of these is one line a later change drops without a test noticing, and
# each failure is quiet: a decide route that also takes "expired" lets an admin
# key close a hold nobody looked at, and the record shows a system closure; a
# withdraw that forgets the run lets one run of an agent close another run's
# hold; an expiry whose UPDATE loses `decision IS NULL` rewrites a hold a person
# decided a moment before, after a token was minted for it. The tests in
# internal/api/hold_close_test.go and internal/store/hold_expiry_test.go hold the
# behaviour; this holds the shapes against the next handler.
#
# WHAT IT READS
#
#   1. handleApprovalDecide refuses every decision but grant and deny, and so does
#      approval.DecideWith.
#   2. Outside internal/store, DecideApproval is called only by approval.DecideWith
#      and by handleApprovalWithdraw with store.DecisionWithdrawn, and
#      ExpireApprovals only by expireHolds.
#   3. handleApprovalWithdraw is registered with requireAuth, refuses an admin key
#      before it reads the body, binds the agent to the key, and compares the
#      hold's agent, run and org with the caller's.
#   4. Both stores' ExpireApprovals close only pending rows and delete the preview:
#      Postgres with `decision IS NULL` in the rows it locks and in the UPDATE, and
#      `DELETE FROM approval_previews` in the same statement; Memory with
#      Pending() and delete(m.previews, ...).
#
# WHAT IT CANNOT DO
#
# It reads source text one function at a time. A closure written through a helper
# it does not know, or SQL built at run time, is not seen. It proves the lines are
# there, not that they are right. Comment lines are skipped.

set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 1

python3 - "$@" <<'PY'
import pathlib
import re
import sys


def nothing(why: str) -> None:
    print(f"FAIL: {why}, so this measured nothing.")
    sys.exit(2)


def code(path: pathlib.Path) -> str:
    # Comment lines are not code.
    return "\n".join(l for l in path.read_text(encoding="utf-8").splitlines() if not l.lstrip().startswith("//"))


def body(src: str, head: str) -> str:
    i = src.find(head)
    if i < 0:
        return ""
    j = src.find("\n}\n", i)
    return src[i:j + 3] if j >= 0 else src[i:]


required = {
    "api": pathlib.Path("internal/api/api.go"),
    "close": pathlib.Path("internal/api/hold_close.go"),
    "keys": pathlib.Path("internal/approval/keys.go"),
    "mem": pathlib.Path("internal/store/memory.go"),
    "pg": pathlib.Path("internal/store/pgstore.go"),
}
for name, p in required.items():
    if not p.is_file():
        nothing(f"{p} is not here")
src = {name: code(p) for name, p in required.items()}

faults = []

decide = body(src["api"], "func (s *Server) handleApprovalDecide(")
withdraw = body(src["close"], "func (s *Server) handleApprovalWithdraw(")
expire_api = body(src["close"], "func (s *Server) expireHolds(")
decide_with = body(src["keys"], "func DecideWith(")
mem_expire = body(src["mem"], "func (m *Memory) ExpireApprovals(")
pg_expire = body(src["pg"], "func (p *Postgres) ExpireApprovals(")
for name, b in [("handleApprovalDecide", decide), ("handleApprovalWithdraw", withdraw), ("expireHolds", expire_api),
                ("approval.DecideWith", decide_with), ("Memory.ExpireApprovals", mem_expire), ("Postgres.ExpireApprovals", pg_expire)]:
    if not b:
        nothing(f"{name} is not here")

# 1. Only grant and deny through the decide route.
if 'if dto.Decision != "grant" && dto.Decision != "deny" {' not in decide:
    faults.append('handleApprovalDecide no longer refuses every decision but "grant" and "deny": an admin key could close a hold as expired or withdrawn')
if 'if decision != "grant" && decision != "deny" {' not in decide_with:
    faults.append('approval.DecideWith no longer refuses every decision but "grant" and "deny"')

# 2. Who closes a hold.
calls = 0
go_files = sorted(
    p for r in ("internal", "cmd") for p in pathlib.Path(r).rglob("*.go")
    if not p.name.endswith("_test.go") and p.parts[:2] != ("internal", "store")
)
if not go_files:
    nothing("there are no Go files under internal or cmd")
func_re = re.compile(r"^func .*$", re.M)
for p in go_files:
    text = code(p)
    for m in re.finditer(r"\.(DecideApproval|ExpireApprovals)\(", text):
        calls += 1
        heads = [h for h in func_re.finditer(text, 0, m.start())]
        fn = heads[-1].group(0) if heads else "(top level)"
        line = text[text.rfind("\n", 0, m.start()) + 1:text.find("\n", m.start())]
        if m.group(1) == "DecideApproval":
            ok = (str(p) == "internal/approval/keys.go" and fn.startswith("func DecideWith(")) or \
                 (str(p) == "internal/api/hold_close.go" and fn.startswith("func (s *Server) handleApprovalWithdraw(") and "store.DecisionWithdrawn" in line)
        else:
            ok = str(p) == "internal/api/hold_close.go" and fn.startswith("func (s *Server) expireHolds(")
        if not ok:
            faults.append(f"{p}: {m.group(1)} is called in {fn.split('(s *Server) ')[-1].split('{')[0].strip()}, which is none of the three ways a hold is closed")
if calls == 0:
    nothing("no DecideApproval or ExpireApprovals call was found outside internal/store")

# 3. The withdraw route.
if 'mux.HandleFunc("POST /v1/approvals/{id}/withdraw", s.requireAuth(s.handleApprovalWithdraw))' not in src["api"]:
    faults.append("the withdraw route is not registered as POST /v1/approvals/{id}/withdraw behind requireAuth")
admin = withdraw.find("if principal.isAdmin() {")
decode = withdraw.find("decodeJSONBody(")
if admin < 0 or (decode >= 0 and admin > decode):
    faults.append("handleApprovalWithdraw does not refuse an admin key before it reads the body")
if "s.allow.speaksFor(principal, dto.AgentID)" not in withdraw:
    faults.append("handleApprovalWithdraw does not bind the agent to the key")
for want, what in [("org != principal.Org", "org"), ("existing.AgentID != dto.AgentID", "agent"), ("existing.RunID != dto.RunID", "run")]:
    if want not in withdraw:
        faults.append(f"handleApprovalWithdraw does not compare the hold's {what} with the caller's ({want})")

# 4. The stores close only pending rows, with their previews.
if pg_expire.count("decision IS NULL") < 2:
    faults.append("Postgres.ExpireApprovals does not require decision IS NULL both in the rows it locks and in its UPDATE")
if "DELETE FROM approval_previews" not in pg_expire:
    faults.append("Postgres.ExpireApprovals does not delete the expired holds' previews in the same statement")
if "!a.Pending()" not in mem_expire:
    faults.append("Memory.ExpireApprovals does not skip a hold that is no longer pending")
if "delete(m.previews, id)" not in mem_expire:
    faults.append("Memory.ExpireApprovals does not delete the expired holds' previews")

if faults:
    print("FAIL: a hold can be closed some other way than the three invariant 52 names:")
    for f in faults:
        print(f"  - {f}")
    sys.exit(1)
print(f"OK: {calls} closing call(s) outside the store, each one of the three ways a hold is closed; "
      "the decide route takes only grant and deny; the withdraw route refuses an admin key and checks agent, run and org; "
      "both stores close only pending holds, with their previews.")
PY
