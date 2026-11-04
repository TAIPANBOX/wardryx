#!/usr/bin/env bash
# With a database, an accepted DPoP proof is one row every wardryx on it reads,
# and a proof the record cannot be asked about is refused (invariant 44).
#
# WHY THIS IS A GATE
#
# G3.10 of the estate's gap register: the record of accepted proofs lived in one
# process, so a restart forgot it and a second instance accepted the same proof.
# Every fault this reads for keeps the suite that runs against a healthy store
# green and answers 200 with a correct-looking decision, which is the shape a
# wrong answer takes here: serve not handing the database to the verifier leaves
# a working per-process record, and a failed record that passes a proof is
# visible only during an outage nobody is testing.
#
# WHAT IT READS
#
#   1. Postgres.TryRecordProof is one INSERT .. ON CONFLICT DO NOTHING, reads
#      nothing first, and reports a claim only for the row it inserted.
#   2. In recordProof, a record that failed returns ErrProofRecord and never nil,
#      and the shared branch returns before the in-process record is reached.
#   3. verifyProof ends with the record, so a proof refused for anything else
#      writes nothing.
#   4. identitySourceFor bounds the check by the store deadline, and on
#      ErrProofRecord it refuses and returns.
#   5. serve hands the database to the verifier, keeps it purged, and says at
#      start when there is no database.
#   6. CI runs the tests that stand on a real database, uncached: go test caches
#      a test by its own binary, and these start another one.
#
# WHAT IT CANNOT DO
#
# It reads source text, a function at a time, with comment lines skipped. A claim
# spelled another way, or a refusal made through a helper it does not know, is not
# seen. It proves the lines are there, not that they are right: the tests named in
# invariant 44 prove that. It refuses to report success when a function or a file
# it reads is gone.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

python3 - <<'PY'
import pathlib
import re
import sys

faults = []


def nothing(what):
    print(f"FAIL: {what}, so this measured nothing.")
    print("      The subject is gone or renamed; an absent subject is not a passing one.")
    sys.exit(2)


def text(path):
    p = pathlib.Path(path)
    if not p.is_file():
        nothing(f"{path} is not here")
    return p.read_text(encoding="utf-8")


def code(block):
    return "\n".join(l for l in block.splitlines() if not l.lstrip().startswith(("//", "--")))


def body(path, signature):
    src = text(path)
    start = src.find("\n" + signature)
    if start < 0:
        nothing(f"{signature} is not in {path}")
    end = src.find("\n}\n", start)
    return code(src[start : end + 3])


def block(src, opener):
    """The text of the brace block that opens on the line holding opener."""
    at = src.find(opener)
    if at < 0:
        return None
    depth, i = 0, src.index("{", at)
    while i < len(src):
        depth += {"{": 1, "}": -1}.get(src[i], 0)
        if depth == 0:
            return src[at : i + 1]
        i += 1
    return None


# 1. The claim is atomic.
claim = body("internal/store/pgstore.go", "func (p *Postgres) TryRecordProof(")
if "INSERT INTO agent_proof_replays" not in claim or "ON CONFLICT (proof_key) DO NOTHING" not in claim:
    faults.append("TryRecordProof is not an atomic INSERT .. ON CONFLICT DO NOTHING on agent_proof_replays")
if re.search(r"\bSELECT\b", claim):
    faults.append("TryRecordProof reads before it writes, so two instances can both see the key absent")
if "return n == 1, nil" not in claim:
    faults.append("TryRecordProof does not report a claim from the row it inserted")

# 2. A record that cannot be asked refuses, and the process does not stand in.
record = body("internal/agenttoken/verifier.go", "func (v *Verifier) recordProof(")
shared = block(record, "if v.cfg.ProofRecord != nil {")
if shared is None:
    nothing("recordProof has no shared branch")
if "TryRecordProof(ctx," not in shared:
    faults.append("recordProof does not ask the shared record under the context it was given")
failed = block(shared, "if err != nil {")
if failed is None or "ErrProofRecord" not in failed or "return nil" in failed:
    faults.append("recordProof does not refuse with ErrProofRecord when the shared record fails: a failed record passes the proof")
if not re.search(r"return nil\s*\}$", shared):
    faults.append("the shared branch of recordProof falls through, so the in-process record stands in for the shared one")
refused = block(shared, "if !claimed {")
if refused is None or "ErrProof" not in refused:
    faults.append("recordProof does not refuse a proof the shared record already holds")

# 3. The record comes last.
verify = body("internal/agenttoken/verifier.go", "func (v *Verifier) verifyProof(")
if not re.search(r"return v\.recordProof\(ctx, thumb, jti, int64\(iat\), now\)\s*\}\s*$", verify):
    faults.append("verifyProof does not end with the record: a proof refused for anything else would write to it")

# 4. The API bounds the call and refuses.
api = body("internal/api/agent_token.go", "func (s *Server) identitySourceFor(")
if not re.search(r"proofCtx, cancel := context\.WithTimeout\(context\.WithoutCancel\(ctx\), s\.storeTimeout\)", api) \
        or "CheckProof(proofCtx," not in api:
    faults.append("identitySourceFor does not bound the proof check by the store deadline of its own")
if not re.search(r"errors\.Is\(err, agenttoken\.ErrProofRecord\) \{\s*s\.writeProofUnrecorded\(w, err\)\s*return \"\", false", api):
    faults.append("identitySourceFor does not refuse on ErrProofRecord")

# 5. serve wires it.
main = code(text("cmd/wardryx/main.go"))
tokens = code(text("cmd/wardryx/agent_tokens.go"))
if "proofRecord = pg" not in main or "buildAgentTokens(cfg, proofRecord)" not in main:
    faults.append("serve does not hand the database to the verifier, so the record stays in the process")
if not re.search(r"ProofRecord:\s+record,", tokens):
    faults.append("buildAgentTokens does not give the verifier the record it was handed")
if "RunProofPurge(" not in tokens:
    faults.append("nothing purges the shared record")
if "proofRecordWarning(cfg.AgentTokenIssuer, *dbDSN)" not in main:
    faults.append("serve does not say at start that the record is per process with no database")

# 6. CI runs what stands on a database.
ci = text(".github/workflows/ci.yml")
run = next((l for l in ci.splitlines() if "-tags integration" in l and not l.lstrip().startswith("#")), None)
if run is None:
    nothing("the workflow runs no integration tests")
for part in ("-count=1", "./internal/store/", "./internal/agenttoken/", "./internal/manifest/"):
    if part not in run:
        faults.append(f"CI's integration step does not carry {part}, so the tests on a real database do not run as they must")

if faults:
    for f in faults:
        print(f"PROBLEM: {f}")
    print()
    print("A proof can be accepted twice, or accepted unchecked. See CLAUDE.md invariant 44.")
    sys.exit(1)

print("OK: the claim is atomic, a failed record refuses, serve wires the database, and CI runs it on a real one.")
PY
