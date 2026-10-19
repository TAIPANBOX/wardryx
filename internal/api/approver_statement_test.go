package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
	"github.com/TAIPANBOX/wardryx/internal/approverstmt"
)

// A person's grant or deny reaches wardryx with the statement the console signed
// after the passkey assertion (CLAUDE.md invariant 43). The approval records the
// person; without a statement it records the key, as before (invariant 37).

func newConsoleKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// consoleVerifier is the verifier wardryx holds for the console's public key.
func consoleVerifier(t *testing.T, k *ecdsa.PrivateKey) *approverstmt.Verifier {
	t.Helper()
	v, err := approverstmt.New([]delegation.JWK{delegation.FromPublic(&k.PublicKey, "")})
	if err != nil {
		t.Fatalf("approverstmt.New: %v", err)
	}
	return v
}

// mintApproverStatement signs a statement for approval aid and decision dec with
// the console key k, as the console does after the passkey assertion.
func mintApproverStatement(t *testing.T, k *ecdsa.PrivateKey, aid, dec, sub string, now time.Time) string {
	t.Helper()
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	kid := delegation.FromPublic(&k.PublicKey, "")
	tp, err := delegation.Thumbprint(kid)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "approver-statement+jwt", "kid": tp})
	c, _ := json.Marshal(map[string]any{
		"v": 1, "sub": sub, "cred": "Y3JlZC0x", "aid": aid, "dec": dec,
		"iat": now.Unix(), "exp": now.Add(60 * time.Second).Unix(), "jti": "stmt-" + aid,
	})
	input := enc(h) + "." + enc(c)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, k, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + enc(sig)
}

func TestAGrantWithAVerifiedStatementRecordsThePersonNotTheKey(t *testing.T) {
	console := newConsoleKey(t)
	h := newOrgHarness(t, "gw:acme:pep,"+approverKey+":acme:admin", false, supportFloor())
	h.srv.WithApprovers(consoleVerifier(t, console))
	id := h.holdFor(t, "gw", bot1)
	stmt := mintApproverStatement(t, console, id, "grant", "approver-1842", time.Now())
	if code := h.decideApproval(t, approverKey, id, approvalDecideRequestDTO{Decision: "grant", ApproverStatement: stmt}); code != http.StatusOK {
		t.Fatalf("grant with a verified statement: %d", code)
	}
	a := approvalByID(h.approvalsAs(t, approverKey), id)
	if a == nil || a["decided_by"] != "approver:approver-1842" || a["approver_kind"] != "person" {
		t.Fatalf("listed approval = %v, want decided_by approver:approver-1842 and approver_kind person", a)
	}
	granted := h.eventsOfType(t, "approval_granted")
	if len(granted) != 1 || granted[0]["approver_kind"] != "person" || granted[0]["approver_id"] != "approver-1842" ||
		granted[0]["credential_id"] != "Y3JlZC0x" || granted[0]["key_fp"] != fp(approverKey) {
		t.Fatalf("approval_granted = %v, want approver_kind person, the approver, the credential, and the key that sent it", granted)
	}
}

func TestAGrantWithoutAStatementIsRecordedAsAKey(t *testing.T) {
	h := newOrgHarness(t, "gw:acme:pep,"+approverKey+":acme:admin", false, supportFloor())
	id := h.holdFor(t, "gw", bot1)
	if code := h.decideApproval(t, approverKey, id, approvalDecideRequestDTO{Decision: "grant"}); code != http.StatusOK {
		t.Fatalf("grant with no statement: %d", code)
	}
	a := approvalByID(h.approvalsAs(t, approverKey), id)
	if a == nil || a["decided_by"] != "key:"+fp(approverKey) || a["approver_kind"] != "key" {
		t.Fatalf("listed approval = %v, want decided_by the key and approver_kind key", a)
	}
}

func TestAStatementThatDoesNotVerifyLeavesTheHoldPending(t *testing.T) {
	console, other := newConsoleKey(t), newConsoleKey(t)
	h := newOrgHarness(t, "gw:acme:pep,"+approverKey+":acme:admin", false, supportFloor())
	h.srv.WithApprovers(consoleVerifier(t, console))
	id := h.holdFor(t, "gw", bot1)
	forged := mintApproverStatement(t, other, id, "grant", "approver-1842", time.Now())
	rec := h.do(t, http.MethodPost, "/v1/approvals/"+id+"/decide", approverKey,
		approvalDecideRequestDTO{Decision: "grant", ApproverStatement: forged})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "approver_statement_invalid") {
		t.Fatalf("a statement the console did not sign: %d %s, want 403 approver_statement_invalid", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), forged) {
		t.Fatal("the refusal echoed the statement")
	}
	if granted := h.eventsOfType(t, "approval_granted"); len(granted) != 0 {
		t.Fatalf("a refused statement granted the approval: %v", granted)
	}
	if a := approvalByID(h.approvalsAs(t, approverKey), id); a == nil || a["decided_by"] != nil {
		t.Fatalf("the hold is no longer pending after a refused statement: %v", a)
	}
}

func TestAStatementForAnotherApprovalIsRefused(t *testing.T) {
	console := newConsoleKey(t)
	h := newOrgHarness(t, "gw:acme:pep,"+approverKey+":acme:admin", false, supportFloor())
	h.srv.WithApprovers(consoleVerifier(t, console))
	id := h.holdFor(t, "gw", bot1)
	stmt := mintApproverStatement(t, console, "approval-some-other", "grant", "approver-1842", time.Now())
	if code := h.decideApproval(t, approverKey, id, approvalDecideRequestDTO{Decision: "grant", ApproverStatement: stmt}); code != http.StatusForbidden {
		t.Fatalf("a statement for another approval: %d, want 403", code)
	}
}

func TestAStatementWithNoApproverKeySetIsRefused(t *testing.T) {
	console := newConsoleKey(t)
	h := newOrgHarness(t, "gw:acme:pep,"+approverKey+":acme:admin", false, supportFloor())
	id := h.holdFor(t, "gw", bot1)
	stmt := mintApproverStatement(t, console, id, "grant", "approver-1842", time.Now())
	rec := h.do(t, http.MethodPost, "/v1/approvals/"+id+"/decide", approverKey,
		approvalDecideRequestDTO{Decision: "grant", ApproverStatement: stmt})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "approver_statement_invalid") {
		t.Fatalf("a statement on a server with no approver key set: %d %s, want 403", rec.Code, rec.Body)
	}
}
