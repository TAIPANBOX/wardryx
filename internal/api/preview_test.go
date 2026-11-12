package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/wardryx/internal/approval"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/preview"
	"github.com/TAIPANBOX/wardryx/internal/previewseal"
	"github.com/TAIPANBOX/wardryx/internal/store"
)

// What a person deciding a held tool call is shown of its arguments, through
// the real handler (CLAUDE.md invariant 51).

const (
	pepKey       = "pep-key-for-previews"
	otherAdmin   = "other-org-admin-key"
	previewAgent = floorAgentID
)

// previewHarness is a server with a floor, a console preview key, a console
// approver key, and three bearer keys: acme's admin, acme's enforcement point,
// and another org's admin.
type previewHarness struct {
	srv     *Server
	mem     *store.Memory
	events  string
	priv    hpke.PrivateKey
	console *ecdsa.PrivateKey
}

func newPreviewHarness(t *testing.T, withRecipient bool, pols ...policy.Policy) *previewHarness {
	t.Helper()
	if len(pols) == 0 {
		pols = []policy.Policy{floorPol()}
	}
	set, err := policy.Compile(pols)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "events.ndjson")
	ew, err := event.NewChainedWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]Principal{
		keyDigest(adminKey):   {Org: "acme", Role: RoleAdmin, KeyFP: "fp-admin", Agents: "agent://acme.example/*"},
		keyDigest(pepKey):     {Org: "acme", Role: RolePEP, KeyFP: "fp-pep"},
		keyDigest(otherAdmin): {Org: "other", Role: RoleAdmin, KeyFP: "fp-other"},
	}
	mem := store.NewMemory()
	srv := New(pdp.New(set, []byte(testHMAC)), mem, ew, nil, keys, []byte(testHMAC), true, set.Policies())
	h := &previewHarness{srv: srv, mem: mem, events: path}
	if withRecipient {
		privText, recText, err := previewseal.GenerateKey(previewseal.KEMHybrid)
		if err != nil {
			t.Fatal(err)
		}
		r, err := previewseal.ParseRecipient(recText)
		if err != nil {
			t.Fatal(err)
		}
		if h.priv, err = previewseal.ParsePrivateKey(privText); err != nil {
			t.Fatal(err)
		}
		srv.WithPreview(r, DefaultPreviewTTL)
	}
	h.console = newConsoleKey(t)
	srv.WithApprovers(consoleVerifier(t, h.console))
	return h
}

// hold sends the broker's body for a call with these argument bytes and
// returns the approval id.
func (h *previewHarness) hold(t *testing.T, tool, args string) string {
	t.Helper()
	rec := doRaw(t, h.srv.Handler(), http.MethodPost, "/v1/decide", adminKey, brokerCall(previewAgent, "mcp:run", tool, args, ""))
	if rec.Code != http.StatusOK {
		t.Fatalf("decide %d: %s", rec.Code, rec.Body.String())
	}
	got := decodeBody[decideResponseDTO](t, rec)
	if got.Decision != pdp.Hold || got.ApprovalID == "" {
		t.Fatalf("not held: %+v", got)
	}
	return got.ApprovalID
}

func (h *previewHarness) approval(t *testing.T, id string) store.Approval {
	t.Helper()
	a, err := h.mem.GetApproval(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (h *previewHarness) fetch(t *testing.T, key, id string) (int, approvalPreviewDTO, http.Header) {
	t.Helper()
	rec := doRaw(t, h.srv.Handler(), http.MethodGet, "/v1/approvals/"+id+"/preview", key, "")
	var dto approvalPreviewDTO
	if rec.Code == http.StatusOK {
		dto = decodeBody[approvalPreviewDTO](t, rec)
	}
	return rec.Code, dto, rec.Header()
}

// open fetches and opens a hold's preview as the console does.
func (h *previewHarness) open(t *testing.T, id string) []byte {
	t.Helper()
	code, dto, _ := h.fetch(t, adminKey, id)
	if code != http.StatusOK || dto.State != PreviewSealed {
		t.Fatalf("preview of %s: %d %+v", id, code, dto)
	}
	sealed, err := base64.StdEncoding.DecodeString(dto.Sealed)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := previewseal.Open(h.priv, previewseal.Binding{Org: "acme", ToolCallDigest: dto.ToolCallDigest, PreviewDigest: dto.Digest, Ruleset: dto.Ruleset}, sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return doc
}

func (h *previewHarness) decide(t *testing.T, id string, dto approvalDecideRequestDTO) (int, string) {
	t.Helper()
	body, _ := json.Marshal(dto)
	rec := doRaw(t, h.srv.Handler(), http.MethodPost, "/v1/approvals/"+id+"/decide", adminKey, string(body))
	return rec.Code, rec.Body.String()
}

func (h *previewHarness) lastDecisionEvent(t *testing.T, id string) map[string]any {
	t.Helper()
	var out map[string]any
	for _, ev := range readEventsFile(t, h.events) {
		if (ev.Type == evApprovalGranted || ev.Type == evApprovalDenied) && ev.Data["approval_id"] == id {
			out = ev.Data
		}
	}
	if out == nil {
		t.Fatalf("no decision event for %s", id)
	}
	return out
}

// statementV2 signs a version 2 statement naming the call and the preview.
func statementV2(t *testing.T, k *ecdsa.PrivateKey, aid, dec, tcd, pvd string) string {
	t.Helper()
	enc := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	tp, err := delegation.Thumbprint(delegation.FromPublic(&k.PublicKey, ""))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	hdr, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "approver-statement+jwt", "kid": tp})
	c, _ := json.Marshal(map[string]any{
		"v": 2, "sub": "person-7", "cred": "Y3JlZC03", "aid": aid, "dec": dec, "tcd": tcd, "pvd": pvd,
		"iat": now.Unix(), "exp": now.Add(60 * time.Second).Unix(), "jti": "stmt2-" + aid + dec,
	})
	input := enc(hdr) + "." + enc(c)
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

func recordedPreview(a store.Approval) previewRecord { return previewOf(a.Context) }

func TestAHeldCallKeepsASealedPreviewThatOnlyTheConsoleKeyOpens(t *testing.T) {
	h := newPreviewHarness(t, true)
	args := `{"url":"https://example.org/report","api_key":"k-secret-1","note":"mail ann@example.com"}`
	id := h.hold(t, "fetch_url", args)
	a := h.approval(t, id)
	rec := recordedPreview(a)
	if rec.state != PreviewSealed || !preview.ValidDigest(rec.digest) || rec.ruleset != preview.Ruleset {
		t.Fatalf("hold records %+v", rec)
	}
	code, dto, hdr := h.fetch(t, adminKey, id)
	if code != http.StatusOK || hdr.Get("Cache-Control") != "no-store" {
		t.Fatalf("fetch %d, cache-control %q", code, hdr.Get("Cache-Control"))
	}
	if dto.Digest != rec.digest || dto.ToolCallDigest != toolCallDigestOf(a.Context) || dto.Suite == "" || dto.ExpiresAt == "" {
		t.Fatalf("dto %+v", dto)
	}
	doc := string(h.open(t, id))
	if !strings.Contains(doc, "https://example.org/report") {
		t.Errorf("the person is not shown the url: %s", doc)
	}
	for _, leaked := range []string{"k-secret-1", "ann@example.com"} {
		if strings.Contains(doc, leaked) {
			t.Errorf("the preview shows %s", leaked)
		}
	}
	// The ciphertext the admin key reads carries none of the arguments.
	sealed, _ := base64.StdEncoding.DecodeString(dto.Sealed)
	if strings.Contains(string(sealed), "example.org") {
		t.Errorf("the sealed preview is readable without the console key")
	}
}

func TestThePreviewIsBuiltFromTheBytesTheGrantIsBoundTo(t *testing.T) {
	h := newPreviewHarness(t, true)
	args := `{"b":"second written first","a":"first written second"}`
	id := h.hold(t, "write_file", args)
	a := h.approval(t, id)
	_, canon, err := preview.Build([]byte(args))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := recordedPreview(a).digest, preview.Digest(canon); got != want {
		t.Fatalf("pvd %s, want the digest of the preview of the bytes as sent %s", got, want)
	}
	if got, want := toolCallDigestOf(a.Context), approval.ToolCallDigest("write_file", "mcp-upstream", []byte(args), false); got != want {
		t.Fatalf("tool call digest %s, want %s", got, want)
	}
	doc := string(h.open(t, id))
	if strings.Index(doc, "second written first") > strings.Index(doc, "first written second") {
		t.Errorf("members are not in the order the bytes hold them: %s", doc)
	}
}

func TestNothingOfTheArgumentsReachesTheRecordTheContextOrTheList(t *testing.T) {
	h := newPreviewHarness(t, true)
	const marker = "plain-visible-marker-9431"
	id := h.hold(t, "fetch_url", `{"q":"`+marker+`"}`)
	raw, _ := os.ReadFile(h.events)
	if strings.Contains(string(raw), marker) {
		t.Errorf("the event record carries the arguments")
	}
	ctxJSON, _ := json.Marshal(h.approval(t, id).Context)
	if strings.Contains(string(ctxJSON), marker) {
		t.Errorf("the hold's context carries the arguments")
	}
	list := doRaw(t, h.srv.Handler(), http.MethodGet, "/v1/approvals", adminKey, "")
	if strings.Contains(list.Body.String(), marker) {
		t.Errorf("the approvals list carries the arguments")
	}
	// The record carries the preview's state and digest.
	var found bool
	for _, ev := range readEventsFile(t, h.events) {
		if ev.Type == evApprovalRequested {
			p, _ := ev.Data[ContextKeyPreview].(map[string]any)
			found = p["state"] == PreviewSealed && p["pvd"] == recordedPreview(h.approval(t, id)).digest
		}
	}
	if !found {
		t.Errorf("approval_requested does not carry the preview's state and digest")
	}
}

func TestAPersonWhoSawThePreviewGrantsAndTheRecordSaysSeen(t *testing.T) {
	h := newPreviewHarness(t, true)
	id := h.hold(t, "fetch_url", `{"url":"https://example.org"}`)
	a := h.approval(t, id)
	stmt := statementV2(t, h.console, id, "grant", toolCallDigestOf(a.Context), recordedPreview(a).digest)
	if code, body := h.decide(t, id, approvalDecideRequestDTO{Decision: "grant", ApproverStatement: stmt}); code != http.StatusOK {
		t.Fatalf("grant %d: %s", code, body)
	}
	ev := h.lastDecisionEvent(t, id)
	if ev[ContextKeyPreview] != PreviewSeen || ev["preview_digest"] != recordedPreview(a).digest ||
		ev["tool_call_digest"] != toolCallDigestOf(a.Context) || ev["preview_state"] != PreviewSealed {
		t.Fatalf("event %v", ev)
	}
	// Decided: the preview is gone.
	if code, _, _ := h.fetch(t, adminKey, id); code != http.StatusGone {
		t.Errorf("the preview of a decided hold answers %d, want 410", code)
	}
	if _, err := h.mem.GetPreview(context.Background(), id); err == nil {
		t.Errorf("the store still keeps the preview of a decided hold")
	}
}

func TestAStatementForAnotherPreviewOrCallIsRefusedAndNothingIsDecided(t *testing.T) {
	h := newPreviewHarness(t, true)
	id := h.hold(t, "fetch_url", `{"url":"https://example.org"}`)
	a := h.approval(t, id)
	tcd, pvd := toolCallDigestOf(a.Context), recordedPreview(a).digest
	other := strings.Repeat("c", 64)
	for name, stmt := range map[string]string{
		"another preview":          statementV2(t, h.console, id, "grant", tcd, other),
		"another call":             statementV2(t, h.console, id, "grant", other, pvd),
		"none while one was shown": statementV2(t, h.console, id, "grant", tcd, "none"),
		"a version 1 statement":    mintApproverStatement(t, h.console, id, "grant", "person-7", time.Now()),
	} {
		code, body := h.decide(t, id, approvalDecideRequestDTO{Decision: "grant", ApproverStatement: stmt})
		if code != http.StatusForbidden || !strings.Contains(body, refusalStatementMismatch) {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	if !h.approval(t, id).Pending() {
		t.Fatal("a refused decision decided the hold")
	}
	if code, _, _ := h.fetch(t, adminKey, id); code != http.StatusOK {
		t.Errorf("a refused decision took the preview away: %d", code)
	}
}

func TestADecisionWithoutAPreviewIsAllowedAndMarkedUnseen(t *testing.T) {
	// No preview key: the hold records off, and a person decides blind.
	h := newPreviewHarness(t, false)
	id := h.hold(t, "fetch_url", `{"url":"https://example.org"}`)
	a := h.approval(t, id)
	if recordedPreview(a).state != PreviewOff {
		t.Fatalf("state %q, want off", recordedPreview(a).state)
	}
	if code, _, _ := h.fetch(t, adminKey, id); code != http.StatusOK {
		t.Fatalf("a hold with no preview answers %d, want its state", code)
	}
	stmt := statementV2(t, h.console, id, "grant", toolCallDigestOf(a.Context), "none")
	if code, body := h.decide(t, id, approvalDecideRequestDTO{Decision: "grant", ApproverStatement: stmt}); code != http.StatusOK {
		t.Fatalf("blind grant %d: %s", code, body)
	}
	ev := h.lastDecisionEvent(t, id)
	if ev[ContextKeyPreview] != PreviewUnseen || ev["preview_state"] != PreviewOff || ev["preview_digest"] != "none" {
		t.Fatalf("event %v", ev)
	}
	// A version 1 statement on a hold with no preview is the decision it
	// always was, marked unseen.
	id2 := h.hold(t, "fetch_url", `{"url":"https://example.org/2"}`)
	if code, body := h.decide(t, id2, approvalDecideRequestDTO{Decision: "deny", ApproverStatement: mintApproverStatement(t, h.console, id2, "deny", "p", time.Now())}); code != http.StatusOK {
		t.Fatalf("v1 deny %d: %s", code, body)
	}
	if h.lastDecisionEvent(t, id2)[ContextKeyPreview] != PreviewUnseen {
		t.Errorf("a v1 decision is not marked unseen")
	}
}

func TestTruncatedArgumentsRecordNoPreview(t *testing.T) {
	h := newPreviewHarness(t, true)
	body := strings.Replace(brokerCall(previewAgent, "mcp:run", "fetch_url", "null", ""), `"arguments":null,`, `"arguments_truncated":true,`, 1)
	rec := doRaw(t, h.srv.Handler(), http.MethodPost, "/v1/decide", adminKey, body)
	got := decodeBody[decideResponseDTO](t, rec)
	if got.Decision != pdp.Hold {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if st := recordedPreview(h.approval(t, got.ApprovalID)).state; st != PreviewTruncated {
		t.Fatalf("state %q, want truncated", st)
	}
}

func TestRequirePreviewRefusesAGrantNobodySawAndAllowsADeny(t *testing.T) {
	pol := floorPol()
	pol.RequirePreview = true
	h := newPreviewHarness(t, true, pol)

	// Sealed and seen: granted.
	id := h.hold(t, "fetch_url", `{"url":"https://example.org"}`)
	a := h.approval(t, id)
	if a.Context[ContextKeyRequirePreview] != true {
		t.Fatalf("the hold does not record require_preview: %v", a.Context)
	}
	stmt := statementV2(t, h.console, id, "grant", toolCallDigestOf(a.Context), recordedPreview(a).digest)
	if code, body := h.decide(t, id, approvalDecideRequestDTO{Decision: "grant", ApproverStatement: stmt}); code != http.StatusOK {
		t.Fatalf("seen grant %d: %s", code, body)
	}

	// Truncated: nothing to show, so a grant is refused and a deny is not.
	body := strings.Replace(brokerCall(previewAgent, "mcp:run", "exec", "null", ""), `"arguments":null,`, `"arguments_truncated":true,`, 1)
	got := decodeBody[decideResponseDTO](t, doRaw(t, h.srv.Handler(), http.MethodPost, "/v1/decide", adminKey, body))
	tid := got.ApprovalID
	ta := h.approval(t, tid)
	blind := statementV2(t, h.console, tid, "grant", toolCallDigestOf(ta.Context), "none")
	if code, body := h.decide(t, tid, approvalDecideRequestDTO{Decision: "grant", ApproverStatement: blind}); code != http.StatusForbidden || !strings.Contains(body, refusalPreviewRequired) {
		t.Fatalf("blind grant under require_preview: %d %s", code, body)
	}
	if !h.approval(t, tid).Pending() {
		t.Fatal("the refused grant decided the hold")
	}
	deny := statementV2(t, h.console, tid, "deny", toolCallDigestOf(ta.Context), "none")
	if code, body := h.decide(t, tid, approvalDecideRequestDTO{Decision: "deny", ApproverStatement: deny}); code != http.StatusOK {
		t.Fatalf("deny under require_preview: %d %s", code, body)
	}

	// A key decides with no statement: nobody was shown anything.
	h.srv.WithAllowKeyApprovals(true)
	kid := h.hold(t, "fetch_url", `{"url":"https://example.org/key"}`)
	if code, body := h.decide(t, kid, approvalDecideRequestDTO{Decision: "grant"}); code != http.StatusForbidden || !strings.Contains(body, refusalPreviewRequired) {
		t.Fatalf("key grant under require_preview: %d %s", code, body)
	}
}

func TestAPreviewPastItsTimeIsNotServedAndIsPurged(t *testing.T) {
	h := newPreviewHarness(t, true)
	id := h.hold(t, "fetch_url", `{"url":"https://example.org"}`)
	h.mem.SetClock(func() time.Time { return time.Now().Add(DefaultPreviewTTL + time.Minute) })
	if code, _, _ := h.fetch(t, adminKey, id); code != http.StatusGone {
		t.Fatalf("an expired preview answers %d, want 410", code)
	}
	n, err := h.mem.PurgePreviews(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("purge removed %d (%v), want 1", n, err)
	}
	// The hold stays: only the preview is gone.
	if !h.approval(t, id).Pending() {
		t.Fatal("the purge decided the hold")
	}
}

func TestAPreviewIsReadOnlyByAnAdminOfTheHoldsOrg(t *testing.T) {
	h := newPreviewHarness(t, true)
	id := h.hold(t, "fetch_url", `{"url":"https://example.org"}`)
	if code, _, _ := h.fetch(t, otherAdmin, id); code != http.StatusNotFound {
		t.Errorf("another org's admin: %d, want 404", code)
	}
	if code, _, _ := h.fetch(t, pepKey, id); code != http.StatusForbidden {
		t.Errorf("the enforcement point's key: %d, want 403", code)
	}
	if code, _, _ := h.fetch(t, "", id); code != http.StatusUnauthorized {
		t.Errorf("no key: %d, want 401", code)
	}
}

func TestARepeatedHeldCallKeepsOnePreview(t *testing.T) {
	h := newPreviewHarness(t, true)
	first := h.hold(t, "fetch_url", `{"url":"https://example.org"}`)
	second := h.hold(t, "fetch_url", `{"url":"https://example.org"}`)
	if first != second {
		t.Fatalf("a repeated call made a second hold")
	}
	if code, _, _ := h.fetch(t, adminKey, first); code != http.StatusOK {
		t.Fatalf("fetch %d", code)
	}
}

func TestRequirePreviewCannotBeWrittenThroughThePolicyAPI(t *testing.T) {
	h := newPreviewHarness(t, true)
	rec := doRaw(t, h.srv.Handler(), http.MethodPut, "/v1/policies/p1", adminKey, `{"target":"agent://acme.example/*","require_preview":true}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "require_preview") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
}

func TestPreviewTTLIsBounded(t *testing.T) {
	if d, err := ParsePreviewTTL(""); err != nil || d != DefaultPreviewTTL {
		t.Errorf("unset: %v %v", d, err)
	}
	if d, err := ParsePreviewTTL("2h"); err != nil || d != 2*time.Hour {
		t.Errorf("2h: %v %v", d, err)
	}
	for _, bad := range []string{"0", "30s", "8d", "169h", "soon", "-1h"} {
		if _, err := ParsePreviewTTL(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestACallWithNoArgumentsHasNothingToShowAndAPersonMayGrantItUnderRequirePreview(t *testing.T) {
	pol := floorPol()
	pol.RequirePreview = true
	h := newPreviewHarness(t, true, pol)
	body := strings.Replace(brokerCall(previewAgent, "mcp:run", "list_files", "null", ""), `"arguments":null,`, ``, 1)
	got := decodeBody[decideResponseDTO](t, doRaw(t, h.srv.Handler(), http.MethodPost, "/v1/decide", adminKey, body))
	if got.Decision != pdp.Hold {
		t.Fatalf("%+v", got)
	}
	a := h.approval(t, got.ApprovalID)
	if st := recordedPreview(a).state; st != PreviewNoArguments {
		t.Fatalf("state %q, want no_arguments", st)
	}
	stmt := statementV2(t, h.console, got.ApprovalID, "grant", toolCallDigestOf(a.Context), "none")
	if code, body := h.decide(t, got.ApprovalID, approvalDecideRequestDTO{Decision: "grant", ApproverStatement: stmt}); code != http.StatusOK {
		t.Fatalf("grant of a call with nothing to show: %d %s", code, body)
	}
}

func TestAHoldWithNoCallRecordsNoPreviewAndIsDecidedAsBefore(t *testing.T) {
	h := newPreviewHarness(t, true, policy.Policy{Name: "pricey", Target: "agent://*", RequireHumanAboveUSD: usd(0)})
	rec := doRaw(t, h.srv.Handler(), http.MethodPost, "/v1/decide", adminKey, `{"agent_id":"`+previewAgent+`","run_id":"r","tool_names":["a"],"est_cost_usd":1}`)
	got := decodeBody[decideResponseDTO](t, rec)
	if got.Decision != pdp.Hold {
		t.Fatalf("%+v", got)
	}
	if _, has := h.approval(t, got.ApprovalID).Context[ContextKeyPreview]; has {
		t.Fatalf("a hold with no call records a preview")
	}
	if code, _, _ := h.fetch(t, adminKey, got.ApprovalID); code != http.StatusNotFound {
		t.Errorf("preview of a hold with no call: %d, want 404", code)
	}
	stmt := statementV2(t, h.console, got.ApprovalID, "grant", "none", "none")
	if code, body := h.decide(t, got.ApprovalID, approvalDecideRequestDTO{Decision: "grant", ApproverStatement: stmt}); code != http.StatusOK {
		t.Fatalf("grant %d %s", code, body)
	}
	if ev := h.lastDecisionEvent(t, got.ApprovalID); ev[ContextKeyPreview] != PreviewNoCall {
		t.Errorf("event preview %v, want no_call", ev[ContextKeyPreview])
	}
}

func TestWatchPreviewsPurgesUntilItsContextEnds(t *testing.T) {
	h := newPreviewHarness(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.srv.WatchPreviews(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("WatchPreviews did not stop with its context")
	}
}

func TestAPersonMayDenyASealedHoldWithoutOpeningItAndTheRecordSaysUnseen(t *testing.T) {
	h := newPreviewHarness(t, true)
	id := h.hold(t, "fetch_url", `{"url":"https://example.org"}`)
	a := h.approval(t, id)
	// A grant without the preview is refused: the preview exists.
	blindGrant := statementV2(t, h.console, id, "grant", toolCallDigestOf(a.Context), "none")
	if code, body := h.decide(t, id, approvalDecideRequestDTO{Decision: "grant", ApproverStatement: blindGrant}); code != http.StatusForbidden || !strings.Contains(body, refusalStatementMismatch) {
		t.Fatalf("a grant of a sealed hold without its preview: %d %s", code, body)
	}
	deny := statementV2(t, h.console, id, "deny", toolCallDigestOf(a.Context), "none")
	if code, body := h.decide(t, id, approvalDecideRequestDTO{Decision: "deny", ApproverStatement: deny}); code != http.StatusOK {
		t.Fatalf("a deny without opening the preview: %d %s", code, body)
	}
	ev := h.lastDecisionEvent(t, id)
	if ev[ContextKeyPreview] != PreviewUnseen || ev["preview_state"] != PreviewSealed || ev["preview_digest"] != "none" {
		t.Fatalf("event %v", ev)
	}
}
