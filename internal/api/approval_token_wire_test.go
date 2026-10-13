package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/pdp"
)

// An approval token reaches /v1/decide in one place: the approval_token field
// of the JSON body. No header carries it. TokenFuse, the enforcement point,
// takes the token from an agent's x-fuse-approval-token header and forwards
// its value in that field, so the header is the gateway's name and never this
// service's. The README's decision table said otherwise until 2026-10-13.
// This test holds the code side of what the README now says;
// TestReadmeNamesNoHeaderWardryxDoesNotRead in cmd/wardryx holds the prose.
func TestAnApprovalTokenSentAsAHeaderIsNotRead(t *testing.T) {
	// Single-use, the default: a header that was read and redeemed would
	// also show up as a spent token on the body presentation at the end.
	srv := newTestServerSingleUse(t)
	h := srv.Handler()
	call := decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "run-1", ToolNames: []string{"generate_report"}, EstCostUSD: 999,
	}

	held := decodeBody[decideResponseDTO](t, doRequest(t, h, http.MethodPost, "/v1/decide", adminKey, call))
	if held.Decision != pdp.Hold {
		t.Fatalf("initial Decision = %q (%s), want hold", held.Decision, held.Reason)
	}
	grantRec := doRequest(t, h, http.MethodPost, "/v1/approvals/"+held.ApprovalID+"/decide", adminKey,
		approvalDecideRequestDTO{Decision: "grant", DecidedBy: "alice@acme.example"})
	granted := decodeBody[approvalDecideResponseDTO](t, grantRec)
	if granted.ApprovalToken == "" {
		t.Fatalf("grant did not return an approval_token: status %d, body %s", grantRec.Code, grantRec.Body.String())
	}

	// The gateway's header first, then two spellings a caller might guess.
	for _, header := range []string{"x-fuse-approval-token", "x-approval-token", "approval-token"} {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(call); err != nil {
			t.Fatalf("encode body: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/decide", &buf)
		req.Header.Set("Authorization", "Bearer "+adminKey)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(header, granted.ApprovalToken)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("token in header %q: status = %d, body = %s", header, rec.Code, rec.Body.String())
		}
		got := decodeBody[decideResponseDTO](t, rec)
		if got.Decision != pdp.Hold {
			t.Fatalf("token in header %q with an empty approval_token field: Decision = %q (%s), want hold: "+
				"/v1/decide reads the token from the approval_token body field and from no header", header, got.Decision, got.Reason)
		}
	}

	inBody := call
	inBody.ApprovalToken = granted.ApprovalToken
	got := decodeBody[decideResponseDTO](t, doRequest(t, h, http.MethodPost, "/v1/decide", adminKey, inBody))
	if got.Decision != pdp.Allow {
		t.Fatalf("the same token in the approval_token body field, after the header attempts: Decision = %q (%s), want allow: "+
			"a header attempt must neither be read nor spend the single-use token", got.Decision, got.Reason)
	}
}
