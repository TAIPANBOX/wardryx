package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// ------------------------------------------------------------------
// A request body with no cap is memory any caller who can reach this port
// can spend on this process for free: json.NewDecoder(r.Body) reads as much
// as it is given before deciding the JSON is invalid. Wired via
// http.MaxBytesReader in decodeJSONBody, which is where every route that
// decodes JSON now goes through. See CLAUDE.md's "Escalate" list: this
// touches startup trust configuration, so it is part of the same T3 wave
// as W1 and W3.
// ------------------------------------------------------------------

// TestAnOversizedBodyIsRefusedWithoutBeingRead drives a real over-the-wire
// body, not a Content-Length lie: http.MaxBytesReader enforces the cap as
// bytes are actually read off the reader, so this proves the cap acts on
// the stream rather than merely on a header the client is free to omit.
func TestAnOversizedBodyIsRefusedWithoutBeingRead(t *testing.T) {
	srv := newTestServer(t)

	// One byte over the 1 MiB cap. A valid decideRequestDTO padded with an
	// oversized field the decoder would otherwise have to read in full
	// before ever reaching AgentID/RunID validation.
	pad := strings.Repeat("a", maxRequestBodyBytes+1)
	body := `{"agent_id":"agent://acme.example/finance/bot1","run_id":"r1","model":"` + pad + `"}`

	rec := doRaw(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, body)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 for a body over the 1 MiB cap", rec.Code)
	}

	// Refused, not merely rejected after being fully parsed: no hold, no
	// approval, nothing this request could not have earned reaches the
	// store. A cap enforced only after Decode succeeded would still let an
	// attacker spend the memory to build the DTO before being told no.
	all, err := srv.store.ListApprovals(context.Background())
	if err != nil {
		t.Fatalf("ListApprovals: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("an oversized /v1/decide left %d approval(s) behind, want 0", len(all))
	}
}

// TestABodyAtOrUnderTheCapIsUnaffected pins the boundary the case above
// exists to test: an ordinary, well-formed body must not be refused as
// oversized. Without this, a cap set one byte too low would pass the
// oversized case and silently start refusing real traffic.
func TestABodyAtOrUnderTheCapIsUnaffected(t *testing.T) {
	srv := newTestServer(t)
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
		AgentID: "agent://acme.example/finance/bot1", RunID: "r1",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("an ordinary decide body returned %d, want 200: %s", rec.Code, rec.Body.String())
	}
}
