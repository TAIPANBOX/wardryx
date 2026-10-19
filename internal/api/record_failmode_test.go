package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// F-011: a decision was returned when its record could not be written. These
// tests hold invariant 40: under the closed record fail mode (the default) an
// allow or a hold whose record was not written is refused, and under the open
// mode it is returned and the failure is visible on /readyz.

// refusingSink is a record writer that refuses every write, the way a full
// volume or an unwritable stream does.
type refusingSink struct{ writes int }

func (r *refusingSink) Write(event.Event) error {
	r.writes++
	return errors.New("write wardryx.ndjson: no space left on device")
}

// okSink accepts every write. What it keeps is not what these tests read.
type okSink struct{}

func (okSink) Write(event.Event) error { return nil }

// recordPolicy allows a call, holds one that costs more than 100 USD, and
// denies shell_exec, so one harness reaches each of the three outcomes.
func recordPolicy() policy.Policy {
	return policy.Policy{
		Name:                 "record-floor",
		Target:               "agent://acme.example/*",
		DenyTool:             []string{"shell_exec"},
		RequireHumanAboveUSD: usd(100),
	}
}

// newRecordHarness returns a server whose record writer refuses every write.
func newRecordHarness(t *testing.T) *orgHarness {
	t.Helper()
	h := newOrgHarness(t, "gw:acme:pep,adm:acme:admin", false, recordPolicy())
	h.srv.records = &refusingSink{}
	return h
}

// assertRecordRefused holds the closed-mode answer: 503 with the one reason
// wardryx writes, and nothing that says what the write hit (invariant 10).
func assertRecordRefused(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("%s whose record could not be written: %d %s, want 503", what, rec.Code, rec.Body.String())
	}
	if got := decodeBody[errorDTO](t, rec).Error; got != "record_unavailable" {
		t.Fatalf("%s refused with %q, want record_unavailable", what, got)
	}
}

func TestAnAllowIsRefusedWhenItsRecordCannotBeWritten(t *testing.T) {
	h := newRecordHarness(t)
	rec := h.decide(t, "gw", decideRequestDTO{AgentID: bot1, RunID: "r1", EstCostUSD: 1})
	assertRecordRefused(t, rec, "an allow")
}

func TestAHoldIsRefusedWhenItsRecordCannotBeWritten(t *testing.T) {
	h := newRecordHarness(t)
	rec := h.decide(t, "gw", decideRequestDTO{AgentID: bot1, RunID: "r1", EstCostUSD: 500})
	assertRecordRefused(t, rec, "a hold")
}

func TestADenyIsStillReturnedWhenItsRecordCannotBeWritten(t *testing.T) {
	h := newRecordHarness(t)
	rec := h.decide(t, "gw", decideRequestDTO{AgentID: bot1, RunID: "r1", ToolNames: []string{"shell_exec"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("a deny with an unwritable record: %d %s, want 200", rec.Code, rec.Body.String())
	}
	if got := decodeBody[decideResponseDTO](t, rec).Decision; got != pdp.Deny {
		t.Fatalf("a deny with an unwritable record came back as %s, want deny", got)
	}
}

func TestTheAllowRecordIsAttemptedBeforeItIsReturned(t *testing.T) {
	h := newRecordHarness(t)
	sink := &refusingSink{}
	h.srv.records = sink
	h.decide(t, "gw", decideRequestDTO{AgentID: bot1, RunID: "r1", EstCostUSD: 1})
	if sink.writes != 1 {
		t.Fatalf("one allow made %d record writes, want 1", sink.writes)
	}
}

func TestOpenModeReturnsTheAllowAndRaisesTheHealthFlag(t *testing.T) {
	h := newRecordHarness(t)
	h.srv.SetRecordFailOpen(true)
	rec := h.decide(t, "gw", decideRequestDTO{AgentID: bot1, RunID: "r1", EstCostUSD: 1})
	if rec.Code != http.StatusOK || decodeBody[decideResponseDTO](t, rec).Decision != pdp.Allow {
		t.Fatalf("open mode with an unwritable record: %d %s, want the allow", rec.Code, rec.Body.String())
	}
	ready := h.do(t, http.MethodGet, "/readyz", "", nil)
	if ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz with a failing record: %d %s, want 503", ready.Code, ready.Body.String())
	}
	if got := decodeBody[map[string]string](t, ready)["record"]; got != "failing" {
		t.Fatalf("/readyz names the record as %q, want failing", got)
	}
}

func TestReadyzClearsWhenARecordWriteSucceedsAgain(t *testing.T) {
	h := newRecordHarness(t)
	if rec := h.decide(t, "gw", decideRequestDTO{AgentID: bot1, RunID: "r1", EstCostUSD: 1}); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed mode with an unwritable record: %d, want 503", rec.Code)
	}
	if ready := h.do(t, http.MethodGet, "/readyz", "", nil); ready.Code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz after a refused record: %d, want 503", ready.Code)
	}
	h.srv.records = okSink{}
	if rec := h.decide(t, "gw", decideRequestDTO{AgentID: bot1, RunID: "r1", EstCostUSD: 1}); rec.Code != http.StatusOK {
		t.Fatalf("an allow once the record writes again: %d %s, want 200", rec.Code, rec.Body.String())
	}
	if ready := h.do(t, http.MethodGet, "/readyz", "", nil); ready.Code != http.StatusOK {
		t.Fatalf("/readyz after a successful record write: %d %s, want 200", ready.Code, ready.Body.String())
	}
}

func TestWithNoRecordWriterNothingIsRefused(t *testing.T) {
	// WARDRYX_EVENTS_PATH unset: no record is configured, so no record write
	// can fail, and closed mode refuses nothing. This is not a failed write.
	h := newRecordHarness(t)
	h.srv.records = nil
	rec := h.decide(t, "gw", decideRequestDTO{AgentID: bot1, RunID: "r1", EstCostUSD: 1})
	if rec.Code != http.StatusOK {
		t.Fatalf("an allow with no record configured: %d %s, want 200", rec.Code, rec.Body.String())
	}
}
