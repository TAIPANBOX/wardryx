package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/wardryx/internal/archive"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/store"
)

// orgHarness is a Server built from a WARDRYX_KEYS spec exactly as serve
// builds it (ParseKeys), with events and a policy archive on disk, so the
// tests of the agent binding, the approver and the org of a policy read what
// an operator would read.
type orgHarness struct {
	srv    *Server
	st     store.Store
	events string
	ew     *event.ChainedWriter
	arch   *archive.Archive
}

// supportFloor denies shell_exec to the support agents and holds anything over
// $100: one deny rule and one hold to observe.
func supportFloor() policy.Policy {
	return policy.Policy{
		Name:                 "support-floor",
		Target:               "agent://*",
		DenyTool:             []string{"shell_exec"},
		RequireHumanAboveUSD: usd(100),
	}
}

func newOrgHarness(t *testing.T, keySpec string, singleUse bool, pols ...policy.Policy) *orgHarness {
	t.Helper()
	keys, _ := ParseKeys(keySpec, false)
	if len(keys) == 0 {
		t.Fatalf("setup: key spec %q parsed to no keys", keySpec)
	}
	return newOrgHarnessKeys(t, keys, singleUse, pols...)
}

func newOrgHarnessKeys(t *testing.T, keys map[string]Principal, singleUse bool, pols ...policy.Policy) *orgHarness {
	t.Helper()
	set, err := policy.Compile(pols)
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	path := filepath.Join(t.TempDir(), "events.ndjson")
	ew, err := event.NewChainedWriter(path)
	if err != nil {
		t.Fatalf("NewChainedWriter: %v", err)
	}
	st := store.NewMemory()
	srv := New(pdp.New(set, []byte(testHMAC)), st, ew, nil, keys, []byte(testHMAC), singleUse, set.Policies())
	a, err := archive.New(t.TempDir())
	if err != nil {
		t.Fatalf("archive.New: %v", err)
	}
	if err := srv.SetPolicyArchive(a); err != nil {
		t.Fatalf("SetPolicyArchive: %v", err)
	}
	return &orgHarness{srv: srv, st: st, events: path, ew: ew, arch: a}
}

func (h *orgHarness) do(t *testing.T, method, path, key string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return doRequest(t, h.srv.Handler(), method, path, key, body)
}

func (h *orgHarness) raw(t *testing.T, method, path, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	return doRaw(t, h.srv.Handler(), method, path, key, body)
}

func (h *orgHarness) decide(t *testing.T, key string, body decideRequestDTO) *httptest.ResponseRecorder {
	t.Helper()
	return h.do(t, http.MethodPost, "/v1/decide", key, body)
}

// eventsOfType returns the data of every event of one type, in file order.
// The writer is left open: an event written later is read by a later call.
func (h *orgHarness) eventsOfType(t *testing.T, typ string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, e := range h.allEvents(t) {
		if e.Type == typ {
			out = append(out, e.Data)
		}
	}
	return out
}

type loggedEvent struct {
	Type    string         `json:"type"`
	AgentID string         `json:"agent_id"`
	RunID   string         `json:"run_id"`
	Data    map[string]any `json:"data"`
}

func (h *orgHarness) allEvents(t *testing.T) []loggedEvent {
	t.Helper()
	raw, err := os.ReadFile(h.events)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	var out []loggedEvent
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var e loggedEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad event line %q: %v", line, err)
		}
		out = append(out, e)
	}
	return out
}

// approvalsAs lists approvals with one key and decodes them generically, so a
// field the list carries is read by its wire name and nothing else.
func (h *orgHarness) approvalsAs(t *testing.T, key string) []map[string]any {
	t.Helper()
	rec := h.do(t, http.MethodGet, "/v1/approvals", key, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/approvals = %d %s", rec.Code, rec.Body.String())
	}
	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode approvals: %v: %s", err, rec.Body.String())
	}
	return out
}

// fp is a key's fingerprint as an operator computes it:
// printf %s "$KEY" | shasum -a 256 | cut -c1-16.
func fp(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:16]
}

func readEventsFile(t *testing.T, path string) []event.Event {
	t.Helper()
	evs, err := event.ReadFile(path)
	if err != nil {
		t.Fatalf("event.ReadFile: %v", err)
	}
	return evs
}

// approvalByID returns the listed approval with one id, or nil.
func approvalByID(list []map[string]any, id string) map[string]any {
	for _, a := range list {
		if a["approval_id"] == id {
			return a
		}
	}
	return nil
}
