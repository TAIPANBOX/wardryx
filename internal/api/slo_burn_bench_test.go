package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/sloburn"
	"github.com/TAIPANBOX/wardryx/internal/store"
)

// What the standing signal costs a decide: the same tool call under the same
// rule, with the option off and on. The reader's lookup is a map read; the rest
// is the signal being built, recorded nowhere here (no event file) and read by
// the engine.
func benchServer(b *testing.B, withFile bool) http.Handler {
	b.Helper()
	set, err := policy.Compile([]policy.Policy{budgetPol("", spent...)})
	if err != nil {
		b.Fatal(err)
	}
	keys := map[string]Principal{keyDigest(adminKey): {Org: "acme", Role: RoleAdmin}}
	srv := New(pdp.New(set, []byte(testHMAC)), store.NewMemory(), nil, nil, keys, []byte(testHMAC), false, set.Policies())
	if withFile {
		path := filepath.Join(b.TempDir(), "events.ndjson")
		w, err := event.NewChainedWriter(path)
		if err != nil {
			b.Fatal(err)
		}
		for i := 0; i < 200; i++ { // a file of a few hundred lines, as a busy fleet leaves
			if err := w.Write(event.Event{
				Schema: "taipanbox.dev/agent-event/v0.2", TS: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano),
				Source: "verdryx", Type: "slo_burn", AgentID: "agent://acme.example/support/other" + string(rune('a'+i%26)),
				Data: map[string]any{"sli": "task_success", "trigger": "exhausted", "burn_events_seen": 9},
			}); err != nil {
				b.Fatal(err)
			}
		}
		_ = w.Close()
		if _, err := os.Stat(path); err != nil {
			b.Fatal(err)
		}
		r := sloburn.New(path, sloburn.DefaultMaxAge)
		if r.Refresh() != sloburn.StateOK {
			b.Fatal("the benchmark's file is not ok")
		}
		srv.WithSLOBurn(r)
	}
	return srv.Handler()
}

func benchDecide(b *testing.B, h http.Handler) {
	body := []byte(`{"agent_id":"agent://acme.example/support/bot1","run_id":"r","tool_names":["search"],"tool_call":{"name":"search","target":"t"}}`)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/decide", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			b.Fatalf("decide answered %d", rec.Code)
		}
	}
}

func BenchmarkDecideWithTheBudgetFileOff(b *testing.B) { benchDecide(b, benchServer(b, false)) }
func BenchmarkDecideWithTheBudgetFileOn(b *testing.B)  { benchDecide(b, benchServer(b, true)) }
