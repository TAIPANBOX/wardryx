package manifest

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
)

// The built binary, started with WARDRYX_SIGNAL_EVENTS pointing at a file
// written the way the quality plane writes it, and a policy that holds on the
// slo_burn signal. Nothing below reaches into the code.

const sloPolicy = `name: budget
target: "agent://acme.example/support/*"
hold_if_signal:
  name: slo_burn
  values: [exhausted, fast_burn]
  min_probability: 1
  when_absent: hold
`

func TestTheBuiltBinaryReadsTheBudgetFileAndSaysSoOnReadyz(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a process")
	}
	bin := buildServe(t)
	dir := t.TempDir()
	bus := filepath.Join(dir, "verdryx-events.ndjson")
	w, err := event.NewChainedWriter(bus)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.Write(event.Event{
		Schema: "taipanbox.dev/agent-event/v0.2", TS: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano),
		Source: "verdryx", Type: "slo_burn", Severity: "high", AgentID: "agent://acme.example/support/spent",
		Data: map[string]any{"sli": "task_success", "trigger": "exhausted", "burn_events_seen": 16},
	}); err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pol, []byte(sloPolicy), 0o600); err != nil {
		t.Fatal(err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	cmd := exec.Command(bin, "serve", "-addr", addr)
	cmd.Env = []string{
		"WARDRYX_KEYS=live-bearer:acme:pep",
		"WARDRYX_POLICY=" + pol,
		"WARDRYX_SIGNAL_EVENTS=" + bus,
	}
	out := &syncBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()

	get := func(path string) (int, string) {
		resp, err := http.Get("http://" + addr + path)
		if err != nil {
			return 0, err.Error()
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		return resp.StatusCode, buf.String()
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		if code, _ := get("/healthz"); code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("wardryx did not come up:\n%s", out.String())
		}
		time.Sleep(100 * time.Millisecond)
	}

	code, body := get("/readyz")
	var ready map[string]string
	if err := json.Unmarshal([]byte(body), &ready); err != nil || code != http.StatusOK || ready["signal_events"] != "ok" {
		t.Fatalf("readyz = %d %s (%v), want 200 with signal_events ok\n%s", code, body, err, out.String())
	}

	decide := func(agent string) string {
		raw, _ := json.Marshal(map[string]any{
			"agent_id": agent, "run_id": "r1", "tool_names": []string{"search"},
			"tool_call": map[string]any{"name": "search", "target": "t"},
		})
		req, _ := http.NewRequest(http.MethodPost, "http://"+addr+"/v1/decide", bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer live-bearer")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var got struct {
			Decision string `json:"decision"`
			Reason   string `json:"reason"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		return got.Decision + ": " + got.Reason
	}
	if got := decide("agent://acme.example/support/spent"); !strings.HasPrefix(got, "hold: ") || !strings.Contains(got, `"exhausted"`) {
		t.Errorf("the agent with a spent budget got %q, want a hold naming exhausted", got)
	}
	if got := decide("agent://acme.example/support/fine"); !strings.HasPrefix(got, "allow: ") {
		t.Errorf("an agent with no event got %q, want allow", got)
	}
	if !strings.Contains(out.String(), "the slo_burn signal is read from "+bus) {
		t.Errorf("the start did not say which file it reads:\n%s", out.String())
	}
}
