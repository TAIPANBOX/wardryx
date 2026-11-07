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

// The built binary with a floor in its policy file, driven over HTTP: the reading
// of the file, the write path and the record, none of which a test that builds its
// own Server goes through.

const floorFile = `- name: tool-hold
  target: "*"
  when_no_grant: hold
- name: grant-search
  target: agent://acme.example/agents/worker
  grant_tool: [search]
`

func TestTheBuiltBinaryHoldsAToolCallNothingGrants(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a process")
	}
	bin := buildServe(t)
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pol, []byte(floorFile), 0o600); err != nil {
		t.Fatal(err)
	}
	events := filepath.Join(dir, "events.ndjson")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	cmd := exec.Command(bin, "serve", "-addr", addr)
	cmd.Env = []string{
		"WARDRYX_KEYS=live-bearer:acme:admin",
		"WARDRYX_POLICY=" + pol,
		"WARDRYX_EVENTS_PATH=" + events,
		"WARDRYX_APPROVAL_SECRET=live-secret",
		"WARDRYX_PENDING_PER_AGENT=1",
	}
	out := &syncBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()

	send := func(method, path, body string) (int, map[string]any) {
		req, _ := http.NewRequest(method, "http://"+addr+path, bytes.NewReader([]byte(body)))
		req.Header.Set("Authorization", "Bearer live-bearer")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return 0, nil
		}
		defer resp.Body.Close()
		var got map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&got)
		return resp.StatusCode, got
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		if code, _ := send(http.MethodGet, "/healthz", ""); code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("wardryx did not come up:\n%s", out.String())
		}
		time.Sleep(100 * time.Millisecond)
	}

	call := func(tool string) map[string]any {
		_, got := send(http.MethodPost, "/v1/decide", `{"agent_id":"agent://acme.example/agents/worker","run_id":"r1","tool_names":["`+tool+`"],"tool_call":{"name":"`+tool+`","target":"t"}}`)
		return got
	}
	if got := call("exec"); got["decision"] != "hold" || got["cacheable"] != false {
		t.Fatalf("an ungranted tool: %v\n%s", got, out.String())
	}
	if got := call("search"); got["decision"] != "allow" {
		t.Fatalf("a granted tool: %v", got)
	}
	// The cap is the variable's, so the second ungranted tool writes no row.
	if got := call("browse"); got["decision"] != "hold" || got["approval_id"] != nil {
		t.Fatalf("past WARDRYX_PENDING_PER_AGENT=1: %v", got)
	}
	_, model := send(http.MethodPost, "/v1/decide", `{"agent_id":"agent://acme.example/agents/worker","run_id":"r1","model":"claude-sonnet-5","tool_names":["exec"]}`)
	if model["decision"] != "allow" {
		t.Fatalf("a model call: %v", model)
	}
	if code, got := send(http.MethodPut, "/v1/policies/sneaky", `{"target":"*","when_no_grant":"hold"}`); code != http.StatusBadRequest {
		t.Fatalf("a floor through PUT answered %d: %v", code, got)
	}
	if code, got := send(http.MethodPut, "/v1/policies/grant-exec", `{"target":"agent://acme.example/agents/worker","grant_tool":["exec"]}`); code != http.StatusOK {
		t.Fatalf("a grant through PUT answered %d: %v", code, got)
	}
	if got := call("exec"); got["decision"] != "allow" {
		t.Fatalf("after the grant: %v", got)
	}

	evs, err := event.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	// The built binary's own record carries only what SPEC 6.2 lists under wardryx,
	// at the severity it gives (invariant 50): no start event, and no event for the
	// agent that reached the cap, whose holds carry queue_full instead.
	row := specRow(t)
	if len(evs) == 0 || evs[0].Type != "approval_requested" {
		t.Fatalf("the first event is not the first hold: the start writes nothing to the bus: %+v", evs)
	}
	full := 0
	for _, ev := range evs {
		if want, listed := row[ev.Type]; !listed || ev.Severity != want {
			t.Errorf("the record carries %q at %q; SPEC 6.2 gives wardryx %v", ev.Type, ev.Severity, row)
		}
		if ev.Data["queue_full"] == true {
			full++
		}
	}
	if full != 1 {
		t.Errorf("%d hold(s) carry queue_full, want the one past WARDRYX_PENDING_PER_AGENT=1", full)
	}
	// The start and the cap are in the log: the start line names the version the
	// first decision names, and the cap line names the agent once.
	first, _ := evs[0].Data["policy_version"].(string)
	start := lineWith(out.String(), "wardryx: policy set loaded ")
	if first == "" || !strings.Contains(start, "policy_version="+first+" ") || !strings.Contains(start, "no_grant_floors=[tool-hold] ") {
		t.Fatalf("the first decision names version %q and the start line is %q:\n%s", first, start, out.String())
	}
	if n := strings.Count(out.String(), "wardryx: an agent reached its pending cap agent_id=agent://acme.example/agents/worker run_id=r1 pending_limit=1"); n != 1 {
		t.Fatalf("the pending cap was logged %d time(s), want once:\n%s", n, out.String())
	}
}

// specRow reads the copy of SPEC 6.2's wardryx row that internal/api's tests and
// scripts/bus-types-are-registered.sh read: type to severity.
func specRow(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "api", "testdata", "spec-6.2-wardryx.json"))
	if err != nil {
		t.Fatalf("the copy of SPEC 6.2's wardryx row is not readable: %v", err)
	}
	var row struct {
		Types map[string]string `json:"types"`
	}
	if err := json.Unmarshal(raw, &row); err != nil || len(row.Types) == 0 {
		t.Fatalf("the copy of SPEC 6.2's wardryx row lists nothing (%v)", err)
	}
	return row.Types
}

// lineWith is the first line of s that contains needle, or "".
func lineWith(s, needle string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	return ""
}
