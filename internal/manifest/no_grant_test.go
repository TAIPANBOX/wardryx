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
	if len(evs) == 0 || evs[0].Type != "policy_loaded" {
		t.Fatalf("the first event is not policy_loaded: %+v", evs)
	}
	loaded, _ := evs[0].Data["policy_version"].(string)
	if loaded == "" || !strings.Contains(out.String(), loaded) {
		t.Fatalf("policy_loaded names version %q and the start line does not:\n%s", loaded, out.String())
	}
}
