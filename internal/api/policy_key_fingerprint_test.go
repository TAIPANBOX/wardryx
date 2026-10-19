package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/store"
)

// Two bearer keys of one organisation. The raw-key test searches the event
// file for these bytes, so the values are distinctive: a string that occurs
// elsewhere in an event would make that search prove nothing.
const (
	fpAlphaKey = "kfp-key-alpha"
	fpBravoKey = "kfp-key-bravo"

	// The first 16 hex characters of SHA-256 of each key, computed outside
	// the code with the operator's own command:
	//   printf %s "$KEY" | shasum -a 256 | cut -c1-16
	fpAlphaFingerprint = "1b4c576a5dbff3eb"
	fpBravoFingerprint = "5d2c8cf00eb9b793"

	// The fingerprint of the empty string. A key_fp computed over the wrong
	// bytes would often land here, so it must never be recorded.
	fpEmptyFingerprint = "e3b0c44298fc1c14"
)

var fingerprintShape = regexp.MustCompile(`^[0-9a-f]{16}$`)

// fingerprintServer returns a Server whose events go to path. Both fpAlphaKey
// and fpBravoKey authenticate as org acme with the admin role.
func fingerprintServer(t *testing.T, path string) *Server {
	t.Helper()
	ew, err := event.NewChainedWriter(path)
	if err != nil {
		t.Fatalf("NewChainedWriter: %v", err)
	}
	set, err := policy.Compile([]policy.Policy{{
		Name:     "ops-floor",
		Target:   "agent://acme.example/floor/*",
		DenyTool: []string{"shell_exec"},
	}})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	engine := pdp.New(set, []byte(testHMAC))
	keys := map[string]Principal{
		fpAlphaKey: {Org: "acme", Role: RoleAdmin},
		fpBravoKey: {Org: "acme", Role: RoleAdmin},
	}
	return New(engine, store.NewMemory(), ew, nil, keys, []byte(testHMAC), false, nil)
}

// policyUpdatedData returns the data object of every policy_updated event in
// the file, in the order they were written.
func policyUpdatedData(t *testing.T, path string) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line == "" {
			continue
		}
		var e struct {
			Type string         `json:"type"`
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("bad event line %q: %v", line, err)
		}
		if e.Type == "policy_updated" {
			out = append(out, e.Data)
		}
	}
	return out
}

// putAndDeleteByDifferentKeys writes one policy with the alpha key and removes
// it with the bravo key, and returns the two policy_updated data objects.
func putAndDeleteByDifferentKeys(t *testing.T) []map[string]any {
	t.Helper()
	path := filepath.Join(t.TempDir(), "events.ndjson")
	srv := fingerprintServer(t, path)
	put := doRequest(t, srv.Handler(), http.MethodPut, "/v1/policies/ops-guard", fpAlphaKey,
		policy.Policy{Target: "agent://acme.example/ops/*", DenyTool: []string{"shell_exec"}})
	if put.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200: %s", put.Code, put.Body.String())
	}
	del := doRequest(t, srv.Handler(), http.MethodDelete, "/v1/policies/ops-guard", fpBravoKey, nil)
	if del.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, want 204: %s", del.Code, del.Body.String())
	}
	got := policyUpdatedData(t, path)
	if len(got) != 2 {
		t.Fatalf("policy_updated events = %d, want 2 (one PUT, one DELETE)", len(got))
	}
	return got
}

func TestAPolicyPutRecordsTheFingerprintOfTheKeyThatMadeIt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	srv := fingerprintServer(t, path)
	rec := doRequest(t, srv.Handler(), http.MethodPut, "/v1/policies/ops-guard", fpAlphaKey,
		policy.Policy{Target: "agent://acme.example/ops/*", DenyTool: []string{"shell_exec"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	got := policyUpdatedData(t, path)
	if len(got) != 1 {
		t.Fatalf("policy_updated events = %d, want 1", len(got))
	}
	if got[0]["key_fp"] != fpAlphaFingerprint {
		t.Errorf("PUT key_fp = %v, want %s (the fingerprint of the key that made the write)", got[0]["key_fp"], fpAlphaFingerprint)
	}
}

func TestAPolicyDeleteRecordsTheFingerprintOfTheKeyThatMadeIt(t *testing.T) {
	got := putAndDeleteByDifferentKeys(t)
	if got[1]["action"] != "delete" {
		t.Fatalf("second event action = %v, want delete", got[1]["action"])
	}
	if got[1]["key_fp"] != fpBravoFingerprint {
		t.Errorf("DELETE key_fp = %v, want %s (the fingerprint of the key that made the delete)", got[1]["key_fp"], fpBravoFingerprint)
	}
}

func TestTheRawKeyNeverReachesTheEventFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	srv := fingerprintServer(t, path)
	doRequest(t, srv.Handler(), http.MethodPut, "/v1/policies/ops-guard", fpAlphaKey,
		policy.Policy{Target: "agent://acme.example/ops/*", DenyTool: []string{"shell_exec"}})
	doRequest(t, srv.Handler(), http.MethodDelete, "/v1/policies/ops-guard", fpBravoKey, nil)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	for _, key := range []string{fpAlphaKey, fpBravoKey} {
		if strings.Contains(string(raw), key) {
			t.Errorf("the event file contains the bearer key %q; only its fingerprint may be written", key)
		}
	}
}

func TestTheRecordedFingerprintIsSixteenLowerCaseHexAndNotTheEmptyKeys(t *testing.T) {
	got := putAndDeleteByDifferentKeys(t)
	for i, d := range got {
		fp, _ := d["key_fp"].(string)
		if !fingerprintShape.MatchString(fp) {
			t.Errorf("event %d key_fp = %q, want 16 lower-case hex characters", i, fp)
		}
		if fp == fpEmptyFingerprint {
			t.Errorf("event %d key_fp is the fingerprint of an empty key, so it was computed over the wrong bytes", i)
		}
	}
}

func TestTwoKeysOfOneOrganisationAreToldApart(t *testing.T) {
	got := putAndDeleteByDifferentKeys(t)
	if got[0]["key_fp"] == got[1]["key_fp"] {
		t.Errorf("two keys of one organisation recorded the same key_fp %v; the record cannot say which key made each change", got[0]["key_fp"])
	}
}

func TestTheDecidedByFieldStillNamesTheOrganisation(t *testing.T) {
	got := putAndDeleteByDifferentKeys(t)
	for i, d := range got {
		if d["decided_by"] != "acme" {
			t.Errorf("event %d decided_by = %v, want acme: the field keeps naming the organisation for current readers", i, d["decided_by"])
		}
	}
}
