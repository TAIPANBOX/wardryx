package api

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/event"
	"github.com/TAIPANBOX/wardryx/internal/archive"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// A recorded decision names a PolicyVersion. These tests hold the server to
// the other half of that promise: the rules behind the name are still there
// afterwards, and no set is ever allowed to decide before they are.

// serverWithArchive returns a Server whose events go to path and whose policy
// archive is dir, with the set in force at that moment already kept.
func serverWithArchive(t *testing.T, path, dir string) (*Server, *event.ChainedWriter, *archive.Archive) {
	t.Helper()
	srv, ew := newTestServerWithEvents(t, path)
	a, err := archive.New(dir)
	if err != nil {
		t.Fatalf("archive.New: %v", err)
	}
	if err := srv.SetPolicyArchive(a); err != nil {
		t.Fatalf("SetPolicyArchive: %v", err)
	}
	return srv, ew, a
}

// TestAttachingAnArchiveKeepsTheSetAlreadyInForce. The set a server starts
// with decides immediately, so it has to be archived at that moment: an
// archive that only records later swaps would leave every decision made
// before the first policy edit unexaminable.
func TestAttachingAnArchiveKeepsTheSetAlreadyInForce(t *testing.T) {
	dir := t.TempDir()
	srv, _, a := serverWithArchive(t, filepath.Join(t.TempDir(), "events.ndjson"), dir)

	versions, err := a.Versions()
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(versions) != 1 {
		t.Fatalf("want the in-force set archived on attach, got %d version(s): %v", len(versions), versions)
	}
	if versions[0] != srv.engine.PolicyVersion() {
		t.Fatalf("archived %s, in force %s", versions[0], srv.engine.PolicyVersion())
	}
}

// TestAPolicySetDecidesOnlyAfterItIsArchived is the ordering invariant. If
// the archive write fails, the swap must not happen: a set that decided and
// was never archived is a decision nobody can re-examine, and unlike a failed
// write that cannot be repaired afterwards.
func TestAPolicySetDecidesOnlyAfterItIsArchived(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	srv, _, _ := serverWithArchive(t, filepath.Join(t.TempDir(), "events.ndjson"), dir)
	before := srv.engine.PolicyVersion()

	// Shut the door only after the in-force set is safely kept, so this
	// test is about the swap and not about attaching.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	rec := doRequest(t, srv.Handler(), http.MethodPut, "/v1/policies/new-rule", adminKey,
		policy.Policy{Name: "block-scraping", Target: "agent://acme.example/scraper/*", DenyTool: []string{"scrape"}})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("PUT with an unwritable archive: status = %d, want 500. body = %s", rec.Code, rec.Body.String())
	}
	if after := srv.engine.PolicyVersion(); after != before {
		t.Fatalf("the set was swapped anyway: %s -> %s. A set that decides unarchived can never be replayed.", before, after)
	}
}

// TestEveryRecordedPolicyVersionCanBeFetchedBack is the invariant stated the
// way an auditor would: take the events this server actually wrote, and for
// every PolicyVersion any of them names, the rules must still be there.
func TestEveryRecordedPolicyVersionCanBeFetchedBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	srv, ew, a := serverWithArchive(t, path, t.TempDir())

	decide := func(runID string, tools []string) {
		doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, decideRequestDTO{
			AgentID: "agent://acme.example/finance/bot1", RunID: runID, ToolNames: tools,
			Domains: []string{"good.example.com"}, Steps: 1, Model: "m", EstCostUSD: 1, AttestationMethod: "tpm",
		})
	}

	decide("r1", []string{"generate_report"})
	// A live policy edit, which changes the version every later decision names.
	if rec := doRequest(t, srv.Handler(), http.MethodPut, "/v1/policies/scraper-guard", adminKey,
		policy.Policy{Name: "block-scraping", Target: "agent://acme.example/scraper/*", DenyTool: []string{"scrape"}}); rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body = %s", rec.Code, rec.Body.String())
	}
	decide("r2", []string{"send_wire_transfer"})
	// A second rule, so the DELETE below lands on a set nothing has archived
	// before. Deleting straight back to the base set would return to a
	// version kept on attach, and the delete path would go unexercised: that
	// is how a mutation removing it entirely survived this test on
	// 2026-08-31.
	if rec := doRequest(t, srv.Handler(), http.MethodPut, "/v1/policies/egress-guard", adminKey,
		policy.Policy{Name: "egress", Target: "agent://acme.example/etl/*", AllowDomains: []string{"warehouse.acme.example"}}); rec.Code != http.StatusOK {
		t.Fatalf("second PUT status = %d, body = %s", rec.Code, rec.Body.String())
	}
	decide("r2b", []string{"generate_report"})
	if rec := doRequest(t, srv.Handler(), http.MethodDelete, "/v1/policies/scraper-guard", adminKey, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, body = %s", rec.Code, rec.Body.String())
	}
	decide("r3", []string{"generate_report"})

	if err := ew.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	events, err := event.ReadFile(path)
	if err != nil {
		t.Fatalf("event.ReadFile: %v", err)
	}

	seen := 0
	for _, ev := range events {
		raw, present := ev.Data["policy_version"]
		if !present {
			continue
		}
		version, ok := raw.(string)
		if !ok || version == "" {
			t.Errorf("%s event carries a policy_version that is not a string: %#v", ev.Type, raw)
			continue
		}
		seen++
		policies, err := a.Get(version)
		if err != nil {
			t.Errorf("%s event names policy_version %s and the archive cannot produce it: %v", ev.Type, version, err)
			continue
		}
		// Not merely present: the archived rules must recompile to the very
		// version the event names, or a replay would run different rules
		// under the right name.
		back, err := policy.Compile(policies)
		if err != nil {
			t.Errorf("archived %s does not compile: %v", version, err)
			continue
		}
		if back.Version() != version {
			t.Errorf("archived under %s but recompiles to %s", version, back.Version())
		}
	}
	if seen < 3 {
		t.Fatalf("only %d event(s) named a policy_version; this test proves nothing without several", seen)
	}
}

// TestAServerWithNoArchiveStillDecides. Archiving is opt-in, and an operator
// who has not configured it loses replay, not the PDP.
func TestAServerWithNoArchiveStillDecides(t *testing.T) {
	srv, _ := newTestServerWithEvents(t, filepath.Join(t.TempDir(), "events.ndjson"))
	if err := srv.SetPolicyArchive(nil); err != nil {
		t.Fatalf("SetPolicyArchive(nil): %v", err)
	}
	rec := doRequest(t, srv.Handler(), http.MethodPut, "/v1/policies/p1", adminKey,
		policy.Policy{Name: "n", Target: "agent://acme.example/other/*"})
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT without an archive: status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

// TestFetchingFromNoArchiveIsNotAnEmptySet guards the shape of the failure a
// future replayer will meet: no archive must be an error, never zero
// policies, because Decide reads an empty set as allow-everything.
func TestFetchingFromNoArchiveIsNotAnEmptySet(t *testing.T) {
	var none *archive.Archive
	got, err := none.Get("f5912efb526d")
	if err == nil {
		t.Fatalf("want an error, got %d policies", len(got))
	}
	if !errors.Is(err, archive.ErrNotArchived) {
		t.Fatalf("want ErrNotArchived, got %v", err)
	}
}
