package archive

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// A replay is only as honest as the rules it replays against. These tests
// hold the archive to one promise: a policy version that ever decided
// anything can be fetched back, byte for byte, and can never be confused
// with a different set that happens to share its short digest.

func set(t *testing.T, domains ...string) *policy.Set {
	t.Helper()
	compiled, err := policy.Compile([]policy.Policy{{
		Name:                 "finance-guardrail",
		Target:               "agent://acme.example/finance/*",
		DenyTool:             []string{"send_wire_transfer"},
		AllowDomains:         domains,
		RequireHumanAboveUSD: 500,
		DenyAboveUSD:         5000,
		MaxSteps:             5,
		DenyIfUnattested:     true,
	}})
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	return compiled
}

func newTemp(t *testing.T) *Archive {
	t.Helper()
	a, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

// TestKeptSetComesBackWholeAndUnchanged is the whole point. A round trip
// that silently drops a field would replay against rules the operator never
// wrote, and every answer would look right.
func TestKeptSetComesBackWholeAndUnchanged(t *testing.T) {
	a := newTemp(t)
	original := set(t, "good.example.com")

	if err := a.Keep(original); err != nil {
		t.Fatalf("Keep: %v", err)
	}
	got, err := a.Get(original.Version())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	// Recompiling the fetched policies must reproduce the same digest.
	// Comparing versions rather than structs is deliberate: the digest is
	// what a recorded decision names, so it is what has to match.
	back, err := policy.Compile(got)
	if err != nil {
		t.Fatalf("recompile what came back: %v", err)
	}
	if back.Version() != original.Version() {
		t.Fatalf("round trip changed the set: kept %s, got back %s", original.Version(), back.Version())
	}

	want := original.Policies()
	if len(got) != len(want) {
		t.Fatalf("kept %d policies, got back %d", len(want), len(got))
	}
	if !reflect.DeepEqual(got[0], want[0]) {
		t.Errorf("policy differs after a round trip:\n kept %+v\n  got %+v", want[0], got[0])
	}
}

// TestKeepingTheSameSetTwiceIsOneFile: the name is the content's own digest,
// so a restart that re-archives the running set must not fail, duplicate, or
// rewrite.
func TestKeepingTheSameSetTwiceIsOneFile(t *testing.T) {
	dir := t.TempDir()
	a, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s := set(t, "good.example.com")

	if err := a.Keep(s); err != nil {
		t.Fatalf("first Keep: %v", err)
	}
	before, err := os.Stat(filepath.Join(dir, s.Version()+".json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if err := a.Keep(s); err != nil {
		t.Fatalf("second Keep: %v", err)
	}
	after, err := os.Stat(filepath.Join(dir, s.Version()+".json"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if !before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() {
		t.Fatal("the second Keep rewrote the file; a content-addressed name must be written once")
	}
	versions, err := a.Versions()
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(versions) != 1 {
		t.Fatalf("want 1 archived version, got %d: %v", len(versions), versions)
	}
}

// TestADifferentSetUnderTheSameVersionIsRefused. PolicyVersion is sha256
// truncated to 48 bits, chosen as "collision-safe for one operator's policy
// history". If that assumption ever fails, replay would answer with the
// wrong rules and look right doing it, so the archive refuses rather than
// overwriting or silently keeping the first.
func TestADifferentSetUnderTheSameVersionIsRefused(t *testing.T) {
	dir := t.TempDir()
	a, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s := set(t, "good.example.com")
	if err := a.Keep(s); err != nil {
		t.Fatalf("Keep: %v", err)
	}

	// Forge the collision the digest is supposed to make improbable.
	other := set(t, "other.example.com")
	if err := os.WriteFile(filepath.Join(dir, s.Version()+".json"),
		mustJSON(t, other.Policies()), 0o600); err != nil {
		t.Fatalf("plant: %v", err)
	}

	err = a.Keep(s)
	if err == nil {
		t.Fatal("keeping a set whose version already names different content must refuse")
	}
	if !errors.Is(err, ErrVersionCollision) {
		t.Fatalf("want ErrVersionCollision, got %v", err)
	}
}

// TestAnUnknownVersionIsDistinguishableFromABrokenArchive. A replayer asking
// for a version nobody kept must be told exactly that, not handed an empty
// set that would replay as "no policy in force", which Decide reads as
// allow-everything.
func TestAnUnknownVersionIsDistinguishableFromABrokenArchive(t *testing.T) {
	a := newTemp(t)
	got, err := a.Get("ffffffffffff")
	if err == nil {
		t.Fatalf("want an error for an unkept version, got %d policies", len(got))
	}
	if !errors.Is(err, ErrNotArchived) {
		t.Fatalf("want ErrNotArchived, got %v", err)
	}
	if got != nil {
		t.Fatalf("an error must not also return policies, got %+v", got)
	}
}

// TestADisabledArchiveKeepsNothingAndFailsNothing. An operator who has not
// configured an archive still gets a working PDP; what they lose is replay,
// and that loss is stated in the docs rather than enforced by a crash.
func TestADisabledArchiveKeepsNothingAndFailsNothing(t *testing.T) {
	a, err := New("")
	if err != nil {
		t.Fatalf("New(\"\"): %v", err)
	}
	if a != nil {
		t.Fatal("an empty directory must produce a nil Archive, so call sites need no second flag")
	}
	if err := a.Keep(set(t, "good.example.com")); err != nil {
		t.Fatalf("Keep on a disabled archive: %v", err)
	}
	if _, err := a.Versions(); err != nil {
		t.Fatalf("Versions on a disabled archive: %v", err)
	}
}

// TestAnUnwritableArchiveReportsRatherThanLosing. The caller swaps the
// policy set only if Keep succeeded, so a Keep that failed quietly would let
// a set decide without ever being fetchable.
func TestAnUnwritableArchiveReportsRatherThanLosing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(dir, 0o500); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	a, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := a.Keep(set(t, "good.example.com")); err == nil {
		t.Fatal("keeping into an unwritable directory must report, not lose")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := marshalPolicies(v.([]policy.Policy))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
