package archive

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

// TestAFailedPlacementIsReportedNotSwallowed. Keep's last act is the atomic
// rename, and a rename that fails while everything before it succeeded is
// the one failure a filesystem will not produce on demand. It is also the
// worst one: the caller swaps the policy set on a nil error, so a swallowed
// rename means a set decides that nobody kept. A mutation that returned nil
// here survived the whole suite until this test existed.
func TestAFailedPlacementIsReportedNotSwallowed(t *testing.T) {
	a := newTemp(t)

	original := renameFile
	renameFile = func(string, string) error { return errors.New("no space left on device") }
	t.Cleanup(func() { renameFile = original })

	err := a.Keep(set(t, "good.example.com"))
	if err == nil {
		t.Fatal("a failed placement must be reported: the caller makes the set effective on a nil error")
	}
	if !strings.Contains(err.Error(), "no space left on device") {
		t.Errorf("the underlying cause is lost: %v", err)
	}

	// And nothing was left behind under the real name.
	versions, vErr := a.Versions()
	if vErr != nil {
		t.Fatalf("Versions: %v", vErr)
	}
	if len(versions) != 0 {
		t.Errorf("a failed Keep left %v archived", versions)
	}
}

// TestACorruptedArchiveFileIsAnErrorNotAnEmptySet. The dangerous reading of
// a damaged file is the permissive one: Decide treats no policy in force as
// allow, so an archive entry that fails to parse must reach the caller as a
// failure and never as zero rules.
func TestACorruptedArchiveFileIsAnErrorNotAnEmptySet(t *testing.T) {
	dir := t.TempDir()
	a, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s := set(t, "good.example.com")
	if err := a.Keep(s); err != nil {
		t.Fatalf("Keep: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, s.Version()+".json"), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}

	got, err := a.Get(s.Version())
	if err == nil {
		t.Fatalf("want an error for a damaged entry, got %d policies", len(got))
	}
	if got != nil {
		t.Fatalf("a damaged entry must yield no policies, got %+v", got)
	}
	if !strings.Contains(err.Error(), "is not a policy set") {
		t.Errorf("the error does not say what is wrong: %v", err)
	}
}

// TestKeepingNothingIsRefused. A nil set is a caller bug, and the permissive
// reading again is the harmful one: silently keeping an empty set under some
// version would archive "no policy in force" as if it were a decision's rules.
func TestKeepingNothingIsRefused(t *testing.T) {
	if err := newTemp(t).Keep(nil); err == nil {
		t.Fatal("Keep(nil) must refuse")
	}
}

// TestAnArchiveDirectoryThatCannotExistIsReportedAtOpen, rather than at the
// first swap hours later, when the failure would block a policy change an
// operator is watching.
func TestAnArchiveDirectoryThatCannotExistIsReportedAtOpen(t *testing.T) {
	file := filepath.Join(t.TempDir(), "a-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := New(filepath.Join(file, "archive")); err == nil {
		t.Fatal("opening an archive under a regular file must fail at New")
	}
}

// TestListingAVanishedArchiveReportsRatherThanReadsEmpty. An archive
// directory removed under a running process must not look like one that has
// kept nothing.
func TestListingAVanishedArchiveReportsRatherThanReadsEmpty(t *testing.T) {
	dir := t.TempDir()
	a, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := a.Versions(); err == nil {
		t.Fatal("listing a vanished archive must report, not read as empty")
	}
}

// TestAPathShapedVersionIsRefusedRatherThanResolved. Get takes its argument
// from a caller that will read it out of a recorded event, so anything shaped
// like a path has to be refused as not-a-version. Refusing on the SHAPE, before
// any join, is what makes the archive directory a boundary rather than a
// starting point.
func TestAPathShapedVersionIsRefusedRatherThanResolved(t *testing.T) {
	dir := t.TempDir()
	a, err := New(filepath.Join(dir, "archive"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// A file the archive must not be able to reach, one level up.
	secret := filepath.Join(dir, "secret.json")
	if err := os.WriteFile(secret, []byte(`[{"target":"agent://x/*"}]`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	for _, bad := range []string{
		"../secret", "../../etc/passwd", "..", ".", "/etc/passwd",
		"a/b", "F5912EFB526D", "f5912efb526d.json", "", "short",
	} {
		got, err := a.Get(bad)
		if err == nil {
			t.Errorf("Get(%q) returned %d policies instead of refusing", bad, len(got))
			continue
		}
		if !errors.Is(err, ErrBadVersion) {
			t.Errorf("Get(%q): want ErrBadVersion, got %v", bad, err)
		}
		if got != nil {
			t.Errorf("Get(%q) refused and still returned policies: %+v", bad, got)
		}
	}
}

// TestAVersionOfADifferentLengthIsStillAcceptable. The digest is 12 hex
// characters today and package policy is free to lengthen it. The bound here
// is deliberately loose so that a change there does not silently make every
// previously archived set unreachable.
func TestAVersionOfADifferentLengthIsStillAcceptable(t *testing.T) {
	a := newTemp(t)
	for _, ok := range []string{"0123456789ab", "0123456789abcdef", "abcdef12"} {
		if _, err := a.Get(ok); !errors.Is(err, ErrNotArchived) {
			t.Errorf("Get(%q): want ErrNotArchived (a well-formed version nobody kept), got %v", ok, err)
		}
	}
}
