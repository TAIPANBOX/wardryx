package archive

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// Who may read what the archive keeps. The archive is evidence for a replay,
// and the replay is often run by another account than the one that wrote it:
// measured on the forge, a console running under a different uid than the
// service got "permission denied" on every file, and `wardryx replay` counted
// each recorded decision as not archived. Reading is opened to the group of
// the writing account and to nobody else; writing stays with the owner alone.

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

// TestANewArchiveIsReadableByItsGroupAndNoOneElse holds the exact modes, not
// a mask: 0750 on the directory and 0640 on a kept file. Equality is the
// point, because "the group can read" is true of 0770 and 0664 too, and
// neither of those is what was asked for.
func TestANewArchiveIsReadableByItsGroupAndNoOneElse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "archive")
	a, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s := set(t, "good.example.com")
	if err := a.Keep(s); err != nil {
		t.Fatalf("Keep: %v", err)
	}

	if got := modeOf(t, dir); got != 0o750 {
		t.Errorf("archive directory is %#o, want 0750: the group enters and reads, nobody else does, nobody but the owner writes", got)
	}
	if got := modeOf(t, filepath.Join(dir, s.Version()+ext)); got != 0o640 {
		t.Errorf("kept file is %#o, want 0640: the group reads, nobody else does, nobody but the owner writes", got)
	}

	// The temp file Keep writes through must not outlive it under a name the
	// group could list.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("want exactly the kept file in the directory, got %d entries", len(entries))
	}
}

// TestAnOwnerOnlyArchiveFromAnEarlierReleaseKeepsWorking. Releases up to 2.5.0
// wrote 0700 and 0600. An archive they made is opened by the new release as
// it stands: its file is read, keeping the same set again is still a no-op
// that touches nothing, and neither its directory nor its file has a mode
// changed behind the operator's back. A set kept now goes in beside it with
// the new file mode.
func TestAnOwnerOnlyArchiveFromAnEarlierReleaseKeepsWorking(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "archive")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	old := set(t, "old.example.com")
	oldFile := filepath.Join(dir, old.Version()+ext)
	if err := os.WriteFile(oldFile, mustJSON(t, old.Policies()), 0o600); err != nil {
		t.Fatalf("write the earlier release's file: %v", err)
	}
	if err := os.Chmod(oldFile, 0o600); err != nil {
		t.Fatalf("chmod file: %v", err)
	}

	a, err := New(dir)
	if err != nil {
		t.Fatalf("New on an existing owner-only directory: %v", err)
	}

	got, err := a.Get(old.Version())
	if err != nil {
		t.Fatalf("Get on the earlier release's file: %v", err)
	}
	back, err := policy.Compile(got)
	if err != nil {
		t.Fatalf("recompile: %v", err)
	}
	if back.Version() != old.Version() {
		t.Fatalf("the earlier file came back as %s, want %s", back.Version(), old.Version())
	}

	if err := a.Keep(old); err != nil {
		t.Fatalf("keeping a set the earlier release already kept: %v", err)
	}
	if got := modeOf(t, oldFile); got != 0o600 {
		t.Errorf("the earlier file is now %#o: an existing file is left as the operator has it", got)
	}
	if got := modeOf(t, dir); got != 0o700 {
		t.Errorf("an existing directory is now %#o: it is left as the operator has it", got)
	}

	fresh := set(t, "new.example.com")
	if err := a.Keep(fresh); err != nil {
		t.Fatalf("Keep beside the earlier file: %v", err)
	}
	if got := modeOf(t, filepath.Join(dir, fresh.Version()+ext)); got != 0o640 {
		t.Errorf("a set kept now is %#o, want 0640", got)
	}
	if got := modeOf(t, oldFile); got != 0o600 {
		t.Errorf("keeping a new set changed the earlier file to %#o", got)
	}
	versions, err := a.Versions()
	if err != nil {
		t.Fatalf("Versions: %v", err)
	}
	if len(versions) != 2 {
		t.Errorf("want both versions listed, got %v", versions)
	}
}
