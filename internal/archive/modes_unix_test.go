//go:build unix

package archive

import (
	"path/filepath"
	"syscall"
	"testing"
)

// TestTheModesDoNotFollowTheProcessUmask. A directory made with mkdir(2) has
// the umask taken off its mode, so under the umask of 077 a container often
// carries, 0750 would silently come out as 0700 and the group would be shut
// out again with nothing logged. The directory is therefore given its mode
// after it is made. A file is written through a temp file that is chmodded
// explicitly, which the umask does not touch; it is held here too, so a later
// change to how the file is created cannot bring the umask back in.
//
// The umask is process-wide, and this package's tests do not run in
// parallel, so changing it here and putting it back is safe.
func TestTheModesDoNotFollowTheProcessUmask(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "archive")

	prev := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(prev) })

	a, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s := set(t, "good.example.com")
	if err := a.Keep(s); err != nil {
		t.Fatalf("Keep: %v", err)
	}

	if got := modeOf(t, dir); got != 0o750 {
		t.Errorf("under umask 077 the directory is %#o, want 0750", got)
	}
	if got := modeOf(t, filepath.Join(dir, s.Version()+ext)); got != 0o640 {
		t.Errorf("under umask 077 the file is %#o, want 0640", got)
	}
}
