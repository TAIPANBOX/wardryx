// Package archive keeps the policy set a decision was taken under, so a
// recorded decision can be re-examined later against the rules that were
// actually in force rather than against whatever is loaded today.
//
// # Why this is not the store
//
// internal/store holds the CURRENT policy set: PutPolicy overwrites and
// DeletePolicy removes, which is right for a live control surface and wrong
// for evidence. A decision recorded on Tuesday names a PolicyVersion, and by
// Friday the rules behind that name can be gone. This package is the other
// half: append-only, content-addressed, and never consulted on the decision
// path.
//
// # Why the file name is the version
//
// PolicyVersion is the digest of the normalized set, so the name IS the
// content's identity. Keeping the same set twice is a no-op rather than a
// rewrite, which is what makes it safe to archive on every start and every
// swap without thinking about how many times that happens.
//
// The digest is sha256 truncated to 48 bits, described where it is computed
// as "collision-safe for one operator's policy history". Keep does not take
// that on faith: a version whose file already holds DIFFERENT bytes is
// refused, because the alternative is a replay that answers with the wrong
// rules and looks right doing it.
package archive

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TAIPANBOX/wardryx/internal/policy"
)

var (
	// ErrNotArchived: nobody kept this version. Distinct from an empty set,
	// which Decide reads as "no policy in force" and therefore as allow.
	ErrNotArchived = errors.New("archive: policy version was never archived")
	// ErrVersionCollision: this version already names different bytes.
	ErrVersionCollision = errors.New("archive: version already names a different policy set")
)

// renameFile is os.Rename, indirected for one reason: the atomic placement is
// the last thing Keep does and the only failure a filesystem will not produce
// on demand. A mutation that made this branch return nil survived the whole
// suite on 2026-08-31, which is exactly the loss this package exists to
// prevent: a Keep that reports success and keeps nothing, while the caller
// makes the set effective on that nil error. Tests swap it; nothing else does.
var renameFile = os.Rename

const (
	ext      = ".json"
	dirPerm  = 0o700
	filePerm = 0o600
)

// Archive is an append-only, content-addressed directory of policy sets. A
// nil *Archive is the disabled archive: every method succeeds and keeps
// nothing, so a deployment that has not configured one needs no second flag
// at any call site.
type Archive struct {
	dir string
}

// New opens (and creates) the archive directory. An empty dir returns a nil
// *Archive and no error: archiving is off, the PDP works, and what is lost
// is the ability to replay, which the docs state rather than a crash.
func New(dir string) (*Archive, error) {
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("archive: create %s: %w", dir, err)
	}
	return &Archive{dir: dir}, nil
}

// Keep archives set under its own version. Keeping a set already archived is
// a no-op; keeping a set whose version names different bytes is refused with
// ErrVersionCollision.
//
// Callers archive BEFORE the set becomes effective. A set that decided
// something and was never archived is a decision nobody can re-examine, and
// unlike a failed write that ordering cannot be repaired afterwards.
func (a *Archive) Keep(set *policy.Set) error {
	if a == nil {
		return nil
	}
	if set == nil {
		return errors.New("archive: keep a nil policy set")
	}
	want, err := marshalPolicies(set.Policies())
	if err != nil {
		return err
	}
	path := a.path(set.Version())

	switch existing, err := os.ReadFile(path); {
	case err == nil:
		if string(existing) == string(want) {
			return nil
		}
		return fmt.Errorf("%w: %s", ErrVersionCollision, set.Version())
	case !errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("archive: read %s: %w", path, err)
	}

	// Written through a temp file in the same directory so a crash mid-write
	// leaves either nothing or the whole set, never a truncated one that a
	// later reader has to judge.
	tmp, err := os.CreateTemp(a.dir, "."+set.Version()+".*")
	if err != nil {
		return fmt.Errorf("archive: create temp in %s: %w", a.dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(want); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("archive: write %s: %w", tmpName, err)
	}
	if err := tmp.Chmod(filePerm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("archive: chmod %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("archive: close %s: %w", tmpName, err)
	}
	if err := renameFile(tmpName, path); err != nil {
		return fmt.Errorf("archive: place %s: %w", path, err)
	}
	return nil
}

// Get returns the policies archived under version. An unkept version is
// ErrNotArchived and no policies: a replayer must never be handed an empty
// set, which Decide reads as no policy in force and therefore as allow.
func (a *Archive) Get(version string) ([]policy.Policy, error) {
	if a == nil {
		return nil, fmt.Errorf("%w: %s (no archive is configured)", ErrNotArchived, version)
	}
	raw, err := os.ReadFile(a.path(version))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotArchived, version)
	}
	if err != nil {
		return nil, fmt.Errorf("archive: read %s: %w", version, err)
	}
	var policies []policy.Policy
	if err := json.Unmarshal(raw, &policies); err != nil {
		return nil, fmt.Errorf("archive: %s is not a policy set: %w", version, err)
	}
	return policies, nil
}

// Versions lists every archived version, unordered.
func (a *Archive) Versions() ([]string, error) {
	if a == nil {
		return nil, nil
	}
	entries, err := os.ReadDir(a.dir)
	if err != nil {
		return nil, fmt.Errorf("archive: list %s: %w", a.dir, err)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ext) {
			continue
		}
		out = append(out, strings.TrimSuffix(name, ext))
	}
	return out, nil
}

func (a *Archive) path(version string) string {
	return filepath.Join(a.dir, version+ext)
}

// marshalPolicies is the archived form. It takes what Set.Policies() returns,
// which is already normalized, so two equivalent sets produce identical bytes
// and the collision check above compares like with like.
func marshalPolicies(policies []policy.Policy) ([]byte, error) {
	if policies == nil {
		policies = []policy.Policy{}
	}
	b, err := json.Marshal(policies)
	if err != nil {
		return nil, fmt.Errorf("archive: marshal policy set: %w", err)
	}
	return b, nil
}
