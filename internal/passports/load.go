// Package passports loads a directory (or glob) of Agent Passport JSON
// documents for Wardryx's offline `check` command.
//
// agent-stack-go's passport package (the shared wire contract) exposes only
// Parse for one document; it deliberately carries no directory-walking
// helper of its own. This package adds exactly that, mirroring the
// resolve-then-parse shape and tolerant-batch semantics of Idryx's
// internal/ingest/passport connector -- which agent-stack-go's own doc
// comment names as the package it publicly mirrors -- so a batch of
// operator-supplied passport files behaves the same way here as it does in
// the rest of the TAIPANBOX stack: one malformed file is counted and
// skipped, never fatal to the rest of the batch.
package passports

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/TAIPANBOX/agent-stack-go/passport"
)

// Report summarizes one Load call: how many passport files were attempted
// and how many were malformed and skipped.
type Report struct {
	Files     int
	Malformed int
}

// Load reads every Passport document reachable from dirOrGlob and parses
// each with passport.Parse.
//
// dirOrGlob is, in order of precedence:
//  1. an existing directory -- every "*.json" file directly inside it
//     (non-recursive) is read;
//  2. a glob pattern such as "passports/*.json";
//  3. otherwise tried as a literal file path, so a genuinely missing input
//     still produces a clear I/O error rather than a silently empty batch.
//
// Files are processed in sorted-path order for a deterministic result. A
// file that fails passport.Parse is counted in Report.Malformed and
// skipped; it never aborts the rest of the batch. Load only returns an
// error for I/O failures (a bad glob pattern or an unreadable
// directory/file); content problems are tolerated and surfaced in the
// returned Report instead.
//
// A duplicate agent id across two files keeps only the first occurrence in
// sorted-path order, so Load's output is deterministic.
func Load(dirOrGlob string) ([]passport.Passport, Report, error) {
	matches, err := resolve(dirOrGlob)
	if err != nil {
		return nil, Report{}, err
	}
	sort.Strings(matches)

	rep := Report{}
	seen := map[string]bool{}
	var out []passport.Passport
	for _, path := range matches {
		data, err := os.ReadFile(path) // #nosec G304 -- path is an operator-supplied CLI argument/glob/directory listing, not untrusted input
		if err != nil {
			return nil, Report{}, fmt.Errorf("passports: read %s: %w", path, err)
		}
		rep.Files++
		p, err := passport.Parse(data)
		if err != nil {
			rep.Malformed++
			continue
		}
		if seen[p.ID] {
			continue
		}
		seen[p.ID] = true
		out = append(out, p)
	}
	return out, rep, nil
}

// resolve expands dirOrGlob into the list of passport files to read, per
// Load's documented precedence.
func resolve(dirOrGlob string) ([]string, error) {
	if info, err := os.Stat(dirOrGlob); err == nil && info.IsDir() {
		matches, err := filepath.Glob(filepath.Join(dirOrGlob, "*.json"))
		if err != nil {
			return nil, fmt.Errorf("passports: bad directory %q: %w", dirOrGlob, err)
		}
		return matches, nil
	}
	matches, err := filepath.Glob(dirOrGlob)
	if err != nil {
		return nil, fmt.Errorf("passports: bad glob %q: %w", dirOrGlob, err)
	}
	if len(matches) == 0 {
		matches = []string{dirOrGlob}
	}
	return matches, nil
}
