// Package passports loads a directory (or glob) of Agent Passport JSON
// documents for Wardryx's offline `check` command.
//
// This is a thin wrapper over agent-stack-go/passport's LoadDir, which
// carries the actual resolve-then-parse-then-dedupe shape shared with
// Idryx's internal/ingest/passport connector: one malformed file is counted
// and skipped, never fatal to the rest of the batch.
package passports

import "github.com/TAIPANBOX/agent-stack-go/passport"

// Report summarizes one Load call: how many passport files were attempted
// and how many were malformed and skipped.
type Report = passport.Report

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
	return passport.LoadDir(dirOrGlob, passport.Parse, func(p passport.Passport) string { return p.ID })
}
