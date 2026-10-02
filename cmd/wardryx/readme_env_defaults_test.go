package main

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/api"
	"github.com/TAIPANBOX/wardryx/internal/config"
)

// The README's environment table is the one place an operator reads what a
// variable does when it is left unset. It drifted once already: from 1.0
// (#53) until #78 its WARDRYX_APPROVAL_SINGLE_USE row said the default was
// false, the pre-1.0 reusable token, while the code had flipped to
// single-use. Nothing compared the two, so the README told an operator the
// replay-safe setting was something they had to opt into.
//
// This test holds the table to the code in both directions:
//
//   - the WARDRYX_* names the module reads (os.Getenv / os.LookupEnv with a
//     literal name, in any non-test Go file) are exactly the table's rows;
//   - every row's Default cell is the value the code arrives at with that
//     variable unset, derived from the code below, never restated;
//   - a row added without a derivation here, or a derivation left for a row
//     that is gone, is a failure, so a new variable cannot slip past.
//
// It refuses rather than passing when its subject is missing (no table, no
// rows, no reads found), per invariant 12.

const readmePath = "../../README.md"

// codeDefaults is what the code uses for each variable when it is unset.
// Every entry reads the code path the serve command takes; none of them is a
// copy of a literal.
func codeDefaults(t *testing.T) map[string]string {
	t.Helper()
	cfg := config.FromEnv()
	// The unanswered sweep: unset means the watcher runs with the server's
	// own default (main.go, runServe), which is this constant.
	unanswered := cfg.ApprovalUnanswered
	if !envSet("WARDRYX_APPROVAL_UNANSWERED_AFTER") {
		unanswered = api.DefaultUnansweredAfter
	}
	return map[string]string{
		"WARDRYX_ADDR":                      orDefault(cfg.Addr, serveAddrFallback(t)),
		"WARDRYX_KEYS":                      cfg.Keys,
		"WARDRYX_ALLOW_DEVKEY":              strconv.FormatBool(cfg.AllowDevkey),
		"WARDRYX_DB":                        cfg.DB,
		"WARDRYX_POLICY":                    cfg.Policy,
		"WARDRYX_EVENTS_PATH":               cfg.EventsPath,
		"WARDRYX_POLICY_ARCHIVE":            cfg.PolicyArchive,
		"WARDRYX_APPROVAL_SECRET":           cfg.ApprovalSecret,
		"WARDRYX_APPROVAL_SINGLE_USE":       strconv.FormatBool(cfg.ApprovalSingleUse),
		"WARDRYX_APPROVAL_UNANSWERED_AFTER": unanswered.String(),
		"WARDRYX_OTLP_ENDPOINT":             cfg.OTLPEndpoint,
	}
}

var addrFallbackRE = regexp.MustCompile(`orDefault\(cfg\.Addr,\s*"([^"]*)"\)`)

// serveAddrFallback is the literal runServe hands orDefault for -addr, read
// from main.go the same way internal/manifest reads it for components.json,
// so the README and the manifest are held to one value.
func serveAddrFallback(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("reading main.go: %v", err)
	}
	m := addrFallbackRE.FindStringSubmatch(string(src))
	if m == nil {
		t.Fatal("main.go no longer falls back for -addr through orDefault(cfg.Addr, \"...\"), " +
			"so the WARDRYX_ADDR default was measured against nothing")
	}
	return m[1]
}

var envReadRE = regexp.MustCompile(`os\.(?:Getenv|LookupEnv)\("(WARDRYX_[A-Z0-9_]+)"\)`)

// namesTheCodeReads walks the module's non-test Go files for literal
// WARDRYX_* reads.
func namesTheCodeReads(t *testing.T) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "vendor" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range envReadRE.FindAllStringSubmatch(string(src), -1) {
			names[m[1]] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}
	if len(names) == 0 {
		t.Fatal("found no os.Getenv/os.LookupEnv of a WARDRYX_* name anywhere in the module: " +
			"this test measured nothing, which is not the same as passing")
	}
	return names
}

var tableNameRE = regexp.MustCompile("^`(WARDRYX_[A-Z0-9_]+)`$")

// readmeDefaults parses the environment table: header
// "| Variable | Flag | Default | Meaning |", then one row per variable until
// the first line that is not a table row.
func readmeDefaults(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer f.Close()

	rows := map[string]string{}
	found := false
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !found {
			found = line == "| Variable | Flag | Default | Meaning |"
			continue
		}
		if !strings.HasPrefix(line, "|") {
			break
		}
		cells := strings.Split(strings.Trim(line, "|"), " | ")
		if strings.HasPrefix(strings.TrimSpace(cells[0]), "---") {
			continue
		}
		if len(cells) != 4 {
			t.Fatalf("%s: environment table row has %d cells, want 4: %s", path, len(cells), line)
		}
		m := tableNameRE.FindStringSubmatch(strings.TrimSpace(cells[0]))
		if m == nil {
			t.Fatalf("%s: environment table row does not name one `WARDRYX_*` variable: %s", path, line)
		}
		if _, dup := rows[m[1]]; dup {
			t.Fatalf("%s: %s has two rows in the environment table", path, m[1])
		}
		rows[m[1]] = strings.TrimSpace(cells[2])
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if !found {
		t.Fatalf("%s has no \"| Variable | Flag | Default | Meaning |\" table: "+
			"this test measured nothing, which is not the same as passing", path)
	}
	if len(rows) == 0 {
		t.Fatalf("%s: the environment table has no rows: this test measured nothing", path)
	}
	return rows
}

// cellValue turns a Default cell into the value it claims: "(empty)" is the
// empty string, a single backticked token is that token.
func cellValue(cell string) (string, bool) {
	if cell == "(empty)" {
		return "", true
	}
	if len(cell) >= 2 && strings.HasPrefix(cell, "`") && strings.HasSuffix(cell, "`") && strings.Count(cell, "`") == 2 {
		return cell[1 : len(cell)-1], true
	}
	return "", false
}

// sameValue compares a claimed default with the code's, reading both as Go
// durations when both parse as one ("15m" and "15m0s" are the same value).
func sameValue(claimed, code string) bool {
	if claimed == code {
		return true
	}
	a, errA := time.ParseDuration(claimed)
	b, errB := time.ParseDuration(code)
	return errA == nil && errB == nil && a == b
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// checkReadmeEnvDefaults returns every disagreement between the README at
// path and the code, so a planted fault can be asserted on without a
// second README on disk.
func checkReadmeEnvDefaults(t *testing.T, path string) []string {
	t.Helper()
	read := namesTheCodeReads(t)
	table := readmeDefaults(t, path)

	// Unset every name, so FromEnv and envSet see what an operator who set
	// nothing sees. t.Setenv first, so the original value comes back after.
	for name := range read {
		t.Setenv(name, "")
		os.Unsetenv(name)
	}
	derived := codeDefaults(t)

	var problems []string
	all := map[string]bool{}
	for n := range read {
		all[n] = true
	}
	for n := range table {
		all[n] = true
	}
	for n := range derived {
		all[n] = true
	}
	for _, n := range sortedKeys(all) {
		cell, inTable := table[n]
		code, inDerived := derived[n]
		switch {
		case read[n] && !inTable:
			problems = append(problems, n+": the code reads it and the README environment table has no row for it")
			continue
		case !read[n] && inTable:
			problems = append(problems, n+": the README environment table lists it and no code reads it")
			continue
		case !read[n] && inDerived:
			problems = append(problems, n+": codeDefaults derives a default for a variable no code reads; remove the entry")
			continue
		case !inDerived:
			problems = append(problems, n+": no derivation in codeDefaults; add one that reads the code path serve takes")
			continue
		}
		claimed, ok := cellValue(cell)
		if !ok {
			problems = append(problems, n+": Default cell "+strconv.Quote(cell)+" is neither (empty) nor one backticked value")
			continue
		}
		if !sameValue(claimed, code) {
			problems = append(problems, n+": README says the default is "+strconv.Quote(claimed)+
				", the code uses "+strconv.Quote(code))
		}
	}
	return problems
}

func TestReadmeEnvTableStatesTheDefaultsTheCodeUses(t *testing.T) {
	for _, p := range checkReadmeEnvDefaults(t, readmePath) {
		t.Error(p)
	}
}

// The check above is only worth something if it can go red. Each case plants
// one fault into a copy of the real README and requires the named problem;
// the unmodified copy must produce none, so the check does not fire on a
// non-fault either.
func TestReadmeEnvCheckCatchesPlantedFaults(t *testing.T) {
	orig, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("reading %s: %v", readmePath, err)
	}
	cases := []struct {
		name, from, to, want string
	}{
		{"unchanged copy", "", "", ""},
		{"single-use default written as the pre-1.0 false",
			"| (none) | `true` |", "| (none) | `false` |",
			`WARDRYX_APPROVAL_SINGLE_USE: README says the default is "false", the code uses "true"`},
		{"a row for a variable nothing reads",
			"| `WARDRYX_OTLP_ENDPOINT` |", "| `WARDRYX_NOBODY_READS_THIS` | (none) | (empty) | x |\n| `WARDRYX_OTLP_ENDPOINT` |",
			"WARDRYX_NOBODY_READS_THIS: the README environment table lists it and no code reads it"},
		{"a variable the code reads has lost its row",
			"| `WARDRYX_POLICY_ARCHIVE` | - | (empty) |", "| `WARDRYX_POLICY_ARCHIVE_X` | - | (empty) |",
			"WARDRYX_POLICY_ARCHIVE: the code reads it and the README environment table has no row for it"},
		{"a default written as prose",
			"| `-addr` | `:8090` |", "| `-addr` | port 8090 |",
			`WARDRYX_ADDR: Default cell "port 8090" is neither (empty) nor one backticked value`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := string(orig)
			if c.from != "" {
				if strings.Count(src, c.from) != 1 {
					t.Fatalf("plant site %q is not exactly once in the README; the plant would measure nothing", c.from)
				}
				src = strings.Replace(src, c.from, c.to, 1)
			}
			path := filepath.Join(t.TempDir(), "README.md")
			if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
				t.Fatal(err)
			}
			got := checkReadmeEnvDefaults(t, path)
			if c.want == "" {
				if len(got) != 0 {
					t.Fatalf("the unmodified README reports problems: %q", got)
				}
				return
			}
			for _, p := range got {
				if p == c.want {
					return
				}
			}
			t.Fatalf("planted %q, want problem %q, got %q", c.name, c.want, got)
		})
	}
}
