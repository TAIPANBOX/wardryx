package main

import (
	"html"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// A header the README or its diagrams name is one of two things: a header
// this service reads, or a header of the enforcement point in front of it, and
// then the sentence that names it says so by naming TokenFuse.
//
// Until 2026-10-13 the README's decision table said a hold is redeemed by
// resubmitting "with header `x-fuse-approval-token`", in the column that
// describes this service's own response, and docs/decisions.svg, the picture
// shown beside the table, carried the same sentence. Wardryx reads no such
// header: the token arrives in the approval_token field of the /v1/decide
// body. The header is TokenFuse's, which reads it from the agent's request and
// forwards its value in that field. A caller of /v1/decide that followed the
// table sent the token where nothing reads it and was held again.
//
// What is read: every line of README.md, code blocks included, and the text of
// every <text> element of docs/*.svg and assets/*.svg. A header is an x- name
// with at least two parts after the x (x-fuse-approval-token, x-api-key). The
// unit a header must be attributed in is one sentence of prose, one cell of a
// table row, one code line, or one diagram text: TokenFuse in another cell of
// the same row, or in the next sentence, does not count.
//
// What this does not read: whether the attributing sentence says the right
// thing about the header (naming TokenFuse is taken as attribution, the
// grammar is not read); a header spelled with a single part after x-; and the
// PNG renders of the diagrams, which are made from the SVGs and are not text.

var (
	headerNameRE = regexp.MustCompile(`(?i)\bx-[a-z0-9]+(?:-[a-z0-9]+)+\b`)
	headerReadRE = regexp.MustCompile(`\.Header\.(?:Get|Values)\("([^"]+)"\)`)
	svgTextRE    = regexp.MustCompile(`(?s)<text\b[^>]*>(.*?)</text>`)
	svgTagRE     = regexp.MustCompile(`<[^>]*>`)
)

// enforcementPoint is the name a unit must carry to attribute a header this
// service does not read.
const enforcementPoint = "TokenFuse"

// headersTheCodeReads returns, lower-cased, every header name a non-test Go
// file of this module reads with r.Header.Get or r.Header.Values and a literal.
func headersTheCodeReads(t *testing.T) map[string]bool {
	t.Helper()
	read := map[string]bool{}
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
		for _, m := range headerReadRE.FindAllStringSubmatch(string(src), -1) {
			read[strings.ToLower(m[1])] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}
	if len(read) == 0 {
		t.Fatal("found no r.Header.Get of any header anywhere in the module, not even Authorization: " +
			"this test measured nothing, which is not the same as passing")
	}
	return read
}

// headerUnit is one piece of text a header must be attributed within.
type headerUnit struct {
	where, text string
}

func readmeUnits(t *testing.T, path string) []headerUnit {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var units []headerUnit
	for i, line := range strings.Split(string(b), "\n") {
		where := filepath.Base(path) + ":" + strconv.Itoa(i+1)
		cells := []string{line}
		if strings.HasPrefix(strings.TrimSpace(line), "|") {
			cells = strings.Split(line, "|")
		}
		for _, cell := range cells {
			for _, sentence := range sentenceSplitRE.Split(cell, -1) {
				units = append(units, headerUnit{where, sentence})
			}
		}
	}
	return units
}

func svgUnits(t *testing.T, path string) []headerUnit {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var units []headerUnit
	for _, m := range svgTextRE.FindAllStringSubmatch(string(b), -1) {
		text := html.UnescapeString(svgTagRE.ReplaceAllString(m[1], ""))
		units = append(units, headerUnit{filepath.Base(path), text})
	}
	if len(units) == 0 {
		t.Fatalf("%s has no <text> element: this test measured nothing in it, which is not the same as passing", path)
	}
	return units
}

// checkHeaderAttribution returns every unit that names a header the code does
// not read without naming the enforcement point, and how many header names it
// examined, so a run that found none can refuse.
func checkHeaderAttribution(t *testing.T, readme string, svgs []string, read map[string]bool) (problems []string, examined int) {
	t.Helper()
	units := readmeUnits(t, readme)
	for _, svg := range svgs {
		units = append(units, svgUnits(t, svg)...)
	}
	for _, u := range units {
		for _, name := range headerNameRE.FindAllString(u.text, -1) {
			examined++
			if read[strings.ToLower(name)] || strings.Contains(u.text, enforcementPoint) {
				continue
			}
			problems = append(problems, u.where+": names header "+name+", which wardryx does not read, "+
				"in a sentence that does not say it is "+enforcementPoint+"'s: "+strconv.Quote(strings.TrimSpace(u.text)))
		}
	}
	return problems, examined
}

func diagramPaths(t *testing.T) []string {
	t.Helper()
	var paths []string
	for _, pattern := range []string{"../../docs/*.svg", "../../assets/*.svg"} {
		m, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("glob %s: %v", pattern, err)
		}
		paths = append(paths, m...)
	}
	if len(paths) == 0 {
		t.Fatal("found no diagram under docs/ or assets/: this test measured nothing in them, which is not the same as passing")
	}
	sort.Strings(paths)
	return paths
}

func TestReadmeNamesNoHeaderWardryxDoesNotRead(t *testing.T) {
	problems, examined := checkHeaderAttribution(t, readmePath, diagramPaths(t), headersTheCodeReads(t))
	if examined == 0 {
		t.Fatal("the README and the diagrams name no x- header at all: " +
			"this test measured nothing, which is not the same as passing")
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// Teeth: each case plants, into a copy of the real README or of a real
// diagram, one sentence and requires a problem naming the header, or, for a
// sentence that is true, none.
func TestReadmeHeaderCheckCatchesPlantedFaults(t *testing.T) {
	origReadme, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("reading %s: %v", readmePath, err)
	}
	const anchor = "## Testing\n"
	if strings.Count(string(origReadme), anchor) != 1 {
		t.Fatalf("plant anchor %q is not exactly once in the README; the plants would measure nothing", anchor)
	}
	const svgName = "../../docs/decisions.svg"
	origSVG, err := os.ReadFile(svgName)
	if err != nil {
		t.Fatalf("reading %s: %v", svgName, err)
	}
	const svgAnchor = "</svg>"
	if strings.Count(string(origSVG), svgAnchor) != 1 {
		t.Fatalf("plant anchor %q is not exactly once in %s; the plants would measure nothing", svgAnchor, svgName)
	}
	const preFixRow = "| `hold` | `est_cost_usd` exceeds a matched `require_human_above_usd`, or a signal satisfies a matched `hold_if_signal`, with no valid `approval_token` presented | HTTP 403 Forbidden; stateless, nothing blocks waiting on a human | `approval_id` issued; resubmit the same call with header `x-fuse-approval-token` to redeem the grant |\n\n"
	const want = "names header x-fuse-approval-token, which wardryx does not read"

	cases := []struct {
		name, readmePlant, svgPlant, extraRead, want string
	}{
		{name: "unchanged copies"},
		{name: "pre-2026-10-13: the decision table row", readmePlant: preFixRow, want: want},
		{name: "TokenFuse in another cell of the row does not attribute this one",
			readmePlant: strings.Replace(preFixRow, "HTTP 403 Forbidden;", "TokenFuse answers HTTP 403 Forbidden;", 1), want: want},
		{name: "TokenFuse in the next sentence does not attribute this one",
			readmePlant: "Resubmit the same call with header `x-fuse-approval-token` to redeem the grant. TokenFuse is the enforcement point.\n\n", want: want},
		{name: "a command line that sends the header to wardryx",
			readmePlant: "```\ncurl -X POST localhost:8090/v1/decide -H 'x-fuse-approval-token: tok'\n```\n\n", want: want},
		{name: "pre-2026-10-13: the diagram's hold card",
			svgPlant: `<text x="584" y="620">response: approval_id issued; resubmit the same call with header x-fuse-approval-token to redeem the grant</text>`, want: want},
		{name: "a sentence that attributes the header to TokenFuse is not a fault",
			readmePlant: "Behind TokenFuse an agent resubmits with the `x-fuse-approval-token` header, and TokenFuse forwards it as `approval_token`.\n\n"},
		{name: "a header the code reads needs no attribution",
			readmePlant: preFixRow, extraRead: "x-fuse-approval-token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			readme := filepath.Join(dir, "README.md")
			if err := os.WriteFile(readme, []byte(strings.Replace(string(origReadme), anchor, c.readmePlant+anchor, 1)), 0o600); err != nil {
				t.Fatal(err)
			}
			svg := filepath.Join(dir, "decisions.svg")
			if err := os.WriteFile(svg, []byte(strings.Replace(string(origSVG), svgAnchor, c.svgPlant+svgAnchor, 1)), 0o600); err != nil {
				t.Fatal(err)
			}
			read := headersTheCodeReads(t)
			if c.extraRead != "" {
				read[c.extraRead] = true
			}
			got, _ := checkHeaderAttribution(t, readme, []string{svg}, read)
			if c.want == "" {
				if len(got) != 0 {
					t.Fatalf("no fault planted, got problems: %q", got)
				}
				return
			}
			for _, p := range got {
				if strings.Contains(p, c.want) {
					return
				}
			}
			t.Fatalf("planted %q, want a problem containing %q, got %q", c.name, c.want, got)
		})
	}
}
