package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The environment table is held to the code by
// TestReadmeEnvTableStatesTheDefaultsTheCodeUses. The prose around it is not
// a table and cannot be parsed as one, and it is where the single-use default
// actually drifted: from 1.0 until #78, four places outside the table still
// described the pre-1.0 reusable token while the code was single-use.
//
// Those four were three shapes, and each is a claim this test can read
// without understanding English:
//
//   - set-to-default: "`WARDRYX_X=V`" where V is already X's default. An
//     operator never needs to be told to set a variable to the value it
//     already has; prose that does is describing an old default as an opt-in
//     ("set `WARDRYX_APPROVAL_SINGLE_USE=true` so each granted token redeems
//     exactly once", "`WARDRYX_APPROVAL_SINGLE_USE=true` with no -db").
//   - stated default: "`WARDRYX_X`, default V" (or "defaults to V", "default
//     is V") within a short span of the name, with nothing backticked in
//     between. V must be the code's default.
//   - optional-but-on: a switch whose default is ON called "optional" or
//     "opt-in" in a sentence naming it ("optional single-use redemption
//     (`WARDRYX_APPROVAL_SINGLE_USE`)").
//
// The environment table's own rows are skipped: they are the other test's
// subject. Everything else in the README is read, code blocks included,
// since a command line that sets a variable to its default makes the same
// false claim. So is the text of every <text> element of docs/*.svg and
// assets/*.svg, the diagrams the README shows: until 2026-10-13
// docs/modes.svg still said tokens are "reusable for the full TTL by default"
// and that WARDRYX_APPROVAL_SINGLE_USE=true makes each redeem once, a month
// after the default flipped (#53) and eleven days after #78 fixed the
// README's own sentences, because nothing read it.
//
// What this does not read: a default restated in words that name no variable
// ("tokens are reusable by default") and paraphrase in general. Those are
// left to review; the shapes above are the ones that drifted. Nor the PNG
// renders of the diagrams, which are made from the SVGs and are not text.

var (
	setToRE   = regexp.MustCompile("(WARDRYX_[A-Z0-9_]+)=(\"[^\"]*\"|'[^']*'|[^\\s`|),;]*)")
	statedRE  = regexp.MustCompile("`(WARDRYX_[A-Z0-9_]+)`[^`.;]{0,40}?\\bdefaults?\\b(?: to| is| of)?:?\\s*(?:`([^`]*)`|([^\\s`.,;)]+)(?:\\s+(seconds?|minutes?|hours?)\\b)?)")
	optionRE  = regexp.MustCompile(`(?i)\b(optional|optionally|opt-in|opt in)\b`)
	mentionRE = regexp.MustCompile("WARDRYX_[A-Z0-9_]+")
	// A sentence ends at a period followed by a space; a README line is
	// otherwise one paragraph or one list item.
	sentenceSplitRE = regexp.MustCompile(`\.\s+`)
)

// sameSetting reports whether two spellings of a setting are the same value:
// equal text, or both bools that agree ("1" and "true"), or both durations
// that agree ("15m" and "15m0s"). Bool is tried only when both sides parse as
// one, so "0" against a duration default compares as a duration.
func sameSetting(a, b string) bool {
	if a == b {
		return true
	}
	if x, errX := strconv.ParseBool(a); errX == nil {
		if y, errY := strconv.ParseBool(b); errY == nil {
			return x == y
		}
	}
	x, errX := time.ParseDuration(a)
	y, errY := time.ParseDuration(b)
	return errX == nil && errY == nil && x == y
}

func unquote(v string) string {
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

// proseLines returns every README line outside the environment table, with
// its 1-based line number.
func proseLines(t *testing.T, path string) map[int]string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	out := map[int]string{}
	inTable, sawTable := false, false
	for i, line := range strings.Split(string(b), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "| Variable | Flag | Default | Meaning |" {
			inTable, sawTable = true, true
			continue
		}
		if inTable {
			if strings.HasPrefix(trimmed, "|") {
				continue
			}
			inTable = false
		}
		out[i+1] = line
	}
	if !sawTable {
		t.Fatalf("%s has no environment table to skip; the line numbers this "+
			"test reports would include the table's rows, which another test owns", path)
	}
	return out
}

// checkReadmeProseDefaults returns every prose claim in the README at readme,
// or in a <text> of one of the diagrams at svgs, that contradicts the code's
// defaults, and how many claims of the three shapes it found, so a run that
// read none can refuse.
func checkReadmeProseDefaults(t *testing.T, readme string, svgs []string) (problems []string, examined int) {
	t.Helper()
	read := namesTheCodeReads(t)
	defaults := unsetAndDerive(t, read)
	lines := proseLines(t, readme)

	numbers := make([]int, 0, len(lines))
	for n := range lines {
		numbers = append(numbers, n)
	}
	sort.Ints(numbers)

	mentions := 0
	var units []headerUnit
	for _, n := range numbers {
		mentions += len(mentionRE.FindAllString(lines[n], -1))
		units = append(units, headerUnit{"README.md:" + strconv.Itoa(n), lines[n]})
	}
	if mentions == 0 {
		t.Fatalf("%s names no WARDRYX_* variable outside the environment table: "+
			"this test measured nothing, which is not the same as passing", readme)
	}
	for _, svg := range svgs {
		units = append(units, svgUnits(t, svg)...)
	}

	for _, u := range units {
		line := u.text
		at := func(msg string) { problems = append(problems, u.where+": "+msg) }

		for _, m := range setToRE.FindAllStringSubmatch(line, -1) {
			def, known := defaults[m[1]]
			if !known {
				continue // a name nothing reads is the table test's finding
			}
			examined++
			if v := unquote(m[2]); sameSetting(v, def) {
				at(m[1] + "=" + m[2] + " sets the variable to its own default (" + strconv.Quote(def) +
					"), which describes the default as something to opt into")
			}
		}

		for _, m := range statedRE.FindAllStringSubmatch(line, -1) {
			def, known := defaults[m[1]]
			if !known {
				continue
			}
			examined++
			v := m[2]
			if m[3] != "" {
				// A bare number with its unit in words, "default 15 minutes",
				// is the duration 15m.
				v = m[3] + map[string]string{"": "", "second": "s", "seconds": "s",
					"minute": "m", "minutes": "m", "hour": "h", "hours": "h"}[m[4]]
			}
			if !sameSetting(v, def) {
				at(m[1] + ": prose says the default is " + strconv.Quote(v) + ", the code uses " + strconv.Quote(def))
			}
		}

		for _, sentence := range sentenceSplitRE.Split(line, -1) {
			word := optionRE.FindString(sentence)
			if word == "" {
				continue
			}
			for _, name := range mentionRE.FindAllString(sentence, -1) {
				def, known := defaults[name]
				if !known {
					continue
				}
				examined++
				if on, err := strconv.ParseBool(def); err == nil && on {
					at(name + " is on by default, and a sentence naming it calls it " + strconv.Quote(word))
				}
			}
		}
	}
	return problems, examined
}

func TestReadmeProseNeverContradictsTheCodeDefaults(t *testing.T) {
	problems, examined := checkReadmeProseDefaults(t, readmePath, diagramPaths(t))
	if examined == 0 {
		t.Fatal("no prose claim of any of the three shapes was found in the README: " +
			"this test measured nothing, which is not the same as passing")
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// Teeth: each case plants, into a copy of the real README or of a real
// diagram, one sentence the README or the diagram actually carried before it
// was fixed, or a close variant of a shape, and requires a problem naming the
// variable. The unchanged copies and a planted sentence that is true must
// produce none.
func TestReadmeProseCheckCatchesPlantedFaults(t *testing.T) {
	orig, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("reading %s: %v", readmePath, err)
	}
	const anchor = "## Testing\n"
	if strings.Count(string(orig), anchor) != 1 {
		t.Fatalf("plant anchor %q is not exactly once in the README; the plants would measure nothing", anchor)
	}
	const svgName = "../../docs/modes.svg"
	origSVG, err := os.ReadFile(svgName)
	if err != nil {
		t.Fatalf("reading %s: %v", svgName, err)
	}
	const svgAnchor = "</svg>"
	if strings.Count(string(origSVG), svgAnchor) != 1 {
		t.Fatalf("plant anchor %q is not exactly once in %s; the plants would measure nothing", svgAnchor, svgName)
	}
	cases := []struct {
		name, plant, svgPlant, want string
	}{
		{name: "unchanged copies"},
		{name: "pre-2026-10-13: the modes diagram's approval-token line",
			svgPlant: `<text x="185" y="674" font-size="11.5">reusable for the full TTL by default (10 min); WARDRYX_APPROVAL_SINGLE_USE=true makes each granted token redeem exactly once</text>`,
			want:     "modes.svg: WARDRYX_APPROVAL_SINGLE_USE=true sets the variable to its own default"},
		{name: "a diagram text that calls an on-by-default switch optional",
			svgPlant: `<text x="185" y="674">optional single-use redemption (WARDRYX_APPROVAL_SINGLE_USE)</text>`,
			want:     `modes.svg: WARDRYX_APPROVAL_SINGLE_USE is on by default, and a sentence naming it calls it "optional"`},
		{name: "a true diagram text is not a fault",
			svgPlant: `<text x="185" y="674">single-use by default; WARDRYX_APPROVAL_SINGLE_USE=false makes a token reusable for its full TTL</text>`},
		{name: "a true sentence is not a fault",
			plant: "Set `WARDRYX_APPROVAL_SINGLE_USE=false` to reuse a token (`WARDRYX_APPROVAL_UNANSWERED_AFTER`, default 15m).\n\n"},
		{name: "pre-#78: the old default as an opt-in",
			plant: "Approval tokens are reusable for the full TTL by default (10 minutes), or set `WARDRYX_APPROVAL_SINGLE_USE=true` so each granted token redeems exactly once.\n\n",
			want:  "WARDRYX_APPROVAL_SINGLE_USE=true sets the variable to its own default"},
		{name: "pre-#78: the caveat tied to an explicit true",
			plant: "- `WARDRYX_APPROVAL_SINGLE_USE=true` with no `-db`/`WARDRYX_DB` only enforces single-use within that one process.\n\n",
			want:  "WARDRYX_APPROVAL_SINGLE_USE=true sets the variable to its own default"},
		{name: "pre-#78: on by default, called optional",
			plant: "- [x] Stateless human-in-the-loop: HMAC-signed approval tokens, configurable TTL, optional single-use redemption (`WARDRYX_APPROVAL_SINGLE_USE`)\n\n",
			want:  `WARDRYX_APPROVAL_SINGLE_USE is on by default, and a sentence naming it calls it "optional"`},
		{name: "a stated default the code does not use",
			plant: "The sweep (`WARDRYX_APPROVAL_UNANSWERED_AFTER`, default 10m) reports and never decides.\n\n",
			want:  `WARDRYX_APPROVAL_UNANSWERED_AFTER: prose says the default is "10m", the code uses "15m0s"`},
		{name: "a stated default with its unit in words",
			plant: "Once a hold is older than `WARDRYX_APPROVAL_UNANSWERED_AFTER` (a Go duration, default 10 minutes), it is reported.\n\n",
			want:  `WARDRYX_APPROVAL_UNANSWERED_AFTER: prose says the default is "10m", the code uses "15m0s"`},
		{name: "a stated bool default in backticks",
			plant: "`WARDRYX_APPROVAL_SINGLE_USE` defaults to `false`.\n\n",
			want:  `WARDRYX_APPROVAL_SINGLE_USE: prose says the default is "false", the code uses "true"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "README.md")
			if err := os.WriteFile(path, []byte(strings.Replace(string(orig), anchor, c.plant+anchor, 1)), 0o600); err != nil {
				t.Fatal(err)
			}
			svg := filepath.Join(dir, "modes.svg")
			if err := os.WriteFile(svg, []byte(strings.Replace(string(origSVG), svgAnchor, c.svgPlant+svgAnchor, 1)), 0o600); err != nil {
				t.Fatal(err)
			}
			got, _ := checkReadmeProseDefaults(t, path, []string{svg})
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
