package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The floor and the grant are read from a file, so most of what can go wrong with
// them goes wrong here: a key that loads and means nothing, a blank that reads as a
// choice, a grant that reaches agents nobody named.

func loadText(t *testing.T, name, doc string) (*Set, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func mustLoadText(t *testing.T, name, doc string) *Set {
	t.Helper()
	set, err := loadText(t, name, doc)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return set
}

// richPolicies sets every field a policy had before the floor, in a file that has
// neither of the two new keys.
const richPolicies = `- name: support-floor
  target: "agent://acme.example/support/*"
  org: acme
  deny_tool: [wire_transfer, shell_exec]
  allow_tool: [search, s3.get_object]
  allow_models: ["claude-*"]
  allow_domains: [api.example.com]
  require_human_above_usd: 5
  deny_above_usd: 100
  max_steps: 50
  deny_if_unattested: true
  require_identity_source: [agent-token, client-key]
  deny_if_chain_unproven: true
  max_chain_depth: 3
  require_root_principal: "user://acme.example/*"
  hold_if_signal:
    name: action.risk_class
    values: [destructive, financial]
    min_probability: 0.8
    when_absent: hold
- name: fleet
  target: "agent://*"
  max_steps: 200
`

// TestAFileWithNeitherFieldKeepsItsPolicyVersion holds the sentence this change is
// allowed to ship on: a file that does not name the floor is the same file. The
// golden values were measured on the tree before the fields existed (5ca25ae).
func TestAFileWithNeitherFieldKeepsItsPolicyVersion(t *testing.T) {
	if got := mustLoadText(t, "rich.yaml", richPolicies).Version(); got != "a62f232c7cb7" {
		t.Errorf("a file with every older field has version %s, measured a62f232c7cb7 before the fields", got)
	}
	if got := Empty().Version(); got != "4f53cda18c2b" {
		t.Errorf("the empty set has version %s, measured 4f53cda18c2b before the fields", got)
	}
	set, err := Load(filepath.Join("..", "..", "docs", "examples", "hold-while-the-budget-is-spent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if got := set.Version(); got != "b4d043f8cd62" {
		t.Errorf("the budget example has version %s, measured b4d043f8cd62 before the fields", got)
	}
}

func TestWhenNoGrantAllowIsTheDefaultAndKeepsTheVersion(t *testing.T) {
	plain := mustLoadText(t, "a.yaml", "name: p\ntarget: \"*\"\nmax_steps: 3\n")
	allow := mustLoadText(t, "b.yaml", "name: p\ntarget: \"*\"\nmax_steps: 3\nwhen_no_grant: allow\n")
	if plain.Version() != allow.Version() {
		t.Fatalf("when_no_grant: allow has version %s and leaving it out %s: they are one policy", allow.Version(), plain.Version())
	}
	if got := allow.Policies()[0].WhenNoGrant; got != "" {
		t.Fatalf("allow is stored as %q, want the default, empty", got)
	}
	hold := mustLoadText(t, "c.yaml", "name: p\ntarget: \"*\"\nmax_steps: 3\nwhen_no_grant: hold\n")
	if hold.Version() == plain.Version() {
		t.Fatal("a floor left the PolicyVersion unchanged: a decision under it could not be told from one before it")
	}
}

func TestWhenNoGrantTakesOnlyHoldOrAllow(t *testing.T) {
	cases := []struct {
		name, ext, doc, want string
	}{
		{"deny in YAML", "yaml", "name: p\ntarget: \"*\"\nwhen_no_grant: deny\n", "never denied"},
		{"deny in JSON", "json", `{"name":"p","target":"*","when_no_grant":"deny"}`, "never denied"},
		{"DENY folded", "yaml", "name: p\ntarget: \"*\"\nwhen_no_grant: \" DENY \"\n", "never denied"},
		{"unknown word", "yaml", "name: p\ntarget: \"*\"\nwhen_no_grant: maybe\n", "not one of hold or allow"},
		{"another case", "yaml", "name: p\ntarget: \"*\"\nwhen_no_grant: Hold\n", "not one of hold or allow"},
		{"padded", "json", `{"name":"p","target":"*","when_no_grant":" hold"}`, "not one of hold or allow"},
		{"no value", "yaml", "name: p\ntarget: \"*\"\nwhen_no_grant:\n", "written as text"},
		{"null in YAML", "yaml", "name: p\ntarget: \"*\"\nwhen_no_grant: null\n", "written as text"},
		{"tilde", "yaml", "name: p\ntarget: \"*\"\nwhen_no_grant: ~\n", "written as text"},
		{"empty text in YAML", "yaml", "name: p\ntarget: \"*\"\nwhen_no_grant: \"\"\n", "written as text"},
		{"blank text in YAML", "yaml", "name: p\ntarget: \"*\"\nwhen_no_grant: \"  \"\n", "written as text"},
		{"a boolean", "yaml", "name: p\ntarget: \"*\"\nwhen_no_grant: true\n", "written as text"},
		{"a number", "yaml", "name: p\ntarget: \"*\"\nwhen_no_grant: 1\n", "written as text"},
		{"a list", "yaml", "name: p\ntarget: \"*\"\nwhen_no_grant: [hold]\n", "written as text"},
		{"inside a list", "yaml", "- name: p\n  target: \"*\"\n  when_no_grant:\n", "written as text"},
		{"in the second document", "yaml", "name: a\ntarget: \"*\"\n---\nname: b\ntarget: \"*\"\nwhen_no_grant:\n", "written as text"},
		{"null in JSON", "json", `{"name":"p","target":"*","when_no_grant":null}`, "written as text"},
		{"empty in JSON", "json", `{"name":"p","target":"*","when_no_grant":""}`, "written as text"},
		{"a number in JSON", "json", `{"name":"p","target":"*","when_no_grant":1}`, "written as text"},
		{"null inside a JSON list", "json", `[{"name":"p","target":"*","when_no_grant":null}]`, "written as text"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := loadText(t, "p."+c.ext, c.doc)
			if err == nil {
				t.Fatalf("loaded: a value that is not hold or allow must not read as a choice")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("refused with %q, want a sentence saying %q", err, c.want)
			}
		})
	}
}

func TestCompileChecksWhenNoGrantOnAPolicyBuiltInGo(t *testing.T) {
	for _, bad := range []NoGrantAction{"deny", "soon", " hold", "   "} {
		if _, err := Compile([]Policy{{Target: "*", WhenNoGrant: bad}}); err == nil {
			t.Errorf("Compile accepted when_no_grant %q", bad)
		}
	}
	for _, good := range []NoGrantAction{"", WhenNoGrantAllow, WhenNoGrantHold} {
		if _, err := Compile([]Policy{{Target: "*", WhenNoGrant: good}}); err != nil {
			t.Errorf("Compile refused when_no_grant %q: %v", good, err)
		}
	}
}

func TestAFloorAndAGrantInOnePolicyAreRefused(t *testing.T) {
	_, err := loadText(t, "p.yaml", "name: both\ntarget: agent://acme.example/*\nwhen_no_grant: hold\ngrant_tool: [ask]\n")
	if err == nil || !strings.Contains(err.Error(), "policies of their own") {
		t.Fatalf("load: %v, want a refusal saying to write two policies", err)
	}
	// allow is no floor, so the same line with allow is a grant and nothing else.
	if _, err := loadText(t, "q.yaml", "name: both\ntarget: agent://acme.example/*\nwhen_no_grant: allow\ngrant_tool: [ask]\n"); err != nil {
		t.Fatalf("when_no_grant: allow beside a grant was refused: %v", err)
	}
}

func TestPinsTrustDomain(t *testing.T) {
	cases := map[string]bool{
		"agent://acme.example":               true,
		"agent://acme.example/":              true,
		"agent://acme.example/*":             true,
		"agent://acme.example/agents/worker": true,
		"agent://acme.example/a?b":           true,
		"agent://mockryx.local/*":            true,
		"*":                                  false,
		"":                                   false,
		"agent://":                           false,
		"agent://*":                          false,
		"agent://*/x":                        false,
		"agent://ac*/x":                      false,
		"agent://ac?me/x":                    false,
		"agent://acme.example*":              false,
		"agent://acme.example*/x":            false,
		"AGENT://acme.example/*":             false,
		"aws-comparable-agent":               false,
		"user://acme.example/x":              false,
		" agent://acme.example/x":            false,
	}
	for target, want := range cases {
		if got := PinsTrustDomain(target); got != want {
			t.Errorf("PinsTrustDomain(%q) = %v, want %v", target, got, want)
		}
	}
}

func TestAGrantOnATargetWithNoTrustDomainIsRefusedAtLoad(t *testing.T) {
	for _, target := range []string{"*", "agent://*", "agent://*/x", "agent://ac*/x", "aws-comparable-agent", "AGENT://acme.example/*"} {
		_, err := Compile([]Policy{{Name: "g", Target: target, GrantTool: []string{"ask"}}})
		if err == nil {
			t.Errorf("grant_tool on %q loaded", target)
			continue
		}
		for _, want := range []string{"grant_tool", target, "agent://<domain>"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("refusal for %q says %q, want it to name %q", target, err, want)
			}
		}
	}
	for _, target := range []string{"agent://acme.example", "agent://acme.example/*", "agent://acme.example/agents/operator"} {
		if _, err := Compile([]Policy{{Name: "g", Target: target, GrantTool: []string{"*"}}}); err != nil {
			t.Errorf("grant_tool on %q refused: %v", target, err)
		}
	}
}

func TestAMalformedGrantToolEntryIsRefusedWithWhatToWrite(t *testing.T) {
	cases := []struct {
		list []string
		want string
	}{
		{[]string{""}, "blank entry"},
		{[]string{"   "}, "blank entry"},
		{[]string{"ask", ""}, "blank entry"},
		{[]string{"fetch*"}, "not a glob"},
		{[]string{"*fetch"}, "not a glob"},
		{[]string{"**"}, "not a glob"},
	}
	for _, c := range cases {
		_, err := Compile([]Policy{{Name: "g", Target: "agent://acme.example/*", GrantTool: c.list}})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("grant_tool %q: %v, want a refusal saying %q", c.list, err, c.want)
		}
		if err != nil && !strings.Contains(err.Error(), `"*"`) {
			t.Errorf("grant_tool %q: the refusal %q does not say what to write", c.list, err)
		}
	}
	for _, list := range [][]string{{"*"}, {" * "}, {"fetch_url", "browse"}} {
		if _, err := Compile([]Policy{{Name: "g", Target: "agent://acme.example/*", GrantTool: list}}); err != nil {
			t.Errorf("grant_tool %q refused: %v", list, err)
		}
	}
}

func TestAGrantListIsPartOfThePolicyVersionAndItsOrderIsNot(t *testing.T) {
	version := func(list ...string) string {
		set, err := Compile([]Policy{{Name: "g", Target: "agent://acme.example/*", GrantTool: list}})
		if err != nil {
			t.Fatal(err)
		}
		return set.Version()
	}
	if version("a", "b") != version("b", "a", "a") {
		t.Fatal("the order of a grant list changed the version: two reads of one rule must compare equal")
	}
	if version("a") == version("a", "b") {
		t.Fatal("a wider grant kept the version: a decision under it could not be told from one before it")
	}
}

func TestBothFieldsLoadFromYAMLAndJSONAndThroughTheLaxDecoder(t *testing.T) {
	floorYAML := mustLoadText(t, "f.yaml", "name: floor\ntarget: \"*\"\nwhen_no_grant: hold\n---\nname: g\ntarget: agent://acme.example/*\ngrant_tool: [b, a]\n")
	floorJSON := mustLoadText(t, "f.json", `[{"name":"floor","target":"*","when_no_grant":"hold"},{"name":"g","target":"agent://acme.example/*","grant_tool":["a","b"]}]`)
	if floorYAML.Version() != floorJSON.Version() {
		t.Fatalf("one set read from YAML and JSON has versions %s and %s", floorYAML.Version(), floorJSON.Version())
	}
	// The way the store and the archive read: json.Unmarshal, no strict field
	// check. A round trip through it must not lose either field.
	raw, err := json.Marshal(floorYAML.Policies())
	if err != nil {
		t.Fatal(err)
	}
	var back []Policy
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("the lax decoder refused what the set marshals to: %v", err)
	}
	again, err := Compile(back)
	if err != nil {
		t.Fatal(err)
	}
	if again.Version() != floorYAML.Version() {
		t.Fatalf("a round trip moved the version from %s to %s: an archived floor would not come back", floorYAML.Version(), again.Version())
	}
}

func TestAMisspelledFieldBesideTheFloorIsStillRefused(t *testing.T) {
	// The check for a blank floor reads the document as nodes first; it must not
	// be what takes the strict field check away.
	if _, err := loadText(t, "p.yaml", "name: p\ntarget: \"*\"\nwhen_no_grant: hold\ngrant_tools: [ask]\n"); err == nil ||
		!strings.Contains(err.Error(), "grant_tools") {
		t.Fatalf("load: %v, want the misspelled key named", err)
	}
}

func TestAFloorIsAWayAHoldCanHappen(t *testing.T) {
	set, err := Compile([]Policy{{Target: "*", WhenNoGrant: WhenNoGrantHold}})
	if err != nil {
		t.Fatal(err)
	}
	if !set.RequiresHumanApproval() {
		t.Fatal("a set with a floor says no hold can happen, so serve would not warn about a missing approval secret")
	}
	set, err = Compile([]Policy{{Target: "agent://acme.example/*", GrantTool: []string{"ask"}}, {Target: "*", WhenNoGrant: WhenNoGrantAllow}})
	if err != nil {
		t.Fatal(err)
	}
	if set.RequiresHumanApproval() {
		t.Fatal("a grant and a floor of allow hold nothing, and the warning would be false")
	}
}

func TestNormalizeHandsOutItsOwnGrantList(t *testing.T) {
	in := []string{"b", "a"}
	set, err := Compile([]Policy{{Target: "agent://acme.example/*", GrantTool: in}})
	if err != nil {
		t.Fatal(err)
	}
	in[0] = "wire_transfer"
	if got := set.Policies()[0].GrantTool; got[0] != "a" || got[1] != "b" {
		t.Fatalf("editing the caller's slice reached the compiled set: %q", got)
	}
}
