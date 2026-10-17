package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

// F-012, the policy half: a policy may carry the org it belongs to. A policy
// that names none applies across orgs, which is every policy written before
// the field existed, so none of them may hash differently.

func TestAPolicyWithoutAnOrgKeepsItsPolicyVersion(t *testing.T) {
	// Golden values measured on the tree before the org field existed
	// (1f6a02c), with this same test.
	cases := []struct {
		name, file, doc, before string
	}{
		{"one yaml policy", "a.yaml", fleetHead + "deny_tool: [shell]\nallow_tool: [search, lookup]\nrequire_human_above_usd: 5\nmax_steps: 40\n", "6d65066ede09"},
		{"two documents, one target", "b.yaml", "name: b\ntarget: \"agent://acme.example/*\"\ndeny_tool: [x]\n---\nname: a\ntarget: \"agent://acme.example/*\"\nallow_domains: [ok.example]\n", "17539d76241d"},
		{"a json list", "c.json", `[{"name":"z","target":"agent://*","deny_above_usd":0},{"target":"agent://b.example/*","deny_if_unattested":true}]`, "37f7b253885e"},
	}
	for _, c := range cases {
		set, err := loadDoc(t, c.file, c.doc)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := set.Version(); got != c.before {
			t.Errorf("%s: PolicyVersion = %q, want %q: a policy with no org must hash as it did before the field existed", c.name, got, c.before)
		}
	}
}

func TestABlankOrPaddedOrgIsRefusedAtLoad(t *testing.T) {
	for _, org := range []string{`"  "`, `" acme"`, `"acme "`, `"ac\tme"`} {
		_, err := loadDoc(t, "p.yaml", fleetHead+"org: "+org+"\n")
		if err == nil || !strings.Contains(err.Error(), "org") {
			t.Errorf("org %s: err = %v, want a refusal naming org", org, err)
		}
	}
	set, err := loadDoc(t, "p.yaml", fleetHead+"org: acme\n")
	if err != nil {
		t.Fatalf("org acme: %v", err)
	}
	raw, err := json.Marshal(set.Policies()[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"org":"acme"`) {
		t.Fatalf("the compiled policy is %s, want it to carry org acme", raw)
	}
	if set.Version() == mustVersion(t, fleetHead) {
		t.Fatalf("a policy with an org has the version of the same policy across orgs")
	}
}

func mustVersion(t *testing.T, doc string) string {
	t.Helper()
	set, err := loadDoc(t, "v.yaml", doc)
	if err != nil {
		t.Fatal(err)
	}
	return set.Version()
}

// MatchIn is Match narrowed to the policies that govern a decision asked in
// one org: those of that org and those across orgs, never another org's.
func TestMatchInReadsOnlyThePoliciesOfTheOrgAskedIn(t *testing.T) {
	set, err := Compile([]Policy{
		{Name: "across", Target: "agent://*"},
		{Name: "acme", Target: "agent://*", Org: "acme"},
		{Name: "globex", Target: "agent://*", Org: "globex"},
		{Name: "elsewhere", Target: "agent://other.example/*", Org: "acme"},
	})
	if err != nil {
		t.Fatal(err)
	}
	names := func(ps []Policy) string {
		var out []string
		for _, p := range ps {
			out = append(out, p.Name)
		}
		return strings.Join(out, ",")
	}
	for org, want := range map[string]string{"acme": "acme,across", "globex": "across,globex", "": "across", "initech": "across"} {
		if got := names(set.MatchIn("agent://acme.example/bot", org)); got != want {
			t.Errorf("MatchIn(%q) = %s, want %s", org, got, want)
		}
	}
	re, err := CompileGlob("agent://acme.example/*")
	if err != nil || !re.MatchString("agent://acme.example/a/b") || re.MatchString("agent://acme.example.evil/x") {
		t.Fatalf("CompileGlob reads a pattern unlike a target: %v", err)
	}
	if _, err := CompileGlob(""); err == nil {
		t.Fatalf("CompileGlob accepted an empty pattern")
	}
}
