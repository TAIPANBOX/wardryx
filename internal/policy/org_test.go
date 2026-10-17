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
