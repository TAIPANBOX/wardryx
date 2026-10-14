package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// allow_models is a list of model names and globs. These tests hold how it is
// read: from a file, through the lax decoder the policy API uses, its blank
// entries, and what it does to the PolicyVersion every decision names.

const fleetHead = "name: fleet\ntarget: \"agent://acme.example/fleet/*\"\n"

func loadDoc(t *testing.T, name, doc string) (*Set, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

// modelsOf reads the compiled list back through the policy's wire form, the
// way a GET returns it.
func modelsOf(t *testing.T, set *Set) []string {
	t.Helper()
	raw, err := json.Marshal(set.Policies()[0])
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		AllowModels []string `json:"allow_models"`
	}
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	return back.AllowModels
}

func TestAllowModelsLoadsFromYAMLAndJSONAndThroughTheLaxDecoder(t *testing.T) {
	want := "claude-sonnet-*,gpt-6-mini"
	set, err := loadDoc(t, "p.yaml", fleetHead+"allow_models: [gpt-6-mini, \"claude-sonnet-*\", gpt-6-mini]\n")
	if err != nil {
		t.Fatalf("YAML: %v", err)
	}
	if got := strings.Join(modelsOf(t, set), ","); got != want {
		t.Fatalf("YAML compiled allow_models to %q, want %q (sorted, deduplicated)", got, want)
	}
	set, err = loadDoc(t, "p.json", `{"name":"fleet","target":"agent://acme.example/fleet/*","allow_models":["claude-sonnet-*","gpt-6-mini"]}`)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if got := strings.Join(modelsOf(t, set), ","); got != want {
		t.Fatalf("JSON compiled allow_models to %q, want %q", got, want)
	}
	var p Policy
	if err := json.Unmarshal([]byte(`{"name":"fleet","target":"agent://acme.example/fleet/*","allow_models":["gpt-6-mini"]}`), &p); err != nil {
		t.Fatal(err)
	}
	set, err = Compile([]Policy{p})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(modelsOf(t, set), ","); got != "gpt-6-mini" {
		t.Fatalf("the lax decoder dropped allow_models: compiled to %q", got)
	}
}

// Normalization drops blank entries, so a list holding only a blank would
// become empty, which reads as no restriction. It is refused instead, in a
// file and through the lax decoder alike.
func TestABlankAllowModelsEntryIsRefusedAtLoad(t *testing.T) {
	for name, list := range map[string]string{
		"only an empty string": `[""]`,
		"only spaces":          `["  "]`,
		"blank beside a name":  `["gpt-6-mini", ""]`,
	} {
		_, err := loadDoc(t, "p.json", `{"name":"fleet","target":"agent://acme.example/fleet/*","allow_models":`+list+`}`)
		if err == nil || !strings.Contains(err.Error(), "allow_models") {
			t.Errorf("%s: a file with allow_models %s: %v, want a refusal naming allow_models", name, list, err)
		}
		var p Policy
		_ = json.Unmarshal([]byte(`{"name":"fleet","target":"agent://acme.example/fleet/*","allow_models":`+list+`}`), &p)
		if _, err := Compile([]Policy{p}); err == nil || !strings.Contains(err.Error(), "allow_models") {
			t.Errorf("%s: Compile after the lax decoder: %v, want a refusal naming allow_models", name, err)
		}
	}
}

// The golden value was measured on main before allow_models existed, with this
// same file. A policy that does not use the key must hash exactly as it did.
func TestAPolicyWithoutAllowModelsKeepsItsPolicyVersion(t *testing.T) {
	const before = "6d65066ede09"
	doc := fleetHead + "deny_tool: [shell]\nallow_tool: [search, lookup]\nrequire_human_above_usd: 5\nmax_steps: 40\n"
	set, err := loadDoc(t, "p.yaml", doc)
	if err != nil {
		t.Fatal(err)
	}
	if got := set.Version(); got != before {
		t.Fatalf("PolicyVersion = %q, want %q: a policy with no allow_models must hash as it did before the key existed", got, before)
	}
	empty, err := loadDoc(t, "q.yaml", doc+"allow_models: []\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := empty.Version(); got != before {
		t.Fatalf("an empty allow_models moved the PolicyVersion to %q (was %q): an empty list restricts nothing and is the same rule", got, before)
	}
}

// The list is a rule, so changing it changes the version; the order its entries
// are written in is not, so it must not.
func TestAnAllowModelsListIsPartOfThePolicyVersionAndItsOrderIsNot(t *testing.T) {
	version := func(list string) string {
		t.Helper()
		set, err := loadDoc(t, "p.yaml", fleetHead+"allow_models: "+list+"\n")
		if err != nil {
			t.Fatalf("allow_models %s: %v", list, err)
		}
		return set.Version()
	}
	written := version(`[gpt-6-mini, "claude-*", gpt-6-mini]`)
	if reordered := version(`["claude-*", gpt-6-mini]`); reordered != written {
		t.Fatalf("the same list in another order has version %q, want %q", reordered, written)
	}
	if narrower := version(`[gpt-6-mini]`); narrower == written {
		t.Fatalf("a narrower list kept the version %q", written)
	}
}
