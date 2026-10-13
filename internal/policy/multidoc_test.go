package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests hold features/multi-document-policy-file.feature: a YAML policy
// file may hold several documents separated by "---", and every one of them is
// a policy in force. Before this change decodeYAML read the first document and
// stopped, so a rule in the second was dropped with no error. A dropped deny is
// a silent allow, which is why each test below asserts the rule itself and not
// only that the load did not fail.

// writePolicyFile writes content to a file of the given name under a test
// directory and returns its path. The name carries the extension, because
// decode dispatches on it.
func writePolicyFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// The scenario "Every document loads, in order": one policy, then a list of
// two, then one policy. Four policies are in force, and the order of the file
// is the order they compile in.
func TestEveryDocumentOfAFileLoads(t *testing.T) {
	path := writePolicyFile(t, "three.yaml",
		"name: first\ntarget: \"agent://a.example/*\"\n"+
			"---\n"+
			"- name: second\n  target: \"agent://b.example/*\"\n"+
			"- name: third\n  target: \"agent://c.example/*\"\n"+
			"---\n"+
			"name: fourth\ntarget: \"agent://d.example/*\"\n")
	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := set.Len(); got != 4 {
		t.Fatalf("Len = %d, want 4: a rule in a document after the first was dropped, and the file loaded smaller than it reads", got)
	}
	for _, target := range []string{"agent://a.example/x", "agent://b.example/x", "agent://c.example/x", "agent://d.example/x"} {
		if m := set.Match(target); len(m) != 1 {
			t.Errorf("Match(%q) = %d policies, want 1: the policy that targets it was not loaded", target, len(m))
		}
	}
}

// The scenario "An empty document is skipped". An empty document in the
// middle and a trailing separator with nothing after it both count as no
// policy: neither is an error, and neither is a policy with no target.
func TestAnEmptyDocumentIsSkippedNotCountedAsAPolicy(t *testing.T) {
	src := "name: a\ntarget: \"agent://a.example/*\"\n" +
		"---\n" +
		"---\n" +
		"name: c\ntarget: \"agent://c.example/*\"\n" +
		"---\n"
	got, err := decodeYAML([]byte(src))
	if err != nil {
		t.Fatalf("empty documents must not be an error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("decoded %d policies, want 2: the document after an empty one was dropped, or an empty document was counted", len(got))
	}
	for _, p := range got {
		if p.Target == "" {
			t.Fatalf("an empty document decoded to a policy with no target: %+v", p)
		}
	}
}

// The scenario "A malformed document fails the whole file, naming it". The
// first document is a valid policy. The second is not, and the file must fail
// as a whole: a loader that kept the first document and reported success would
// leave the second document's rules out of force with no message. Two shapes of
// bad second document are covered, because they are caught at different points:
// a syntax error by the pass that counts the documents, and a value of the
// wrong type by the pass that reads each one as a policy.
func TestAMalformedDocumentFailsTheWholeFileNamingIt(t *testing.T) {
	cases := []struct {
		name, second string
	}{
		{"a syntax error", "target: [this is not a valid policy shape\n"},
		{"a value of the wrong type", "target: \"agent://b.example/*\"\nmax_steps: many\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := writePolicyFile(t, "bad-second.yaml",
				"name: good\ntarget: \"agent://a.example/*\"\n---\n"+c.second)
			set, err := Load(path)
			if err == nil {
				t.Fatalf("a file whose second document has %s loaded with %d policies and no error", c.name, set.Len())
			}
			if !strings.Contains(err.Error(), "document 2") {
				t.Fatalf("the error does not name the document that failed: %v", err)
			}
			if set != nil {
				t.Fatalf("a failed load returned a set of %d policies, which a caller could enforce by mistake", set.Len())
			}
		})
	}
}

// The scenario "A misspelled field in a later document is refused". The strict
// decoder refuses a field the Policy struct does not declare, in every
// document, not only the first. Otherwise a deny_tool misspelled in the second
// document would load, match its agents, and deny nothing.
func TestAMisspelledFieldInALaterDocumentIsRefused(t *testing.T) {
	src := "name: good\ntarget: \"agent://a.example/*\"\n" +
		"---\n" +
		"name: wire\ntarget: \"agent://a.example/*\"\ndeny_tolls:\n  - send_wire_transfer\n"
	got, err := decodeYAML([]byte(src))
	if err == nil {
		t.Fatalf("a misspelled field in the second document loaded cleanly as %d policies: "+
			"its deny would be dropped and the operator told the rule is in force", len(got))
	}
	if !strings.Contains(err.Error(), "document 2") || !strings.Contains(err.Error(), "deny_tolls") {
		t.Fatalf("the error should name the document and the field, got: %v", err)
	}
}

// The scenario "A single-document file keeps its PolicyVersion". The golden
// values were measured on the tree before this change (go run of
// `wardryx check`, which prints the version it loaded), and a one-document file
// must still report them byte for byte. A leading separator, and a trailing
// separator with nothing after it, open or close the same one document and must
// not move the version either.
func TestASingleDocumentFileKeepsItsPolicyVersion(t *testing.T) {
	golden := map[string]string{
		"testdata/policies/finance.yaml": "a954061880f2",
		"testdata/single/global.yaml":    "f2be9c3a9462",
	}
	for path, want := range golden {
		set, err := Load(path)
		if err != nil {
			t.Fatalf("Load(%s): %v", path, err)
		}
		if got := set.Version(); got != want {
			t.Errorf("Load(%s).Version() = %q, want %q: a single-document file changed its PolicyVersion", path, got, want)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for name, variant := range map[string]string{
			"leading separator":  "---\n" + string(data),
			"trailing separator": string(data) + "---\n",
		} {
			vp := writePolicyFile(t, "variant.yaml", variant)
			vset, err := Load(vp)
			if err != nil {
				t.Fatalf("Load(%s with a %s): %v", path, name, err)
			}
			if got := vset.Version(); got != want {
				t.Errorf("%s with a %s: Version() = %q, want %q", path, name, got, want)
			}
		}
	}

	dirSet, err := Load("testdata/policies")
	if err != nil {
		t.Fatalf("Load(testdata/policies): %v", err)
	}
	if got, want := dirSet.Version(), "b057dd1f1a3b"; got != want {
		t.Errorf("Load(testdata/policies).Version() = %q, want %q: a directory of single-document files changed its PolicyVersion", got, want)
	}
}

// The scenario "The version of a multi-document file covers every loaded
// policy". Before the fix the second document was not in the set, so changing
// it moved nothing and the version reported the first document alone.
func TestTheVersionOfAMultiDocumentFileCoversEveryPolicy(t *testing.T) {
	first := "name: floor\ntarget: \"agent://acme.example/*\"\ndeny_tool:\n  - delete_account\n"
	before := writePolicyFile(t, "two.yaml", first+"---\nname: wire\ntarget: \"agent://acme.example/*\"\ndeny_tool:\n  - send_wire_transfer\n")
	after := writePolicyFile(t, "two-changed.yaml", first+"---\nname: wire\ntarget: \"agent://acme.example/*\"\ndeny_tool:\n  - send_wire_transfer\n  - delete_account_export\n")

	a, err := Load(before)
	if err != nil {
		t.Fatalf("Load before: %v", err)
	}
	b, err := Load(after)
	if err != nil {
		t.Fatalf("Load after: %v", err)
	}
	if a.Version() == b.Version() {
		t.Fatalf("changing a deny in the second document left the version at %q: the version does not cover the rules in force", a.Version())
	}

	// The version of the multi-document file is the version of every policy in
	// it, compiled together, whatever order the documents were written in.
	both, err := Compile([]Policy{
		{Name: "floor", Target: "agent://acme.example/*", DenyTool: []string{"delete_account"}},
		{Name: "wire", Target: "agent://acme.example/*", DenyTool: []string{"send_wire_transfer"}},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if a.Version() != both.Version() {
		t.Fatalf("Load(two documents) = %q, Compile(the same two policies) = %q: the file's version is not the version of the policies in it",
			a.Version(), both.Version())
	}
}

// A directory of files, one of which holds several documents, loads every
// document of every file. The directory loader calls the same decode, and this
// test is what says so.
func TestADirectoryLoadsEveryDocumentOfEveryFile(t *testing.T) {
	dir := t.TempDir()
	twoDocs := "name: a1\ntarget: \"agent://a.example/*\"\n---\nname: a2\ntarget: \"agent://a.example/x/*\"\n"
	listOfTwo := "- name: b1\n  target: \"agent://b.example/*\"\n- name: b2\n  target: \"agent://b.example/x/*\"\n"
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(twoDocs), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.yml"), []byte(listOfTwo), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := Load(dir)
	if err != nil {
		t.Fatalf("Load(dir): %v", err)
	}
	if got := set.Len(); got != 4 {
		t.Fatalf("Len = %d, want 4 (two documents in a.yaml, a list of two in b.yml): a document was dropped", got)
	}
}
