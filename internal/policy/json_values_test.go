package policy

import (
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// These tests hold the JSON half of features/multi-document-policy-file.feature:
// a .json policy file may hold several values, read in order, with the same
// rules a YAML file's documents follow. Before this change decodeJSON read the
// first value and stopped, so a second object in the file was dropped with no
// error, which is the same silent drop the YAML loader had.

// The scenario "Every value of a JSON policy file loads, in order": one object,
// a list of two, a null that holds no policy, and one object. Four policies are
// in force, in the order the file gives them.
func TestEveryValueOfAJSONFileLoads(t *testing.T) {
	path := writePolicyFile(t, "three.json",
		`{"name":"first","target":"agent://a.example/*"}`+"\n"+
			`[{"name":"second","target":"agent://b.example/*"},{"name":"third","target":"agent://c.example/*"}]`+"\n"+
			`null`+"\n"+
			`{"name":"fourth","target":"agent://d.example/*"}`+"\n")
	set, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := set.Len(); got != 4 {
		t.Fatalf("Len = %d, want 4: a value after the first was dropped, and the file loaded smaller than it reads", got)
	}
	for _, target := range []string{"agent://a.example/x", "agent://b.example/x", "agent://c.example/x", "agent://d.example/x"} {
		if m := set.Match(target); len(m) != 1 {
			t.Errorf("Match(%q) = %d policies, want 1: the policy that targets it was not loaded", target, len(m))
		}
	}
}

// The scenario "Data after a JSON value is refused, not ignored". Bytes that are
// not a whole JSON value, after a valid policy, must fail the file and name the
// value. Read as nothing, they would leave whatever the cut-off value meant out
// of force with no message. (A second complete object is a value, and loads: see
// TestEveryValueOfAJSONFileLoads.)
func TestDataAfterAJSONValueIsRefusedNotIgnored(t *testing.T) {
	first := `{"name":"a","target":"agent://a.example/*"}` + "\n"
	cases := []struct {
		name, second string
	}{
		{"bytes that are not JSON", `xyz`},
		{"a truncated object", `{"name":"b","target":"agent://b.example/*","deny_tool":["send_wire_transfer"]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := decodeJSON([]byte(first + c.second))
			if err == nil {
				t.Fatalf("a file with %s after a valid policy loaded %d policies and no error: the data after the first value was ignored", c.name, len(got))
			}
			if !strings.Contains(err.Error(), "value 2") {
				t.Fatalf("the error does not name the value that failed: %v", err)
			}
			if got != nil {
				t.Fatalf("a failed decode returned %d policies, which a caller could enforce by mistake", len(got))
			}
		})
	}
}

// The scenario "A JSON value that fails strict decoding fails the whole file,
// naming the value". The strict field check and the type check apply to every
// value, not only the first.
func TestAJSONValueThatFailsStrictDecodingFailsTheFileNamingIt(t *testing.T) {
	first := `{"name":"a","target":"agent://a.example/*"}` + "\n"
	cases := []struct {
		name, second, field string
	}{
		{"a misspelled field", `{"name":"b","target":"agent://b.example/*","deny_tolls":["x"]}`, "deny_tolls"},
		{"a value of the wrong type", `{"name":"b","target":"agent://b.example/*","max_steps":"many"}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := decodeJSON([]byte(first + c.second))
			if err == nil {
				t.Fatalf("a file whose second value has %s loaded %d policies and no error", c.name, len(got))
			}
			if !strings.Contains(err.Error(), "value 2") {
				t.Fatalf("the error does not name the value that failed: %v", err)
			}
			if c.field != "" && !strings.Contains(err.Error(), c.field) {
				t.Fatalf("the error does not name the field %q: %v", c.field, err)
			}
			if got != nil {
				t.Fatalf("a failed decode returned %d policies", len(got))
			}
		})
	}
}

// The scenario "An empty JSON file is refused, as before". An empty file has no
// value to read and was refused with the decoder's io.EOF before this change.
// It stays refused, with the same error, so nothing that relied on it changes.
func TestAnEmptyJSONFileIsRefusedAsBefore(t *testing.T) {
	for _, src := range []string{"", " \n\t"} {
		_, err := decodeJSON([]byte(src))
		if !errors.Is(err, io.EOF) {
			t.Fatalf("decodeJSON(%q) = %v, want io.EOF as before: an empty JSON file must stay refused", src, err)
		}
	}
}

// The scenario "A single-value JSON file keeps its PolicyVersion". The golden
// value was measured on b8d365e, before this change (`wardryx check` prints the
// version it loaded). Whitespace around the one value opens or closes nothing
// and must not move it.
func TestASingleValueJSONFileKeepsItsPolicyVersion(t *testing.T) {
	const want = "44e4daa4f612"
	set, err := Load("testdata/policies/support.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := set.Version(); got != want {
		t.Fatalf("Version() = %q, want %q: a single-value JSON file changed its PolicyVersion", got, want)
	}
	raw, err := os.ReadFile("testdata/policies/support.json")
	if err != nil {
		t.Fatalf("read support.json: %v", err)
	}
	padded := "  " + strings.TrimSpace(string(raw)) + "\n\n"
	vset, err := Load(writePolicyFile(t, "padded.json", padded))
	if err != nil {
		t.Fatalf("Load padded: %v", err)
	}
	if got := vset.Version(); got != want {
		t.Fatalf("padded Version() = %q, want %q", got, want)
	}
}
