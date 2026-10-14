package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// when_absent says what a hold_if_signal rule does with a tool call that arrives
// with no signal of the rule's name. It takes allow (the default, what the rule
// always did) or hold. It never takes deny: a missing signal is a missing
// probability, and a probability can only hold (invariant 25). These tests hold
// that at every place a policy is read.

const absentHead = "name: lab-risk\ntarget: \"agent://lab.example/agents/*\"\nhold_if_signal:\n  name: action.risk_class\n  values: [destructive]\n  min_probability: 0.5\n"

func TestWhenAbsentTakesOnlyAllowOrHold(t *testing.T) {
	dir := t.TempDir()
	load := func(t *testing.T, name, doc string) (*Set, error) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		return Load(path)
	}

	t.Run("allow and hold load from YAML and JSON", func(t *testing.T) {
		for i, v := range []string{"allow", "hold"} {
			set, err := load(t, "ok"+v+".yaml", absentHead+"  when_absent: "+v+"\n")
			if err != nil {
				t.Fatalf("when_absent: %s refused in YAML: %v", v, err)
			}
			// Read back through the rule's own wire form: hold is kept, and
			// allow, the default, is stored as the default (no key), so the
			// version does not move.
			enc, err := json.Marshal(set.Match("agent://lab.example/agents/a")[0].HoldIfSignal)
			if err != nil {
				t.Fatal(err)
			}
			kept := strings.Contains(string(enc), `"when_absent":"hold"`)
			if (v == "hold") != kept || (v == "allow" && strings.Contains(string(enc), "when_absent")) {
				t.Errorf("YAML when_absent: %s compiled to %s", v, enc)
			}
			js := `{"name":"lab-risk","target":"agent://lab.example/agents/*","hold_if_signal":{"name":"action.risk_class","values":["destructive"],"min_probability":0.5,"when_absent":"` + v + `"}}`
			if _, err := load(t, "ok"+v+string(rune('0'+i))+".json", js); err != nil {
				t.Fatalf("when_absent: %s refused in JSON: %v", v, err)
			}
		}
	})

	refused := []struct {
		name, value, want string
	}{
		{"deny", "deny", "a signal can only hold"},
		{"Deny in capitals", "Deny", "a signal can only hold"},
		{"block", "block", "allow or hold"},
		{"a capitalised hold", "Hold", "allow or hold"},
		{"true", "true", "allow or hold"},
		{"an empty string", `""`, "when_absent"},
		{"no value at all", "", "when_absent"},
		{"null", "null", "when_absent"},
	}
	for i, c := range refused {
		t.Run("YAML refuses "+c.name, func(t *testing.T) {
			doc := absentHead + "  when_absent: " + c.value + "\n"
			_, err := load(t, "bad"+string(rune('a'+i))+".yaml", doc)
			if err == nil {
				t.Fatalf("loaded cleanly:\n%s", doc)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("refused, but not saying %q: %v", c.want, err)
			}
		})
		t.Run("YAML inside a list refuses "+c.name, func(t *testing.T) {
			list := "- name: other\n  target: \"agent://x/*\"\n- " + strings.ReplaceAll(strings.TrimSuffix(absentHead+"  when_absent: "+c.value, "\n"), "\n", "\n  ") + "\n"
			_, err := load(t, "list"+string(rune('a'+i))+".yaml", list)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("a list carrying when_absent: %s: %v, want a refusal saying %q", c.value, err, c.want)
			}
		})
		jsonValue := c.value
		switch c.value {
		case "", `""`:
			jsonValue = `""`
		case "null", "true":
		default:
			jsonValue = `"` + c.value + `"`
		}
		rule := `{"name":"action.risk_class","values":["destructive"],"min_probability":0.5,"when_absent":` + jsonValue + `}`
		t.Run("JSON file refuses "+c.name, func(t *testing.T) {
			doc := `[{"name":"other","target":"agent://x/*"},{"name":"lab-risk","target":"agent://lab.example/agents/*","hold_if_signal":` + rule + `}]`
			_, err := load(t, "bad"+string(rune('a'+i))+".json", doc)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("JSON when_absent: %s: %v, want a refusal saying %q", jsonValue, err, c.want)
			}
		})
		// The policy API decodes with a decoder that does not refuse unknown
		// policy fields; the rule's own decoder and Compile must still refuse.
		t.Run("the lax decoder and Compile refuse "+c.name, func(t *testing.T) {
			var p Policy
			err := json.Unmarshal([]byte(`{"name":"lab-risk","target":"agent://lab.example/agents/*","hold_if_signal":`+rule+`}`), &p)
			if err == nil {
				_, err = Compile([]Policy{p})
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("lax when_absent: %s: %v, want a refusal saying %q", jsonValue, err, c.want)
			}
		})
	}
}

// The digest below was computed on main before when_absent existed, from this
// same rule. A policy that leaves the key out, or writes the default, keeps it:
// archived decisions name it, and a version nothing can reproduce is a record
// nobody can check.
func TestAPolicyWithoutWhenAbsentKeepsItsPolicyVersion(t *testing.T) {
	const before = "b46e83f7dcd0"
	write := func(t *testing.T, doc string) *Set {
		t.Helper()
		path := filepath.Join(t.TempDir(), "p.yaml")
		if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		set, err := Load(path)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		return set
	}
	if got := write(t, absentHead).Version(); got != before {
		t.Fatalf("a rule without when_absent moved its PolicyVersion to %s (was %s)", got, before)
	}
	if got := write(t, absentHead+"  when_absent: allow\n").Version(); got != before {
		t.Fatalf("when_absent: allow, the default, moved the PolicyVersion to %s (was %s)", got, before)
	}
	if got := write(t, absentHead+"  when_absent: hold\n").Version(); got == before {
		t.Fatal("when_absent: hold did not change the PolicyVersion: a replay would run a set that does not hold on absence")
	}
}

// A rule assembled in Go rather than decoded meets the same check in Compile,
// and the default is stored as the default however it was written.
func TestCompileChecksWhenAbsentOnARuleBuiltInGo(t *testing.T) {
	rule := func(v string) *SignalRule {
		return &SignalRule{Name: "n", Values: []string{"v"}, MinProbability: f64p(0.5), WhenAbsent: v}
	}
	if _, err := Compile([]Policy{{Name: "p", Target: "agent://x/*", HoldIfSignal: rule("deny")}}); err == nil || !strings.Contains(err.Error(), "a signal can only hold") {
		t.Fatalf("Compile accepted when_absent deny: %v", err)
	}
	if _, err := Compile([]Policy{{Name: "p", Target: "agent://x/*", HoldIfSignal: rule("sometimes")}}); err == nil || !strings.Contains(err.Error(), "allow or hold") {
		t.Fatalf("Compile accepted when_absent sometimes: %v", err)
	}
	versions := map[string]string{}
	for _, v := range []string{"", WhenAbsentAllow, WhenAbsentHold} {
		set, err := Compile([]Policy{{Name: "p", Target: "agent://x/*", HoldIfSignal: rule(v)}})
		if err != nil {
			t.Fatalf("when_absent %q: %v", v, err)
		}
		versions[v] = set.Version()
		if got := set.Policies()[0].HoldIfSignal.WhenAbsent; v == WhenAbsentHold && got != WhenAbsentHold || v != WhenAbsentHold && got != "" {
			t.Errorf("when_absent %q compiled to %q", v, got)
		}
	}
	if versions[""] != versions[WhenAbsentAllow] || versions[""] == versions[WhenAbsentHold] {
		t.Fatalf("versions: %v; want the default and allow equal, hold different", versions)
	}
}
