package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hold_if_signal can only hold. A policy that tries to make a signal deny must
// be refused where it is loaded, in every decoder, with a sentence saying why:
// the alternative is a rule that is believed and does something else.

func f64p(v float64) *float64 { return &v }

const signalYAML = `name: risk
target: "agent://acme.example/support/*"
hold_if_signal:
  name: action.risk_class
  values: [destructive, external_send, financial]
  min_probability: 0.8
`

func TestHoldIfSignalLoadsFromYAMLAndJSON(t *testing.T) {
	check := func(t *testing.T, ps []Policy, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("a well-formed hold_if_signal rule failed to load: %v", err)
		}
		if len(ps) != 1 || ps[0].HoldIfSignal == nil {
			t.Fatalf("the rule did not decode: %+v", ps)
		}
		r := ps[0].HoldIfSignal
		if r.Name != "action.risk_class" || len(r.Values) != 3 || r.MinProbability == nil || *r.MinProbability != 0.8 {
			t.Fatalf("decoded rule is wrong: %+v", r)
		}
		if _, err := Compile(ps); err != nil {
			t.Fatalf("Compile refused a well-formed rule: %v", err)
		}
	}
	t.Run("yaml", func(t *testing.T) { ps, err := decodeYAML([]byte(signalYAML)); check(t, ps, err) })
	t.Run("json", func(t *testing.T) {
		ps, err := decodeJSON([]byte(`{"name":"risk","target":"agent://acme.example/support/*","hold_if_signal":{"name":"action.risk_class","values":["destructive","external_send","financial"],"min_probability":0.8}}`))
		check(t, ps, err)
	})
	t.Run("an explicit zero threshold is a real threshold", func(t *testing.T) {
		ps, err := decodeYAML([]byte("target: \"agent://x/*\"\nhold_if_signal:\n  name: n\n  values: [v]\n  min_probability: 0\n"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Compile(ps); err != nil {
			t.Fatalf("an explicit min_probability of 0 was refused: %v", err)
		}
	})
}

// Every way a policy can try to make a signal produce a deny, and the
// malformed rules besides. Each must fail to load, and each message must say
// what is wrong rather than only that something is.
func TestAPolicyThatTriesToMakeASignalDenyIsRefusedAtLoad(t *testing.T) {
	head := "target: \"agent://x.example/*\"\n"
	rule := "hold_if_signal:\n  name: n\n  values: [v]\n  min_probability: 0.5\n"
	cases := []struct {
		name, doc, want string
	}{
		{"deny_if_signal, a rule shaped like the hold", head + "deny_if_signal:\n  name: n\n  values: [v]\n  min_probability: 0.5\n", "deny_if_signal is refused"},
		{"deny_if_signal, true", head + "deny_if_signal: true\n", "deny_if_signal is refused"},
		{"deny_if_signal, false", head + "deny_if_signal: false\n", "deny_if_signal is refused"},
		{"hold_if_signal with a decision of deny", head + "hold_if_signal:\n  name: n\n  values: [v]\n  min_probability: 0.5\n  decision: deny\n", "a signal can only hold"},
		{"hold_if_signal with an action of deny", head + "hold_if_signal:\n  name: n\n  values: [v]\n  min_probability: 0.5\n  action: deny\n", "a signal can only hold"},
		{"hold_if_signal with on_match deny", head + "hold_if_signal:\n  name: n\n  values: [v]\n  min_probability: 0.5\n  on_match: deny\n", "a signal can only hold"},
		{"hold_if_signal with deny: true", head + "hold_if_signal:\n  name: n\n  values: [v]\n  min_probability: 0.5\n  deny: true\n", "a signal can only hold"},
		{"hold_if_signal that is not a mapping", head + "hold_if_signal: deny\n", "hold_if_signal must be a mapping"},
		{"no name", head + "hold_if_signal:\n  values: [v]\n  min_probability: 0.5\n", "hold_if_signal.name is required"},
		{"no values", head + "hold_if_signal:\n  name: n\n  min_probability: 0.5\n", "hold_if_signal.values is required"},
		{"a blank value", head + "hold_if_signal:\n  name: n\n  values: [v, \" \"]\n  min_probability: 0.5\n", "blank value"},
		{"no threshold", head + "hold_if_signal:\n  name: n\n  values: [v]\n", "min_probability is required"},
		{"threshold above one", head + "hold_if_signal:\n  name: n\n  values: [v]\n  min_probability: 1.1\n", "between 0 and 1"},
		{"threshold below zero", head + "hold_if_signal:\n  name: n\n  values: [v]\n  min_probability: -0.1\n", "between 0 and 1"},
		{"threshold NaN", head + "hold_if_signal:\n  name: n\n  values: [v]\n  min_probability: .nan\n", "between 0 and 1"},
	}
	dir := t.TempDir()
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(dir, "p"+string(rune('a'+i))+".yaml")
			if err := os.WriteFile(path, []byte(c.doc), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatalf("loaded cleanly:\n%s", c.doc)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("refused, but not saying %q:\n  %v", c.want, err)
			}
		})
	}
	_ = rule
}

// The same refusal through the JSON decoder in its two shapes, a single
// document and a list. A list must not fall through to the single-document
// attempt, which would hide this refusal behind a type error.
func TestTheSameRefusalHoldsInJSONAndInsideAList(t *testing.T) {
	docs := map[string]string{
		"single, deny_if_signal": `{"target":"agent://x/*","deny_if_signal":{"name":"n","values":["v"],"min_probability":0.5}}`,
		"list, deny_if_signal":   `[{"target":"agent://x/*"},{"target":"agent://y/*","deny_if_signal":{"name":"n","values":["v"],"min_probability":0.5}}]`,
		"single, extra key":      `{"target":"agent://x/*","hold_if_signal":{"name":"n","values":["v"],"min_probability":0.5,"decision":"deny"}}`,
		"list, extra key":        `[{"target":"agent://x/*","hold_if_signal":{"name":"n","values":["v"],"min_probability":0.5,"decision":"deny"}}]`,
	}
	for name, doc := range docs {
		t.Run(name, func(t *testing.T) {
			ps, err := decodeJSON([]byte(doc))
			if err == nil {
				_, err = Compile(ps)
			}
			if err == nil {
				t.Fatal("loaded cleanly")
			}
			msg := err.Error()
			if !strings.Contains(msg, "deny_if_signal") && !strings.Contains(msg, "a signal can only hold") {
				t.Fatalf("refused, but the message does not say why: %v", err)
			}
		})
	}
}

// The policy-as-code API decodes with a lax decoder, so a deny_if_signal
// there arrives as a Policy with DenyIfSignal set: Compile must refuse it
// without a strict decoder in front.
func TestCompileRefusesADenyIfSignalThatArrivedThroughALaxDecoder(t *testing.T) {
	_, err := Compile([]Policy{{Name: "p", Target: "agent://x/*", DenyIfSignal: map[string]any{"name": "n"}}})
	if err == nil || !strings.Contains(err.Error(), "deny_if_signal is refused") {
		t.Fatalf("Compile accepted a deny_if_signal policy: %v", err)
	}
}

// A policy that does not use the new fields must not change identity: its
// PolicyVersion is what archived decisions name. The digest below was
// computed on main before hold_if_signal existed.
func TestAPolicyWithoutASignalRuleKeepsItsPolicyVersion(t *testing.T) {
	set, err := Compile([]Policy{{
		Name: "finance-guardrail", Target: "agent://acme.example/finance/*",
		DenyTool: []string{"send_wire_transfer"}, AllowDomains: []string{"good.example.com"},
		RequireHumanAboveUSD: f64p(500), MaxSteps: 5,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := set.Version(), "f5912efb526d"; got != want {
		t.Fatalf("PolicyVersion moved to %s (was %s): archived decisions would name a version nothing can reproduce", got, want)
	}
}

func TestASignalRuleChangesThePolicyVersion(t *testing.T) {
	base := Policy{Name: "p", Target: "agent://x/*"}
	with := base
	with.HoldIfSignal = &SignalRule{Name: "n", Values: []string{"v"}, MinProbability: f64p(0.5)}
	a, _ := Compile([]Policy{base})
	b, _ := Compile([]Policy{with})
	if a.Version() == b.Version() {
		t.Fatal("adding a hold_if_signal rule did not change the PolicyVersion")
	}
	with.HoldIfSignal = &SignalRule{Name: "n", Values: []string{"v"}, MinProbability: f64p(0.6)}
	c, _ := Compile([]Policy{with})
	if b.Version() == c.Version() {
		t.Fatal("changing the threshold did not change the PolicyVersion")
	}
}

func TestASignalRuleCountsAsAWayToHold(t *testing.T) {
	set, err := Compile([]Policy{{Name: "p", Target: "agent://x/*", HoldIfSignal: &SignalRule{Name: "n", Values: []string{"v"}, MinProbability: f64p(0.5)}}})
	if err != nil {
		t.Fatal(err)
	}
	if !set.RequiresHumanApproval() {
		t.Fatal("RequiresHumanApproval is false for a set that can hold on a signal: serve would not warn that a hold cannot be granted without WARDRYX_APPROVAL_SECRET")
	}
}

// What a Set holds is its own: editing the policy a caller compiled from must
// not reach into the rules in force (invariant 11's cousin on the compile side).
func TestACompiledSetDoesNotAliasTheRuleItWasBuiltFrom(t *testing.T) {
	rule := &SignalRule{Name: "n", Values: []string{"v", "w"}, MinProbability: f64p(0.5)}
	set, err := Compile([]Policy{{Name: "p", Target: "agent://x/*", HoldIfSignal: rule}})
	if err != nil {
		t.Fatal(err)
	}
	rule.Values[0] = "edited"
	*rule.MinProbability = 0.99
	rule.Name = "edited"
	got := set.Match("agent://x/a")[0].HoldIfSignal
	if got.Name != "n" || got.Values[0] != "v" || *got.MinProbability != 0.5 {
		t.Fatalf("editing the source rule reached the compiled set: %+v", got)
	}
}
