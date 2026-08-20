package policy

import (
	"regexp"
	"strings"
	"testing"
)

// The helpers underneath the policy set. None was fully covered and each one
// decides something whose failure is quiet.
//
// A version that does not move when the set moves reports "unchanged" about a
// changed guardrail. A glob that matches too widely blocks agents nobody meant
// to bound; one that matches too narrowly leaves an agent ungoverned while the
// policy sits there looking applied. Neither is red anywhere.

// The nil branch of computeVersion, which was the uncovered quarter of it.
//
// It matters because Empty() and a set built from an explicitly empty list are
// the same set, and if they hashed differently the same policy set would
// report two different versions depending on how it was constructed. Anything
// comparing versions across deployments would see drift that is not there.
func TestAnEmptySetHasOneVersionHoweverItWasBuilt(t *testing.T) {
	fromNil := computeVersion(nil)
	fromEmpty := computeVersion([]Policy{})
	if fromNil != fromEmpty {
		t.Fatalf("computeVersion(nil) = %q and computeVersion([]) = %q. The "+
			"same empty set would report two versions depending on how it was "+
			"constructed, and anything comparing versions across deployments "+
			"would see drift that is not there", fromNil, fromEmpty)
	}
	if fromNil == "" {
		t.Fatal("an empty set has no version at all, so nothing can say which " +
			"empty set it is looking at")
	}
	if Empty().Version() != fromNil {
		t.Fatalf("Empty().Version() = %q, computeVersion(nil) = %q",
			Empty().Version(), fromNil)
	}
}

func TestTheVersionIsStableAcrossCallsAndMovesWhenThePolicyDoes(t *testing.T) {
	base := []Policy{{Name: "a", Target: "agent://acme.example/*", MaxSteps: 5}}

	first := computeVersion(base)
	if second := computeVersion(base); first != second {
		t.Fatalf("two calls over the same set gave %q and %q: nothing could "+
			"compare versions at all", first, second)
	}

	changed := []Policy{{Name: "a", Target: "agent://acme.example/*", MaxSteps: 6}}
	if computeVersion(changed) == first {
		t.Fatal("raising MaxSteps from 5 to 6 did not move the version. A " +
			"deployment comparing versions would report the guardrail as " +
			"unchanged while it had in fact been loosened")
	}

	renamed := []Policy{{Name: "b", Target: "agent://acme.example/*", MaxSteps: 5}}
	if computeVersion(renamed) == first {
		t.Fatal("renaming a policy did not move the version")
	}
}

func TestTheVersionIsShortEnoughToReadAndLongEnoughToTrust(t *testing.T) {
	v := computeVersion([]Policy{{Name: "a", Target: "agent://x/*"}})
	if len(v) != 12 {
		t.Fatalf("the version is %d characters (%q), want 12", len(v), v)
	}
	if !regexp.MustCompile(`^[0-9a-f]{12}$`).MatchString(v) {
		t.Fatalf("the version is not lowercase hex: %q", v)
	}
}

// The glob is what decides which agents a policy is about.
func TestTheTargetGlobMatchesWhatItSaysAndNothingElse(t *testing.T) {
	cases := []struct {
		pattern string
		yes     []string
		no      []string
		why     string
	}{
		{
			"agent://acme.example/finance/*",
			[]string{
				"agent://acme.example/finance/bot",
				"agent://acme.example/finance/deep/nested/bot",
			},
			[]string{
				"agent://acme.example/support/bot",
				"agent://acme.example/finance",
				"agent://other.example/finance/bot",
			},
			"* spans / on purpose, so a whole department is one line",
		},
		{
			"agent://acme.example/*",
			[]string{"agent://acme.example/finance/bot", "agent://acme.example/x"},
			[]string{"agent://acmeXexample/finance/bot"},
			"the dot in the domain is a literal dot, not any character. A glob " +
				"that let it match anything would apply an operator's policy to " +
				"a lookalike domain",
		},
		{
			"agent://acme.example/bot?",
			[]string{"agent://acme.example/bot1", "agent://acme.example/botX"},
			[]string{"agent://acme.example/bot", "agent://acme.example/bot12"},
			"? is exactly one character, not zero and not many",
		},
		{
			"agent://acme.example/finance/bot",
			[]string{"agent://acme.example/finance/bot"},
			[]string{
				"agent://acme.example/finance/bot2",
				"xagent://acme.example/finance/bot",
			},
			"a pattern with no wildcard is anchored at both ends, so it is one " +
				"agent and not a substring match",
		},
	}
	for _, c := range cases {
		t.Run(c.pattern, func(t *testing.T) {
			re, err := compileGlob(c.pattern)
			if err != nil {
				t.Fatalf("compileGlob(%q): %v", c.pattern, err)
			}
			for _, s := range c.yes {
				if !re.MatchString(s) {
					t.Errorf("%q does not match %q. %s", c.pattern, s, c.why)
				}
			}
			for _, s := range c.no {
				if re.MatchString(s) {
					t.Errorf("%q matches %q, which it must not. %s", c.pattern, s, c.why)
				}
			}
		})
	}
}

// An empty target is refused rather than compiled into something that matches
// everything or nothing. Either would be a policy applied to a set of agents
// nobody chose.
func TestAnEmptyTargetGlobIsRefused(t *testing.T) {
	re, err := compileGlob("")
	if err == nil {
		t.Fatalf("an empty glob compiled to %v. Whatever it matches, nobody "+
			"chose that set of agents", re)
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("the error does not say the glob was empty: %v", err)
	}
}

// A nil Set is a real state: it is what a caller holds before Compile returns.
// Len must answer rather than panic, because the alternative is a crash on a
// path that only runs during startup or a reload failure.
func TestANilSetAnswersRatherThanCrashing(t *testing.T) {
	var s *Set
	if got := s.Len(); got != 0 {
		t.Fatalf("(*Set)(nil).Len() = %d, want 0", got)
	}
}

func TestAnEmptySetIsEmptyAndSaysSo(t *testing.T) {
	e := Empty()
	if e == nil {
		t.Fatal("Empty() returned nil")
	}
	if got := e.Len(); got != 0 {
		t.Fatalf("Empty().Len() = %d, want 0", got)
	}
	if got := len(e.Policies()); got != 0 {
		t.Fatalf("Empty().Policies() has %d entries", got)
	}
}

// decode dispatches on extension. An unsupported one is an error and never a
// silent zero policies: a policy file with a typo'd extension that loaded as
// nothing would leave every agent ungoverned with no message at all.
func TestAPolicyFileWithAnExtensionNobodySupportsIsAnError(t *testing.T) {
	for _, name := range []string{"policies.toml", "policies.txt", "policies", "policies.yamll"} {
		t.Run(name, func(t *testing.T) {
			got, err := decode(name, []byte("name: x\n"))
			if err == nil {
				t.Fatalf("%q decoded to %d policies. A policy file nobody reads "+
					"leaves every agent ungoverned and says nothing", name, len(got))
			}
			if !strings.Contains(err.Error(), "extension") {
				t.Fatalf("the error does not mention the extension: %v", err)
			}
		})
	}
}

// isUnknownFieldError separates a misspelled field from a shape mismatch. Both
// decoders try the list shape first and fall through, and a LIST carrying a
// misspelled field must not fall through: the second attempt fails with a
// shape error that sends the reader looking in the wrong place.
func TestAMisspelledFieldIsToldApartFromAShapeMismatch(t *testing.T) {
	unknown := []error{
		errString("yaml: unmarshal errors:\n  line 3: field deny_toolz not found in type policy.Policy"),
		errString(`json: unknown field "deny_toolz"`),
	}
	for _, err := range unknown {
		if !isUnknownFieldError(err) {
			t.Errorf("a misspelled field was not recognised as one: %v", err)
		}
	}

	shape := []error{
		nil,
		errString("yaml: cannot unmarshal !!seq into policy.Policy"),
		errString("json: cannot unmarshal array into Go value of type policy.Policy"),
		errString("open policies.yaml: no such file or directory"),
	}
	for _, err := range shape {
		if isUnknownFieldError(err) {
			t.Errorf("a shape mismatch was reported as a misspelled field: %v", err)
		}
	}
}

type errString string

func (e errString) Error() string { return string(e) }
