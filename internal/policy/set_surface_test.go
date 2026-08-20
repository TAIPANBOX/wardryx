package policy

import "testing"

// Two accessors on a compiled Set that carry more weight than their size.
// Neither had a test.
//
// `Policies` is the inverse of Compile, and the API's policy-as-code routes
// depend on it: every write recompiles the file-loaded base plus the store's
// rows, so a `Policies` that dropped anything would let an API write silently
// delete rules an operator put in a file and never edited through the API.
//
// `RequiresHumanApproval` decides whether startup warns that
// WARDRYX_APPROVAL_SECRET is missing. Without the secret the approvals-grant
// path fails closed, so an agent held for a human can never be released. A
// false answer here means the operator is not told.

func policiesFixture() []Policy {
	return []Policy{
		{Name: "deny-shell", Target: "agent://ops.local/*", DenyTool: []string{"shell_exec"}},
		{Name: "hold-costly", Target: "agent://finance.local/*", RequireHumanAboveUSD: 5},
		{Name: "cap-steps", Target: "agent://ops.local/deploy", MaxSteps: 10},
	}
}

func TestPoliciesGivesBackEveryRuleSoAWriteCannotDeleteTheFileLoadedOnes(t *testing.T) {
	t.Parallel()

	in := policiesFixture()
	set, err := Compile(in)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}

	out := set.Policies()
	if len(out) != len(in) {
		t.Fatalf("got %d policies back, put %d in; the API layer recompiles base+store "+
			"from this, so anything missing here is a rule an API write deletes", len(out), len(in))
	}

	byName := map[string]Policy{}
	for _, p := range out {
		byName[p.Name] = p
	}
	for _, want := range in {
		got, ok := byName[want.Name]
		if !ok {
			t.Errorf("policy %q did not come back", want.Name)
			continue
		}
		if got.Target != want.Target {
			t.Errorf("%s: target %q, want %q", want.Name, got.Target, want.Target)
		}
		if got.RequireHumanAboveUSD != want.RequireHumanAboveUSD {
			t.Errorf("%s: threshold %v, want %v", want.Name, got.RequireHumanAboveUSD, want.RequireHumanAboveUSD)
		}
		if len(got.DenyTool) != len(want.DenyTool) {
			t.Errorf("%s: deny_tool %v, want %v", want.Name, got.DenyTool, want.DenyTool)
		}
	}
}

func TestPoliciesRoundTripsThroughCompileToTheSameEffectiveSet(t *testing.T) {
	t.Parallel()

	// The property the API layer actually relies on: recompiling what a Set
	// reports gives the same set. If it did not, every policy write would shift
	// the version a decision carries without any rule having changed.
	first, err := Compile(policiesFixture())
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	second, err := Compile(first.Policies())
	if err != nil {
		t.Fatalf("recompiling what the set reported: %v", err)
	}
	if first.Version() != second.Version() {
		t.Errorf("version %q became %q on a round trip through Policies()",
			first.Version(), second.Version())
	}
}

func TestANilSetReportsNoPoliciesRatherThanPanicking(t *testing.T) {
	t.Parallel()

	// Reached wherever a Set has not been loaded yet, which is startup and
	// every error path that returns before one exists.
	var s *Set
	if got := s.Policies(); got != nil {
		t.Errorf("got %#v, want nil", got)
	}
	if s.RequiresHumanApproval() {
		t.Error("a nil set cannot hold anything for a human, so it must say false")
	}
}

func TestRequiresHumanApprovalIsTrueExactlyWhenAHoldCanHappen(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		in   []Policy
		want bool
	}{
		{"no policies at all", nil, false},
		{
			"a policy with no threshold",
			[]Policy{{Name: "deny", Target: "agent://a/*", DenyTool: []string{"shell_exec"}}},
			false,
		},
		{
			"a threshold of exactly zero, which holds nothing",
			[]Policy{{Name: "z", Target: "agent://a/*", RequireHumanAboveUSD: 0}},
			false,
		},
		{
			"one policy above zero among several",
			[]Policy{
				{Name: "deny", Target: "agent://a/*", DenyTool: []string{"shell_exec"}},
				{Name: "hold", Target: "agent://b/*", RequireHumanAboveUSD: 0.01},
			},
			true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			set, err := Compile(tc.in)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			if got := set.RequiresHumanApproval(); got != tc.want {
				t.Errorf("got %v, want %v; startup warns about a missing "+
					"WARDRYX_APPROVAL_SECRET on this answer, and without the secret a "+
					"held agent can never be released", got, tc.want)
			}
		})
	}
}
