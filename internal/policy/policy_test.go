package policy

import (
	"testing"
)

func TestLoadDirectory(t *testing.T) {
	set, err := Load("testdata/policies")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if set.Len() != 2 {
		t.Fatalf("Len = %d, want 2", set.Len())
	}
	if len(set.Version()) != 12 {
		t.Errorf("Version = %q, want 12 hex chars", set.Version())
	}
}

func TestMatchGlobPerTrustDomainSegment(t *testing.T) {
	set, err := Load("testdata/policies")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	fin := set.Match("agent://acme.example/finance/bot1")
	if len(fin) != 1 || fin[0].Name != "finance-guardrail" {
		t.Fatalf("finance match = %+v, want exactly finance-guardrail", fin)
	}

	sup := set.Match("agent://acme.example/support/bot2")
	if len(sup) != 1 || sup[0].Name != "support-baseline" {
		t.Fatalf("support match = %+v, want exactly support-baseline", sup)
	}

	none := set.Match("agent://other.example/anything/bot3")
	if len(none) != 0 {
		t.Fatalf("cross-domain match = %+v, want none", none)
	}
}

func TestMatchWildcardCrossesSlashes(t *testing.T) {
	set, err := Compile([]Policy{{Target: "agent://acme.example/*"}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if m := set.Match("agent://acme.example/finance/deep/nested/bot"); len(m) != 1 {
		t.Errorf("expected the wildcard to cross multiple path segments, got %+v", m)
	}
	if m := set.Match("agent://other.example/finance/bot"); len(m) != 0 {
		t.Errorf("expected no match across trust domains, got %+v", m)
	}
}

func TestMatchQuestionMarkMatchesExactlyOneChar(t *testing.T) {
	set, err := Compile([]Policy{{Target: "agent://acme.example/bot?"}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if m := set.Match("agent://acme.example/bot1"); len(m) != 1 {
		t.Errorf("expected bot1 to match bot?, got %+v", m)
	}
	if m := set.Match("agent://acme.example/bot12"); len(m) != 0 {
		t.Errorf("expected bot12 NOT to match bot? (single char), got %+v", m)
	}
}

func TestDenyToolDedupedAndSorted(t *testing.T) {
	set, err := Load("testdata/policies")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	fin := set.Match("agent://acme.example/finance/bot1")
	if len(fin) != 1 {
		t.Fatalf("expected exactly one match, got %d", len(fin))
	}
	want := []string{"delete_account", "send_wire_transfer"}
	got := fin[0].DenyTool
	if len(got) != len(want) {
		t.Fatalf("DenyTool = %v, want %v (duplicate send_wire_transfer must be deduped)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("DenyTool[%d] = %q, want %q (must be sorted)", i, got[i], want[i])
		}
	}
}

func TestPolicyVersionStableAcrossEquivalentOrder(t *testing.T) {
	a, err := Compile([]Policy{
		{Name: "a", Target: "agent://x/*", DenyTool: []string{"foo", "bar"}},
		{Name: "b", Target: "agent://y/*"},
	})
	if err != nil {
		t.Fatalf("Compile a: %v", err)
	}
	b, err := Compile([]Policy{
		{Name: "b", Target: "agent://y/*"},
		{Name: "a", Target: "agent://x/*", DenyTool: []string{"bar", "foo"}},
	})
	if err != nil {
		t.Fatalf("Compile b: %v", err)
	}
	if a.Version() != b.Version() {
		t.Errorf("Version differs for equivalent policy sets in different order: %q vs %q", a.Version(), b.Version())
	}
}

func TestPolicyVersionChangesWithContent(t *testing.T) {
	a, err := Compile([]Policy{{Name: "a", Target: "agent://x/*"}})
	if err != nil {
		t.Fatalf("Compile a: %v", err)
	}
	b, err := Compile([]Policy{{Name: "a", Target: "agent://x/*", DenyIfUnattested: true}})
	if err != nil {
		t.Fatalf("Compile b: %v", err)
	}
	if a.Version() == b.Version() {
		t.Errorf("Version must change when policy content changes, both = %q", a.Version())
	}
}

func TestLoadIsDeterministicAcrossRepeatedLoads(t *testing.T) {
	a, err := Load("testdata/policies")
	if err != nil {
		t.Fatalf("Load 1: %v", err)
	}
	b, err := Load("testdata/policies")
	if err != nil {
		t.Fatalf("Load 2: %v", err)
	}
	if a.Version() != b.Version() {
		t.Errorf("repeated Load of the same directory produced different versions: %q vs %q", a.Version(), b.Version())
	}
}

func TestLoadMalformedFileErrors(t *testing.T) {
	if _, err := Load("testdata/malformed"); err == nil {
		t.Fatal("Load(testdata/malformed): expected an error, got nil")
	}
}

func TestLoadEmptyPathReturnsEmptySet(t *testing.T) {
	set, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\"): %v", err)
	}
	if set.Len() != 0 {
		t.Errorf("Len = %d, want 0", set.Len())
	}
	if m := set.Match("agent://anything/at/all"); m != nil {
		t.Errorf("Match on an empty set = %+v, want nil", m)
	}
	if set.Version() == "" {
		t.Error("Version on an empty set must still be defined")
	}
}

func TestLoadSingleFileArrayForm(t *testing.T) {
	set, err := Load("testdata/single/global.yaml")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if set.Len() != 1 {
		t.Fatalf("Len = %d, want 1", set.Len())
	}
	m := set.Match("agent://anything.example/at/all")
	if len(m) != 1 || m[0].Name != "global-floor" {
		t.Fatalf("Match = %+v, want exactly global-floor", m)
	}
}

func TestCompileRejectsEmptyTarget(t *testing.T) {
	if _, err := Compile([]Policy{{Name: "no-target"}}); err == nil {
		t.Fatal("Compile with empty target: expected an error, got nil")
	}
}

func TestCompileRejectsNegativeThreshold(t *testing.T) {
	if _, err := Compile([]Policy{{Target: "agent://x/*", RequireHumanAboveUSD: -1}}); err == nil {
		t.Fatal("Compile with negative require_human_above_usd: expected an error, got nil")
	}
}

func TestCompileRejectsNegativeMaxSteps(t *testing.T) {
	if _, err := Compile([]Policy{{Target: "agent://x/*", MaxSteps: -1}}); err == nil {
		t.Fatal("Compile with negative max_steps: expected an error, got nil")
	}
}

func TestCompileNilIsValidEmptySet(t *testing.T) {
	set, err := Compile(nil)
	if err != nil {
		t.Fatalf("Compile(nil): %v", err)
	}
	if set.Len() != 0 {
		t.Errorf("Len = %d, want 0", set.Len())
	}
}

func TestNameDefaultsToTarget(t *testing.T) {
	set, err := Compile([]Policy{{Target: "agent://x/*"}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	m := set.Match("agent://x/bot")
	if len(m) != 1 || m[0].Name != "agent://x/*" {
		t.Fatalf("Match = %+v, want Name defaulted to target", m)
	}
}
