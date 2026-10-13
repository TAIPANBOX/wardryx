package policy

import "testing"

// TestAPolicyWithoutAllowToolKeepsItsPolicyVersion is the scenario "A policy
// without an allow-list keeps its policy version" (features/allow-tool.feature).
// The version is what every decision names, and what an archived rule set is
// filed under, so a policy that does not use the new field must hash exactly as
// it did before the field existed. The golden value was measured on the tree
// before allow_tool was added (be92ffb), with this same fixture.
func TestAPolicyWithoutAllowToolKeepsItsPolicyVersion(t *testing.T) {
	set, err := Compile([]Policy{{
		Name:                 "finance-guardrail",
		Target:               "agent://acme.example/finance/*",
		DenyTool:             []string{"send_wire_transfer", "delete_account"},
		AllowDomains:         []string{"payments.acme.example"},
		RequireHumanAboveUSD: floatPtr(500),
		DenyAboveUSD:         floatPtr(1000),
		MaxSteps:             40,
		DenyIfUnattested:     true,
	}})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	const want = "75aff5527f42"
	if got := set.Version(); got != want {
		t.Fatalf("PolicyVersion = %q, want %q: a policy with no allow_tool must hash as it did before the field existed", got, want)
	}
}

func floatPtr(v float64) *float64 { return &v }

// TestAnAllowListIsPartOfThePolicyVersionAndItsOrderIsNot: the list is a rule,
// so changing it changes the version every decision names; the order its
// entries are written in is not a rule, so it must not.
func TestAnAllowListIsPartOfThePolicyVersionAndItsOrderIsNot(t *testing.T) {
	version := func(allow ...string) string {
		t.Helper()
		set, err := Compile([]Policy{{Name: "shop", Target: "agent://acme.example/shop/*", AllowTool: allow}})
		if err != nil {
			t.Fatalf("Compile(%v): %v", allow, err)
		}
		return set.Version()
	}
	written := version("search", "lookup", "search")
	if reordered := version("lookup", "search"); reordered != written {
		t.Fatalf("PolicyVersion %q for the same list in another order, want %q", reordered, written)
	}
	if narrower := version("search"); narrower == written {
		t.Fatalf("PolicyVersion did not change when the allow-list changed: both %q", written)
	}
}

// TestABlankAllowToolEntryIsRefusedAtLoad: normalization drops blank entries,
// so a list holding only a blank would become empty, which reads as no
// restriction. The compile refuses it instead.
func TestABlankAllowToolEntryIsRefusedAtLoad(t *testing.T) {
	for name, allow := range map[string][]string{
		"only an empty string": {""},
		"only spaces":          {"  "},
		"blank beside a name":  {"search", ""},
	} {
		_, err := Compile([]Policy{{Name: "shop", Target: "agent://acme.example/shop/*", AllowTool: allow}})
		if err == nil {
			t.Fatalf("%s: Compile accepted allow_tool %q, which would be read as no restriction", name, allow)
		}
	}
}
