package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// usd returns a pointer to v, for constructing a Policy with an explicit
// RequireHumanAboveUSD or DenyAboveUSD (including an explicit zero, which a
// bare float64 field could not represent as distinct from "unset").
func usd(v float64) *float64 { return &v }

// zeroUSD is usd(0), named so a reader sees "an explicit zero" rather than
// wondering whether 0 is a typo.
func zeroUSD() *float64 { return usd(0) }

// usdEqual compares two *float64 fields by value (nil-ness and, if both
// non-nil, the pointed-to number), never by pointer identity: normalize's
// defensive copy (cloneUSD) deliberately gives every Policy its own
// pointer, so a plain != on two *float64 read back from a Set would always
// be true even when they hold the same value.
func usdEqual(a, b *float64) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	return a == nil || *a == *b
}

func usdString(p *float64) string {
	if p == nil {
		return "<unset>"
	}
	return fmt.Sprintf("%v", *p)
}

// TestExplicitZeroDenyAboveUSDInAYAMLFileIsDistinctFromOmitted is the "YAML
// file case" for the defect measured 2026-09-27: a policy file that writes
// deny_above_usd: 0 on purpose must compile to a different PolicyVersion
// than a file that never mentions the field at all, because the two mean
// different things (a real zero ceiling versus no ceiling). Run against the
// pre-fix code (deny_above_usd a plain float64 with yaml:",omitempty"),
// both decode to the Go zero value and compile to the SAME version, which
// is the failure this test is written to catch.
func TestExplicitZeroDenyAboveUSDInAYAMLFileIsDistinctFromOmitted(t *testing.T) {
	dir := t.TempDir()

	omitted := filepath.Join(dir, "omitted.yaml")
	if err := os.WriteFile(omitted, []byte("target: agent://x/*\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", omitted, err)
	}
	explicitZero := filepath.Join(dir, "explicit-zero.yaml")
	if err := os.WriteFile(explicitZero, []byte("target: agent://x/*\ndeny_above_usd: 0\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", explicitZero, err)
	}

	setOmitted, err := Load(omitted)
	if err != nil {
		t.Fatalf("Load(omitted): %v", err)
	}
	setExplicit, err := Load(explicitZero)
	if err != nil {
		t.Fatalf("Load(explicitZero): %v", err)
	}

	if setOmitted.Version() == setExplicit.Version() {
		t.Errorf("PolicyVersion is %q for both an omitted deny_above_usd and an explicit deny_above_usd: 0; "+
			"they are different policies (no ceiling vs. a ceiling of zero) and must compile to different versions",
			setOmitted.Version())
	}
}

// TestExplicitZeroRequireHumanAboveUSDInAJSONFileIsDistinctFromOmitted is
// the same case for require_human_above_usd, over the JSON decoder instead
// of YAML, so both strict decoders (see strict_test.go) are covered.
func TestExplicitZeroRequireHumanAboveUSDInAJSONFileIsDistinctFromOmitted(t *testing.T) {
	dir := t.TempDir()

	omitted := filepath.Join(dir, "omitted.json")
	if err := os.WriteFile(omitted, []byte(`{"target":"agent://x/*"}`), 0o600); err != nil {
		t.Fatalf("write %s: %v", omitted, err)
	}
	explicitZero := filepath.Join(dir, "explicit-zero.json")
	if err := os.WriteFile(explicitZero, []byte(`{"target":"agent://x/*","require_human_above_usd":0}`), 0o600); err != nil {
		t.Fatalf("write %s: %v", explicitZero, err)
	}

	setOmitted, err := Load(omitted)
	if err != nil {
		t.Fatalf("Load(omitted): %v", err)
	}
	setExplicit, err := Load(explicitZero)
	if err != nil {
		t.Fatalf("Load(explicitZero): %v", err)
	}

	if setOmitted.Version() == setExplicit.Version() {
		t.Errorf("PolicyVersion is %q for both an omitted require_human_above_usd and an explicit "+
			"require_human_above_usd: 0; they are different policies and must compile to different versions",
			setOmitted.Version())
	}
}
