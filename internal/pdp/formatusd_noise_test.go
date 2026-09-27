package pdp

import "testing"

// A computed amount (an estimate summed from priced parts, a ceiling times a
// factor) carries float64 noise, and formatUSD printed it: "$0.0055000000000000005"
// for 0.0016*3+0.0007. Money here is counted in micro-dollars, so the
// reason rounds to the micro-dollar and drops trailing zeros; whole cents keep
// the two-decimal form, and a nonzero amount never prints as zero.
func TestFormatUSDPrintsNoFloatNoise(t *testing.T) {
	// Variables, not constants: Go folds constant expressions exactly at
	// compile time, which is not how a gateway's estimate arrives.
	ceiling, part, tenth, fifth := 0.0016, 0.0007, 0.1, 0.2
	for _, c := range []struct {
		in   float64
		want string
	}{
		{ceiling*3 + part, "$0.0055"},
		{tenth + fifth, "$0.30"},
		{0.0999999999, "$0.10"},
		{100, "$100.00"},
		{12.34, "$12.34"},
		{0.0005, "$0.0005"},
		{0.005, "$0.005"},
		{0.000001, "$0.000001"},
		{0, "$0.00"},
	} {
		if got := formatUSD(c.in); got != c.want {
			t.Errorf("formatUSD(%v) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := formatUSD(0.0000001); got == "$0" || got == "$0.00" || got == "$0.000000" {
		t.Errorf("formatUSD(1e-7) = %q: a nonzero amount must never read as zero", got)
	}
}
