package config

import (
	"testing"
)

// WARDRYX_ALLOW_KEY_APPROVALS is on only when it is exactly 1 (invariant 43). Any
// other value, including true, leaves key-kind approvals refused, since an
// operator who wrote something other than the switch did not choose it.
func TestAllowKeyApprovalsIsOnlyExactlyOne(t *testing.T) {
	cases := map[string]bool{"1": true, "0": false, "true": false, "yes": false, "": false, " 1": false}
	for value, want := range cases {
		t.Setenv("WARDRYX_ALLOW_KEY_APPROVALS", value)
		if got := FromEnv().AllowKeyApprovals; got != want {
			t.Errorf("WARDRYX_ALLOW_KEY_APPROVALS=%q: AllowKeyApprovals = %v, want %v", value, got, want)
		}
	}
}
