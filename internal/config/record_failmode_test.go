package config

import "testing"

// WARDRYX_RECORD_FAILMODE (invariant 40): closed is the default, and only an
// explicit "open" selects the open mode. Anything else reads as closed, the
// safe side, as WARDRYX_APPROVAL_SINGLE_USE does.

func TestTheRecordFailModeDefaultsToClosed(t *testing.T) {
	t.Setenv("WARDRYX_RECORD_FAILMODE", "")
	if got := FromEnv().RecordFailMode; got != "closed" {
		t.Fatalf("unset WARDRYX_RECORD_FAILMODE reads as %q, want closed", got)
	}
}

func TestRecordFailModeIsOpenOnlyWhenAskedFor(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"open", "open"},
		{" OPEN ", "open"},
		{"closed", "closed"},
		{"Closed", "closed"},
		{"", "closed"},
		{"opened", "closed"},
		{"0", "closed"},
		{"false", "closed"},
	}
	for _, c := range cases {
		t.Run(c.raw, func(t *testing.T) {
			t.Setenv("WARDRYX_RECORD_FAILMODE", c.raw)
			if got := FromEnv().RecordFailMode; got != c.want {
				t.Fatalf("WARDRYX_RECORD_FAILMODE=%q reads as %q, want %q", c.raw, got, c.want)
			}
		})
	}
}
