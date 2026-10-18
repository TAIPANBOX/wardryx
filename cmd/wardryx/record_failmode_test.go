package main

import (
	"strings"
	"testing"
)

// An open record fail mode is a deliberate choice that lets a decision go out
// unrecorded, so serve says so at startup. The closed default says nothing.
func TestTheOpenFailModeIsWarnedAtStartup(t *testing.T) {
	warn := recordFailModeWarning("open")
	if !strings.Contains(warn, "WARDRYX_RECORD_FAILMODE=open") {
		t.Fatalf("open mode warned %q, want the variable named", warn)
	}
	if !strings.Contains(warn, "/readyz") {
		t.Fatalf("open mode warned %q, want the health signal named", warn)
	}
	if got := recordFailModeWarning("closed"); got != "" {
		t.Fatalf("closed mode warned %q, want no warning", got)
	}
}
