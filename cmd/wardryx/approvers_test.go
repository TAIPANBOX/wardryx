package main

import (
	"strings"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/config"
)

// Supervisor decision, relayed 2026-10-19 (`@decided 2026-10-19`, paraphrased):
// key-kind approvals are refused once a console key set is configured, unless
// the operator sets WARDRYX_ALLOW_KEY_APPROVALS=1, and that switch is warned about
// at start. The warnings are built here so the start line is tested, not read.

func TestTheStartWarnsWhenKeyApprovalsAreAllowed(t *testing.T) {
	cfg := config.Config{ApproverJWKSFile: "/etc/wardryx/console-keys.json", AllowKeyApprovals: true}
	got := approverStartWarnings(cfg)
	if len(got) != 1 || !strings.Contains(got[0], "WARDRYX_ALLOW_KEY_APPROVALS") || !strings.Contains(got[0], "key") {
		t.Fatalf("start warnings with the key set and the switch = %q, want one warning naming WARDRYX_ALLOW_KEY_APPROVALS", got)
	}
}

func TestTheSwitchWithNoKeySetSaysItHasNoEffect(t *testing.T) {
	cfg := config.Config{AllowKeyApprovals: true}
	got := approverStartWarnings(cfg)
	if len(got) != 1 || !strings.Contains(got[0], "no effect") {
		t.Fatalf("start warnings with the switch and no key set = %q, want one saying it has no effect", got)
	}
}

func TestNoWarningWhenNoApproverSettingIsGiven(t *testing.T) {
	if got := approverStartWarnings(config.Config{}); len(got) != 0 {
		t.Fatalf("start warnings with no approver setting = %q, want none", got)
	}
	if got := approverStartWarnings(config.Config{ApproverJWKSFile: "/etc/wardryx/console-keys.json"}); len(got) != 0 {
		t.Fatalf("start warnings with a key set and no switch = %q, want none", got)
	}
}
