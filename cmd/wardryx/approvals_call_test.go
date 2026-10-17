package main

import (
	"strings"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/store"
)

// `wardryx approvals` shows the tool and target a person is approving, and
// nothing of the arguments.
func TestTheApprovalsListNamesTheCallBeingApproved(t *testing.T) {
	held := store.Approval{Context: map[string]any{
		"tool_call": map[string]any{"name": "s3.delete_object", "target": "s3://prod-backups", "digest": strings.Repeat("a", 64)},
	}}
	if got := approvalCall(held); got != "s3.delete_object s3://prod-backups" {
		t.Fatalf("approvalCall = %q, want the tool and target", got)
	}
	if got := approvalCall(store.Approval{Context: map[string]any{"est_cost_usd": 5.0}}); got != "-" {
		t.Fatalf("a hold with no tool call = %q, want a dash", got)
	}
	noTarget := store.Approval{Context: map[string]any{"tool_call": map[string]any{"name": "shell"}}}
	if got := approvalCall(noTarget); got != "shell" {
		t.Fatalf("a call with no target = %q, want just the tool", got)
	}
	if got := approvalCall(store.Approval{Context: map[string]any{"tool_call": "garbage"}}); got != "-" {
		t.Fatalf("a damaged entry = %q, want a dash, never a panic", got)
	}
	if got := approvalCall(store.Approval{}); got != "-" {
		t.Fatalf("a nil context = %q, want a dash", got)
	}
}

// The DECIDED_BY column names the key that decided and, beside it, the label
// the decision was sent with, quoted so a label never reaches the terminal as
// anything but text.
func TestTheApprovalsListShowsTheApproverAndTheLabel(t *testing.T) {
	decided := store.Approval{Decision: "grant", DecidedBy: "key:0123456789abcdef", DecidedByLabel: "alice"}
	if got := approvalDecidedBy(decided); got != `key:0123456789abcdef ("alice")` {
		t.Fatalf("approvalDecidedBy = %q, want the key and the quoted label", got)
	}
	decided.DecidedByLabel = "a\x1b[2J"
	if got := approvalDecidedBy(decided); strings.ContainsRune(got, 0x1b) {
		t.Fatalf("approvalDecidedBy = %q printed an escape", got)
	}
	if got := approvalDecidedBy(store.Approval{Decision: "deny", DecidedBy: "key:fedcba9876543210"}); got != "key:fedcba9876543210" {
		t.Fatalf("no label = %q, want the key alone", got)
	}
	if got := approvalDecidedBy(store.Approval{}); got != "-" {
		t.Fatalf("pending = %q, want a dash", got)
	}
}
