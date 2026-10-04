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
