package store

import (
	"context"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// The deep copies, tested through the store rather than directly, because the
// property is about what a CALLER can still do after the call returns.
//
// A shallow copy here is not a crash and not a wrong answer at the time. It is
// a caller holding a live reference into the store: the map they passed to
// CreateApproval, or the slice inside the policy they passed to PutPolicy. They
// reuse it, as anybody would, and a governance record changes underneath
// whoever reads it next. Nothing in the store ever saw a write.

func TestMutatingTheContextAfterCreateDoesNotReachTheStore(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()

	passed := map[string]any{
		"est_cost_usd": 1250.75,
		"tool_names":   []any{"send_wire_transfer"},
	}
	if err := m.CreateApproval(ctx, Approval{
		ApprovalID: "a1", AgentID: "agent://acme.example/finance/bot", RunID: "r1",
		RequestedAt: time.Now().UTC(), Context: passed,
	}); err != nil {
		t.Fatal(err)
	}

	// The caller reuses their own map, which is the ordinary thing to do.
	passed["est_cost_usd"] = 1.0
	passed["tool_names"] = []any{"read_file"}
	delete(passed, "est_cost_usd")

	got, err := m.GetApproval(ctx, "a1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Context["est_cost_usd"] != 1250.75 {
		t.Fatalf("the stored cost is %v, want 1250.75. The caller's later edit "+
			"reached the record: the ceiling a grant is minted against is now "+
			"whatever they happened to reuse the map for",
			got.Context["est_cost_usd"])
	}
	tools, _ := got.Context["tool_names"].([]any)
	if len(tools) != 1 || tools[0] != "send_wire_transfer" {
		t.Fatalf("the stored tool list is %v, want [send_wire_transfer]", tools)
	}
}

// And the other direction: what GetApproval hands back must not be a way into
// the store either.
func TestMutatingWhatGetApprovalReturnsDoesNotReachTheStore(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	if err := m.CreateApproval(ctx, Approval{
		ApprovalID: "a1", AgentID: "agent://acme.example/finance/bot", RunID: "r1",
		RequestedAt: time.Now().UTC(),
		Context:     map[string]any{"est_cost_usd": 1250.75},
	}); err != nil {
		t.Fatal(err)
	}

	first, err := m.GetApproval(ctx, "a1")
	if err != nil {
		t.Fatal(err)
	}
	first.Context["est_cost_usd"] = 1.0

	second, err := m.GetApproval(ctx, "a1")
	if err != nil {
		t.Fatal(err)
	}
	if second.Context["est_cost_usd"] != 1250.75 {
		t.Fatalf("a second read returned %v: what the store hands out is a way "+
			"back into it, so any reader can rewrite a governance record by "+
			"accident", second.Context["est_cost_usd"])
	}
}

// A nil context stores as an empty map, not as nil. The two mean different
// things to a reader, and a nil that reaches JSON serialization renders as
// null where Postgres would have an object.
func TestANilContextIsStoredAsAnEmptyObject(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	if err := m.CreateApproval(ctx, Approval{
		ApprovalID: "a1", AgentID: "agent://acme.example/finance/bot", RunID: "r1",
		RequestedAt: time.Now().UTC(), Context: nil,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := m.GetApproval(ctx, "a1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Context == nil {
		t.Fatal("a nil context stayed nil. Postgres stores an empty jsonb " +
			"object, so the two backends would disagree about the same record")
	}
	if len(got.Context) != 0 {
		t.Fatalf("a nil context became %v", got.Context)
	}
}

// The same property for a policy's slice fields, which is where it is easiest
// to get wrong: a struct copy copies the slice HEADER, so both sides share the
// array underneath and an append or an index write is shared.
func TestMutatingAPolicysSlicesAfterPutDoesNotReachTheStore(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()

	p := policy.Policy{
		Name:         "finance-guardrail",
		Target:       "agent://acme.example/finance/*",
		DenyTool:     []string{"send_wire_transfer"},
		AllowDomains: []string{"good.example.com"},
	}
	if err := m.PutPolicy(ctx, "p1", p, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	// A struct copy would share these arrays.
	p.DenyTool[0] = "nothing_at_all"
	p.AllowDomains[0] = "evil.example.com"

	got, err := m.GetPolicy(ctx, "p1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Policy.DenyTool[0] != "send_wire_transfer" {
		t.Fatalf("the stored deny list is %v. A caller reusing their own slice "+
			"disarmed a guardrail, and nothing in the store saw a write",
			got.Policy.DenyTool)
	}
	if got.Policy.AllowDomains[0] != "good.example.com" {
		t.Fatalf("the stored allow list is %v. A caller reusing their own slice "+
			"widened where an agent may reach", got.Policy.AllowDomains)
	}
}

// Close on the memory store is a no-op and must stay one that reports success:
// callers defer it, and an error there would surface as a shutdown failure on
// a store that has nothing to shut down.
func TestClosingTheMemoryStoreSucceedsAndIsRepeatable(t *testing.T) {
	m := NewMemory()
	for i := range 3 {
		if err := m.Close(); err != nil {
			t.Fatalf("Close #%d: %v", i+1, err)
		}
	}
}

// The same for the list, which is the shape the operator-facing endpoint uses.
func TestMutatingWhatListApprovalsReturnsDoesNotReachTheStore(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	if err := m.CreateApproval(ctx, Approval{
		ApprovalID: "a1", AgentID: "agent://acme.example/finance/bot", RunID: "r1",
		RequestedAt: time.Now().UTC(),
		Context:     map[string]any{"est_cost_usd": 1250.75},
	}); err != nil {
		t.Fatal(err)
	}

	list, err := m.ListApprovals(ctx)
	if err != nil {
		t.Fatal(err)
	}
	list[0].Context["est_cost_usd"] = 1.0

	got, err := m.GetApproval(ctx, "a1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Context["est_cost_usd"] != 1250.75 {
		t.Fatalf("editing a listing entry reached the record: %v",
			got.Context["est_cost_usd"])
	}
}

// And for a policy read back out. This is the direction that disarms a
// guardrail: a caller edits the deny list they were handed, and the store's
// own copy changes with it.
func TestMutatingWhatGetPolicyReturnsDoesNotReachTheStore(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	if err := m.PutPolicy(ctx, "p1", policy.Policy{
		Name:         "finance-guardrail",
		Target:       "agent://acme.example/finance/*",
		DenyTool:     []string{"send_wire_transfer"},
		AllowDomains: []string{"good.example.com"},
	}, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	first, err := m.GetPolicy(ctx, "p1")
	if err != nil {
		t.Fatal(err)
	}
	first.Policy.DenyTool[0] = "nothing_at_all"
	first.Policy.AllowDomains[0] = "evil.example.com"

	second, err := m.GetPolicy(ctx, "p1")
	if err != nil {
		t.Fatal(err)
	}
	if second.Policy.DenyTool[0] != "send_wire_transfer" {
		t.Fatalf("a reader disarmed the deny list by editing what they were "+
			"handed: %v", second.Policy.DenyTool)
	}
	if second.Policy.AllowDomains[0] != "good.example.com" {
		t.Fatalf("a reader widened the allow list the same way: %v",
			second.Policy.AllowDomains)
	}
}
