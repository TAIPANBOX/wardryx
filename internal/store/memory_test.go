package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestMemoryCreateAndGet(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	a := Approval{
		ApprovalID:  "ap_1",
		AgentID:     "agent://x/bot",
		RunID:       "run-1",
		RequestedAt: time.Now().UTC(),
		Context:     map[string]any{"tool_names": []string{"send_wire_transfer"}, "org": "acme"},
	}
	if err := m.CreateApproval(ctx, a); err != nil {
		t.Fatalf("CreateApproval: %v", err)
	}
	got, err := m.GetApproval(ctx, "ap_1")
	if err != nil {
		t.Fatalf("GetApproval: %v", err)
	}
	if got.AgentID != a.AgentID || got.RunID != a.RunID {
		t.Errorf("GetApproval = %+v, want agent/run to match %+v", got, a)
	}
	if !got.Pending() {
		t.Error("freshly created approval should be Pending")
	}
	// tool_names must decode as []any, not []string, matching what a JSON
	// round trip through Postgres' jsonb column would produce -- the two
	// backends must behave identically.
	tools, ok := got.Context["tool_names"].([]any)
	if !ok || len(tools) != 1 || tools[0] != "send_wire_transfer" {
		t.Errorf("Context[tool_names] = %#v, want []any{\"send_wire_transfer\"}", got.Context["tool_names"])
	}
}

func TestMemoryCreateDuplicateIDErrors(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	a := Approval{ApprovalID: "ap_dup", AgentID: "agent://x/bot", RunID: "r1", RequestedAt: time.Now()}
	if err := m.CreateApproval(ctx, a); err != nil {
		t.Fatalf("first CreateApproval: %v", err)
	}
	if err := m.CreateApproval(ctx, a); err == nil {
		t.Fatal("second CreateApproval with the same id: expected an error, got nil")
	}
}

func TestMemoryContextIsDeepCopied(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	mutable := map[string]any{"org": "acme"}
	a := Approval{ApprovalID: "ap_2", AgentID: "agent://x/bot", RunID: "r1", RequestedAt: time.Now(), Context: mutable}
	if err := m.CreateApproval(ctx, a); err != nil {
		t.Fatalf("CreateApproval: %v", err)
	}
	mutable["org"] = "mutated-after-create"

	got, err := m.GetApproval(ctx, "ap_2")
	if err != nil {
		t.Fatalf("GetApproval: %v", err)
	}
	if got.Context["org"] != "acme" {
		t.Errorf("Context[org] = %v, want \"acme\" (mutating the caller's map after Create must not affect the stored copy)", got.Context["org"])
	}
}

func TestMemoryGetNotFound(t *testing.T) {
	m := NewMemory()
	if _, err := m.GetApproval(context.Background(), "missing"); err == nil {
		t.Fatal("GetApproval(missing): expected an error, got nil")
	}
}

func TestMemoryListOrderedByRequestedAt(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	base := time.Now().UTC()
	// Insert out of chronological order to prove List sorts, not just echoes insertion order.
	later := Approval{ApprovalID: "ap_later", AgentID: "agent://x/bot", RunID: "r1", RequestedAt: base.Add(time.Minute)}
	earlier := Approval{ApprovalID: "ap_earlier", AgentID: "agent://x/bot", RunID: "r2", RequestedAt: base}
	if err := m.CreateApproval(ctx, later); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateApproval(ctx, earlier); err != nil {
		t.Fatal(err)
	}
	list, err := m.ListApprovals(ctx)
	if err != nil {
		t.Fatalf("ListApprovals: %v", err)
	}
	if len(list) != 2 || list[0].ApprovalID != "ap_earlier" || list[1].ApprovalID != "ap_later" {
		t.Fatalf("ListApprovals = %+v, want [ap_earlier, ap_later]", list)
	}
}

func TestMemoryDecideApprovalGrantThenAlreadyDecided(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	a := Approval{ApprovalID: "ap_3", AgentID: "agent://x/bot", RunID: "r1", RequestedAt: time.Now()}
	if err := m.CreateApproval(ctx, a); err != nil {
		t.Fatal(err)
	}
	decidedAt := time.Now().UTC()
	got, err := m.DecideApproval(ctx, "ap_3", "grant", "alice@acme.example", decidedAt)
	if err != nil {
		t.Fatalf("DecideApproval: %v", err)
	}
	if got.Decision != "grant" || got.DecidedBy != "alice@acme.example" || got.Pending() {
		t.Errorf("DecideApproval result = %+v, want decided grant by alice", got)
	}

	if _, err := m.DecideApproval(ctx, "ap_3", "deny", "bob@acme.example", time.Now()); err == nil {
		t.Fatal("deciding an already-decided approval: expected ErrAlreadyDecided, got nil")
	} else if !errors.Is(err, ErrAlreadyDecided) {
		t.Errorf("deciding an already-decided approval: got %v, want ErrAlreadyDecided", err)
	}
}

func TestMemoryDecideApprovalNotFound(t *testing.T) {
	m := NewMemory()
	if _, err := m.DecideApproval(context.Background(), "missing", "grant", "alice", time.Now()); err == nil {
		t.Fatal("DecideApproval(missing): expected an error, got nil")
	} else if !errors.Is(err, ErrNotFound) {
		t.Errorf("DecideApproval(missing): got %v, want ErrNotFound", err)
	}
}

// TestMemoryTryRedeemAtomic is the table test WARDRYX_APPROVAL_SINGLE_USE
// relies on: hitting TryRedeem twice with the same key returns true then
// false (allow-once), and different keys are independent claims.
func TestMemoryTryRedeemAtomic(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()

	first, err := m.TryRedeem(ctx, "key-a")
	if err != nil {
		t.Fatalf("first TryRedeem: %v", err)
	}
	if !first {
		t.Fatal("first TryRedeem(key-a) = false, want true (nothing has claimed it yet)")
	}

	second, err := m.TryRedeem(ctx, "key-a")
	if err != nil {
		t.Fatalf("second TryRedeem: %v", err)
	}
	if second {
		t.Fatal("second TryRedeem(key-a) = true, want false (already claimed)")
	}

	// A third call is still false: the claim is permanent, not one-shot-then-reset.
	third, err := m.TryRedeem(ctx, "key-a")
	if err != nil {
		t.Fatalf("third TryRedeem: %v", err)
	}
	if third {
		t.Fatal("third TryRedeem(key-a) = true, want false")
	}

	// A different key is an independent claim.
	otherKey, err := m.TryRedeem(ctx, "key-b")
	if err != nil {
		t.Fatalf("TryRedeem(key-b): %v", err)
	}
	if !otherKey {
		t.Error("TryRedeem(key-b) = false, want true: a different key must not be blocked by key-a's claim")
	}
}

// TestMemoryTryRedeemRaceSafe drives many goroutines at the same key
// concurrently and asserts exactly one of them observes true. Run with
// -race to additionally confirm the mutex actually guards the map (not
// just that the counts happen to work out).
func TestMemoryTryRedeemRaceSafe(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	const n = 50

	var wg sync.WaitGroup
	results := make([]bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ok, err := m.TryRedeem(ctx, "contended-key")
			if err != nil {
				t.Errorf("TryRedeem: %v", err)
				return
			}
			results[i] = ok
		}(i)
	}
	wg.Wait()

	wins := 0
	for _, ok := range results {
		if ok {
			wins++
		}
	}
	if wins != 1 {
		t.Errorf("concurrent TryRedeem(contended-key) across %d goroutines: %d observed true, want exactly 1", n, wins)
	}
}

// TestMemoryTryRedeemManyKeysConcurrentlyAreIndependent complements
// TestMemoryTryRedeemRaceSafe: distinct keys claimed concurrently must each
// succeed exactly once, proving the lock isn't serializing away unrelated
// claims.
func TestMemoryTryRedeemManyKeysConcurrentlyAreIndependent(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	const n = 50

	var wg sync.WaitGroup
	results := make([]bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ok, err := m.TryRedeem(ctx, fmt.Sprintf("key-%d", i))
			if err != nil {
				t.Errorf("TryRedeem: %v", err)
				return
			}
			results[i] = ok
		}(i)
	}
	wg.Wait()

	for i, ok := range results {
		if !ok {
			t.Errorf("TryRedeem(key-%d) = false, want true: distinct keys must not contend with each other", i)
		}
	}
}
