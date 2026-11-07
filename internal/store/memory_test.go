package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/policy"
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
	got, err := m.DecideApproval(ctx, "ap_3", "grant", "alice@acme.example", "", decidedAt)
	if err != nil {
		t.Fatalf("DecideApproval: %v", err)
	}
	if got.Decision != "grant" || got.DecidedBy != "alice@acme.example" || got.Pending() {
		t.Errorf("DecideApproval result = %+v, want decided grant by alice", got)
	}

	if _, err := m.DecideApproval(ctx, "ap_3", "deny", "bob@acme.example", "", time.Now()); err == nil {
		t.Fatal("deciding an already-decided approval: expected ErrAlreadyDecided, got nil")
	} else if !errors.Is(err, ErrAlreadyDecided) {
		t.Errorf("deciding an already-decided approval: got %v, want ErrAlreadyDecided", err)
	}
}

// The label a decision was sent with is kept beside the approver, and read
// back by every read path; no label stays empty rather than becoming the
// approver.
func TestMemoryDecideApprovalKeepsTheLabelApartFromTheApprover(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	for _, id := range []string{"ap_l1", "ap_l2"} {
		if err := m.CreateApproval(ctx, Approval{ApprovalID: id, AgentID: "agent://x/bot", RunID: "r1", RequestedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := m.DecideApproval(ctx, "ap_l1", "grant", "key:0123456789abcdef", "alice", time.Now().UTC())
	if err != nil || got.DecidedBy != "key:0123456789abcdef" || got.DecidedByLabel != "alice" {
		t.Fatalf("DecideApproval = %+v, %v", got, err)
	}
	if read, _ := m.GetApproval(ctx, "ap_l1"); read.DecidedByLabel != "alice" || read.DecidedBy != "key:0123456789abcdef" {
		t.Fatalf("GetApproval = %+v", read)
	}
	if _, err := m.DecideApproval(ctx, "ap_l2", "deny", "key:fedcba9876543210", "", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	list, _ := m.ListApprovals(ctx)
	for _, a := range list {
		if a.ApprovalID == "ap_l2" && (a.DecidedByLabel != "" || a.DecidedBy != "key:fedcba9876543210") {
			t.Fatalf("ListApprovals row = %+v, want no label", a)
		}
	}
}

func TestMemoryDecideApprovalNotFound(t *testing.T) {
	m := NewMemory()
	if _, err := m.DecideApproval(context.Background(), "missing", "grant", "alice", "", time.Now()); err == nil {
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

// ------------------------------------------------------------------
// Policy CRUD (PutPolicy/GetPolicy/ListPolicies/DeletePolicy)
// ------------------------------------------------------------------

func TestMemoryPutAndGetPolicy(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	p := policy.Policy{Name: "finance-guardrail", Target: "agent://acme.example/finance/*", DenyTool: []string{"send_wire_transfer"}}
	updatedAt := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)

	if err := m.PutPolicy(ctx, "finance", p, updatedAt); err != nil {
		t.Fatalf("PutPolicy: %v", err)
	}
	got, err := m.GetPolicy(ctx, "finance")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if got.ID != "finance" || got.Policy.Target != p.Target || len(got.Policy.DenyTool) != 1 || got.Policy.DenyTool[0] != "send_wire_transfer" {
		t.Errorf("GetPolicy = %+v, want id=finance matching %+v", got, p)
	}
	if !got.UpdatedAt.Equal(updatedAt) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, updatedAt)
	}
}

func TestMemoryGetPolicyNotFound(t *testing.T) {
	m := NewMemory()
	if _, err := m.GetPolicy(context.Background(), "does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetPolicy(missing) = %v, want ErrNotFound", err)
	}
}

// TestMemoryPutPolicyReplacesExisting proves PutPolicy is upsert semantics,
// not create-only: a second Put under the same id overwrites the first
// rather than erroring (contrast CreateApproval, which does error on a
// duplicate id).
func TestMemoryPutPolicyReplacesExisting(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	first := policy.Policy{Name: "v1", Target: "agent://x/*", MaxSteps: 5}
	second := policy.Policy{Name: "v2", Target: "agent://x/*", MaxSteps: 10}

	if err := m.PutPolicy(ctx, "p1", first, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := m.PutPolicy(ctx, "p1", second, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := m.GetPolicy(ctx, "p1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Policy.Name != "v2" || got.Policy.MaxSteps != 10 {
		t.Errorf("GetPolicy after replace = %+v, want the second write (v2, MaxSteps=10)", got.Policy)
	}
}

func TestMemoryPolicyIsDeepCopied(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	tools := []string{"send_wire_transfer"}
	p := policy.Policy{Name: "x", Target: "agent://x/*", DenyTool: tools}
	if err := m.PutPolicy(ctx, "p1", p, time.Now()); err != nil {
		t.Fatal(err)
	}

	// Mutate the caller's slice after Put returns; the stored copy must be
	// unaffected, the same protection deepCopyContext gives Approval.Context.
	tools[0] = "mutated"

	got, err := m.GetPolicy(ctx, "p1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Policy.DenyTool[0] != "send_wire_transfer" {
		t.Errorf("DenyTool[0] = %q, want the original value unaffected by the caller's later mutation", got.Policy.DenyTool[0])
	}
}

func TestMemoryListPoliciesOrderedByID(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	for _, id := range []string{"zebra", "alpha", "mid"} {
		if err := m.PutPolicy(ctx, id, policy.Policy{Target: "agent://x/*"}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	list, err := m.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("ListPolicies len = %d, want 3", len(list))
	}
	var ids []string
	for _, r := range list {
		ids = append(ids, r.ID)
	}
	want := []string{"alpha", "mid", "zebra"}
	for i, id := range ids {
		if id != want[i] {
			t.Errorf("ListPolicies order = %v, want %v", ids, want)
			break
		}
	}
}

func TestMemoryListPoliciesEmpty(t *testing.T) {
	m := NewMemory()
	list, err := m.ListPolicies(context.Background())
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("ListPolicies on an empty store = %+v, want empty", list)
	}
}

func TestMemoryDeletePolicy(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	if err := m.PutPolicy(ctx, "p1", policy.Policy{Target: "agent://x/*"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := m.DeletePolicy(ctx, "p1"); err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
	if _, err := m.GetPolicy(ctx, "p1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetPolicy after delete = %v, want ErrNotFound", err)
	}
}

func TestMemoryDeletePolicyNotFound(t *testing.T) {
	m := NewMemory()
	if err := m.DeletePolicy(context.Background(), "does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeletePolicy(missing) = %v, want ErrNotFound", err)
	}
}

// CreateApprovalOnce is what keeps a queue a person reads from being a log of what
// an agent in a loop tried. The Postgres twin of each of these is in
// pgstore_integration_test.go.

func onceApproval(id, agent, run, org string) Approval {
	return Approval{ApprovalID: id, AgentID: agent, RunID: run, RequestedAt: time.Now().UTC(), Context: map[string]any{"org": org}}
}

func TestMemoryOneCallIsOnePendingRow(t *testing.T) {
	m, ctx := NewMemory(), context.Background()
	a, outcome, err := m.CreateApprovalOnce(ctx, onceApproval("ap1", "agent://x/a", "r", "acme"), "k", 5)
	if err != nil || outcome != PendingCreated || a.ApprovalID != "ap1" {
		t.Fatalf("first: %+v %v %v", a, outcome, err)
	}
	b, outcome, err := m.CreateApprovalOnce(ctx, onceApproval("ap2", "agent://x/a", "r", "acme"), "k", 5)
	if err != nil || outcome != PendingExisting || b.ApprovalID != "ap1" {
		t.Fatalf("second: %+v %v %v, want the row it has", b, outcome, err)
	}
	if all, _ := m.ListApprovals(ctx); len(all) != 1 {
		t.Fatalf("%d rows", len(all))
	}
}

func TestMemoryAnotherKeyRunOrAgentIsAnotherRow(t *testing.T) {
	m, ctx := NewMemory(), context.Background()
	for i, c := range []struct{ agent, run, key string }{
		{"agent://x/a", "r", "k"}, {"agent://x/a", "r", "k2"}, {"agent://x/a", "r2", "k"}, {"agent://x/b", "r", "k"},
	} {
		if _, outcome, err := m.CreateApprovalOnce(ctx, onceApproval(fmt.Sprintf("ap%d", i), c.agent, c.run, "acme"), c.key, 5); err != nil || outcome != PendingCreated {
			t.Fatalf("case %d: %v %v", i, outcome, err)
		}
	}
}

func TestMemoryADecidedRowNoLongerCounts(t *testing.T) {
	m, ctx := NewMemory(), context.Background()
	if _, _, err := m.CreateApprovalOnce(ctx, onceApproval("ap1", "agent://x/a", "r", "acme"), "k", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := m.DecideApproval(ctx, "ap1", "deny", "key:x", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	got, outcome, err := m.CreateApprovalOnce(ctx, onceApproval("ap2", "agent://x/a", "r", "acme"), "k", 1)
	if err != nil || outcome != PendingCreated || got.ApprovalID != "ap2" {
		t.Fatalf("after a decision: %+v %v %v", got, outcome, err)
	}
}

func TestMemoryTheLimitIsPerAgentAndOrgAndARepeatIsNotStoppedByIt(t *testing.T) {
	m, ctx := NewMemory(), context.Background()
	if _, _, err := m.CreateApprovalOnce(ctx, onceApproval("ap1", "agent://x/a", "r", "acme"), "k1", 1); err != nil {
		t.Fatal(err)
	}
	if _, outcome, err := m.CreateApprovalOnce(ctx, onceApproval("ap2", "agent://x/a", "r", "acme"), "k2", 1); err != nil || outcome != PendingQueueFull {
		t.Fatalf("past the limit: %v %v", outcome, err)
	}
	if got, outcome, _ := m.CreateApprovalOnce(ctx, onceApproval("ap3", "agent://x/a", "r", "acme"), "k1", 1); outcome != PendingExisting || got.ApprovalID != "ap1" {
		t.Fatalf("a repeat at the limit: %+v %v", got, outcome)
	}
	if _, outcome, _ := m.CreateApprovalOnce(ctx, onceApproval("ap4", "agent://x/b", "r", "acme"), "k1", 1); outcome != PendingCreated {
		t.Fatalf("another agent: %v", outcome)
	}
	if _, outcome, _ := m.CreateApprovalOnce(ctx, onceApproval("ap5", "agent://x/a", "r", "other"), "k9", 1); outcome != PendingCreated {
		t.Fatalf("another org: %v", outcome)
	}
	// A plain CreateApproval row counts: a person reads one queue.
	if err := m.CreateApproval(ctx, onceApproval("ap6", "agent://x/c", "r", "acme")); err != nil {
		t.Fatal(err)
	}
	if _, outcome, _ := m.CreateApprovalOnce(ctx, onceApproval("ap7", "agent://x/c", "r", "acme"), "k1", 1); outcome != PendingQueueFull {
		t.Fatalf("beside a plain row: %v", outcome)
	}
}

func TestMemoryOneCallIsOneRowUnderConcurrency(t *testing.T) {
	m, ctx := NewMemory(), context.Background()
	const callers = 64
	var wg sync.WaitGroup
	created := make(chan string, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got, outcome, err := m.CreateApprovalOnce(ctx, onceApproval(fmt.Sprintf("ap%d", i), "agent://x/a", "r", "acme"), "k", 5)
			if err != nil {
				t.Error(err)
			}
			if outcome == PendingCreated {
				created <- got.ApprovalID
			}
		}(i)
	}
	wg.Wait()
	close(created)
	if n := len(created); n != 1 {
		t.Fatalf("%d callers wrote the row, want exactly one", n)
	}
}

func TestMemoryCreateApprovalOnceRefusesAnIDThatIsTaken(t *testing.T) {
	m, ctx := NewMemory(), context.Background()
	if err := m.CreateApproval(ctx, onceApproval("ap1", "agent://x/a", "r", "acme")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.CreateApprovalOnce(ctx, onceApproval("ap1", "agent://x/b", "r", "acme"), "k", 5); err == nil {
		t.Fatal("an id already taken was written over")
	}
}

func TestMemoryCreateApprovalOnceRefusesAContextThatDoesNotMarshal(t *testing.T) {
	m := NewMemory()
	bad := onceApproval("ap1", "agent://x/a", "r", "acme")
	bad.Context["c"] = make(chan int)
	if _, _, err := m.CreateApprovalOnce(context.Background(), bad, "k", 5); err == nil {
		t.Fatal("a context that does not marshal was accepted")
	}
}

func TestMemoryListPendingApprovalsLeavesOutWhatWasDecided(t *testing.T) {
	m, ctx := NewMemory(), context.Background()
	base := time.Now().UTC()
	for i, id := range []string{"ap_new", "ap_old", "ap_done"} {
		a := onceApproval(id, "agent://x/a", "r", "acme")
		a.RequestedAt = base.Add(time.Duration(2-i) * time.Minute)
		if err := m.CreateApproval(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.DecideApproval(ctx, "ap_done", "grant", "key:x", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := m.ListPendingApprovals(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ApprovalID != "ap_old" || got[1].ApprovalID != "ap_new" {
		t.Fatalf("%+v, want the two pending rows, oldest first", got)
	}
}
