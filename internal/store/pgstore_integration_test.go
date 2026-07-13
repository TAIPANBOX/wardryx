//go:build integration

// These tests require a real Postgres. Run with:
//
//	DATABASE_URL=postgres://user:pass@localhost:5432/wardryx_test?sslmode=disable \
//	    go test -tags integration ./internal/store/
package store

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/policy"
)

func testDB(t *testing.T) *Postgres {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	p, err := OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := p.db.Exec(`TRUNCATE approvals, approval_redemptions, policies`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(func() { p.Close() })
	return p
}

func TestPgCreateAndGetApproval(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()

	a := Approval{
		ApprovalID:  "ap_pg_1",
		AgentID:     "agent://acme.example/finance/bot1",
		RunID:       "run-1",
		RequestedAt: time.Date(2026, 7, 9, 10, 0, 0, 0, time.UTC),
		Context: map[string]any{
			"org":          "acme",
			"tool_names":   []string{"send_wire_transfer"},
			"est_cost_usd": 1200.50,
		},
	}
	if err := p.CreateApproval(ctx, a); err != nil {
		t.Fatalf("CreateApproval: %v", err)
	}

	got, err := p.GetApproval(ctx, "ap_pg_1")
	if err != nil {
		t.Fatalf("GetApproval: %v", err)
	}
	if got.AgentID != a.AgentID || got.RunID != a.RunID {
		t.Errorf("GetApproval = %+v, want agent/run to match %+v", got, a)
	}
	if !got.RequestedAt.Equal(a.RequestedAt) {
		t.Errorf("RequestedAt = %v, want %v", got.RequestedAt, a.RequestedAt)
	}
	if !got.Pending() {
		t.Error("freshly created approval should be Pending")
	}
	if got.Context["org"] != "acme" {
		t.Errorf("Context[org] = %v, want acme", got.Context["org"])
	}
	tools, ok := got.Context["tool_names"].([]any)
	if !ok || len(tools) != 1 || tools[0] != "send_wire_transfer" {
		t.Errorf("Context[tool_names] = %#v, want []any{\"send_wire_transfer\"}", got.Context["tool_names"])
	}
}

func TestPgGetApprovalNotFound(t *testing.T) {
	p := testDB(t)
	if _, err := p.GetApproval(context.Background(), "does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetApproval(missing) = %v, want ErrNotFound", err)
	}
}

func TestPgListApprovalsOrderedByRequestedAt(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	base := time.Date(2026, 7, 9, 9, 0, 0, 0, time.UTC)

	later := Approval{ApprovalID: "ap_pg_later", AgentID: "agent://x/bot", RunID: "r1", RequestedAt: base.Add(time.Hour)}
	earlier := Approval{ApprovalID: "ap_pg_earlier", AgentID: "agent://x/bot", RunID: "r2", RequestedAt: base}
	if err := p.CreateApproval(ctx, later); err != nil {
		t.Fatal(err)
	}
	if err := p.CreateApproval(ctx, earlier); err != nil {
		t.Fatal(err)
	}

	list, err := p.ListApprovals(ctx)
	if err != nil {
		t.Fatalf("ListApprovals: %v", err)
	}
	if len(list) != 2 || list[0].ApprovalID != "ap_pg_earlier" || list[1].ApprovalID != "ap_pg_later" {
		t.Fatalf("ListApprovals = %+v, want [ap_pg_earlier, ap_pg_later]", list)
	}
}

func TestPgDecideApprovalGrantThenAlreadyDecided(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	a := Approval{ApprovalID: "ap_pg_decide", AgentID: "agent://x/bot", RunID: "r1", RequestedAt: time.Now().UTC()}
	if err := p.CreateApproval(ctx, a); err != nil {
		t.Fatal(err)
	}

	decidedAt := time.Now().UTC().Truncate(time.Microsecond)
	got, err := p.DecideApproval(ctx, "ap_pg_decide", "grant", "alice@acme.example", decidedAt)
	if err != nil {
		t.Fatalf("DecideApproval: %v", err)
	}
	if got.Decision != "grant" || got.DecidedBy != "alice@acme.example" || got.Pending() {
		t.Errorf("DecideApproval result = %+v, want decided grant by alice", got)
	}

	if _, err := p.DecideApproval(ctx, "ap_pg_decide", "deny", "bob@acme.example", time.Now()); !errors.Is(err, ErrAlreadyDecided) {
		t.Errorf("second DecideApproval = %v, want ErrAlreadyDecided", err)
	}
}

func TestPgDecideApprovalNotFound(t *testing.T) {
	p := testDB(t)
	if _, err := p.DecideApproval(context.Background(), "does-not-exist", "grant", "alice", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("DecideApproval(missing) = %v, want ErrNotFound", err)
	}
}

// TestPgMigrateIsIdempotent mirrors Idryx's own re-migrate coverage: applying
// schema.sql twice against the same database must never fail.
func TestPgMigrateIsIdempotent(t *testing.T) {
	p := testDB(t)
	if err := p.migrate(context.Background()); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
}

// TestPgTryRedeemAtomic mirrors TestMemoryTryRedeemAtomic against a real
// Postgres: hitting TryRedeem twice with the same key returns true then
// false, backed by approval_redemptions' primary key rather than an
// in-process mutex.
func TestPgTryRedeemAtomic(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()

	first, err := p.TryRedeem(ctx, "pg-key-a")
	if err != nil {
		t.Fatalf("first TryRedeem: %v", err)
	}
	if !first {
		t.Fatal("first TryRedeem(pg-key-a) = false, want true")
	}

	second, err := p.TryRedeem(ctx, "pg-key-a")
	if err != nil {
		t.Fatalf("second TryRedeem: %v", err)
	}
	if second {
		t.Fatal("second TryRedeem(pg-key-a) = true, want false (already claimed)")
	}

	otherKey, err := p.TryRedeem(ctx, "pg-key-b")
	if err != nil {
		t.Fatalf("TryRedeem(pg-key-b): %v", err)
	}
	if !otherKey {
		t.Error("TryRedeem(pg-key-b) = false, want true: a different key must not be blocked by pg-key-a's claim")
	}
}

// TestPgTryRedeemRaceSafe mirrors TestMemoryTryRedeemRaceSafe: many
// concurrent callers claiming the same key against a real Postgres, backed
// by approval_redemptions' unique constraint (INSERT .. ON CONFLICT DO
// NOTHING) rather than any client-side lock, must still let exactly one of
// them win. Run with -race for the client-side goroutine coordination in
// this test itself; the atomicity guarantee under test is the database's.
func TestPgTryRedeemRaceSafe(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	const n = 20

	var wg sync.WaitGroup
	results := make([]bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ok, err := p.TryRedeem(ctx, "pg-contended-key")
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
		t.Errorf("concurrent TryRedeem(pg-contended-key) across %d goroutines: %d observed true, want exactly 1", n, wins)
	}
}

// ------------------------------------------------------------------
// Policy CRUD against a real Postgres, mirroring the Memory coverage in
// memory_test.go so both Store implementations are proven to behave
// identically, per store.go's documented contract.
// ------------------------------------------------------------------

func TestPgPutAndGetPolicy(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	pol := policy.Policy{Name: "finance-guardrail", Target: "agent://acme.example/finance/*", DenyTool: []string{"send_wire_transfer"}, RequireHumanAboveUSD: 500}
	updatedAt := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)

	if err := p.PutPolicy(ctx, "finance", pol, updatedAt); err != nil {
		t.Fatalf("PutPolicy: %v", err)
	}
	got, err := p.GetPolicy(ctx, "finance")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if got.ID != "finance" || got.Policy.Target != pol.Target || got.Policy.RequireHumanAboveUSD != 500 {
		t.Errorf("GetPolicy = %+v, want id=finance matching %+v", got, pol)
	}
	if len(got.Policy.DenyTool) != 1 || got.Policy.DenyTool[0] != "send_wire_transfer" {
		t.Errorf("DenyTool = %v, want [send_wire_transfer]", got.Policy.DenyTool)
	}
	if !got.UpdatedAt.Equal(updatedAt) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, updatedAt)
	}
}

func TestPgGetPolicyNotFound(t *testing.T) {
	p := testDB(t)
	if _, err := p.GetPolicy(context.Background(), "does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetPolicy(missing) = %v, want ErrNotFound", err)
	}
}

// TestPgPutPolicyReplacesExisting proves the ON CONFLICT DO UPDATE upsert
// works against a real Postgres, not just Memory's map assignment.
func TestPgPutPolicyReplacesExisting(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	if err := p.PutPolicy(ctx, "p1", policy.Policy{Name: "v1", Target: "agent://x/*", MaxSteps: 5}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := p.PutPolicy(ctx, "p1", policy.Policy{Name: "v2", Target: "agent://x/*", MaxSteps: 10}, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := p.GetPolicy(ctx, "p1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Policy.Name != "v2" || got.Policy.MaxSteps != 10 {
		t.Errorf("GetPolicy after replace = %+v, want the second write (v2, MaxSteps=10)", got.Policy)
	}

	// Exactly one row for this id, not two -- ON CONFLICT DO UPDATE, not a
	// second INSERT that would violate the primary key or silently duplicate.
	list, err := p.ListPolicies(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Errorf("ListPolicies after replace = %+v, want exactly 1 row for policy_id=p1", list)
	}
}

func TestPgListPoliciesOrderedByID(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	for _, id := range []string{"zebra", "alpha", "mid"} {
		if err := p.PutPolicy(ctx, id, policy.Policy{Target: "agent://x/*"}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	list, err := p.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(list) != 3 || list[0].ID != "alpha" || list[1].ID != "mid" || list[2].ID != "zebra" {
		t.Fatalf("ListPolicies = %+v, want [alpha, mid, zebra]", list)
	}
}

func TestPgDeletePolicy(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	if err := p.PutPolicy(ctx, "p1", policy.Policy{Target: "agent://x/*"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := p.DeletePolicy(ctx, "p1"); err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
	if _, err := p.GetPolicy(ctx, "p1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetPolicy after delete = %v, want ErrNotFound", err)
	}
}

func TestPgDeletePolicyNotFound(t *testing.T) {
	p := testDB(t)
	if err := p.DeletePolicy(context.Background(), "does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeletePolicy(missing) = %v, want ErrNotFound", err)
	}
}

// TestPgPolicyRoundTripsFullPolicyShape proves every Policy field survives
// the JSONB round trip, not just the fields the other tests happen to set.
func TestPgPolicyRoundTripsFullPolicyShape(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	full := policy.Policy{
		Name:                 "full",
		Target:               "agent://acme.example/*",
		DenyTool:             []string{"a", "b"},
		AllowDomains:         []string{"good.example.com"},
		RequireHumanAboveUSD: 500,
		DenyAboveUSD:         5000,
		MaxSteps:             40,
		DenyIfUnattested:     true,
	}
	if err := p.PutPolicy(ctx, "full", full, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := p.GetPolicy(ctx, "full")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Policy, full) {
		t.Errorf("round-tripped policy = %+v, want %+v", got.Policy, full)
	}
}
