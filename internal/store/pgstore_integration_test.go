//go:build integration

// These tests require a real Postgres. Run with:
//
//	DATABASE_URL=postgres://user:pass@localhost:5432/wardryx_test?sslmode=disable \
//	    go test -tags integration ./internal/store/
package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// usd returns a pointer to v, for constructing a policy.Policy's
// RequireHumanAboveUSD/DenyAboveUSD fields (*float64, so a caller can say
// zero and be believed).
func usd(v float64) *float64 { return &v }

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
	if _, err := p.db.Exec(`TRUNCATE approvals, approval_redemptions, policies, agent_proof_replays, approval_previews`); err != nil {
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
	got, err := p.DecideApproval(ctx, "ap_pg_decide", "grant", "alice@acme.example", "", decidedAt)
	if err != nil {
		t.Fatalf("DecideApproval: %v", err)
	}
	if got.Decision != "grant" || got.DecidedBy != "alice@acme.example" || got.Pending() {
		t.Errorf("DecideApproval result = %+v, want decided grant by alice", got)
	}

	if _, err := p.DecideApproval(ctx, "ap_pg_decide", "deny", "bob@acme.example", "", time.Now()); !errors.Is(err, ErrAlreadyDecided) {
		t.Errorf("second DecideApproval = %v, want ErrAlreadyDecided", err)
	}
}

// The Postgres twin of TestMemoryDecideApprovalKeepsTheLabelApartFromTheApprover:
// the label column is written, read by GetApproval and ListApprovals, and an
// empty label is stored as NULL and read back as empty.
func TestPgDecideApprovalKeepsTheLabelApartFromTheApprover(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	for _, id := range []string{"ap_pg_l1", "ap_pg_l2"} {
		if err := p.CreateApproval(ctx, Approval{ApprovalID: id, AgentID: "agent://x/bot", RunID: "r1", RequestedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := p.DecideApproval(ctx, "ap_pg_l1", "grant", "key:0123456789abcdef", "alice", time.Now().UTC())
	if err != nil || got.DecidedBy != "key:0123456789abcdef" || got.DecidedByLabel != "alice" {
		t.Fatalf("DecideApproval = %+v, %v", got, err)
	}
	if _, err := p.DecideApproval(ctx, "ap_pg_l2", "deny", "key:fedcba9876543210", "", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	list, err := p.ListApprovals(ctx)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, a := range list {
		switch a.ApprovalID {
		case "ap_pg_l1":
			seen++
			if a.DecidedByLabel != "alice" {
				t.Errorf("listed ap_pg_l1 = %+v, want label alice", a)
			}
		case "ap_pg_l2":
			seen++
			if a.DecidedByLabel != "" || a.DecidedBy != "key:fedcba9876543210" {
				t.Errorf("listed ap_pg_l2 = %+v, want no label", a)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("listed %d of the two approvals", seen)
	}
}

func TestPgDecideApprovalNotFound(t *testing.T) {
	p := testDB(t)
	if _, err := p.DecideApproval(context.Background(), "does-not-exist", "grant", "alice", "", time.Now()); !errors.Is(err, ErrNotFound) {
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
	pol := policy.Policy{Name: "finance-guardrail", Target: "agent://acme.example/finance/*", DenyTool: []string{"send_wire_transfer"}, RequireHumanAboveUSD: usd(500)}
	updatedAt := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)

	if err := p.PutPolicy(ctx, "finance", pol, updatedAt); err != nil {
		t.Fatalf("PutPolicy: %v", err)
	}
	got, err := p.GetPolicy(ctx, "finance")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if got.ID != "finance" || got.Policy.Target != pol.Target || got.Policy.RequireHumanAboveUSD == nil || *got.Policy.RequireHumanAboveUSD != 500 {
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
		RequireHumanAboveUSD: usd(500),
		DenyAboveUSD:         usd(5000),
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

func TestPgTryRecordProofClaimsAKeyOnce(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	until := time.Now().Add(time.Minute)

	first, err := p.TryRecordProof(ctx, "proof-a", until)
	if err != nil || !first {
		t.Fatalf("the first claim: claimed %v, err %v; want true", first, err)
	}
	second, err := p.TryRecordProof(ctx, "proof-a", until)
	if err != nil || second {
		t.Fatalf("the second claim: claimed %v, err %v; want false and no error", second, err)
	}
	other, err := p.TryRecordProof(ctx, "proof-b", until)
	if err != nil || !other {
		t.Fatalf("another key: claimed %v, err %v; want true", other, err)
	}
}

// Two handles on one database are two wardryx instances. Exactly one caller may
// see true, however many ask at once, and that is the database's doing: no lock
// in this process spans the two handles.
func TestPgTryRecordProofIsAtomicAcrossConnections(t *testing.T) {
	first := testDB(t)
	second, err := OpenPostgres(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("open the second handle: %v", err)
	}
	t.Cleanup(func() { second.Close() })
	handles := []*Postgres{first, second}
	until := time.Now().Add(time.Minute)

	var claimed atomic.Int32
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := handles[i%2].TryRecordProof(context.Background(), "proof-race", until)
			if err != nil {
				t.Errorf("TryRecordProof: %v", err)
			}
			if ok {
				claimed.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := claimed.Load(); got != 1 {
		t.Fatalf("%d callers claimed one key, want exactly 1", got)
	}
}

// A restart is a new pool on the same table.
func TestPgAProofRecordSurvivesReopeningTheStore(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	if ok, err := p.TryRecordProof(ctx, "proof-restart", time.Now().Add(time.Minute)); err != nil || !ok {
		t.Fatalf("the claim: claimed %v, err %v", ok, err)
	}
	reopened, err := OpenPostgres(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()
	if ok, err := reopened.TryRecordProof(ctx, "proof-restart", time.Now().Add(time.Minute)); err != nil || ok {
		t.Fatalf("the claim after reopening: claimed %v, err %v; want false, the row is in the table", ok, err)
	}
}

func TestPgPurgeProofsRemovesOnlyRowsPastTheirWindowAndTheGrace(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	const grace = 5 * time.Minute
	rows := []struct {
		key  string
		age  time.Duration // how long ago the window closed; negative is still open
		gone bool
	}{
		{"window-still-open", -time.Minute, false},
		{"closed-inside-the-grace", grace - time.Minute, false},
		{"closed-past-the-grace", grace + time.Minute, true},
		{"closed-long-ago", 24 * time.Hour, true},
	}
	for _, r := range rows {
		if ok, err := p.TryRecordProof(ctx, r.key, time.Now().Add(-r.age)); err != nil || !ok {
			t.Fatalf("%s: claimed %v, err %v", r.key, ok, err)
		}
	}
	removed, err := p.PurgeProofs(ctx, grace)
	if err != nil {
		t.Fatalf("PurgeProofs: %v", err)
	}
	if removed != 2 {
		t.Fatalf("PurgeProofs removed %d rows, want 2", removed)
	}
	for _, r := range rows {
		claimed, err := p.TryRecordProof(ctx, r.key, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatalf("%s: %v", r.key, err)
		}
		if claimed != r.gone {
			t.Errorf("%s: claimable again is %v, want %v", r.key, claimed, r.gone)
		}
	}
}

// The record is on the decide path, so a burst must not cost a new connection per
// call. Measured 2026-11-04 on the built binary at 32 callers: database/sql's
// default of two idle connections opened 2241 sessions for 5952 decides, and the
// p99 went from tens of milliseconds to hundreds.
func TestPgABurstOfProofsReusesItsConnections(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	sessions := func() int64 {
		var n int64
		if err := p.db.QueryRowContext(ctx,
			`SELECT sessions FROM pg_stat_database WHERE datname = current_database()`).Scan(&n); err != nil {
			t.Fatalf("read the session count: %v", err)
		}
		return n
	}
	burst := func(round int) {
		var wg sync.WaitGroup
		for i := range maxPoolConns {
			wg.Add(1)
			go func() {
				defer wg.Done()
				key := fmt.Sprintf("burst-%d-%d", round, i)
				if _, err := p.TryRecordProof(ctx, key, time.Now().Add(time.Minute)); err != nil {
					t.Errorf("TryRecordProof: %v", err)
				}
			}()
		}
		wg.Wait()
	}
	burst(0) // the pool fills
	before := sessions()
	for round := 1; round <= 5; round++ {
		burst(round)
	}
	// pg_stat_database counts a session when it ends, so this reads the sessions
	// the pool closed. Reopening them per burst is the churn under test.
	time.Sleep(600 * time.Millisecond)
	if got := sessions() - before; got > int64(maxPoolConns) {
		t.Fatalf("five bursts on a warm pool closed %d sessions, want none beyond the pool's own %d", got, maxPoolConns)
	}
}

func TestPgThePoolIsBounded(t *testing.T) {
	p := testDB(t)
	if got := p.db.Stats().MaxOpenConnections; got != maxPoolConns {
		t.Fatalf("the pool's limit is %d, want %d: with no limit a burst past max_connections reads as a store failure", got, maxPoolConns)
	}
}

// A second run of the schema is what every start does.
func TestPgTheProofRecordSchemaAppliesTwice(t *testing.T) {
	p := testDB(t)
	if err := p.migrate(context.Background()); err != nil {
		t.Fatalf("a second migrate: %v", err)
	}
}

func pgOnce(id, agent, run, org string) Approval {
	return Approval{ApprovalID: id, AgentID: agent, RunID: run, RequestedAt: time.Now().UTC(), Context: map[string]any{"org": org}}
}

func TestPgOneCallIsOnePendingRow(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	a, outcome, err := p.CreateApprovalOnce(ctx, pgOnce("ap1", "agent://x/a", "r", "acme"), "k", 5)
	if err != nil || outcome != PendingCreated || a.ApprovalID != "ap1" || a.Context["org"] != "acme" {
		t.Fatalf("first: %+v %v %v", a, outcome, err)
	}
	b, outcome, err := p.CreateApprovalOnce(ctx, pgOnce("ap2", "agent://x/a", "r", "acme"), "k", 5)
	if err != nil || outcome != PendingExisting || b.ApprovalID != "ap1" {
		t.Fatalf("second: %+v %v %v, want the row it has", b, outcome, err)
	}
	all, err := p.ListApprovals(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("%d rows, %v", len(all), err)
	}
}

func TestPgADecidedRowLeavesTheIndex(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	if _, _, err := p.CreateApprovalOnce(ctx, pgOnce("ap1", "agent://x/a", "r", "acme"), "k", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := p.DecideApproval(ctx, "ap1", "deny", "key:x", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	got, outcome, err := p.CreateApprovalOnce(ctx, pgOnce("ap2", "agent://x/a", "r", "acme"), "k", 1)
	if err != nil || outcome != PendingCreated || got.ApprovalID != "ap2" {
		t.Fatalf("after a decision: %+v %v %v", got, outcome, err)
	}
}

func TestPgTheLimitIsPerAgentAndOrgAndARepeatIsNotStoppedByIt(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	if _, _, err := p.CreateApprovalOnce(ctx, pgOnce("ap1", "agent://x/a", "r", "acme"), "k1", 1); err != nil {
		t.Fatal(err)
	}
	if got, outcome, err := p.CreateApprovalOnce(ctx, pgOnce("ap2", "agent://x/a", "r", "acme"), "k2", 1); err != nil || outcome != PendingQueueFull || got.ApprovalID != "" {
		t.Fatalf("past the limit: %+v %v %v", got, outcome, err)
	}
	if got, outcome, err := p.CreateApprovalOnce(ctx, pgOnce("ap3", "agent://x/a", "r", "acme"), "k1", 1); err != nil || outcome != PendingExisting || got.ApprovalID != "ap1" {
		t.Fatalf("a repeat at the limit: %+v %v %v", got, outcome, err)
	}
	if _, outcome, err := p.CreateApprovalOnce(ctx, pgOnce("ap4", "agent://x/b", "r", "acme"), "k1", 1); err != nil || outcome != PendingCreated {
		t.Fatalf("another agent: %v %v", outcome, err)
	}
	if _, outcome, err := p.CreateApprovalOnce(ctx, pgOnce("ap5", "agent://x/a", "r", "other"), "k9", 1); err != nil || outcome != PendingCreated {
		t.Fatalf("another org: %v %v", outcome, err)
	}
	if err := p.CreateApproval(ctx, pgOnce("ap6", "agent://x/c", "r", "acme")); err != nil {
		t.Fatal(err)
	}
	if _, outcome, err := p.CreateApprovalOnce(ctx, pgOnce("ap7", "agent://x/c", "r", "acme"), "k1", 1); err != nil || outcome != PendingQueueFull {
		t.Fatalf("beside a plain row: %v %v", outcome, err)
	}
}

// A call stopped by the limit is looked up, to tell a repeat from a new call, and the
// row a person already answered must not read as that repeat.
func TestPgADecidedRowIsNotReportedAsPendingAtTheLimit(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	if _, _, err := p.CreateApprovalOnce(ctx, pgOnce("ap1", "agent://x/a", "r", "acme"), "k1", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := p.DecideApproval(ctx, "ap1", "deny", "key:x", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.CreateApprovalOnce(ctx, pgOnce("ap2", "agent://x/a", "r", "acme"), "k2", 1); err != nil {
		t.Fatal(err)
	}
	got, outcome, err := p.CreateApprovalOnce(ctx, pgOnce("ap3", "agent://x/a", "r", "acme"), "k1", 1)
	if err != nil || outcome != PendingQueueFull || got.ApprovalID != "" {
		t.Fatalf("the call of an answered row at the limit: %+v %v %v, want the queue full", got, outcome, err)
	}
}

func TestPgOneCallIsOneRowAcrossConnections(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	const callers = 48
	var (
		wg      sync.WaitGroup
		created atomic.Int32
		ids     sync.Map
	)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got, outcome, err := p.CreateApprovalOnce(ctx, pgOnce(fmt.Sprintf("ap%d", i), "agent://x/a", "r", "acme"), "k", 5)
			if err != nil {
				t.Error(err)
				return
			}
			if outcome == PendingCreated {
				created.Add(1)
			}
			if outcome == PendingQueueFull {
				t.Error("one call reported the queue full")
			}
			ids.Store(got.ApprovalID, true)
		}(i)
	}
	wg.Wait()
	distinct := 0
	ids.Range(func(any, any) bool { distinct++; return true })
	if created.Load() != 1 || distinct != 1 {
		t.Fatalf("%d callers wrote and %d ids came back, want one of each", created.Load(), distinct)
	}
}

// The limit is read in the statement's snapshot, so a burst may pass it. It must not
// pass it by more than the statements running at that moment, the pool's size.
func TestPgABurstPastTheLimitStaysNearIt(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	const callers, limit = 200, 5
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, _, err := p.CreateApprovalOnce(ctx, pgOnce(fmt.Sprintf("ap%d", i), "agent://x/a", "r", "acme"), fmt.Sprintf("k%d", i), limit); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	all, err := p.ListPendingApprovals(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < limit || len(all) > limit+maxPoolConns {
		t.Fatalf("%d rows pending after a burst of %d against a limit of %d: the bound is the limit plus the pool, %d", len(all), callers, limit, limit+maxPoolConns)
	}
	if _, outcome, err := p.CreateApprovalOnce(ctx, pgOnce("after", "agent://x/a", "r", "acme"), "after", limit); err != nil || outcome != PendingQueueFull {
		t.Fatalf("after the burst: %v %v", outcome, err)
	}
}

func TestPgListPendingApprovalsLeavesOutWhatWasDecided(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	base := time.Now().UTC().Truncate(time.Second)
	for i, id := range []string{"ap_new", "ap_old", "ap_done"} {
		a := pgOnce(id, "agent://x/a", "r", "acme")
		a.RequestedAt = base.Add(time.Duration(2-i) * time.Minute)
		if err := p.CreateApproval(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.DecideApproval(ctx, "ap_done", "grant", "key:x", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := p.ListPendingApprovals(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].ApprovalID != "ap_old" || got[1].ApprovalID != "ap_new" {
		t.Fatalf("%+v, want the two pending rows, oldest first", got)
	}
}

// An upgrade meets a table that already holds identical pending rows, written
// before dedup existed. The schema is applied at open, so an index that refused
// them would be a process that does not start.
func TestPgTheSchemaUpgradesATableThatAlreadyHoldsDuplicates(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	if _, err := p.db.ExecContext(ctx, `DROP INDEX IF EXISTS approvals_pending_call`); err != nil {
		t.Fatal(err)
	}
	if _, err := p.db.ExecContext(ctx, `ALTER TABLE approvals DROP COLUMN IF EXISTS pending_key`); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"old1", "old2"} {
		a := pgOnce(id, "agent://x/a", "r", "acme")
		a.Context["tool_call"] = map[string]any{"digest": "same"}
		if err := p.CreateApproval(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := p.migrate(ctx); err != nil {
			t.Fatalf("apply %d: %v", i+1, err)
		}
	}
	if all, _ := p.ListPendingApprovals(ctx); len(all) != 2 {
		t.Fatalf("%d rows after the upgrade", len(all))
	}
}

func TestPgKeepsAPreviewUntilItIsDecidedOrExpires(t *testing.T) {
	p := testDB(t)
	// Postgres reads expiry by its own clock, so the test moves the rows, not
	// the clock: setNow shifts every row's expires_at back by the difference.
	var shifted time.Duration
	base := time.Now().UTC()
	previewStoreContract(t, p, func(at time.Time) {
		d := at.Sub(base) - shifted
		shifted += d
		if _, err := p.db.Exec(`UPDATE approval_previews SET expires_at = expires_at - make_interval(secs => $1)`, d.Seconds()); err != nil {
			t.Fatal(err)
		}
	})
}

// Invariant 52 on a real Postgres: the same contracts Memory is held to, plus the
// two that only a database can show, two instances checking at once and a backlog
// larger than one statement.

func TestPgExpiresOnlyPendingHoldsPastTheCutoff(t *testing.T) {
	holdExpiryContract(t, testDB(t))
}

func TestPgAnExpiredHoldFreesItsPlaceUnderTheCap(t *testing.T) {
	expiryFreesThePendingCap(t, testDB(t))
}

func TestPgAWithdrawnHoldLosesItsPreviewAndCannotBeDecided(t *testing.T) {
	withdrawContract(t, testDB(t))
}

func TestPgTwoInstancesAndAPersonCloseEachHoldOnce(t *testing.T) {
	p := testDB(t)
	other, err := OpenPostgres(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatalf("open the second instance: %v", err)
	}
	t.Cleanup(func() { other.Close() })
	expiryRacesDecisions(t, p, []HoldExpirer{p, other})
}

func TestPgABacklogLargerThanOneStatementIsClosedInOneCall(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	n := expireBatch*2 + 7
	base := time.Now().UTC().Add(-72 * time.Hour)
	for i := 0; i < n; i++ {
		if err := p.CreateApproval(ctx, Approval{ApprovalID: fmt.Sprintf("ap-back-%04d", i), AgentID: "agent://a", RunID: "r", RequestedAt: base.Add(time.Duration(i) * time.Millisecond)}); err != nil {
			t.Fatal(err)
		}
	}
	closed, err := p.ExpireApprovals(ctx, base.Add(time.Hour), ttlApprover, time.Now().UTC())
	if err != nil || len(closed) != n {
		t.Fatalf("closed %d (%v), want %d", len(closed), err, n)
	}
	if pending, _ := p.ListPendingApprovals(ctx); len(pending) != 0 {
		t.Fatalf("%d holds stayed pending", len(pending))
	}
}

// A hold written before this build, as on a database that already holds them, is
// closed by the first check of a store opened after the upgrade.
func TestPgHoldsWrittenBeforeARestartAreClosedByTheFirstCheckAfterIt(t *testing.T) {
	p := testDB(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 14, 0, 9, 0, 0, time.UTC)
	for i := 0; i < 3; i++ {
		if err := p.CreateApproval(ctx, Approval{ApprovalID: fmt.Sprintf("ap-forge-%d", i), AgentID: "agent://a", RunID: "r", RequestedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	p.Close()
	reopened, err := OpenPostgres(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	closed, err := reopened.ExpireApprovals(ctx, at.Add(24*time.Hour+time.Minute), ttlApprover, time.Now().UTC())
	if err != nil || len(closed) != 3 {
		t.Fatalf("the first check after a restart closed %v (%v), want the three holds", ids(closed), err)
	}
}
