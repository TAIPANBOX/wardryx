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
	"testing"
	"time"
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
	if _, err := p.db.Exec(`TRUNCATE approvals`); err != nil {
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
