package store

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver

	"github.com/TAIPANBOX/wardryx/internal/policy"
)

//go:embed schema.sql
var schema string

// Postgres is a pgx/v5-backed Store, mirroring Idryx's internal/graph.PgStore:
// database/sql over the pgx stdlib driver, with the schema embedded and
// applied idempotently on open.
type Postgres struct {
	db *sql.DB
}

// OpenPostgres opens dsn, verifies the connection, and applies schema.sql.
// dsn is a standard Postgres URL or key/value string.
func OpenPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open postgres: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: ping postgres: %w", err)
	}
	p := &Postgres{db: db}
	if err := p.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return p, nil
}

func (p *Postgres) migrate(ctx context.Context) error {
	if _, err := p.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("store: apply schema: %w", err)
	}
	return nil
}

// Close releases the underlying connection pool.
func (p *Postgres) Close() error { return p.db.Close() }

func (p *Postgres) CreateApproval(ctx context.Context, a Approval) error {
	ctxJSON, err := marshalContext(a.Context)
	if err != nil {
		return err
	}
	_, err = p.db.ExecContext(ctx,
		`INSERT INTO approvals (approval_id, agent_id, run_id, requested_at, context_json)
		 VALUES ($1, $2, $3, $4, $5)`,
		a.ApprovalID, a.AgentID, a.RunID, a.RequestedAt, ctxJSON)
	if err != nil {
		return fmt.Errorf("store: insert approval %q: %w", a.ApprovalID, err)
	}
	return nil
}

func (p *Postgres) GetApproval(ctx context.Context, id string) (Approval, error) {
	row := p.db.QueryRowContext(ctx,
		`SELECT approval_id, agent_id, run_id, requested_at, decided_at, decided_by, decision, context_json
		 FROM approvals WHERE approval_id = $1`, id)
	a, err := scanApproval(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Approval{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return Approval{}, fmt.Errorf("store: get approval %q: %w", id, err)
	}
	return a, nil
}

func (p *Postgres) ListApprovals(ctx context.Context) ([]Approval, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT approval_id, agent_id, run_id, requested_at, decided_at, decided_by, decision, context_json
		 FROM approvals ORDER BY requested_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list approvals: %w", err)
	}
	defer rows.Close()

	var out []Approval
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan approval: %w", err)
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list approvals: %w", err)
	}
	return out, nil
}

func (p *Postgres) DecideApproval(ctx context.Context, id, decision, decidedBy string, decidedAt time.Time) (Approval, error) {
	res, err := p.db.ExecContext(ctx,
		`UPDATE approvals SET decision = $2, decided_by = $3, decided_at = $4
		 WHERE approval_id = $1 AND decision IS NULL`,
		id, decision, decidedBy, decidedAt)
	if err != nil {
		return Approval{}, fmt.Errorf("store: decide approval %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Approval{}, fmt.Errorf("store: decide approval %q: %w", id, err)
	}
	if n == 0 {
		// Either the row does not exist, or it exists but was already
		// decided; distinguish so the caller can respond precisely.
		if _, getErr := p.GetApproval(ctx, id); errors.Is(getErr, ErrNotFound) {
			return Approval{}, fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		return Approval{}, fmt.Errorf("%w: %s", ErrAlreadyDecided, id)
	}
	return p.GetApproval(ctx, id)
}

// TryRedeem claims key via an INSERT .. ON CONFLICT DO NOTHING against
// approval_redemptions: the database's own unique constraint on
// redemption_key makes the check-and-set atomic across every wardryx
// instance sharing this Postgres, not just within one process (contrast
// Memory.TryRedeem, which is only atomic within its own process).
func (p *Postgres) TryRedeem(ctx context.Context, key string) (bool, error) {
	res, err := p.db.ExecContext(ctx,
		`INSERT INTO approval_redemptions (redemption_key) VALUES ($1)
		 ON CONFLICT (redemption_key) DO NOTHING`,
		key)
	if err != nil {
		return false, fmt.Errorf("store: try redeem %q: %w", key, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: try redeem %q: %w", key, err)
	}
	return n == 1, nil
}

func (p *Postgres) PutPolicy(ctx context.Context, id string, pol policy.Policy, updatedAt time.Time) error {
	polJSON, err := json.Marshal(pol)
	if err != nil {
		return fmt.Errorf("store: marshal policy %q: %w", id, err)
	}
	_, err = p.db.ExecContext(ctx,
		`INSERT INTO policies (policy_id, policy_json, updated_at) VALUES ($1, $2, $3)
		 ON CONFLICT (policy_id) DO UPDATE SET policy_json = $2, updated_at = $3`,
		id, polJSON, updatedAt)
	if err != nil {
		return fmt.Errorf("store: put policy %q: %w", id, err)
	}
	return nil
}

func (p *Postgres) GetPolicy(ctx context.Context, id string) (PolicyRecord, error) {
	row := p.db.QueryRowContext(ctx,
		`SELECT policy_id, policy_json, updated_at FROM policies WHERE policy_id = $1`, id)
	r, err := scanPolicy(row)
	if errors.Is(err, sql.ErrNoRows) {
		return PolicyRecord{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if err != nil {
		return PolicyRecord{}, fmt.Errorf("store: get policy %q: %w", id, err)
	}
	return r, nil
}

func (p *Postgres) ListPolicies(ctx context.Context) ([]PolicyRecord, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT policy_id, policy_json, updated_at FROM policies ORDER BY policy_id ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list policies: %w", err)
	}
	defer rows.Close()

	var out []PolicyRecord
	for rows.Next() {
		r, err := scanPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan policy: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list policies: %w", err)
	}
	return out, nil
}

func (p *Postgres) DeletePolicy(ctx context.Context, id string) error {
	res, err := p.db.ExecContext(ctx, `DELETE FROM policies WHERE policy_id = $1`, id)
	if err != nil {
		return fmt.Errorf("store: delete policy %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: delete policy %q: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return nil
}

func scanPolicy(row rowScanner) (PolicyRecord, error) {
	var (
		r          PolicyRecord
		policyJSON []byte
	)
	if err := row.Scan(&r.ID, &policyJSON, &r.UpdatedAt); err != nil {
		return PolicyRecord{}, err
	}
	if err := json.Unmarshal(policyJSON, &r.Policy); err != nil {
		return PolicyRecord{}, fmt.Errorf("store: unmarshal policy %q: %w", r.ID, err)
	}
	return r, nil
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanApproval(row rowScanner) (Approval, error) {
	var (
		a          Approval
		decidedAt  sql.NullTime
		decidedBy  sql.NullString
		decision   sql.NullString
		contextRaw []byte
	)
	if err := row.Scan(&a.ApprovalID, &a.AgentID, &a.RunID, &a.RequestedAt,
		&decidedAt, &decidedBy, &decision, &contextRaw); err != nil {
		return Approval{}, err
	}
	if decidedAt.Valid {
		a.DecidedAt = decidedAt.Time
	}
	if decidedBy.Valid {
		a.DecidedBy = decidedBy.String
	}
	if decision.Valid {
		a.Decision = decision.String
	}
	ctxMap, err := unmarshalContext(contextRaw)
	if err != nil {
		return Approval{}, err
	}
	a.Context = ctxMap
	return a, nil
}

func marshalContext(ctx map[string]any) ([]byte, error) {
	if ctx == nil {
		ctx = map[string]any{}
	}
	b, err := json.Marshal(ctx)
	if err != nil {
		return nil, fmt.Errorf("store: marshal context: %w", err)
	}
	return b, nil
}

func unmarshalContext(raw []byte) (map[string]any, error) {
	if len(raw) == 0 {
		return map[string]any{}, nil
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("store: unmarshal context: %w", err)
	}
	return out, nil
}
