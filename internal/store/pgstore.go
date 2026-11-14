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

// maxPoolConns is how many connections one wardryx holds to Postgres, open and
// idle alike. The pool is on the decide path once a shared proof record is in
// use (invariant 44): at database/sql's defaults every burst closes all but two
// connections and opens the rest again, without limit, so a burst past the
// server's max_connections reads as a store failure. Past this limit a caller
// waits for a connection until its own deadline.
const maxPoolConns = 16

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
	db.SetMaxOpenConns(maxPoolConns)
	db.SetMaxIdleConns(maxPoolConns)
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

// Ping is one round trip to the database, on a pooled connection when the
// pool has one and on a fresh dial when it does not, which is the case that
// matters: once the database has gone, the pool's dead connections are
// dropped on their first failure and every later call dials again. The dial,
// the wait for a free connection when the pool is at maxPoolConns, and the wait
// for the server's first bytes all stop at ctx's deadline.
func (p *Postgres) Ping(ctx context.Context) error {
	if err := p.db.PingContext(ctx); err != nil {
		return fmt.Errorf("store: ping postgres: %w", err)
	}
	return nil
}

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

// CreateApprovalOnce writes a in one statement: the partial unique index on
// (agent_id, run_id, pending_key) makes the key atomic across every wardryx on this
// database, the way TryRedeem's primary key does, and the count in the same
// statement stops the row at the limit.
//
// The limit is a bound on a queue, not a budget, and it is read in the statement's
// snapshot: instances writing for one agent at the same moment can each see room,
// so a burst can pass it by as many statements as run at that moment. Each of
// those is a different call, and the next one is refused.
//
// A statement that wrote nothing was stopped by the key or by the limit. Which one
// is asked afterwards, and a key whose row was decided in between is written again,
// once. An approval that is pending is reported as such whatever the count says.
func (p *Postgres) CreateApprovalOnce(ctx context.Context, a Approval, key string, limit int) (Approval, PendingOutcome, error) {
	ctxJSON, err := marshalContext(a.Context)
	if err != nil {
		return Approval{}, PendingCreated, err
	}
	org, _ := a.Context["org"].(string)
	for attempt := 0; attempt < 2; attempt++ {
		res, err := p.db.ExecContext(ctx,
			`INSERT INTO approvals (approval_id, agent_id, run_id, requested_at, context_json, pending_key)
			 SELECT $1::text, $2::text, $3::text, $4::timestamptz, $5::jsonb, $6::text
			 WHERE (SELECT count(*) FROM approvals
			        WHERE agent_id = $2::text AND decision IS NULL
			          AND COALESCE(context_json->>'org', '') = $7::text) < $8::bigint
			 ON CONFLICT (agent_id, run_id, pending_key) WHERE decision IS NULL AND pending_key IS NOT NULL
			 DO NOTHING`,
			a.ApprovalID, a.AgentID, a.RunID, a.RequestedAt, ctxJSON, key, org, limit)
		if err != nil {
			return Approval{}, PendingCreated, fmt.Errorf("store: insert approval %q: %w", a.ApprovalID, err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return Approval{}, PendingCreated, fmt.Errorf("store: insert approval %q: %w", a.ApprovalID, err)
		}
		if n == 1 {
			return a, PendingCreated, nil
		}
		row := p.db.QueryRowContext(ctx,
			`SELECT approval_id, agent_id, run_id, requested_at, decided_at, decided_by, decided_by_label, decision, context_json
			 FROM approvals
			 WHERE agent_id = $1 AND run_id = $2 AND pending_key = $3 AND decision IS NULL`,
			a.AgentID, a.RunID, key)
		existing, err := scanApproval(row)
		if err == nil {
			return existing, PendingExisting, nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return Approval{}, PendingCreated, fmt.Errorf("store: read pending approval: %w", err)
		}
	}
	return Approval{}, PendingQueueFull, nil
}

func (p *Postgres) GetApproval(ctx context.Context, id string) (Approval, error) {
	row := p.db.QueryRowContext(ctx,
		`SELECT approval_id, agent_id, run_id, requested_at, decided_at, decided_by, decided_by_label, decision, context_json
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
		`SELECT approval_id, agent_id, run_id, requested_at, decided_at, decided_by, decided_by_label, decision, context_json
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

func (p *Postgres) ListPendingApprovals(ctx context.Context) ([]Approval, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT approval_id, agent_id, run_id, requested_at, decided_at, decided_by, decided_by_label, decision, context_json
		 FROM approvals WHERE decision IS NULL ORDER BY requested_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("store: list pending approvals: %w", err)
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
		return nil, fmt.Errorf("store: list pending approvals: %w", err)
	}
	return out, nil
}

func (p *Postgres) DecideApproval(ctx context.Context, id, decision, decidedBy, label string, decidedAt time.Time) (Approval, error) {
	// The decision and the deletion of the hold's sealed preview are one
	// transaction, so no decided hold keeps a preview and no failed decision
	// loses one (invariant 51).
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return Approval{}, fmt.Errorf("store: decide approval %q: %w", id, err)
	}
	defer func() { _ = tx.Rollback() }()
	// An empty label is stored as NULL, the value every row decided before
	// the column existed holds, so "no label was sent" has one spelling.
	res, err := tx.ExecContext(ctx,
		`UPDATE approvals SET decision = $2, decided_by = $3, decided_at = $4, decided_by_label = NULLIF($5, '')
		 WHERE approval_id = $1 AND decision IS NULL`,
		id, decision, decidedBy, decidedAt, label)
	if err != nil {
		return Approval{}, fmt.Errorf("store: decide approval %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Approval{}, fmt.Errorf("store: decide approval %q: %w", id, err)
	}
	if n == 0 {
		_ = tx.Rollback()
		// Either the row does not exist, or it exists but was already
		// decided; distinguish so the caller can respond precisely.
		if _, getErr := p.GetApproval(ctx, id); errors.Is(getErr, ErrNotFound) {
			return Approval{}, fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		return Approval{}, fmt.Errorf("%w: %s", ErrAlreadyDecided, id)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM approval_previews WHERE approval_id = $1`, id); err != nil {
		return Approval{}, fmt.Errorf("store: decide approval %q: delete its preview: %w", id, err)
	}
	if err := tx.Commit(); err != nil {
		return Approval{}, fmt.Errorf("store: decide approval %q: %w", id, err)
	}
	return p.GetApproval(ctx, id)
}

// expireBatch is how many holds one statement of ExpireApprovals closes. The
// method repeats until a statement closes fewer, so a backlog (a database that
// has held holds since before the TTL existed) is closed in one call without one
// statement locking all of it.
const expireBatch = 500

// ExpireApprovals closes the pending approvals requested at or before
// requestedBefore. Each batch is one statement: the rows are locked FOR UPDATE
// SKIP LOCKED, updated only while decision IS NULL, and their previews deleted,
// all in that statement, so it commits whole or not at all. A row a person is
// deciding at that moment is locked by their UPDATE and skipped; a row they
// decided first no longer matches decision IS NULL on the recheck Postgres makes
// for a locked row; and of two instances running this at once, the second skips
// or rechecks every row the first took. So each hold is returned once.
func (p *Postgres) ExpireApprovals(ctx context.Context, requestedBefore time.Time, decidedBy string, decidedAt time.Time) ([]Approval, error) {
	var out []Approval
	for {
		rows, err := p.db.QueryContext(ctx,
			`WITH due AS (
			     SELECT approval_id FROM approvals
			     WHERE decision IS NULL AND requested_at <= $1
			     ORDER BY requested_at
			     LIMIT $5
			     FOR UPDATE SKIP LOCKED
			 ), closed AS (
			     UPDATE approvals a
			     SET decision = $2, decided_by = $3, decided_at = $4, decided_by_label = NULL
			     FROM due
			     WHERE a.approval_id = due.approval_id AND a.decision IS NULL
			     RETURNING a.approval_id, a.agent_id, a.run_id, a.requested_at, a.decided_at,
			               a.decided_by, a.decided_by_label, a.decision, a.context_json
			 ), previews AS (
			     DELETE FROM approval_previews pv USING closed
			     WHERE pv.approval_id = closed.approval_id
			 )
			 SELECT approval_id, agent_id, run_id, requested_at, decided_at, decided_by, decided_by_label, decision, context_json
			 FROM closed ORDER BY requested_at ASC`,
			requestedBefore, DecisionExpired, decidedBy, decidedAt, expireBatch)
		if err != nil {
			return out, fmt.Errorf("store: expire approvals: %w", err)
		}
		n := 0
		for rows.Next() {
			a, err := scanApproval(rows)
			if err != nil {
				_ = rows.Close()
				return out, fmt.Errorf("store: scan expired approval: %w", err)
			}
			out = append(out, a)
			n++
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return out, fmt.Errorf("store: expire approvals: %w", err)
		}
		_ = rows.Close()
		if n < expireBatch {
			return out, nil
		}
	}
}

// PutPreview writes a sealed preview with ON CONFLICT DO NOTHING: a repeated
// call already has its preview, and it is the same one.
func (p *Postgres) PutPreview(ctx context.Context, pv Preview) error {
	_, err := p.db.ExecContext(ctx,
		`INSERT INTO approval_previews (approval_id, org, sealed, pvd, ruleset, suite, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (approval_id) DO NOTHING`,
		pv.ApprovalID, pv.Org, pv.Sealed, pv.Digest, pv.Ruleset, pv.Suite, pv.ExpiresAt)
	if err != nil {
		return fmt.Errorf("store: put preview %q: %w", pv.ApprovalID, err)
	}
	return nil
}

// GetPreview reads a preview that has not expired by the database's clock, so
// every instance agrees on what has.
func (p *Postgres) GetPreview(ctx context.Context, id string) (Preview, error) {
	var pv Preview
	err := p.db.QueryRowContext(ctx,
		`SELECT approval_id, org, sealed, pvd, ruleset, suite, expires_at FROM approval_previews
		 WHERE approval_id = $1 AND expires_at > now()`, id).
		Scan(&pv.ApprovalID, &pv.Org, &pv.Sealed, &pv.Digest, &pv.Ruleset, &pv.Suite, &pv.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Preview{}, fmt.Errorf("%w: preview %s", ErrNotFound, id)
	}
	if err != nil {
		return Preview{}, fmt.Errorf("store: get preview %q: %w", id, err)
	}
	return pv, nil
}

// PurgePreviews deletes the expired rows by the database's clock.
func (p *Postgres) PurgePreviews(ctx context.Context) (int64, error) {
	res, err := p.db.ExecContext(ctx, `DELETE FROM approval_previews WHERE expires_at <= now()`)
	if err != nil {
		return 0, fmt.Errorf("store: purge previews: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: purge previews: %w", err)
	}
	return n, nil
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

// TryRecordProof claims key in the record of accepted DPoP proofs, the way
// TryRedeem claims a redemption: an INSERT .. ON CONFLICT DO NOTHING, so the
// table's own primary key makes the check-and-set atomic across every wardryx on
// this database and across a restart of any of them. A key whose row is past
// until and not yet purged stays claimed, which refuses a holder that used one
// jti twice minutes apart and nobody else.
func (p *Postgres) TryRecordProof(ctx context.Context, key string, until time.Time) (bool, error) {
	res, err := p.db.ExecContext(ctx,
		`INSERT INTO agent_proof_replays (proof_key, expires_at) VALUES ($1, $2)
		 ON CONFLICT (proof_key) DO NOTHING`,
		key, until)
	if err != nil {
		return false, fmt.Errorf("store: record proof: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("store: record proof: %w", err)
	}
	return n == 1, nil
}

// PurgeProofs removes the rows whose time passed more than grace ago and reports
// how many went. The cutoff is the database's clock, so every instance
// purging at once reads one clock, and one that runs fast cannot remove a row
// another instance would still need.
func (p *Postgres) PurgeProofs(ctx context.Context, grace time.Duration) (int64, error) {
	res, err := p.db.ExecContext(ctx,
		`DELETE FROM agent_proof_replays WHERE expires_at < now() - make_interval(secs => $1)`,
		grace.Seconds())
	if err != nil {
		return 0, fmt.Errorf("store: purge proofs: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: purge proofs: %w", err)
	}
	return n, nil
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
		label      sql.NullString
		decision   sql.NullString
		contextRaw []byte
	)
	if err := row.Scan(&a.ApprovalID, &a.AgentID, &a.RunID, &a.RequestedAt,
		&decidedAt, &decidedBy, &label, &decision, &contextRaw); err != nil {
		return Approval{}, err
	}
	if label.Valid {
		a.DecidedByLabel = label.String
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
