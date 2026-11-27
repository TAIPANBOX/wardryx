package store

// The Postgres store's own logic, without a Postgres: what each method does
// with the rows, counts and errors database/sql hands back. The SQL itself
// (its locking, its constraints, its snapshot) is proven against a real
// database by pgstore_integration_test.go under -tags integration; what is
// proven here is the Go around it: which outcome a count of zero means, how
// often a write is tried again, when a batch loop stops, how a NULL column
// reads, and that every failure keeps its cause and names its method.
//
// The double is a database/sql driver from the standard library's
// database/sql/driver interfaces, scripted per statement. It runs no SQL.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// scripted is what one statement answers.
type scripted struct {
	cols     []string
	rows     [][]driver.Value
	rowsErr  error // returned by the cursor after the rows, so rows.Err sees it
	affected int64
	affErr   error // returned by RowsAffected
	err      error // returned by the statement itself
}

type seenStmt struct {
	query string
	args  []any
	inTx  bool
}

// scriptDB is the driver, the connector and the record of what ran.
type scriptDB struct {
	mu        sync.Mutex
	answer    func(query string, args []any) scripted
	seen      []seenStmt
	beginErr  error
	commitErr error
	commits   int
	rollbacks int
	inTx      bool
}

func (s *scriptDB) Connect(context.Context) (driver.Conn, error) { return &scriptConn{db: s}, nil }
func (s *scriptDB) Driver() driver.Driver                        { return scriptDriver{} }

type scriptDriver struct{}

func (scriptDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("scriptDriver: open by name is not supported")
}

func (s *scriptDB) run(query string, named []driver.NamedValue) scripted {
	args := make([]any, len(named))
	for i, nv := range named {
		args[i] = nv.Value
	}
	s.mu.Lock()
	s.seen = append(s.seen, seenStmt{query: query, args: args, inTx: s.inTx})
	s.mu.Unlock()
	return s.answer(query, args)
}

func (s *scriptDB) statements() []seenStmt {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]seenStmt(nil), s.seen...)
}

func (s *scriptDB) count(fragment string) int {
	n := 0
	for _, st := range s.statements() {
		if strings.Contains(st.query, fragment) {
			n++
		}
	}
	return n
}

type scriptConn struct{ db *scriptDB }

func (c *scriptConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("scriptConn: prepare is not supported")
}
func (c *scriptConn) Close() error { return nil }
func (c *scriptConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}

func (c *scriptConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	c.db.mu.Lock()
	defer c.db.mu.Unlock()
	if c.db.beginErr != nil {
		return nil, c.db.beginErr
	}
	c.db.inTx = true
	return &scriptTx{db: c.db}, nil
}

func (c *scriptConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	r := c.db.run(query, args)
	if r.err != nil {
		return nil, r.err
	}
	return scriptResult{affected: r.affected, err: r.affErr}, nil
}

func (c *scriptConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	r := c.db.run(query, args)
	if r.err != nil {
		return nil, r.err
	}
	return &scriptRows{cols: r.cols, rows: r.rows, err: r.rowsErr}, nil
}

type scriptTx struct{ db *scriptDB }

func (t *scriptTx) Commit() error {
	t.db.mu.Lock()
	defer t.db.mu.Unlock()
	t.db.inTx = false
	if t.db.commitErr != nil {
		return t.db.commitErr
	}
	t.db.commits++
	return nil
}

func (t *scriptTx) Rollback() error {
	t.db.mu.Lock()
	defer t.db.mu.Unlock()
	t.db.inTx = false
	t.db.rollbacks++
	return nil
}

type scriptResult struct {
	affected int64
	err      error
}

func (r scriptResult) LastInsertId() (int64, error) { return 0, errors.New("not supported") }
func (r scriptResult) RowsAffected() (int64, error) { return r.affected, r.err }

type scriptRows struct {
	cols []string
	rows [][]driver.Value
	err  error
	i    int
}

func (r *scriptRows) Columns() []string { return r.cols }
func (r *scriptRows) Close() error      { return nil }
func (r *scriptRows) Next(dest []driver.Value) error {
	if r.i >= len(r.rows) {
		if r.err != nil {
			return r.err
		}
		return io.EOF
	}
	copy(dest, r.rows[r.i])
	r.i++
	return nil
}

// scriptedStore is a Postgres over the scripted driver.
func scriptedStore(t *testing.T, answer func(query string, args []any) scripted) (*Postgres, *scriptDB) {
	t.Helper()
	s := &scriptDB{answer: answer}
	db := sql.OpenDB(s)
	// One connection, so a transaction and the statements around it are seen
	// in the order they ran.
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return &Postgres{db: db}, s
}

var approvalCols = []string{"approval_id", "agent_id", "run_id", "requested_at", "decided_at", "decided_by", "decided_by_label", "decision", "context_json"}

var t0 = time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)

// pendingRow is an undecided approval as the table returns it: every decided_*
// column NULL.
func pendingRow(id string, ctxJSON string) []driver.Value {
	return []driver.Value{id, "agent://acme.example/bot", "run-1", t0, nil, nil, nil, nil, []byte(ctxJSON)}
}

func decidedRow(id, decision, by, label string) []driver.Value {
	var lab driver.Value
	if label != "" {
		lab = label
	}
	return []driver.Value{id, "agent://acme.example/bot", "run-1", t0, t0.Add(time.Minute), by, lab, decision, []byte(`{"org":"acme"}`)}
}

var errBoom = errors.New("boom from the driver")

// ------------------------------------------------------------------ approvals

func TestPgCreateApprovalStoresAnAbsentContextAsAnEmptyObject(t *testing.T) {
	p, s := scriptedStore(t, func(string, []any) scripted { return scripted{affected: 1} })
	a := Approval{ApprovalID: "ap1", AgentID: "agent://a/b", RunID: "r", RequestedAt: t0}
	if err := p.CreateApproval(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	st := s.statements()
	if len(st) != 1 || !strings.Contains(st[0].query, "INSERT INTO approvals") {
		t.Fatalf("statements %+v", st)
	}
	if got := string(st[0].args[4].([]byte)); got != "{}" {
		t.Fatalf("context_json %q, want {} so a NULL never reads back as a different shape", got)
	}
}

func TestPgCreateApprovalNamesTheApprovalOnAFailedInsert(t *testing.T) {
	p, _ := scriptedStore(t, func(string, []any) scripted { return scripted{err: errBoom} })
	err := p.CreateApproval(context.Background(), Approval{ApprovalID: "ap1", Context: map[string]any{"org": "acme"}})
	if !errors.Is(err, errBoom) || !strings.Contains(err.Error(), `insert approval "ap1"`) {
		t.Fatalf("err %v", err)
	}
}

func TestPgAContextThatIsNotJSONIsRefusedBeforeAnyWrite(t *testing.T) {
	p, s := scriptedStore(t, func(string, []any) scripted { return scripted{affected: 1} })
	bad := Approval{ApprovalID: "ap1", Context: map[string]any{"fn": func() {}}}
	if err := p.CreateApproval(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "marshal context") {
		t.Fatalf("CreateApproval err %v", err)
	}
	if _, out, err := p.CreateApprovalOnce(context.Background(), bad, "k", 5); err == nil || out != PendingCreated || !strings.Contains(err.Error(), "marshal context") {
		t.Fatalf("CreateApprovalOnce err %v outcome %v", err, out)
	}
	if n := len(s.statements()); n != 0 {
		t.Fatalf("%d statements ran for a context that cannot be stored", n)
	}
}

func TestPgCreateApprovalOnceWritesWhenTheStatementInsertsARow(t *testing.T) {
	p, s := scriptedStore(t, func(string, []any) scripted { return scripted{affected: 1} })
	a := Approval{ApprovalID: "ap1", AgentID: "agent://a/b", RunID: "r", RequestedAt: t0, Context: map[string]any{"org": "acme"}}
	got, out, err := p.CreateApprovalOnce(context.Background(), a, "key-1", 7)
	if err != nil || out != PendingCreated || got.ApprovalID != "ap1" {
		t.Fatalf("got %+v outcome %v err %v", got, out, err)
	}
	st := s.statements()
	if len(st) != 1 {
		t.Fatalf("%d statements, want the one insert", len(st))
	}
	// The key, the org the limit is counted in, and the limit itself.
	if st[0].args[5] != "key-1" || st[0].args[6] != "acme" || st[0].args[7] != int64(7) {
		t.Fatalf("insert args %v", st[0].args)
	}
}

func TestPgCreateApprovalOnceReturnsThePendingApprovalItCollidedWith(t *testing.T) {
	p, s := scriptedStore(t, func(q string, _ []any) scripted {
		if strings.HasPrefix(strings.TrimSpace(q), "INSERT") {
			return scripted{affected: 0}
		}
		return scripted{cols: approvalCols, rows: [][]driver.Value{pendingRow("ap-existing", `{"org":"acme"}`)}}
	})
	got, out, err := p.CreateApprovalOnce(context.Background(), Approval{ApprovalID: "ap-new", AgentID: "agent://acme.example/bot", RunID: "run-1"}, "k", 5)
	if err != nil || out != PendingExisting {
		t.Fatalf("outcome %v err %v, want PendingExisting", out, err)
	}
	if got.ApprovalID != "ap-existing" || !got.Pending() || got.Context["org"] != "acme" {
		t.Fatalf("returned %+v, want the pending approval already there", got)
	}
	if n := s.count("INSERT INTO approvals"); n != 1 {
		t.Fatalf("%d inserts, want one: a pending duplicate is not retried", n)
	}
}

func TestPgCreateApprovalOnceTriesOnceMoreThenReportsTheQueueFull(t *testing.T) {
	p, s := scriptedStore(t, func(q string, _ []any) scripted {
		if strings.HasPrefix(strings.TrimSpace(q), "INSERT") {
			return scripted{affected: 0}
		}
		return scripted{cols: approvalCols} // no pending row: the limit stopped it
	})
	got, out, err := p.CreateApprovalOnce(context.Background(), Approval{ApprovalID: "ap1"}, "k", 1)
	if err != nil || out != PendingQueueFull || got.ApprovalID != "" {
		t.Fatalf("got %+v outcome %v err %v, want PendingQueueFull and nothing written", got, out, err)
	}
	if n := s.count("INSERT INTO approvals"); n != 2 {
		t.Fatalf("%d inserts, want exactly two: one try and one more for a key decided in between", n)
	}
}

func TestPgCreateApprovalOnceWritesAgainWhenTheCollidingRowWasDecidedInBetween(t *testing.T) {
	inserts := 0
	p, _ := scriptedStore(t, func(q string, _ []any) scripted {
		if strings.HasPrefix(strings.TrimSpace(q), "INSERT") {
			inserts++
			if inserts == 1 {
				return scripted{affected: 0}
			}
			return scripted{affected: 1}
		}
		return scripted{cols: approvalCols}
	})
	got, out, err := p.CreateApprovalOnce(context.Background(), Approval{ApprovalID: "ap1"}, "k", 5)
	if err != nil || out != PendingCreated || got.ApprovalID != "ap1" {
		t.Fatalf("got %+v outcome %v err %v", got, out, err)
	}
}

func TestPgCreateApprovalOnceFailuresKeepTheirCause(t *testing.T) {
	cases := []struct {
		name   string
		answer func(q string) scripted
		want   string
	}{
		{"the insert", func(string) scripted { return scripted{err: errBoom} }, `insert approval "ap1"`},
		{"the count", func(string) scripted { return scripted{affErr: errBoom} }, `insert approval "ap1"`},
		{"the read of the pending row", func(q string) scripted {
			if strings.HasPrefix(strings.TrimSpace(q), "INSERT") {
				return scripted{affected: 0}
			}
			return scripted{err: errBoom}
		}, "read pending approval"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, _ := scriptedStore(t, func(q string, _ []any) scripted { return c.answer(q) })
			got, out, err := p.CreateApprovalOnce(context.Background(), Approval{ApprovalID: "ap1"}, "k", 5)
			if !errors.Is(err, errBoom) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q wrapping the driver's error", err, c.want)
			}
			if out != PendingCreated || got.ApprovalID != "" {
				t.Fatalf("a failure returned %+v / %v, want nothing", got, out)
			}
		})
	}
}

func TestPgGetApprovalReadsNullColumnsAsEmpty(t *testing.T) {
	p, s := scriptedStore(t, func(string, []any) scripted {
		return scripted{cols: approvalCols, rows: [][]driver.Value{pendingRow("ap1", "")}}
	})
	got, err := p.GetApproval(context.Background(), "ap1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != "" || got.DecidedBy != "" || got.DecidedByLabel != "" || !got.DecidedAt.IsZero() || !got.Pending() {
		t.Fatalf("a row with NULL decided_* reads %+v, want a pending approval", got)
	}
	if got.Context == nil || len(got.Context) != 0 {
		t.Fatalf("an empty context_json reads %#v, want an empty map", got.Context)
	}
	if st := s.statements(); st[0].args[0] != "ap1" {
		t.Fatalf("queried %v", st[0].args)
	}
}

func TestPgGetApprovalReadsADecidedRow(t *testing.T) {
	p, _ := scriptedStore(t, func(string, []any) scripted {
		return scripted{cols: approvalCols, rows: [][]driver.Value{decidedRow("ap1", "grant", "key:abc", "Ops on call")}}
	})
	got, err := p.GetApproval(context.Background(), "ap1")
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != "grant" || got.DecidedBy != "key:abc" || got.DecidedByLabel != "Ops on call" || !got.DecidedAt.Equal(t0.Add(time.Minute)) || got.Pending() {
		t.Fatalf("decided row reads %+v", got)
	}
}

func TestPgGetApprovalTellsMissingFromBroken(t *testing.T) {
	p, _ := scriptedStore(t, func(string, []any) scripted { return scripted{cols: approvalCols} })
	if _, err := p.GetApproval(context.Background(), "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no row: err %v, want ErrNotFound", err)
	}
	p, _ = scriptedStore(t, func(string, []any) scripted { return scripted{err: errBoom} })
	_, err := p.GetApproval(context.Background(), "ap1")
	if errors.Is(err, ErrNotFound) || !errors.Is(err, errBoom) || !strings.Contains(err.Error(), `get approval "ap1"`) {
		t.Fatalf("driver failure: err %v, want it wrapped and not read as not-found", err)
	}
	p, _ = scriptedStore(t, func(string, []any) scripted {
		return scripted{cols: approvalCols, rows: [][]driver.Value{pendingRow("ap1", "{not json")}}
	})
	if _, err := p.GetApproval(context.Background(), "ap1"); err == nil || !strings.Contains(err.Error(), "unmarshal context") {
		t.Fatalf("a corrupt context: err %v", err)
	}
}

func TestPgListApprovalsAndPendingReturnRowsInOrderAndKeepEveryFailure(t *testing.T) {
	lists := []struct {
		name   string
		list   func(*Postgres, context.Context) ([]Approval, error)
		filter string
		errMsg string
	}{
		{"all", (*Postgres).ListApprovals, "ORDER BY requested_at", "list approvals"},
		{"pending", (*Postgres).ListPendingApprovals, "WHERE decision IS NULL", "list pending approvals"},
	}
	for _, l := range lists {
		t.Run(l.name, func(t *testing.T) {
			p, s := scriptedStore(t, func(string, []any) scripted {
				return scripted{cols: approvalCols, rows: [][]driver.Value{pendingRow("ap1", `{}`), pendingRow("ap2", `{"org":"acme"}`)}}
			})
			got, err := l.list(p, context.Background())
			if err != nil || len(got) != 2 || got[0].ApprovalID != "ap1" || got[1].ApprovalID != "ap2" || got[1].Context["org"] != "acme" {
				t.Fatalf("got %+v err %v", got, err)
			}
			if q := s.statements()[0].query; !strings.Contains(q, l.filter) {
				t.Fatalf("query %q does not contain %q", q, l.filter)
			}

			p, _ = scriptedStore(t, func(string, []any) scripted { return scripted{err: errBoom} })
			if _, err := l.list(p, context.Background()); !errors.Is(err, errBoom) || !strings.Contains(err.Error(), l.errMsg) {
				t.Fatalf("query failure: %v", err)
			}
			p, _ = scriptedStore(t, func(string, []any) scripted {
				return scripted{cols: approvalCols, rows: [][]driver.Value{pendingRow("ap1", "[")}}
			})
			if got, err := l.list(p, context.Background()); err == nil || got != nil || !strings.Contains(err.Error(), "scan approval") {
				t.Fatalf("a corrupt row: got %v err %v, want no list and a scan error", got, err)
			}
			p, _ = scriptedStore(t, func(string, []any) scripted {
				return scripted{cols: approvalCols, rows: [][]driver.Value{pendingRow("ap1", `{}`)}, rowsErr: errBoom}
			})
			if got, err := l.list(p, context.Background()); !errors.Is(err, errBoom) || got != nil {
				t.Fatalf("a cursor that failed part way: got %v err %v, want no partial list", got, err)
			}
		})
	}
}

// ------------------------------------------------------------------ decide

// decideScript answers DecideApproval's statements: the UPDATE with updated
// rows, the preview DELETE with delErr, and the read after with readRow (nil
// for no row).
func decideScript(updated int64, updErr, affErr, delErr error, readRow []driver.Value) func(string, []any) scripted {
	return func(q string, _ []any) scripted {
		switch {
		case strings.Contains(q, "UPDATE approvals"):
			return scripted{affected: updated, err: updErr, affErr: affErr}
		case strings.Contains(q, "DELETE FROM approval_previews"):
			return scripted{affected: 1, err: delErr}
		default:
			if readRow == nil {
				return scripted{cols: approvalCols}
			}
			return scripted{cols: approvalCols, rows: [][]driver.Value{readRow}}
		}
	}
}

func TestPgDecideApprovalDecidesAndDropsThePreviewInOneTransaction(t *testing.T) {
	p, s := scriptedStore(t, decideScript(1, nil, nil, nil, decidedRow("ap1", "grant", "key:abc", "Ops")))
	got, err := p.DecideApproval(context.Background(), "ap1", "grant", "key:abc", "Ops", t0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Decision != "grant" || got.DecidedByLabel != "Ops" {
		t.Fatalf("returned %+v, want the row as decided", got)
	}
	st := s.statements()
	if len(st) != 3 || !st[0].inTx || !st[1].inTx || !strings.Contains(st[1].query, "DELETE FROM approval_previews") || st[2].inTx {
		t.Fatalf("statements %+v: want UPDATE and DELETE inside the transaction, then the read after it", st)
	}
	if st[0].args[0] != "ap1" || st[0].args[1] != "grant" || st[0].args[2] != "key:abc" || st[0].args[4] != "Ops" {
		t.Fatalf("update args %v", st[0].args)
	}
	if s.commits != 1 {
		t.Fatalf("%d commits, want 1", s.commits)
	}
}

func TestPgDecidingAnApprovalTwiceIsRefusedAsAlreadyDecided(t *testing.T) {
	p, s := scriptedStore(t, decideScript(0, nil, nil, nil, decidedRow("ap1", "deny", "key:first", "")))
	_, err := p.DecideApproval(context.Background(), "ap1", "grant", "key:second", "", t0)
	if !errors.Is(err, ErrAlreadyDecided) || errors.Is(err, ErrNotFound) {
		t.Fatalf("err %v, want ErrAlreadyDecided: the first decision may already have minted a token", err)
	}
	if s.commits != 0 || s.count("DELETE FROM approval_previews") != 0 {
		t.Fatalf("a refused decision committed %d times and deleted %d previews", s.commits, s.count("DELETE FROM approval_previews"))
	}
}

func TestPgDecidingAnApprovalThatDoesNotExistIsNotFound(t *testing.T) {
	p, s := scriptedStore(t, decideScript(0, nil, nil, nil, nil))
	_, err := p.DecideApproval(context.Background(), "ghost", "grant", "key:abc", "", t0)
	if !errors.Is(err, ErrNotFound) || errors.Is(err, ErrAlreadyDecided) {
		t.Fatalf("err %v, want ErrNotFound", err)
	}
	if s.commits != 0 {
		t.Fatal("a decision on nothing committed")
	}
}

func TestPgDecideApprovalFailuresCommitNothing(t *testing.T) {
	cases := []struct {
		name      string
		script    func(string, []any) scripted
		beginErr  error
		commitErr error
		want      string
	}{
		{"begin", decideScript(1, nil, nil, nil, nil), errBoom, nil, `decide approval "ap1"`},
		{"update", decideScript(1, errBoom, nil, nil, nil), nil, nil, `decide approval "ap1"`},
		{"count", decideScript(1, nil, errBoom, nil, nil), nil, nil, `decide approval "ap1"`},
		{"preview delete", decideScript(1, nil, nil, errBoom, nil), nil, nil, "delete its preview"},
		{"commit", decideScript(1, nil, nil, nil, nil), nil, errBoom, `decide approval "ap1"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, s := scriptedStore(t, c.script)
			s.beginErr, s.commitErr = c.beginErr, c.commitErr
			got, err := p.DecideApproval(context.Background(), "ap1", "grant", "key:abc", "", t0)
			if !errors.Is(err, errBoom) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q wrapping the driver's error", err, c.want)
			}
			if got.Decision != "" || s.commits != 0 {
				t.Fatalf("a failed decision returned %+v and committed %d times", got, s.commits)
			}
		})
	}
}

// ------------------------------------------------------------------ expiry

func TestPgExpireApprovalsRunsAnotherBatchUntilOneComesBackShort(t *testing.T) {
	batch := 0
	p, s := scriptedStore(t, func(string, []any) scripted {
		batch++
		n := expireBatch
		if batch == 2 {
			n = 3
		}
		rows := make([][]driver.Value, n)
		for i := range rows {
			rows[i] = decidedRow(fmt.Sprintf("ap-%d-%d", batch, i), DecisionExpired, "wardryx:hold-ttl", "")
		}
		return scripted{cols: approvalCols, rows: rows}
	})
	got, err := p.ExpireApprovals(context.Background(), t0, "wardryx:hold-ttl", t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != expireBatch+3 || batch != 2 {
		t.Fatalf("closed %d in %d statements, want %d in 2: a full batch means there may be more", len(got), batch, expireBatch+3)
	}
	args := s.statements()[0].args
	if args[1] != DecisionExpired || args[2] != "wardryx:hold-ttl" || args[4] != int64(expireBatch) {
		t.Fatalf("expire args %v", args)
	}
}

func TestPgExpireApprovalsStopsOnAnEmptyBatch(t *testing.T) {
	p, s := scriptedStore(t, func(string, []any) scripted { return scripted{cols: approvalCols} })
	got, err := p.ExpireApprovals(context.Background(), t0, "x", t0)
	if err != nil || len(got) != 0 || len(s.statements()) != 1 {
		t.Fatalf("got %v err %v after %d statements", got, err, len(s.statements()))
	}
}

func TestPgExpireApprovalsReturnsWhatItClosedBeforeAFailure(t *testing.T) {
	full := func(prefix string) [][]driver.Value {
		rows := make([][]driver.Value, expireBatch)
		for i := range rows {
			rows[i] = decidedRow(fmt.Sprintf("%s-%d", prefix, i), DecisionExpired, "x", "")
		}
		return rows
	}
	cases := []struct {
		name   string
		second scripted
		want   string
	}{
		{"the statement", scripted{err: errBoom}, "expire approvals"},
		{"a row", scripted{cols: approvalCols, rows: [][]driver.Value{pendingRow("bad", "{")}}, "scan expired approval"},
		{"the cursor", scripted{cols: approvalCols, rowsErr: errBoom}, "expire approvals"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := 0
			p, _ := scriptedStore(t, func(string, []any) scripted {
				n++
				if n == 1 {
					return scripted{cols: approvalCols, rows: full("first")}
				}
				return c.second
			})
			got, err := p.ExpireApprovals(context.Background(), t0, "x", t0)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %v, want %q", err, c.want)
			}
			// The first batch committed: those holds are closed and must still
			// be reported, or nothing downstream says they were.
			if len(got) != expireBatch {
				t.Fatalf("returned %d closed holds with the failure, want the %d already closed", len(got), expireBatch)
			}
		})
	}
}

// ------------------------------------------------------------------ previews

var previewCols = []string{"approval_id", "org", "sealed", "pvd", "ruleset", "suite", "expires_at"}

func TestPgPreviewsRoundTripAndMissingIsNotFound(t *testing.T) {
	p, s := scriptedStore(t, func(q string, _ []any) scripted {
		if strings.Contains(q, "SELECT") {
			return scripted{cols: previewCols, rows: [][]driver.Value{{"ap1", "acme", []byte{1, 2, 3}, "pvd-1", "rules-1", "suite-1", t0}}}
		}
		return scripted{affected: 1}
	})
	pv := Preview{ApprovalID: "ap1", Org: "acme", Sealed: []byte{1, 2, 3}, Digest: "pvd-1", Ruleset: "rules-1", Suite: "suite-1", ExpiresAt: t0}
	if err := p.PutPreview(context.Background(), pv); err != nil {
		t.Fatal(err)
	}
	if st := s.statements()[0]; !strings.Contains(st.query, "ON CONFLICT (approval_id) DO NOTHING") || st.args[3] != "pvd-1" {
		t.Fatalf("put %+v", st)
	}
	got, err := p.GetPreview(context.Background(), "ap1")
	if err != nil || got.Org != "acme" || string(got.Sealed) != "\x01\x02\x03" || got.Digest != "pvd-1" || !got.ExpiresAt.Equal(t0) {
		t.Fatalf("got %+v err %v", got, err)
	}

	p, _ = scriptedStore(t, func(string, []any) scripted { return scripted{cols: previewCols} })
	if _, err := p.GetPreview(context.Background(), "ap1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no row: %v", err)
	}
	p, _ = scriptedStore(t, func(string, []any) scripted { return scripted{err: errBoom} })
	if _, err := p.GetPreview(context.Background(), "ap1"); errors.Is(err, ErrNotFound) || !errors.Is(err, errBoom) {
		t.Fatalf("driver failure read as %v", err)
	}
	if err := p.PutPreview(context.Background(), pv); !errors.Is(err, errBoom) || !strings.Contains(err.Error(), `put preview "ap1"`) {
		t.Fatalf("put failure %v", err)
	}
}

func TestPgPurgePreviewsReportsTheCount(t *testing.T) {
	p, _ := scriptedStore(t, func(string, []any) scripted { return scripted{affected: 4} })
	if n, err := p.PurgePreviews(context.Background()); n != 4 || err != nil {
		t.Fatalf("n %d err %v", n, err)
	}
	for _, sc := range []scripted{{err: errBoom}, {affErr: errBoom}} {
		p, _ := scriptedStore(t, func(string, []any) scripted { return sc })
		if n, err := p.PurgePreviews(context.Background()); n != 0 || !errors.Is(err, errBoom) {
			t.Fatalf("n %d err %v", n, err)
		}
	}
}

// ------------------------------------------------------------------ single use

// A key is claimed only when this statement inserted its row. A count of zero
// means some instance claimed it first, and the redemption or the proof is a
// replay.
func TestPgTryRedeemAndTryRecordProofClaimOnlyWhenTheRowWasInserted(t *testing.T) {
	claims := []struct {
		name string
		try  func(*Postgres) (bool, error)
		want string
	}{
		{"redeem", func(p *Postgres) (bool, error) { return p.TryRedeem(context.Background(), "jti-1") }, `try redeem "jti-1"`},
		{"proof", func(p *Postgres) (bool, error) {
			return p.TryRecordProof(context.Background(), "jti-1", t0)
		}, "record proof"},
	}
	for _, c := range claims {
		t.Run(c.name, func(t *testing.T) {
			p, s := scriptedStore(t, func(string, []any) scripted { return scripted{affected: 1} })
			if ok, err := c.try(p); !ok || err != nil {
				t.Fatalf("first claim: %v %v", ok, err)
			}
			if s.statements()[0].args[0] != "jti-1" {
				t.Fatalf("claimed %v", s.statements()[0].args)
			}
			p, _ = scriptedStore(t, func(string, []any) scripted { return scripted{affected: 0} })
			if ok, err := c.try(p); ok || err != nil {
				t.Fatalf("a key claimed before: %v %v, want false: a replay must not be accepted", ok, err)
			}
			for _, sc := range []scripted{{err: errBoom}, {affErr: errBoom}} {
				p, _ := scriptedStore(t, func(string, []any) scripted { return sc })
				if ok, err := c.try(p); ok || !errors.Is(err, errBoom) || !strings.Contains(err.Error(), c.want) {
					t.Fatalf("a failure: %v %v, want false and %q", ok, err, c.want)
				}
			}
		})
	}
}

func TestPgPurgeProofsSendsTheGraceInSeconds(t *testing.T) {
	p, s := scriptedStore(t, func(string, []any) scripted { return scripted{affected: 2} })
	n, err := p.PurgeProofs(context.Background(), 90*time.Second)
	if n != 2 || err != nil {
		t.Fatalf("n %d err %v", n, err)
	}
	if got := s.statements()[0].args[0]; got != 90.0 {
		t.Fatalf("grace sent as %v, want 90 seconds", got)
	}
	p, _ = scriptedStore(t, func(string, []any) scripted { return scripted{affErr: errBoom} })
	if n, err := p.PurgeProofs(context.Background(), time.Minute); n != 0 || !errors.Is(err, errBoom) {
		t.Fatalf("n %d err %v", n, err)
	}
}

// ------------------------------------------------------------------ policies

var policyCols = []string{"policy_id", "policy_json", "updated_at"}

func policyJSON(t *testing.T, pol policy.Policy) []byte {
	t.Helper()
	b, err := json.Marshal(pol)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPgPoliciesRoundTripThroughTheirJSON(t *testing.T) {
	pol := policy.Policy{Name: "deny-wires", Target: "agent://acme.example/*", DenyTool: []string{"send_wire_transfer"}}
	raw := policyJSON(t, pol)
	p, s := scriptedStore(t, func(q string, _ []any) scripted {
		if strings.Contains(q, "SELECT") {
			return scripted{cols: policyCols, rows: [][]driver.Value{{"p1", raw, t0}, {"p2", raw, t0}}}
		}
		return scripted{affected: 1}
	})
	if err := p.PutPolicy(context.Background(), "p1", pol, t0); err != nil {
		t.Fatal(err)
	}
	var stored policy.Policy
	if err := json.Unmarshal(s.statements()[0].args[1].([]byte), &stored); err != nil || stored.Name != "deny-wires" || len(stored.DenyTool) != 1 {
		t.Fatalf("stored %+v err %v", stored, err)
	}
	got, err := p.GetPolicy(context.Background(), "p1")
	if err != nil || got.ID != "p1" || got.Policy.DenyTool[0] != "send_wire_transfer" || !got.UpdatedAt.Equal(t0) {
		t.Fatalf("get %+v err %v", got, err)
	}
	list, err := p.ListPolicies(context.Background())
	if err != nil || len(list) != 2 || list[1].ID != "p2" {
		t.Fatalf("list %+v err %v", list, err)
	}
}

func TestPgPolicyReadsTellMissingCorruptAndBroken(t *testing.T) {
	p, _ := scriptedStore(t, func(string, []any) scripted { return scripted{cols: policyCols} })
	if _, err := p.GetPolicy(context.Background(), "p1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("no row: %v", err)
	}
	p, _ = scriptedStore(t, func(string, []any) scripted {
		return scripted{cols: policyCols, rows: [][]driver.Value{{"p1", []byte("{"), t0}}}
	})
	if _, err := p.GetPolicy(context.Background(), "p1"); err == nil || !strings.Contains(err.Error(), `unmarshal policy "p1"`) {
		t.Fatalf("corrupt policy_json: %v", err)
	}
	if l, err := p.ListPolicies(context.Background()); l != nil || err == nil || !strings.Contains(err.Error(), "scan policy") {
		t.Fatalf("corrupt list: %v %v", l, err)
	}
	p, _ = scriptedStore(t, func(string, []any) scripted { return scripted{err: errBoom} })
	if _, err := p.GetPolicy(context.Background(), "p1"); errors.Is(err, ErrNotFound) || !errors.Is(err, errBoom) {
		t.Fatalf("driver failure: %v", err)
	}
	p, _ = scriptedStore(t, func(string, []any) scripted {
		return scripted{cols: policyCols, rows: [][]driver.Value{{"p1", []byte("{}"), t0}}, rowsErr: errBoom}
	})
	if l, err := p.ListPolicies(context.Background()); l != nil || !errors.Is(err, errBoom) {
		t.Fatalf("cursor failure: %v %v", l, err)
	}
}

func TestPgDeletePolicyOfNothingIsNotFound(t *testing.T) {
	p, s := scriptedStore(t, func(string, []any) scripted { return scripted{affected: 1} })
	if err := p.DeletePolicy(context.Background(), "p1"); err != nil {
		t.Fatal(err)
	}
	if s.statements()[0].args[0] != "p1" {
		t.Fatalf("deleted %v", s.statements()[0].args)
	}
	p, _ = scriptedStore(t, func(string, []any) scripted { return scripted{affected: 0} })
	if err := p.DeletePolicy(context.Background(), "p1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("zero rows: %v, want ErrNotFound", err)
	}
	p, _ = scriptedStore(t, func(string, []any) scripted { return scripted{affErr: errBoom} })
	if err := p.DeletePolicy(context.Background(), "p1"); !errors.Is(err, errBoom) || errors.Is(err, ErrNotFound) {
		t.Fatalf("count failure: %v", err)
	}
}

// ------------------------------------------------------------------ open

func TestPgMigrateAppliesTheEmbeddedSchema(t *testing.T) {
	p, s := scriptedStore(t, func(string, []any) scripted { return scripted{} })
	if err := p.migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if st := s.statements(); len(st) != 1 || st[0].query != schema || !strings.Contains(schema, "CREATE TABLE") {
		t.Fatalf("migrate ran %d statements, want the embedded schema once", len(st))
	}
	p, _ = scriptedStore(t, func(string, []any) scripted { return scripted{err: errBoom} })
	if err := p.migrate(context.Background()); !errors.Is(err, errBoom) || !strings.Contains(err.Error(), "apply schema") {
		t.Fatalf("err %v", err)
	}
}

func TestPgCloseReleasesThePool(t *testing.T) {
	p, _ := scriptedStore(t, func(string, []any) scripted { return scripted{} })
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.Ping(context.Background()); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("ping after close: %v", err)
	}
}

func TestOpenPostgresRefusesADatabaseItCannotReach(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), farPast)
	defer cancel()
	p, err := OpenPostgres(ctx, "postgres://wardryx:secret@"+closedPort(t)+"/wardryx?sslmode=disable")
	if p != nil || err == nil || !strings.Contains(err.Error(), "store: ping postgres") || !IsUnavailable(err) {
		t.Fatalf("refused port: %v %v, want a ping failure classified as unavailable", p, err)
	}
}
