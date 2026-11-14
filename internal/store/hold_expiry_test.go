package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// A hold nobody decided is closed as expired once it has waited its TTL, and only
// then (CLAUDE.md invariant 52). These contracts are what both stores do with it,
// run against Memory here and against a real Postgres in the integration job.

type expiringStore interface {
	Store
	PreviewStore
	HoldExpirer
}

const ttlApprover = "wardryx:hold-ttl"

// holdExpiryContract: rows at or before the cutoff close, rows after it and rows a
// person decided do not, the preview goes with the row, a second call closes
// nothing, and a closed row cannot then be decided.
func holdExpiryContract(t *testing.T, st expiringStore) {
	t.Helper()
	ctx := context.Background()
	base := time.Date(2026, 11, 14, 0, 9, 0, 0, time.UTC)
	cutoff := base.Add(time.Minute)
	mk := func(id string, at time.Time) {
		t.Helper()
		if err := st.CreateApproval(ctx, Approval{ApprovalID: id, AgentID: "agent://acme.example/bot", RunID: "r1", RequestedAt: at, Context: map[string]any{"org": "acme"}}); err != nil {
			t.Fatalf("CreateApproval %s: %v", id, err)
		}
	}
	mk("ap-old", base)
	mk("ap-at-cutoff", cutoff)
	mk("ap-just-after", cutoff.Add(time.Microsecond))
	mk("ap-decided", base)
	if _, err := st.DecideApproval(ctx, "ap-decided", "deny", "key:abc", "", base.Add(time.Second)); err != nil {
		t.Fatalf("DecideApproval: %v", err)
	}
	if err := st.PutPreview(ctx, Preview{ApprovalID: "ap-old", Org: "acme", Sealed: []byte{1}, Digest: "d", Ruleset: "r1", Suite: "s", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatalf("PutPreview: %v", err)
	}

	at := cutoff.Add(24 * time.Hour)
	closed, err := st.ExpireApprovals(ctx, cutoff, ttlApprover, at)
	if err != nil {
		t.Fatalf("ExpireApprovals: %v", err)
	}
	if len(closed) != 2 || closed[0].ApprovalID != "ap-old" || closed[1].ApprovalID != "ap-at-cutoff" {
		t.Fatalf("closed %v, want ap-old and ap-at-cutoff in that order", ids(closed))
	}
	for _, a := range closed {
		if a.Decision != DecisionExpired || a.DecidedBy != ttlApprover || !a.DecidedAt.Equal(at) || a.DecidedByLabel != "" {
			t.Fatalf("closed row %+v, want decision %q by %q at %v with no label", a, DecisionExpired, ttlApprover, at)
		}
	}
	if _, err := st.GetPreview(ctx, "ap-old"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("the expired hold kept its preview: %v", err)
	}
	if got, _ := st.GetApproval(ctx, "ap-decided"); got.Decision != "deny" || got.DecidedBy != "key:abc" {
		t.Fatalf("a hold a person decided was rewritten: %+v", got)
	}
	if got, _ := st.GetApproval(ctx, "ap-just-after"); !got.Pending() {
		t.Fatalf("a hold requested after the cutoff was closed: %+v", got)
	}
	again, err := st.ExpireApprovals(ctx, cutoff, ttlApprover, at)
	if err != nil || len(again) != 0 {
		t.Fatalf("a second check closed %v (%v), want nothing", ids(again), err)
	}
	if _, err := st.DecideApproval(ctx, "ap-old", "grant", "key:abc", "", at); !errors.Is(err, ErrAlreadyDecided) {
		t.Fatalf("a person decided an expired hold: %v", err)
	}
	pending, err := st.ListPendingApprovals(ctx)
	if err != nil || len(pending) != 1 || pending[0].ApprovalID != "ap-just-after" {
		t.Fatalf("pending after the check: %v (%v), want only ap-just-after", ids(pending), err)
	}
}

// expiryFreesThePendingCap: a closed row leaves the pending count and the pending
// key, so the agent's next call is a new row.
func expiryFreesThePendingCap(t *testing.T, st expiringStore) {
	t.Helper()
	ctx := context.Background()
	base := time.Now().UTC().Add(-48 * time.Hour)
	once := func(id, key string) PendingOutcome {
		t.Helper()
		_, out, err := st.CreateApprovalOnce(ctx, Approval{ApprovalID: id, AgentID: "agent://acme.example/w", RunID: "r", RequestedAt: base, Context: map[string]any{"org": "acme"}}, key, 1)
		if err != nil {
			t.Fatalf("CreateApprovalOnce %s: %v", id, err)
		}
		return out
	}
	if out := once("ap-cap-1", "k1"); out != PendingCreated {
		t.Fatalf("first call: %v", out)
	}
	if out := once("ap-cap-2", "k2"); out != PendingQueueFull {
		t.Fatalf("second call at the cap: %v, want queue full", out)
	}
	if _, err := st.ExpireApprovals(ctx, base, ttlApprover, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if out := once("ap-cap-3", "k2"); out != PendingCreated {
		t.Fatalf("after the expiry another call: %v, want a new row", out)
	}
	if out := once("ap-cap-4", "k1"); out != PendingQueueFull {
		t.Fatalf("the expired call again at the cap: %v, want queue full (its old row left the index, the new one fills the cap)", out)
	}
}

// expiryRacesDecisions: a person deciding and any number of checks running at
// once leave every hold closed exactly once, and no check reports a hold a person
// closed or a hold another check closed. Each expirer is a separate caller; on
// Postgres they are separate connections pools, which is what two instances are.
func expiryRacesDecisions(t *testing.T, st Store, expirers []HoldExpirer) {
	t.Helper()
	ctx := context.Background()
	const n = 60
	base := time.Now().UTC().Add(-48 * time.Hour)
	for i := 0; i < n; i++ {
		if err := st.CreateApproval(ctx, Approval{ApprovalID: fmt.Sprintf("ap-race-%02d", i), AgentID: "agent://acme.example/bot", RunID: "r", RequestedAt: base}); err != nil {
			t.Fatal(err)
		}
	}
	var (
		mu       sync.Mutex
		expired  = map[string]int{}
		decided  = map[string]bool{}
		wg       sync.WaitGroup
		failures []error
	)
	for i := 0; i < n; i++ {
		if i%2 != 0 {
			continue
		}
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_, err := st.DecideApproval(ctx, id, "deny", "key:abc", "", time.Now().UTC())
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				decided[id] = true
			case errors.Is(err, ErrAlreadyDecided):
			default:
				failures = append(failures, err)
			}
		}(fmt.Sprintf("ap-race-%02d", i))
	}
	for _, ex := range expirers {
		for k := 0; k < 3; k++ {
			wg.Add(1)
			go func(ex HoldExpirer) {
				defer wg.Done()
				closed, err := ex.ExpireApprovals(ctx, base, ttlApprover, time.Now().UTC())
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					failures = append(failures, err)
				}
				for _, a := range closed {
					expired[a.ApprovalID]++
				}
			}(ex)
		}
	}
	wg.Wait()
	if len(failures) > 0 {
		t.Fatalf("calls failed: %v", failures)
	}
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("ap-race-%02d", i)
		got, err := st.GetApproval(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case expired[id] > 1:
			t.Errorf("%s was reported expired %d times", id, expired[id])
		case expired[id] == 1 && decided[id]:
			t.Errorf("%s was both decided by a person and reported expired", id)
		case expired[id] == 1 && got.Decision != DecisionExpired:
			t.Errorf("%s was reported expired and holds %q", id, got.Decision)
		case decided[id] && got.Decision != "deny":
			t.Errorf("%s was decided by a person and holds %q", id, got.Decision)
		case expired[id] == 0 && !decided[id]:
			t.Errorf("%s ended %q with nobody reporting it closed", id, got.Decision)
		}
	}
}

func ids(as []Approval) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, a.ApprovalID)
	}
	return out
}

func TestMemoryExpiresOnlyPendingHoldsPastTheCutoff(t *testing.T) {
	holdExpiryContract(t, NewMemory())
}

func TestMemoryAnExpiredHoldFreesItsPlaceUnderTheCap(t *testing.T) {
	expiryFreesThePendingCap(t, NewMemory())
}

func TestMemoryExpiryAndADecisionCloseEachHoldOnce(t *testing.T) {
	m := NewMemory()
	expiryRacesDecisions(t, m, []HoldExpirer{m, m})
}

func TestMemoryExpireApprovalsHandsOutCopies(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	if err := m.CreateApproval(ctx, Approval{ApprovalID: "ap-c", AgentID: "agent://a", RunID: "r", RequestedAt: time.Unix(0, 0), Context: map[string]any{"org": "acme"}}); err != nil {
		t.Fatal(err)
	}
	closed, err := m.ExpireApprovals(ctx, time.Now(), ttlApprover, time.Now())
	if err != nil || len(closed) != 1 {
		t.Fatalf("closed %v %v", ids(closed), err)
	}
	closed[0].Context["org"] = "evil"
	if got, _ := m.GetApproval(ctx, "ap-c"); got.Context["org"] != "acme" {
		t.Fatalf("a caller's edit of an expired row reached the store: %v", got.Context["org"])
	}
}

// A withdrawn hold is DecideApproval with DecisionWithdrawn: it closes once and
// takes its preview with it, like any decision.
func withdrawContract(t *testing.T, st expiringStore) {
	t.Helper()
	ctx := context.Background()
	if err := st.CreateApproval(ctx, Approval{ApprovalID: "ap-w", AgentID: "agent://a", RunID: "r", RequestedAt: time.Now().UTC(), Context: map[string]any{"org": "acme"}}); err != nil {
		t.Fatal(err)
	}
	if err := st.PutPreview(ctx, Preview{ApprovalID: "ap-w", Org: "acme", Sealed: []byte{1}, Digest: "d", Ruleset: "r1", Suite: "s", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	got, err := st.DecideApproval(ctx, "ap-w", DecisionWithdrawn, "agent:agent://a", "", time.Now().UTC())
	if err != nil || got.Decision != DecisionWithdrawn {
		t.Fatalf("withdraw: %+v %v", got, err)
	}
	if _, err := st.GetPreview(ctx, "ap-w"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a withdrawn hold kept its preview: %v", err)
	}
	if _, err := st.DecideApproval(ctx, "ap-w", "grant", "key:abc", "", time.Now().UTC()); !errors.Is(err, ErrAlreadyDecided) {
		t.Fatalf("a withdrawn hold was granted: %v", err)
	}
}

func TestMemoryAWithdrawnHoldLosesItsPreviewAndCannotBeDecided(t *testing.T) {
	withdrawContract(t, NewMemory())
}
