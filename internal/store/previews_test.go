package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// previewStoreContract is what both stores do with a sealed preview
// (CLAUDE.md invariant 51), run against each. now is the clock the store
// reads expiry against; setNow moves it.
func previewStoreContract(t *testing.T, st interface {
	Store
	PreviewStore
}, setNow func(time.Time)) {
	ctx := context.Background()
	base := time.Now().UTC()
	a := Approval{ApprovalID: "ap-prev-1", AgentID: "agent://a", RunID: "r", RequestedAt: base, Context: map[string]any{"org": "acme"}}
	if err := st.CreateApproval(ctx, a); err != nil {
		t.Fatal(err)
	}
	pv := Preview{ApprovalID: a.ApprovalID, Org: "acme", Sealed: []byte{1, 2, 3}, Digest: "d1", Ruleset: "r1", Suite: "s", ExpiresAt: base.Add(time.Hour)}
	if err := st.PutPreview(ctx, pv); err != nil {
		t.Fatal(err)
	}
	// A second put for the same approval changes nothing.
	again := pv
	again.Sealed, again.Digest = []byte{9}, "d2"
	if err := st.PutPreview(ctx, again); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetPreview(ctx, a.ApprovalID)
	if err != nil || got.Digest != "d1" || len(got.Sealed) != 3 {
		t.Fatalf("got %+v %v, want the first preview", got, err)
	}
	// What is handed out is a copy.
	got.Sealed[0] = 42
	if again, _ := st.GetPreview(ctx, a.ApprovalID); again.Sealed[0] != 1 {
		t.Fatalf("a caller's edit reached the store")
	}
	// Past its time it is not served, and a purge removes it.
	setNow(base.Add(2 * time.Hour))
	if _, err := st.GetPreview(ctx, a.ApprovalID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an expired preview was served: %v", err)
	}
	if n, err := st.PurgePreviews(ctx); err != nil || n != 1 {
		t.Fatalf("purge %d %v", n, err)
	}
	setNow(base)
	// A decision deletes the preview of its approval, and only that one.
	b := Approval{ApprovalID: "ap-prev-2", AgentID: "agent://a", RunID: "r", RequestedAt: base, Context: map[string]any{}}
	c := Approval{ApprovalID: "ap-prev-3", AgentID: "agent://a", RunID: "r", RequestedAt: base, Context: map[string]any{}}
	for _, x := range []Approval{b, c} {
		if err := st.CreateApproval(ctx, x); err != nil {
			t.Fatal(err)
		}
		p := pv
		p.ApprovalID = x.ApprovalID
		if err := st.PutPreview(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := st.DecideApproval(ctx, b.ApprovalID, "grant", "key:x", "", base); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetPreview(ctx, b.ApprovalID); !errors.Is(err, ErrNotFound) {
		t.Errorf("the decided approval still has its preview: %v", err)
	}
	if _, err := st.GetPreview(ctx, c.ApprovalID); err != nil {
		t.Errorf("deciding one approval took another's preview: %v", err)
	}
	// A decision refused as already made deletes nothing new and keeps c's.
	if _, err := st.DecideApproval(ctx, b.ApprovalID, "deny", "key:x", "", base); !errors.Is(err, ErrAlreadyDecided) {
		t.Fatalf("second decision: %v", err)
	}
}

func TestTheMemoryStoreKeepsAPreviewUntilItIsDecidedOrExpires(t *testing.T) {
	m := NewMemory()
	var now time.Time
	m.SetClock(func() time.Time { return now })
	now = time.Now().UTC()
	previewStoreContract(t, m, func(t time.Time) { now = t })
}
