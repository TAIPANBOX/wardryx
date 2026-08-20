package api

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/store"
)

// ------------------------------------------------------------------
// The LOOP, as opposed to the sweep it runs.
//
// The sweep was already tested from four angles. Nothing tested the loop
// around it, and the loop is what decides whether the sweep ever happens at
// all. A detector that works perfectly and is never called is indistinguishable
// from a queue nobody has neglected: both are silence.
// ------------------------------------------------------------------

// Both clamps, and the range between them. Neither had ever been executed.
func TestTheSweepIntervalIsClampedAtBothEnds(t *testing.T) {
	cases := []struct {
		name      string
		threshold time.Duration
		want      time.Duration
		why       string
	}{
		{
			"a short threshold does not tick faster than once a second",
			2 * time.Second, time.Second,
			"a quarter of two seconds is 500ms, and a wardryx listing every " +
				"approval twice a second is a cost nobody asked for",
		},
		{
			"an ordinary threshold is a quarter of itself",
			time.Minute, 15 * time.Second,
			"between the clamps nothing is adjusted",
		},
		{
			"the boundary itself is not clamped",
			4 * time.Second, time.Second,
			"exactly one second is allowed; the clamp is < and not <=",
		},
		{
			"a long threshold still looks once a minute",
			24 * time.Hour, time.Minute,
			"a quarter of a day is six hours, so a hold would be reported " +
				"up to six hours after it crossed the threshold it is measured against",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sweepInterval(c.threshold); got != c.want {
				t.Fatalf("sweepInterval(%s) = %s, want %s: %s",
					c.threshold, got, c.want, c.why)
			}
		})
	}
}

// The loop actually calls the sweep. This is the one that cannot avoid real
// time: the interval floor is a second by design, so proving a tick happened
// means waiting for one.
func TestTheWatcherRunsTheSweepAndNotJustTheFirstReturn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	srv, ew := newTestServerWithEvents(t, path)
	// Four seconds gives the smallest interval the clamp allows.
	srv.SetUnansweredAfter(4 * time.Second)

	if err := srv.store.CreateApproval(context.Background(), store.Approval{
		ApprovalID: "a1", AgentID: "agent://acme.example/finance/bot", RunID: "r1",
		RequestedAt: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { srv.WatchUnansweredApprovals(ctx); close(done) }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the watcher did not return when its context was done")
	}
	_ = ew.Close()

	if n := countEventsOfType(t, path, "approval_unanswered"); n == 0 {
		t.Fatal("the watcher ticked for three seconds over an hour-old hold and " +
			"reported nothing: the sweep is correct but nothing is calling it")
	}
}

// Cancelling has to return, not merely stop reporting. A watcher that ignores
// its context keeps a goroutine and a ticker alive for the life of the
// process, and nothing about the output would say so.
func TestCancellingTheContextStopsTheWatcher(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.ndjson")
	srv, ew := newTestServerWithEvents(t, path)
	defer func() { _ = ew.Close() }()
	// Long enough that no tick can fire, so the only way out is ctx.Done.
	srv.SetUnansweredAfter(time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.WatchUnansweredApprovals(ctx); close(done) }()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the watcher outlived its context: with a one-hour threshold " +
			"the next tick is a minute away, so it is not waiting on the ticker")
	}
}
