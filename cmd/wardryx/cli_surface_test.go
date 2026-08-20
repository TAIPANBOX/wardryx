package main

import (
	"strings"
	"testing"

	"github.com/TAIPANBOX/agent-stack-go/event"
)

// envSet, chainPreview and orDash were all at 0%, and runApprovals at a third.
// Small functions, and one of them holds a distinction that decides whether a
// detector runs at all.

// envSet is how the unanswered-approval sweep tells "unset, use the default"
// from an explicit "0" meaning off. os.Getenv cannot: it returns "" for both.
//
// So an operator who set WARDRYX_APPROVAL_UNANSWERED_AFTER=0 to turn the sweep
// off would silently get the fifteen-minute default back, and start receiving
// the reports they had decided not to receive. The other direction is worse in
// a quieter way: nothing anywhere says the setting was ignored.
func TestEnvSetTellsUnsetApartFromSetToEmpty(t *testing.T) {
	const name = "WARDRYX_A_VARIABLE_FOR_THIS_TEST"

	if envSet(name) {
		t.Fatalf("%s reads as set before anything set it", name)
	}

	t.Setenv(name, "")
	if !envSet(name) {
		t.Fatalf("%s set to the empty string reads as unset. An operator who "+
			"turned something off explicitly would silently get the default "+
			"back, and nothing would say the setting was ignored", name)
	}

	t.Setenv(name, "0")
	if !envSet(name) {
		t.Fatalf("%s set to \"0\" reads as unset", name)
	}
}

// chainPreview shortens a chain hash for display. Too short and two different
// records look identical in a listing; too long and the column wraps and
// nobody reads it.
func TestChainPreviewKeepsThePrefixThatIdentifiesARecord(t *testing.T) {
	want := len(event.ChainHashPrefix) + 12

	full := event.ChainHashPrefix + strings.Repeat("a", 52)
	got := chainPreview(full)
	if len(got) != want {
		t.Fatalf("chainPreview kept %d characters, want %d", len(got), want)
	}
	if !strings.HasPrefix(full, got) {
		t.Fatalf("chainPreview(%q) = %q, which is not a prefix of its input", full, got)
	}

	// Two hashes differing after the preview length would look the same, which
	// is the cost of shortening and is accepted. Two differing WITHIN it must
	// not.
	// Differing at the LAST kept character. The first version of this made
	// them differ at position 13, which is past the cut, so it was asserting
	// against the accepted collision rather than against the preview.
	a := chainPreview(event.ChainHashPrefix + "0123456789abcdef")
	b := chainPreview(event.ChainHashPrefix + "0123456789aXcdef")
	if a == b {
		t.Fatalf("two hashes differing inside the preview render the same: %q", a)
	}

	// Shorter than the preview length is returned whole rather than padded or
	// sliced past its end.
	for _, short := range []string{"", "abc", event.ChainHashPrefix} {
		if got := chainPreview(short); got != short {
			t.Fatalf("chainPreview(%q) = %q, want it unchanged", short, got)
		}
	}
}

// A missing value renders as a dash rather than as nothing. An empty cell in a
// tab-separated listing shifts the eye to the next column and reads as the
// value that belongs there.
func TestAnAbsentValueRendersAsADash(t *testing.T) {
	if got := orDash(""); got != "-" {
		t.Fatalf("orDash(\"\") = %q, want \"-\"", got)
	}
	for _, s := range []string{"alice", "-", " "} {
		if got := orDash(s); got != s {
			t.Fatalf("orDash(%q) = %q, want it unchanged", s, got)
		}
	}
}

// approvals without a database is an ERROR and never an empty listing. The
// reason is in the message: a freshly started in-memory store is always empty,
// so reporting "No approvals recorded" would tell an operator there are no
// held actions when there may be a queue of them in Postgres.
func TestApprovalsWithoutADatabaseRefusesRatherThanReportingNone(t *testing.T) {
	t.Setenv("WARDRYX_DB", "")

	err := runApprovals(nil)
	if err == nil {
		t.Fatal("approvals with no database succeeded. Whatever it printed, an " +
			"operator reading it learns that nothing is held, and a queue of " +
			"held actions in Postgres is exactly what they would not see")
	}
	if !strings.Contains(err.Error(), "-db") {
		t.Fatalf("the error does not name the flag that would fix it: %v", err)
	}
	if !strings.Contains(err.Error(), "in-memory") {
		t.Fatalf("the error does not say why an empty listing would be wrong, "+
			"which is the part that stops somebody adding a fallback: %v", err)
	}
}

func TestApprovalsRejectsAFlagItDoesNotKnow(t *testing.T) {
	if err := runApprovals([]string{"-not-a-flag"}); err == nil {
		t.Fatal("an unknown flag was accepted, so a misspelled -db would run " +
			"against whatever the environment happened to hold")
	}
}
