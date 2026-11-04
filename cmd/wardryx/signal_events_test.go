package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/config"
	"github.com/TAIPANBOX/wardryx/internal/sloburn"
)

// WARDRYX_SIGNAL_EVENTS turns on the slo_burn signal and
// WARDRYX_SIGNAL_EVENTS_MAX_AGE says how long an event keeps signalling. A
// setting that cannot work refuses the start, naming itself; neither set is
// the option off.

func TestTheSignalMaxAgeNeedsTheFileAndAUsableValue(t *testing.T) {
	file := filepath.Join(t.TempDir(), "events.ndjson")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	// Nothing set is the option off: no reader, no error.
	if r, err := buildSLOBurn(config.Config{}); err != nil || r != nil {
		t.Fatalf("nothing configured: err %v, reader %v; want neither", err, r)
	}
	// An age with no file is a half-set pair.
	_, err := buildSLOBurn(config.Config{SignalEventsMaxAge: "24h"})
	if err == nil || !strings.Contains(err.Error(), "WARDRYX_SIGNAL_EVENTS_MAX_AGE") || !strings.Contains(err.Error(), "WARDRYX_SIGNAL_EVENTS") {
		t.Fatalf("an age with no file: err %v, want a refusal naming both settings", err)
	}
	// An age nobody can use.
	for _, bad := range []string{"0", "0s", "-1h", "soon", "30", "59s", "721h", "1h30"} {
		r, err := buildSLOBurn(config.Config{SignalEvents: file, SignalEventsMaxAge: bad})
		if err == nil || r != nil || !strings.Contains(err.Error(), "WARDRYX_SIGNAL_EVENTS_MAX_AGE") {
			t.Errorf("age %q: err %v, reader %v; want a refusal naming WARDRYX_SIGNAL_EVENTS_MAX_AGE", bad, err, r)
		}
	}
	// The file alone takes the default, and the limits are the limits.
	if r, err := buildSLOBurn(config.Config{SignalEvents: file}); err != nil || r == nil {
		t.Fatalf("the file alone: err %v, reader %v; want a reader", err, r)
	}
	for _, ok := range []string{"1m", "36h", "720h"} {
		if r, err := buildSLOBurn(config.Config{SignalEvents: file, SignalEventsMaxAge: ok}); err != nil || r == nil {
			t.Errorf("age %q: err %v, reader %v; want a reader", ok, err, r)
		}
	}
}

// A file that is not there yet is the ordinary state before the quality plane's
// first event, so the service starts. It says at once, in the log, which file
// and what is wrong, and the signal stays absent until it can be read.
func TestTheSignalFileIsNamedAtStartWhenItCannotBeRead(t *testing.T) {
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	missing := filepath.Join(t.TempDir(), "not-yet.ndjson")
	r, err := buildSLOBurn(config.Config{SignalEvents: missing})
	if err != nil || r == nil {
		t.Fatalf("a missing file refused the start: err %v, reader %v", err, r)
	}
	if st := r.State(); st != sloburn.StateUnreadable {
		t.Fatalf("state %q, want unreadable", st)
	}
	if out := logged.String(); !strings.Contains(out, missing) || !strings.Contains(out, "unreadable") {
		t.Fatalf("the start did not name the file and the problem in the log: %q", out)
	}
}
