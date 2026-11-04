package main

import (
	"errors"
	"strings"

	"github.com/TAIPANBOX/wardryx/internal/config"
	"github.com/TAIPANBOX/wardryx/internal/sloburn"
)

// buildSLOBurn turns WARDRYX_SIGNAL_EVENTS and WARDRYX_SIGNAL_EVENTS_MAX_AGE into
// the reader of the quality plane's event file (invariant 45). With neither set
// the option is off and nothing is returned. An age with no file is refused, and
// so is an age that is not a duration from one minute to thirty days: a setting
// that cannot work is not run with.
//
// The file is read once here, so the state is known before the first request. A
// file that cannot be read does not stop the start: it may not exist before the
// quality plane's first event, and the signal is simply absent until it can be
// read. The reader says so in the log, naming the file.
func buildSLOBurn(cfg config.Config) (*sloburn.Reader, error) {
	path := strings.TrimSpace(cfg.SignalEvents)
	if path == "" {
		if strings.TrimSpace(cfg.SignalEventsMaxAge) != "" {
			return nil, errors.New("WARDRYX_SIGNAL_EVENTS_MAX_AGE is set but WARDRYX_SIGNAL_EVENTS is not: set the file or unset the age")
		}
		return nil, nil
	}
	maxAge, err := sloburn.ParseMaxAge(strings.TrimSpace(cfg.SignalEventsMaxAge))
	if err != nil {
		return nil, err
	}
	r := sloburn.New(path, maxAge)
	r.Refresh()
	return r, nil
}
