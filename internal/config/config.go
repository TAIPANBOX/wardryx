// Package config reads Wardryx's WARDRYX_* environment variables exactly
// once at process startup. Nothing else in this codebase calls os.Getenv on
// this prefix: every other package receives configuration as plain
// function/struct arguments, so a value read here never drifts or gets
// re-read mid-request.
package config

import "os"

// Config holds every WARDRYX_* environment variable. Fields are the raw
// string (or, for the approval secret, byte) values; callers apply their
// own defaults where a corresponding CLI flag has one (e.g. -addr defaults
// to ":8090" when both the flag and WARDRYX_ADDR are empty).
type Config struct {
	// Addr is WARDRYX_ADDR: the listen address for `serve`.
	Addr string
	// Keys is WARDRYX_KEYS: the "key:org[:role],..." bearer-key spec. No
	// CLI flag mirrors this one; it is env-only.
	Keys string
	// DB is WARDRYX_DB: a Postgres DSN. Empty selects the in-memory store.
	DB string
	// Policy is WARDRYX_POLICY: a policy file or directory.
	Policy string
	// EventsPath is WARDRYX_EVENTS_PATH: the NDJSON agent-event output
	// path. Empty disables event emission entirely (opt-in, no-op).
	EventsPath string
	// ApprovalSecret is WARDRYX_APPROVAL_SECRET: the HMAC key approval
	// tokens are signed and verified with. No CLI flag mirrors this one;
	// it is env-only, and empty fails closed wherever it is used
	// (internal/approval), never falls back to an unsigned token.
	ApprovalSecret string
	// OTLPEndpoint is WARDRYX_OTLP_ENDPOINT. Read and carried on Config
	// for forward compatibility; nothing in this build exports traces or
	// metrics yet, so it is not otherwise consulted today.
	OTLPEndpoint string
}

// FromEnv reads every WARDRYX_* variable once. Call it a single time per
// process (main, or each CLI subcommand's entry point) and thread the
// result through as a value.
func FromEnv() Config {
	return Config{
		Addr:           os.Getenv("WARDRYX_ADDR"),
		Keys:           os.Getenv("WARDRYX_KEYS"),
		DB:             os.Getenv("WARDRYX_DB"),
		Policy:         os.Getenv("WARDRYX_POLICY"),
		EventsPath:     os.Getenv("WARDRYX_EVENTS_PATH"),
		ApprovalSecret: os.Getenv("WARDRYX_APPROVAL_SECRET"),
		OTLPEndpoint:   os.Getenv("WARDRYX_OTLP_ENDPOINT"),
	}
}
