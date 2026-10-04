package config

import "testing"

func TestFromEnv(t *testing.T) {
	t.Setenv("WARDRYX_ADDR", ":9999")
	t.Setenv("WARDRYX_KEYS", "k:org")
	t.Setenv("WARDRYX_DB", "postgres://x")
	t.Setenv("WARDRYX_POLICY", "/etc/wardryx/policy")
	t.Setenv("WARDRYX_EVENTS_PATH", "/var/log/wardryx/events.ndjson")
	t.Setenv("WARDRYX_APPROVAL_SECRET", "shh")
	t.Setenv("WARDRYX_APPROVAL_SINGLE_USE", "true")
	t.Setenv("WARDRYX_OTLP_ENDPOINT", "http://otel:4318")

	cfg := FromEnv()
	want := Config{
		Addr:              ":9999",
		Keys:              "k:org",
		DB:                "postgres://x",
		Policy:            "/etc/wardryx/policy",
		EventsPath:        "/var/log/wardryx/events.ndjson",
		ApprovalSecret:    "shh",
		ApprovalSingleUse: true,
		OTLPEndpoint:      "http://otel:4318",
	}
	if cfg != want {
		t.Errorf("FromEnv = %+v, want %+v", cfg, want)
	}
}

func TestFromEnvUnsetIsZeroValue(t *testing.T) {
	for _, k := range []string{
		"WARDRYX_ADDR", "WARDRYX_KEYS", "WARDRYX_DB", "WARDRYX_POLICY",
		"WARDRYX_EVENTS_PATH", "WARDRYX_APPROVAL_SECRET", "WARDRYX_APPROVAL_SINGLE_USE", "WARDRYX_OTLP_ENDPOINT",
	} {
		t.Setenv(k, "")
	}
	cfg := FromEnv()
	// Every field is its zero value with one exception, named so nobody reads
	// it as drift: ApprovalSingleUse defaults to true since 1.0 (invariant 5),
	// and TestFromEnvApprovalSingleUseDefaultsOn pins that on its own.
	want := Config{ApprovalSingleUse: true}
	if cfg != want {
		t.Errorf("FromEnv with everything unset = %+v, want %+v", cfg, want)
	}
}

// TestFromEnvApprovalSingleUseDefaultsOn pins the 1.0 default (decided
// 2026-09-13, invariant 5): an unset WARDRYX_APPROVAL_SINGLE_USE means a
// redeemed approval_token allows exactly one /v1/decide call. Replay of an
// approval is the whole attack, and the stack is closed by default everywhere
// else; before 1.0 the default was off and a token stayed reusable for its
// TTL, which an operator can still choose by setting the variable to false.
func TestFromEnvApprovalSingleUseDefaultsOn(t *testing.T) {
	for _, name := range []string{
		"WARDRYX_ADDR", "WARDRYX_KEYS", "WARDRYX_ALLOW_DEVKEY", "WARDRYX_DB", "WARDRYX_POLICY",
		"WARDRYX_EVENTS_PATH", "WARDRYX_APPROVAL_SECRET", "WARDRYX_APPROVAL_SINGLE_USE", "WARDRYX_OTLP_ENDPOINT",
	} {
		t.Setenv(name, "")
	}
	if !FromEnv().ApprovalSingleUse {
		t.Error("ApprovalSingleUse = false with WARDRYX_APPROVAL_SINGLE_USE unset, want true (the 1.0 default: single-use)")
	}
}

// TestFromEnvApprovalSingleUseParsing covers the handling of
// WARDRYX_APPROVAL_SINGLE_USE across the values strconv.ParseBool accepts,
// plus the fail-closed behavior on anything it doesn't: single-use is the
// default, so an unparsable value must never be silently treated as "off".
// Only an explicit false turns reuse back on.
func TestFromEnvApprovalSingleUseParsing(t *testing.T) {
	cases := []struct {
		value string
		want  bool
	}{
		{"true", true},
		{"1", true},
		{"t", true},
		{"TRUE", true},
		{"false", false},
		{"0", false},
		{"f", false},
		{"FALSE", false},
		{"", true},           // unset: the 1.0 default, single-use
		{"not-a-bool", true}, // unparsable: fail closed, never silently reusable
		{"yes", true},        // strconv.ParseBool does not accept "yes"; fail closed, not error out
	}
	for _, c := range cases {
		t.Run("value="+c.value, func(t *testing.T) {
			t.Setenv("WARDRYX_APPROVAL_SINGLE_USE", c.value)
			if got := FromEnv().ApprovalSingleUse; got != c.want {
				t.Errorf("FromEnv().ApprovalSingleUse with WARDRYX_APPROVAL_SINGLE_USE=%q = %v, want %v", c.value, got, c.want)
			}
		})
	}
}

// Signal enrichment is off unless WARDRYX_TYPRYX_URL is set. The timeout is the
// one setting that can be wrong in a way worth telling apart: unset is the
// default, a positive whole number is itself, and anything else is -1, which
// serve refuses by name rather than guessing a number for the operator.
func TestFromEnvReadsTheTyprxSettings(t *testing.T) {
	t.Setenv("WARDRYX_TYPRYX_URL", "http://typryx:4320")
	t.Setenv("WARDRYX_TYPRYX_KEY_FILE", "/run/secrets/typryx-key")
	t.Setenv("WARDRYX_TYPRYX_TIMEOUT_MS", "80")
	cfg := FromEnv()
	if cfg.TypryxURL != "http://typryx:4320" || cfg.TypryxKeyFile != "/run/secrets/typryx-key" || cfg.TypryxTimeoutMS != 80 {
		t.Fatalf("FromEnv = %+v", cfg)
	}
}

func TestTyprxTimeoutIsUnsetPositiveOrInvalid(t *testing.T) {
	cases := []struct {
		value string
		want  int
	}{
		{"", 0}, {"150", 150}, {"1", 1}, {"5000", 5000},
		{"0", -1}, {"-5", -1}, {"abc", -1}, {"1.5", -1}, {"150ms", -1}, {" 150", -1}, {"99999999999999999999", -1},
	}
	for _, c := range cases {
		t.Run("value="+c.value, func(t *testing.T) {
			t.Setenv("WARDRYX_TYPRYX_TIMEOUT_MS", c.value)
			if got := FromEnv().TypryxTimeoutMS; got != c.want {
				t.Errorf("WARDRYX_TYPRYX_TIMEOUT_MS=%q read as %d, want %d", c.value, got, c.want)
			}
		})
	}
}
