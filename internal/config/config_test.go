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
	if cfg != (Config{}) {
		t.Errorf("FromEnv with everything unset = %+v, want the zero Config", cfg)
	}
	// The zero Config's ApprovalSingleUse is false: an unset
	// WARDRYX_APPROVAL_SINGLE_USE must preserve the original (pre-single-use)
	// behavior of a token remaining reusable for its full TTL.
	if cfg.ApprovalSingleUse {
		t.Error("ApprovalSingleUse = true with WARDRYX_APPROVAL_SINGLE_USE unset, want false (the default-off behavior)")
	}
}

// TestFromEnvApprovalSingleUseParsing covers parseBool's handling of
// WARDRYX_APPROVAL_SINGLE_USE across the values strconv.ParseBool accepts,
// plus the fail-safe-to-false behavior on anything it doesn't: single-use
// is opt-in, so an unparsable value must never be silently treated as "on".
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
		{"", false},
		{"not-a-bool", false},
		{"yes", false}, // strconv.ParseBool does not accept "yes"; must fail safe to false, not error out
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
