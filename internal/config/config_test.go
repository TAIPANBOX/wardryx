package config

import "testing"

func TestFromEnv(t *testing.T) {
	t.Setenv("WARDRYX_ADDR", ":9999")
	t.Setenv("WARDRYX_KEYS", "k:org")
	t.Setenv("WARDRYX_DB", "postgres://x")
	t.Setenv("WARDRYX_POLICY", "/etc/wardryx/policy")
	t.Setenv("WARDRYX_EVENTS_PATH", "/var/log/wardryx/events.ndjson")
	t.Setenv("WARDRYX_APPROVAL_SECRET", "shh")
	t.Setenv("WARDRYX_OTLP_ENDPOINT", "http://otel:4318")

	cfg := FromEnv()
	want := Config{
		Addr:           ":9999",
		Keys:           "k:org",
		DB:             "postgres://x",
		Policy:         "/etc/wardryx/policy",
		EventsPath:     "/var/log/wardryx/events.ndjson",
		ApprovalSecret: "shh",
		OTLPEndpoint:   "http://otel:4318",
	}
	if cfg != want {
		t.Errorf("FromEnv = %+v, want %+v", cfg, want)
	}
}

func TestFromEnvUnsetIsZeroValue(t *testing.T) {
	for _, k := range []string{
		"WARDRYX_ADDR", "WARDRYX_KEYS", "WARDRYX_DB", "WARDRYX_POLICY",
		"WARDRYX_EVENTS_PATH", "WARDRYX_APPROVAL_SECRET", "WARDRYX_OTLP_ENDPOINT",
	} {
		t.Setenv(k, "")
	}
	cfg := FromEnv()
	if cfg != (Config{}) {
		t.Errorf("FromEnv with everything unset = %+v, want the zero Config", cfg)
	}
}
