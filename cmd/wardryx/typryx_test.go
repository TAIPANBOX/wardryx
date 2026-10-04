package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/config"
	"github.com/TAIPANBOX/wardryx/internal/enrich"
)

// Signal enrichment is off unless an operator names a typryx. Set, it is
// validated before anything is opened, and a typo is a refusal that names the
// variable, never a silent fallback to "off" that an operator would read as
// "on".

func keyFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "typryx.key")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTyprxEnrichmentIsOffByDefault(t *testing.T) {
	c, err := typryxFromConfig(config.Config{})
	if err != nil || c != nil {
		t.Fatalf("typryxFromConfig(zero) = %v, %v; want nil, nil: nothing is asked unless an operator names a typryx", c, err)
	}
	// Settings that only make sense with a URL do not switch anything on.
	c, err = typryxFromConfig(config.Config{TypryxKeyFile: "/nope", TypryxTimeoutMS: 80})
	if err != nil || c != nil {
		t.Fatalf("a key file or timeout with no URL switched enrichment on or failed: %v, %v", c, err)
	}
	if w := typryxWarning(config.Config{TypryxKeyFile: "/nope"}); !strings.Contains(w, "WARDRYX_TYPRYX_URL") {
		t.Errorf("a key file with no URL gave no warning naming WARDRYX_TYPRYX_URL: %q", w)
	}
	if w := typryxWarning(config.Config{}); w != "" {
		t.Errorf("a plain configuration warned about typryx: %q", w)
	}
}

func TestTyprxEnrichmentStartsWithTheDefaultTimeoutAndTheKeyRead(t *testing.T) {
	c, err := typryxFromConfig(config.Config{TypryxURL: "http://typryx:4320", TypryxKeyFile: keyFile(t, "  the-key\n")})
	if err != nil || c == nil {
		t.Fatalf("a valid configuration did not start enrichment: %v, %v", c, err)
	}
	if c.Timeout() != enrich.DefaultTimeout || c.Timeout() != 150*time.Millisecond {
		t.Errorf("timeout = %s, want the 150ms default", c.Timeout())
	}
	c, err = typryxFromConfig(config.Config{TypryxURL: "http://typryx:4320", TypryxTimeoutMS: 80})
	if err != nil || c.Timeout() != 80*time.Millisecond {
		t.Fatalf("an 80ms timeout: %v, %v", c, err)
	}
}

func TestAnUnusableTyprxConfigurationRefusesToStartNamingTheVariable(t *testing.T) {
	cases := []struct {
		name string
		cfg  config.Config
		want string
	}{
		{"a URL with no scheme", config.Config{TypryxURL: "typryx:4320"}, "WARDRYX_TYPRYX_URL"},
		{"a URL with userinfo", config.Config{TypryxURL: "http://u:p@typryx"}, "WARDRYX_TYPRYX_URL"},
		{"an unparsable timeout", config.Config{TypryxURL: "http://typryx", TypryxTimeoutMS: -1}, "WARDRYX_TYPRYX_TIMEOUT_MS"},
		{"a timeout over the ceiling", config.Config{TypryxURL: "http://typryx", TypryxTimeoutMS: 60000}, "WARDRYX_TYPRYX_TIMEOUT_MS"},
		{"a missing key file", config.Config{TypryxURL: "http://typryx", TypryxKeyFile: "/definitely/not/here"}, "WARDRYX_TYPRYX_KEY_FILE"},
		{"an empty key file", config.Config{TypryxURL: "http://typryx", TypryxKeyFile: keyFile(t, " \n")}, "WARDRYX_TYPRYX_KEY_FILE"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := typryxFromConfig(c.cfg)
			if err == nil || got != nil {
				t.Fatalf("accepted: %v, %v", got, err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("the refusal does not name %s: %v", c.want, err)
			}
		})
	}
}

func TestTheKeyNeverAppearsInARefusal(t *testing.T) {
	const secret = "KEY-CONTENT-MUST-NOT-LEAK"
	_, err := typryxFromConfig(config.Config{TypryxURL: "not a url", TypryxKeyFile: keyFile(t, secret)})
	if err == nil {
		t.Fatal("accepted")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("the refusal carries the key: %v", err)
	}
	_, err = typryxFromConfig(config.Config{TypryxURL: "http://typryx", TypryxKeyFile: keyFile(t, secret+"\nline two")})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("a two-line key file: %v", err)
	}
}
