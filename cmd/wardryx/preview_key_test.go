package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/config"
	"github.com/TAIPANBOX/wardryx/internal/previewseal"
)

func TestAPreviewRecipientOrTTLThatDoesNotParseRefusesTheStart(t *testing.T) {
	if r, _, err := buildPreview(config.Config{}); err != nil || r != nil {
		t.Fatalf("unset: %v %v", r, err)
	}
	if _, _, err := buildPreview(config.Config{PreviewRecipient: "hpke:0020:!!"}); err == nil {
		t.Error("a recipient that does not parse started")
	}
	if _, _, err := buildPreview(config.Config{PreviewTTL: "forever"}); err == nil {
		t.Error("a TTL that does not parse started")
	}
}

func TestPreviewKeyWritesAPrivateFileAndPrintsTheRecipient(t *testing.T) {
	out := filepath.Join(t.TempDir(), "preview.key")
	if err := runPreviewKey([]string{"-out", out}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(out)
	if err != nil || fi.Mode().Perm() != 0o400 {
		t.Fatalf("key file %v %v", fi, err)
	}
	raw, _ := os.ReadFile(out)
	if _, err := previewseal.ParsePrivateKey(strings.TrimSpace(string(raw))); err != nil {
		t.Fatalf("the written key does not parse: %v", err)
	}
	// It never overwrites.
	if err := runPreviewKey([]string{"-out", out}); err == nil {
		t.Error("an existing key file was overwritten")
	}
}
