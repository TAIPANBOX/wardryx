package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/api"
	"github.com/TAIPANBOX/wardryx/internal/config"
	"github.com/TAIPANBOX/wardryx/internal/previewseal"
)

// buildPreview reads WARDRYX_PREVIEW_RECIPIENT and WARDRYX_PREVIEW_TTL. Unset
// recipient keeps no preview; a recipient or a TTL that does not parse refuses
// the start, so a typo cannot read as previews being kept (invariant 51).
func buildPreview(cfg config.Config) (*previewseal.Recipient, time.Duration, error) {
	ttl, err := api.ParsePreviewTTL(cfg.PreviewTTL)
	if err != nil {
		return nil, 0, err
	}
	if cfg.PreviewRecipient == "" {
		return nil, ttl, nil
	}
	r, err := previewseal.ParseRecipient(cfg.PreviewRecipient)
	if err != nil {
		return nil, 0, fmt.Errorf("WARDRYX_PREVIEW_RECIPIENT: %w", err)
	}
	return r, ttl, nil
}

// runPreviewKey generates a preview key pair: the private key goes to a new
// file only its owner can read, and the recipient, which is public, is printed
// for WARDRYX_PREVIEW_RECIPIENT. The private key belongs to the console; wardryx
// never reads it.
func runPreviewKey(args []string) error {
	fs := flag.NewFlagSet("preview-key", flag.ContinueOnError)
	out := fs.String("out", "", "file to write the private key to (must not exist)")
	classic := fs.Bool("x25519", false, "use DHKEM(X25519) instead of the hybrid ML-KEM-768 with X25519")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return errors.New("preview-key needs -out <file> for the private key")
	}
	kem := previewseal.KEMHybrid
	if *classic {
		kem = previewseal.KEMX25519
	}
	priv, recipient, err := previewseal.GenerateKey(kem)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400) // #nosec G304 -- the operator names the file
	if err != nil {
		return fmt.Errorf("preview-key: %w", err)
	}
	if _, err := fmt.Fprintln(f, priv); err != nil {
		_ = f.Close()
		return fmt.Errorf("preview-key: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("preview-key: %w", err)
	}
	fmt.Println(recipient)
	return nil
}
