package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/approval"
	"github.com/TAIPANBOX/wardryx/internal/config"
	"github.com/TAIPANBOX/wardryx/internal/keyryx"
)

// keyryxRefreshEvery is how often the verified key set is fetched again. Keyryx
// publishes a new key at least 15 minutes before it signs with it, so a minute
// is far inside that window.
const keyryxRefreshEvery = time.Minute

// buildApprovalKeys reads WARDRYX_APPROVAL_SIGNER and its companions into the
// keys approval tokens are minted and verified with. The second result, when
// non-nil, is the refresh loop for Keyryx's key set; the caller starts it.
//
// With no signer a grant mints v2 under WARDRYX_APPROVAL_SECRET, as before. With
// "keyryx" a grant mints v3 through Keyryx, and a v2 token verifies only until
// WARDRYX_APPROVAL_V2_UNTIL. A deployment that signs with Keyryx and sets no
// deadline refuses every v2 token: the tokens in flight at the switch go back to
// a person rather than verify forever.
func buildApprovalKeys(cfg config.Config) (approval.Keys, func(context.Context, func(error)), error) {
	var v2 approval.V2Rule
	if raw := strings.TrimSpace(cfg.ApprovalV2Until); raw != "" {
		until, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return approval.Keys{}, nil, fmt.Errorf("WARDRYX_APPROVAL_V2_UNTIL is not an RFC 3339 time: %w", err)
		}
		v2 = approval.V2Rule{Accepted: true, Until: until}
	}
	keys := approval.Keys{Secret: []byte(cfg.ApprovalSecret), V2: approval.V2Rule{Accepted: true}}

	switch strings.ToLower(strings.TrimSpace(cfg.ApprovalSigner)) {
	case "":
		if v2.Until.IsZero() {
			return keys, nil, nil
		}
		keys.V2 = v2
		return keys, nil, nil
	case "keyryx":
	default:
		return approval.Keys{}, nil, fmt.Errorf("WARDRYX_APPROVAL_SIGNER %q is not a signer this build knows; use keyryx or leave it unset", cfg.ApprovalSigner)
	}

	if strings.TrimSpace(cfg.KeyryxURL) == "" {
		return approval.Keys{}, nil, fmt.Errorf("WARDRYX_APPROVAL_SIGNER=keyryx needs WARDRYX_KEYRYX_URL")
	}
	credential := ""
	if cfg.KeyryxCredentialFile != "" {
		raw, err := os.ReadFile(cfg.KeyryxCredentialFile)
		if err != nil {
			return approval.Keys{}, nil, fmt.Errorf("read WARDRYX_KEYRYX_CREDENTIAL_FILE: %w", err)
		}
		credential = strings.TrimSpace(string(raw))
	}
	client, err := keyryx.NewClient(cfg.KeyryxURL, credential)
	if err != nil {
		return approval.Keys{}, nil, err
	}
	cache := keyryx.NewCache(client)
	keys.Signer = client
	keys.JWKS = cache
	keys.V2 = v2 // not accepted at all when no deadline is set
	fmt.Fprintf(os.Stderr, "wardryx: approval tokens are signed by Keyryx (key %s at %s); v2 tokens verify %s\n",
		keyryx.KeyName, cfg.KeyryxURL, v2Clause(v2))
	return keys, func(ctx context.Context, report func(error)) {
		cache.Run(ctx, keyryxRefreshEvery, report)
	}, nil
}

func v2Clause(v2 approval.V2Rule) string {
	switch {
	case !v2.Accepted:
		return "not at all (WARDRYX_APPROVAL_V2_UNTIL is unset)"
	case v2.Until.IsZero():
		return "without a deadline"
	default:
		return "until " + v2.Until.UTC().Format(time.RFC3339)
	}
}
