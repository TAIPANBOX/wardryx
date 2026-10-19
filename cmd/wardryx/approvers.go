package main

import (
	"github.com/TAIPANBOX/wardryx/internal/approverstmt"
	"github.com/TAIPANBOX/wardryx/internal/config"
)

// buildApprovers loads the console keys named by WARDRYX_APPROVER_JWKS, or
// returns nil when it is unset. A file that does not read is a refusal to start:
// a deployment that meant to verify statements must not run without them.
func buildApprovers(cfg config.Config) (*approverstmt.Verifier, error) {
	if cfg.ApproverJWKSFile == "" {
		return nil, nil
	}
	return approverstmt.ReadKeyFile(cfg.ApproverJWKSFile)
}
