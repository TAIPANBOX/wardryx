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

// approverStartWarnings is what serve prints about the approver settings at
// start. Nothing is printed for the defaults. With the switch on, the start line
// says key-kind approvals are accepted; with the switch on and no key set, it
// says the switch has no effect.
func approverStartWarnings(cfg config.Config) []string {
	if !cfg.AllowKeyApprovals {
		return nil
	}
	if cfg.ApproverJWKSFile == "" {
		return []string{"WARDRYX_ALLOW_KEY_APPROVALS=1 has no effect: WARDRYX_APPROVER_JWKS is not set, so no approval statement is required"}
	}
	return []string{"WARDRYX_ALLOW_KEY_APPROVALS=1: approvals may be decided by a bearer key with no approver statement, and each such decision is logged"}
}
