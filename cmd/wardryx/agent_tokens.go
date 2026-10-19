package main

import (
	"context"

	"github.com/TAIPANBOX/wardryx/internal/agenttoken"
	"github.com/TAIPANBOX/wardryx/internal/config"
)

// buildAgentTokens turns WARDRYX_AGENT_TOKEN_* into a verifier. Scaffold: builds
// nothing, so a partial configuration is not refused yet.
func buildAgentTokens(cfg config.Config) (*agenttoken.Verifier, func(context.Context, func(error)), error) {
	return nil, nil, nil
}
