package main

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/agenttoken"
	"github.com/TAIPANBOX/wardryx/internal/config"
)

// agentTokenPollEvery is how often the agent-token key set and revocation list
// are polled. The revocation cache's own age limit is one minute, so a poll
// every 30 seconds keeps a fetched list inside it.
const agentTokenPollEvery = 30 * time.Second

// buildAgentTokens turns WARDRYX_AGENT_TOKEN_* into a verifier. With no issuer
// and no other setting, verification is off and nothing is returned. A partial
// configuration is refused: a verifier that is missing a setting would verify
// less than the operator asked for, or nothing. The key set is loaded here, so
// a process whose key set cannot be read does not start.
func buildAgentTokens(cfg config.Config) (*agenttoken.Verifier, func(context.Context, func(error)), []string, error) {
	others := cfg.AgentTokenJWKSURL != "" || cfg.AgentTokenJWKSFile != "" ||
		cfg.AgentTokenAudiences != "" || cfg.AgentTokenRevocationURL != ""
	if strings.TrimSpace(cfg.AgentTokenIssuer) == "" {
		if others {
			return nil, nil, nil, errors.New("WARDRYX_AGENT_TOKEN_* names a setting but WARDRYX_AGENT_TOKEN_ISSUER is not set: set the issuer or unset the rest")
		}
		return nil, nil, nil, nil
	}
	v, err := agenttoken.New(agenttoken.Config{
		Issuer:        cfg.AgentTokenIssuer,
		Audiences:     strings.Split(cfg.AgentTokenAudiences, ","),
		JWKSURL:       cfg.AgentTokenJWKSURL,
		JWKSFile:      cfg.AgentTokenJWKSFile,
		RevocationURL: cfg.AgentTokenRevocationURL,
	}, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := v.Load(context.Background()); err != nil {
		return nil, nil, nil, err
	}
	run := func(ctx context.Context, report func(error)) {
		v.Run(ctx, agentTokenPollEvery, report)
	}
	return v, run, nil, nil
}
