package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/agenttoken"
	"github.com/TAIPANBOX/wardryx/internal/config"
)

// agentTokenPollEvery is how often the agent-token key set and revocation list
// are polled. The revocation cache's own age limit is one minute, so a poll
// every 30 seconds keeps a fetched list inside it.
const agentTokenPollEvery = 30 * time.Second

// buildAgentTokens turns WARDRYX_AGENT_TOKEN_* into a verifier, and the warnings
// the operator must read at startup. With no issuer and no other setting,
// verification is off and nothing is returned. A partial configuration is
// refused: a verifier missing a setting would verify less than the operator asked
// for, or nothing. The key set is loaded here, so a process whose key set cannot
// be read does not start.
func buildAgentTokens(cfg config.Config) (*agenttoken.Verifier, func(context.Context, func(error)), []string, error) {
	others := cfg.AgentTokenJWKSURL != "" || cfg.AgentTokenJWKSFile != "" ||
		cfg.AgentTokenAudiences != "" || cfg.AgentTokenRevocationURL != "" ||
		cfg.AgentTokenDoorOrigins != "" || cfg.AgentTokenRequireProof != "" ||
		cfg.AgentTokenProofMaxAgeSeconds != ""
	if strings.TrimSpace(cfg.AgentTokenIssuer) == "" {
		if others {
			return nil, nil, nil, errors.New("WARDRYX_AGENT_TOKEN_* names a setting but WARDRYX_AGENT_TOKEN_ISSUER is not set: set the issuer or unset the rest")
		}
		return nil, nil, nil, nil
	}

	// Proofs are required unless WARDRYX_AGENT_TOKEN_REQUIRE_PROOF=0, which is
	// said at startup, because a token alone is then usable by whoever holds it.
	var warnings []string
	proofOptional := false
	switch strings.TrimSpace(cfg.AgentTokenRequireProof) {
	case "", "1":
	case "0":
		proofOptional = true
		warnings = append(warnings, "WARDRYX_AGENT_TOKEN_REQUIRE_PROOF=0: agent tokens are accepted with no DPoP proof, so a token alone is usable by whoever holds it, through any door, for its five-minute life")
	default:
		return nil, nil, nil, fmt.Errorf("WARDRYX_AGENT_TOKEN_REQUIRE_PROOF must be 0 or 1, not %q", cfg.AgentTokenRequireProof)
	}
	var maxAge time.Duration
	if raw := strings.TrimSpace(cfg.AgentTokenProofMaxAgeSeconds); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 300 {
			return nil, nil, nil, fmt.Errorf("WARDRYX_AGENT_TOKEN_PROOF_MAX_AGE_SECONDS must be a whole number from 1 to 300, not %q", raw)
		}
		maxAge = time.Duration(n) * time.Second
	}

	v, err := agenttoken.New(agenttoken.Config{
		Issuer:        cfg.AgentTokenIssuer,
		Audiences:     strings.Split(cfg.AgentTokenAudiences, ","),
		JWKSURL:       cfg.AgentTokenJWKSURL,
		JWKSFile:      cfg.AgentTokenJWKSFile,
		RevocationURL: cfg.AgentTokenRevocationURL,
		DoorOrigins:   strings.Split(cfg.AgentTokenDoorOrigins, ","),
		ProofOptional: proofOptional,
		ProofMaxAge:   maxAge,
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
	return v, run, warnings, nil
}
