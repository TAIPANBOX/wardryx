package api

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/event"
	"github.com/TAIPANBOX/wardryx/internal/agenttoken"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// evIdentityMismatch is the event for a request whose verified agent token names
// a different agent than the request does. It is not a SPEC 6.2 row for source
// wardryx (the registry lists identity_mismatch for tokenfuse only); see the
// report that introduced it before it is registered.
const evIdentityMismatch = "identity_mismatch"

// agentTokenAgentID is wardryx's own agent id, the one its events carry for a
// refusal made in its name, as authAgentID is for the key binding.
const agentTokenAgentID = "agent://wardryx.internal/auth/agent-token" // #nosec G101 -- an agent id, not a credential

// WithAgentTokens sets the verifier for an agent's own token. Nil, the default,
// means no token is verified: a token in a request is ignored, and the request's
// identity source is decided as it was before (invariant 13).
func (s *Server) WithAgentTokens(v *agenttoken.Verifier) *Server {
	s.agentTokens = v
	return s
}

// identitySourceFor decides the identity source a decide request is made with.
// It runs after the key is bound to the agent and before any rule is read. With
// no verifier, the request's own claim stands and a token is ignored (logged
// once per process). With a verifier:
//   - a token that verifies, for the agent the request names, makes the source
//     agent-token, which is wardryx's own verification and not the claim;
//   - a token that verifies for another agent is refused (agent_contradicts_token)
//     and an identity_mismatch event is written;
//   - a token that does not verify is refused (agent_token_invalid);
//   - a request claiming agent-token with no token is refused (agent_token_required).
//
// The refusals echo nothing of the request and reach no rule. It returns false
// when it has answered the request.
func (s *Server) identitySourceFor(w http.ResponseWriter, principal Principal, agentID, runID, token, proof, claim string) (string, bool) {
	claimed := policy.IdentitySourceOf(claim)
	if s.agentTokens == nil {
		if token != "" {
			s.agentTokenIgnoredOnce.Do(func() {
				log.Printf("wardryx: a decide request carries agent_token but WARDRYX_AGENT_TOKEN_ISSUER is not set, so the token is ignored and the request's identity_source is taken as claimed (logged once per process)")
			})
		}
		return claimed, true
	}
	if token == "" {
		if claimed == policy.IdentitySourceAgentToken {
			writeError(w, http.StatusForbidden, "agent_token_required")
			return "", false
		}
		return claimed, true
	}
	verified, err := s.agentTokens.Verify(token, time.Now())
	if err != nil {
		// The reason is for the operator's log. The token itself is never logged.
		log.Printf("wardryx: agent token refused on /v1/decide for agent %q: %v", agentID, err)
		writeError(w, http.StatusForbidden, "agent_token_invalid")
		return "", false
	}
	if verified.Subject != agentID {
		s.emit(evIdentityMismatch, event.SeverityHigh, agentTokenAgentID, "", nil, map[string]any{
			"route":             "/v1/decide",
			"asserted_agent_id": agentID,
			"asserted_run_id":   runID,
			"token_subject":     verified.Subject,
			"org":               principal.Org,
			"role":              principal.Role,
			"key_fp":            principal.KeyFP,
		})
		writeError(w, http.StatusForbidden, "agent_contradicts_token")
		return "", false
	}
	// The proof is the holder's, for this token and this door (invariant 13). A
	// token with no proof is refused when proofs are required.
	if err := s.agentTokens.CheckProof(proof, token, verified, time.Now()); err != nil {
		if errors.Is(err, agenttoken.ErrProofRequired) {
			writeError(w, http.StatusForbidden, "agent_token_proof_required")
			return "", false
		}
		log.Printf("wardryx: agent token proof refused on /v1/decide for agent %q: %v", agentID, err)
		writeError(w, http.StatusForbidden, "agent_token_proof_invalid")
		return "", false
	}
	return policy.IdentitySourceAgentToken, true
}
