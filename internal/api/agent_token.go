package api

import "github.com/TAIPANBOX/wardryx/internal/agenttoken"

// WithAgentTokens sets the verifier for an agent's own token. Nil, the default,
// means the token is not verified and is ignored. Scaffold: stored, not used.
func (s *Server) WithAgentTokens(v *agenttoken.Verifier) *Server {
	s.agentTokens = v
	return s
}
