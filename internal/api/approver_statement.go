package api

import "github.com/TAIPANBOX/wardryx/internal/approverstmt"

// WithApprovers sets the verifier for the approval statements a console signs
// for a person's decision (CLAUDE.md invariant 43). Nil, the default, refuses
// every statement: a request that names one is refused, not recorded as a key.
func (s *Server) WithApprovers(v *approverstmt.Verifier) *Server {
	s.approvers = v
	return s
}
