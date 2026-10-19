package api

import "github.com/TAIPANBOX/wardryx/internal/approverstmt"

// WithApprovers sets the verifier for the approval statements a console signs
// for a person's decision (CLAUDE.md invariant 43). Nil, the default, refuses
// every statement: a request that names one is refused, not recorded as a key.
func (s *Server) WithApprovers(v *approverstmt.Verifier) *Server {
	s.approvers = v
	return s
}

// WithAllowKeyApprovals sets whether a decision made by a bearer key, with no
// approver statement, is accepted while a console key set is configured
// (CLAUDE.md invariant 43). False, the default, refuses it with 403
// approver_statement_required; with no key set it changes nothing.
func (s *Server) WithAllowKeyApprovals(allow bool) *Server {
	s.allowKeyApprovals = allow
	return s
}
