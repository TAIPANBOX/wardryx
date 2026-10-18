package api

import "github.com/TAIPANBOX/wardryx/internal/approval"

// WithApprovalKeys sets the keys approval tokens are minted and verified with,
// here and in the engine that decides approved allows. It returns the server
// so a caller can set them where the server is built.
func (s *Server) WithApprovalKeys(k approval.Keys) *Server {
	s.approvals = k
	s.engine.WithApprovalKeys(k)
	return s
}
