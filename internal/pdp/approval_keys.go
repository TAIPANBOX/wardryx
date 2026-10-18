package pdp

import "github.com/TAIPANBOX/wardryx/internal/approval"

// WithApprovalKeys sets the keys the engine verifies approval tokens with. It
// returns the engine so a caller can set them where the engine is built.
func (e *Engine) WithApprovalKeys(k approval.Keys) *Engine {
	e.approvals = k
	return e
}
