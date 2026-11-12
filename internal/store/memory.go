package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// Memory is an in-process Store: the default when -db/WARDRYX_DB is unset.
// State does not survive process restart, so it is only meaningful for the
// lifetime of one `wardryx serve` run. Safe for concurrent use.
//
// Because redeemed lives only in this process's memory, WARDRYX_APPROVAL_
// SINGLE_USE enforced against a Memory store only holds within one process:
// it gives no cross-instance guarantee behind a load balancer. cmd/wardryx
// warns about exactly this at startup. Policies stored here are equally
// process-local: an API-managed policy written to a Memory store does not
// survive a restart, unlike the file-based -policy path -- cmd/wardryx
// warns about this too (see runServe).
type Memory struct {
	mu         sync.Mutex
	byID       map[string]Approval
	order      []string             // insertion order, for a deterministic ListApprovals
	redeemed   map[string]time.Time // TryRedeem's claimed keys, by approval.RedemptionKey
	policyByID map[string]PolicyRecord
	// pendingCall maps a call to the approval id CreateApprovalOnce wrote for it.
	// An entry whose approval has been decided no longer counts, the way a decided
	// row leaves the partial index in Postgres, and is overwritten by the next one.
	pendingCall map[pendingCallKey]string
	// previews are the sealed previews by approval id (invariant 51).
	previews map[string]Preview
	// now is the clock a preview's expiry is read against; time.Now unless a
	// test sets it.
	now func() time.Time
}

// pendingCallKey is what makes two holds the same call: the agent, the run and the
// key CreateApprovalOnce is given. Postgres's partial unique index is on these
// three columns.
type pendingCallKey struct{ agent, run, key string }

// NewMemory returns an empty in-memory Store.
func NewMemory() *Memory {
	return &Memory{
		byID:        make(map[string]Approval),
		redeemed:    make(map[string]time.Time),
		policyByID:  make(map[string]PolicyRecord),
		pendingCall: make(map[pendingCallKey]string),
		previews:    make(map[string]Preview),
		now:         time.Now,
	}
}

// deepCopyContext round-trips a.Context through JSON, the same
// serialization Postgres applies via the jsonb column. This keeps Memory
// and Postgres behaviorally identical -- e.g. Context["tool_names"] decodes
// as []any on both backends, never []string on one and []any on the
// other -- and it protects the store from a caller mutating the map it
// passed to CreateApproval after the call returns.
func deepCopyContext(in map[string]any) (map[string]any, error) {
	if in == nil {
		return map[string]any{}, nil
	}
	b, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("store: marshal context: %w", err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("store: unmarshal context: %w", err)
	}
	return out, nil
}

func (m *Memory) CreateApproval(_ context.Context, a Approval) error {
	ctxCopy, err := deepCopyContext(a.Context)
	if err != nil {
		return err
	}
	a.Context = ctxCopy

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.byID[a.ApprovalID]; exists {
		return fmt.Errorf("store: approval %q already exists", a.ApprovalID)
	}
	m.byID[a.ApprovalID] = a
	m.order = append(m.order, a.ApprovalID)
	return nil
}

// CreateApprovalOnce writes a unless the same call is pending or the agent is at
// limit, as Store documents. The mutex makes the check and the write one step, so
// here the limit is exact; across Postgres connections it is not (see Postgres).
func (m *Memory) CreateApprovalOnce(_ context.Context, a Approval, key string, limit int) (Approval, PendingOutcome, error) {
	ctxCopy, err := deepCopyContext(a.Context)
	if err != nil {
		return Approval{}, PendingCreated, err
	}
	a.Context = ctxCopy

	m.mu.Lock()
	defer m.mu.Unlock()
	call := pendingCallKey{a.AgentID, a.RunID, key}
	if id, ok := m.pendingCall[call]; ok {
		if existing := m.byID[id]; existing.Pending() {
			out, err := copyOut(existing)
			return out, PendingExisting, err
		}
	}
	org, _ := a.Context["org"].(string)
	waiting := 0
	for _, other := range m.byID {
		if otherOrg, _ := other.Context["org"].(string); other.Pending() && other.AgentID == a.AgentID && otherOrg == org {
			waiting++
		}
	}
	if waiting >= limit {
		return Approval{}, PendingQueueFull, nil
	}
	if _, exists := m.byID[a.ApprovalID]; exists {
		return Approval{}, PendingCreated, fmt.Errorf("store: approval %q already exists", a.ApprovalID)
	}
	m.byID[a.ApprovalID] = a
	m.order = append(m.order, a.ApprovalID)
	m.pendingCall[call] = a.ApprovalID
	out, err := copyOut(a)
	return out, PendingCreated, err
}

// copyOut is deepCopyContext on the way OUT, and it exists because a struct
// copy is not a copy of what the struct points at. Approval.Context is a map,
// so returning the stored value by value hands the caller the store's own map:
// they hold a live reference into a governance record, and an edit made for
// their own reasons rewrites it with nothing anywhere seeing a write.
//
// The write path had this from the start. The read path did not, which also
// made the two backends disagree: Postgres reconstructs from rows on every
// read and cannot alias, so the same code against the same data behaved
// differently depending on which store was configured. That is precisely what
// deepCopyContext's own comment says it exists to prevent.
func copyOut(a Approval) (Approval, error) {
	c, err := deepCopyContext(a.Context)
	if err != nil {
		return Approval{}, err
	}
	a.Context = c
	return a, nil
}

// copyPolicyOut is the same for a policy's slice fields. A struct copy copies
// the slice HEADER, so both sides share the array underneath and an index
// write reaches the store: a caller could disarm a deny list by editing what
// they were handed.
func copyPolicyOut(r PolicyRecord) (PolicyRecord, error) {
	p, err := deepCopyPolicy(r.Policy)
	if err != nil {
		return PolicyRecord{}, err
	}
	r.Policy = p
	return r, nil
}

func (m *Memory) GetApproval(_ context.Context, id string) (Approval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.byID[id]
	if !ok {
		return Approval{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return copyOut(a)
}

func (m *Memory) ListApprovals(_ context.Context) ([]Approval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Approval, 0, len(m.order))
	for _, id := range m.order {
		a, err := copyOut(m.byID[id])
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].RequestedAt.Before(out[j].RequestedAt)
	})
	return out, nil
}

func (m *Memory) ListPendingApprovals(_ context.Context) ([]Approval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Approval, 0, len(m.order))
	for _, id := range m.order {
		if !m.byID[id].Pending() {
			continue
		}
		a, err := copyOut(m.byID[id])
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].RequestedAt.Before(out[j].RequestedAt)
	})
	return out, nil
}

func (m *Memory) DecideApproval(_ context.Context, id, decision, decidedBy, label string, decidedAt time.Time) (Approval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.byID[id]
	if !ok {
		return Approval{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	if !a.Pending() {
		return Approval{}, fmt.Errorf("%w: %s", ErrAlreadyDecided, id)
	}
	a.Decision = decision
	a.DecidedBy = decidedBy
	a.DecidedByLabel = label
	a.DecidedAt = decidedAt
	m.byID[id] = a
	// Under the same lock as the decision, as Postgres does it in one
	// transaction (invariant 51).
	delete(m.previews, id)
	return copyOut(a)
}

// PutPreview keeps a copy of pv unless its approval already has one.
func (m *Memory) PutPreview(_ context.Context, pv Preview) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.previews[pv.ApprovalID]; ok {
		return nil
	}
	m.previews[pv.ApprovalID] = copyPreviewOut(pv)
	return nil
}

// GetPreview returns a copy of a preview that has not expired.
func (m *Memory) GetPreview(_ context.Context, id string) (Preview, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pv, ok := m.previews[id]
	if !ok || !pv.ExpiresAt.After(m.now()) {
		return Preview{}, fmt.Errorf("%w: preview %s", ErrNotFound, id)
	}
	return copyPreviewOut(pv), nil
}

// PurgePreviews drops the expired previews.
func (m *Memory) PurgePreviews(_ context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	now := m.now()
	for id, pv := range m.previews {
		if !pv.ExpiresAt.After(now) {
			delete(m.previews, id)
			n++
		}
	}
	return n, nil
}

// SetClock sets the clock a preview's expiry is read against. For tests.
func (m *Memory) SetClock(now func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = now
}

// copyPreviewOut is a Preview that shares no memory with the one given.
func copyPreviewOut(pv Preview) Preview {
	pv.Sealed = append([]byte(nil), pv.Sealed...)
	return pv
}

func (m *Memory) TryRedeem(_ context.Context, key string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, claimed := m.redeemed[key]; claimed {
		return false, nil
	}
	m.redeemed[key] = time.Now().UTC()
	return true, nil
}

func (m *Memory) Close() error { return nil }

// Ping always answers: the in-memory store is this process, and a process
// that can run this method is reachable by definition.
func (m *Memory) Ping(_ context.Context) error { return nil }

// deepCopyPolicy round-trips p through JSON for the same reason
// deepCopyContext does: keep Memory and Postgres behaviorally identical,
// and protect the store from a caller mutating a policy.Policy's slice
// fields (DenyTool, AllowDomains) after PutPolicy returns.
func deepCopyPolicy(p policy.Policy) (policy.Policy, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return policy.Policy{}, fmt.Errorf("store: marshal policy: %w", err)
	}
	var out policy.Policy
	if err := json.Unmarshal(b, &out); err != nil {
		return policy.Policy{}, fmt.Errorf("store: unmarshal policy: %w", err)
	}
	return out, nil
}

func (m *Memory) PutPolicy(_ context.Context, id string, p policy.Policy, updatedAt time.Time) error {
	pCopy, err := deepCopyPolicy(p)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policyByID[id] = PolicyRecord{ID: id, Policy: pCopy, UpdatedAt: updatedAt}
	return nil
}

func (m *Memory) GetPolicy(_ context.Context, id string) (PolicyRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.policyByID[id]
	if !ok {
		return PolicyRecord{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return copyPolicyOut(r)
}

func (m *Memory) ListPolicies(_ context.Context) ([]PolicyRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, 0, len(m.policyByID))
	for id := range m.policyByID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]PolicyRecord, 0, len(ids))
	for _, id := range ids {
		r, err := copyPolicyOut(m.policyByID[id])
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (m *Memory) DeletePolicy(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.policyByID[id]; !ok {
		return fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	delete(m.policyByID, id)
	return nil
}
