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
}

// NewMemory returns an empty in-memory Store.
func NewMemory() *Memory {
	return &Memory{
		byID:       make(map[string]Approval),
		redeemed:   make(map[string]time.Time),
		policyByID: make(map[string]PolicyRecord),
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

func (m *Memory) DecideApproval(_ context.Context, id, decision, decidedBy string, decidedAt time.Time) (Approval, error) {
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
	a.DecidedAt = decidedAt
	m.byID[id] = a
	return copyOut(a)
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
