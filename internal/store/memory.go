package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Memory is an in-process Store: the default when -db/WARDRYX_DB is unset.
// State does not survive process restart, so it is only meaningful for the
// lifetime of one `wardryx serve` run. Safe for concurrent use.
type Memory struct {
	mu    sync.Mutex
	byID  map[string]Approval
	order []string // insertion order, for a deterministic ListApprovals
}

// NewMemory returns an empty in-memory Store.
func NewMemory() *Memory {
	return &Memory{byID: make(map[string]Approval)}
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

func (m *Memory) GetApproval(_ context.Context, id string) (Approval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.byID[id]
	if !ok {
		return Approval{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return a, nil
}

func (m *Memory) ListApprovals(_ context.Context) ([]Approval, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Approval, 0, len(m.order))
	for _, id := range m.order {
		out = append(out, m.byID[id])
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
	return a, nil
}

func (m *Memory) Close() error { return nil }
