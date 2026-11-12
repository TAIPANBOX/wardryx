package api

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/approval"
	"github.com/TAIPANBOX/wardryx/internal/approverstmt"
	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/preview"
	"github.com/TAIPANBOX/wardryx/internal/previewseal"
	"github.com/TAIPANBOX/wardryx/internal/store"
)

// What a person deciding a held tool call is shown of its arguments
// (CLAUDE.md invariant 51). wardryx builds the preview from the argument bytes
// it hashes, seals it to the console's preview key, keeps the ciphertext until
// the hold is decided or its time runs out, and records only the preview's
// digest. A decision names the preview the person saw, and a grant that a
// policy says needs one is refused without it. The preview changes no verdict.

// ContextKeyPreview is the key under which a hold's context records its
// preview: the state, and for a sealed one its digest and ruleset. Never the
// preview itself.
const ContextKeyPreview = "preview"

// ContextKeyRequirePreview is set in a hold's context when a matched policy
// sets require_preview.
const ContextKeyRequirePreview = "require_preview"

// The states a hold's preview can be in.
const (
	// PreviewSealed: built, sealed and kept; the console can fetch it.
	PreviewSealed = "sealed"
	// PreviewTruncated: the enforcement point sent no arguments, they were too
	// large, so there is nothing to show.
	PreviewTruncated = "truncated"
	// PreviewNoArguments: the call carried no arguments, so a person sees all
	// there is in its name and target.
	PreviewNoArguments = "no_arguments"
	// PreviewOff: no preview key is configured (WARDRYX_PREVIEW_RECIPIENT).
	PreviewOff = "off"
	// PreviewUnavailable: building or sealing failed. Named, and never a
	// verdict.
	PreviewUnavailable = "unavailable"
)

// What a decision says about the preview, recorded on approval_granted and
// approval_denied as "preview".
const (
	// PreviewSeen: a person's version 2 statement names the preview the hold
	// records.
	PreviewSeen = "seen"
	// PreviewUnseen: the call had a preview state other than seen: a person
	// decided without one (blind), or a key decided.
	PreviewUnseen = "unseen"
	// PreviewNoCall: the hold named no call.
	PreviewNoCall = "no_call"
)

// DefaultPreviewTTL is how long a sealed preview is kept for a hold nobody
// answers. Override with WARDRYX_PREVIEW_TTL.
const DefaultPreviewTTL = 24 * time.Hour

// MaxPreviewTTL and MinPreviewTTL bound WARDRYX_PREVIEW_TTL.
const (
	MaxPreviewTTL = 7 * 24 * time.Hour
	MinPreviewTTL = time.Minute
)

// previewPurgeEvery is how often WatchPreviews removes expired rows. An
// expired row is never served whether or not it has been purged.
const previewPurgeEvery = time.Minute

// ParsePreviewTTL reads WARDRYX_PREVIEW_TTL: unset is the default, anything
// that is not a Go duration between the bounds is an error serve refuses to
// start on.
func ParsePreviewTTL(raw string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return DefaultPreviewTTL, nil
	}
	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil || d < MinPreviewTTL || d > MaxPreviewTTL {
		return 0, fmt.Errorf("WARDRYX_PREVIEW_TTL is a duration from %s to %s, like 24h", MinPreviewTTL, MaxPreviewTTL)
	}
	return d, nil
}

// WithPreview sets the console's preview key and how long a sealed preview is
// kept. A nil recipient, the default, keeps no preview, and every hold of a
// call records its preview as off.
func (s *Server) WithPreview(r *previewseal.Recipient, ttl time.Duration) *Server {
	s.previewRecipient = r
	if ttl > 0 {
		s.previewTTL = ttl
	}
	return s
}

// previewPlan is a hold's preview before the hold is written.
type previewPlan struct {
	state  string
	digest string
	sealed []byte
	suite  string
}

// planPreview builds and seals the preview of a held call. It reads the bytes
// the call's digest is over, tc.Arguments, and nothing else.
func (s *Server) planPreview(tc *pdp.ToolCall, org string) previewPlan {
	switch {
	case tc.ArgumentsTruncated:
		return previewPlan{state: PreviewTruncated}
	case len(tc.Arguments) == 0:
		return previewPlan{state: PreviewNoArguments}
	case s.previewRecipient == nil:
		return previewPlan{state: PreviewOff}
	}
	if _, ok := s.store.(store.PreviewStore); !ok {
		return previewPlan{state: PreviewUnavailable}
	}
	_, canon, err := preview.Build(tc.Arguments)
	if err != nil {
		log.Printf("wardryx: the preview of a held call could not be built: %v", err)
		return previewPlan{state: PreviewUnavailable}
	}
	digest := preview.Digest(canon)
	sealed, err := previewseal.Seal(s.previewRecipient, previewseal.Binding{
		Org: org, ToolCallDigest: tc.Digest(), PreviewDigest: digest, Ruleset: preview.Ruleset,
	}, canon)
	if err != nil {
		log.Printf("wardryx: the preview of a held call could not be sealed: %v", err)
		return previewPlan{state: PreviewUnavailable}
	}
	return previewPlan{state: PreviewSealed, digest: digest, sealed: sealed, suite: s.previewRecipient.Suite()}
}

// contextValue is what the hold's context records of the plan, and what the
// approval_requested record carries: the state, and for a sealed preview its
// digest and ruleset.
func (p previewPlan) contextValue() map[string]any {
	v := map[string]any{"state": p.state}
	if p.state == PreviewSealed {
		v["pvd"] = p.digest
		v["ruleset"] = preview.Ruleset
	}
	return v
}

// keepPreview writes a sealed preview for the hold it was planned for. A hold
// that was already pending (a repeated call of the floor) keeps its own, and
// one whose recorded digest is not this plan's (made under another ruleset)
// gets nothing new. A write that fails is logged and changes nothing else: the
// console then finds no preview and says so.
func (s *Server) keepPreview(ctx context.Context, held store.Approval, org string, p previewPlan) {
	if p.state != PreviewSealed || held.ApprovalID == "" {
		return
	}
	if rec := previewOf(held.Context); rec.state != PreviewSealed || rec.digest != p.digest {
		return
	}
	ps, ok := s.store.(store.PreviewStore)
	if !ok {
		return
	}
	err := ps.PutPreview(ctx, store.Preview{
		ApprovalID: held.ApprovalID, Org: org, Sealed: p.sealed, Digest: p.digest,
		Ruleset: preview.Ruleset, Suite: p.suite, ExpiresAt: time.Now().UTC().Add(s.previewTTL),
	})
	if err != nil {
		log.Printf("wardryx: the sealed preview of approval %s was not kept: %v", held.ApprovalID, err)
	}
}

// previewRecord is a hold's recorded preview.
type previewRecord struct {
	state   string
	digest  string
	ruleset string
}

// previewOf reads ContextKeyPreview. A hold made before previews existed has
// none, and reads as the empty state.
func previewOf(ctx map[string]any) previewRecord {
	m, _ := ctx[ContextKeyPreview].(map[string]any)
	if m == nil {
		return previewRecord{}
	}
	state, _ := m["state"].(string)
	digest, _ := m["pvd"].(string)
	ruleset, _ := m["ruleset"].(string)
	return previewRecord{state: state, digest: digest, ruleset: ruleset}
}

// toolCallDigestOf reads the digest of the call a hold names, "" for none.
func toolCallDigestOf(ctx map[string]any) string {
	m, _ := ctx[approval.ContextKeyToolCall].(map[string]any)
	if m == nil {
		return ""
	}
	d, _ := m[approval.ContextKeyDigest].(string)
	return d
}

// The refusals of a decision for its preview.
const (
	refusalStatementMismatch = "approver_statement_mismatch"
	refusalPreviewRequired   = "preview_required"
)

// previewAtDecide checks a decision against the hold's preview and says what
// the record will carry: seen, unseen or no_call. A refusal is returned
// before anything is decided.
//
// A person's version 2 statement must name the hold's call (tcd, or none for a
// hold with no call) and the hold's preview (pvd when one was sealed, none
// otherwise). A version 1 statement names neither, so it is refused on a hold
// whose preview was sealed: the person could have been shown it, and the
// record must say whether they were. A grant of a hold a policy marked
// require_preview needs a person who saw the preview, or a call that had no
// arguments to see.
func previewAtDecide(ctx map[string]any, decision string, stmt approverstmt.Statement, person bool) (string, string) {
	tcd := toolCallDigestOf(ctx)
	rec := previewOf(ctx)
	outcome := PreviewUnseen
	if tcd == "" {
		outcome = PreviewNoCall
	}
	switch {
	case person && stmt.Version == 2:
		wantTCD := tcd
		if wantTCD == "" {
			wantTCD = approverstmt.None
		}
		if stmt.ToolCallDigest != wantTCD {
			return "", refusalStatementMismatch
		}
		if rec.state == PreviewSealed {
			if stmt.PreviewDigest != rec.digest {
				return "", refusalStatementMismatch
			}
			outcome = PreviewSeen
		} else if stmt.PreviewDigest != approverstmt.None {
			return "", refusalStatementMismatch
		}
	case person:
		if rec.state == PreviewSealed {
			return "", refusalStatementMismatch
		}
	}
	if decision == "grant" && ctx[ContextKeyRequirePreview] == true {
		nothingToSee := person && rec.state == PreviewNoArguments
		if outcome != PreviewSeen && !nothingToSee {
			return "", refusalPreviewRequired
		}
	}
	return outcome, ""
}

// --- GET /v1/approvals/{id}/preview ---

type approvalPreviewDTO struct {
	ApprovalID     string `json:"approval_id"`
	State          string `json:"state"`
	ToolCallDigest string `json:"tool_call_digest,omitempty"`
	Digest         string `json:"pvd,omitempty"`
	Ruleset        string `json:"ruleset,omitempty"`
	Suite          string `json:"suite,omitempty"`
	Sealed         string `json:"sealed,omitempty"`
	ExpiresAt      string `json:"expires_at,omitempty"`
}

// handleApprovalPreview hands the console the sealed preview of a pending hold
// of the caller's org. It is ciphertext: only the console's preview key opens
// it, so an admin key reads nothing it could not before. The answer is never
// cached. A hold with no sealed preview answers its state; a sealed one that
// was decided, expired or not kept answers 410.
func (s *Server) handleApprovalPreview(w http.ResponseWriter, r *http.Request, principal Principal) {
	w.Header().Set("Cache-Control", "no-store")
	id := r.PathValue("id")
	existing, err := s.store.GetApproval(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "approval not found")
		return
	case err != nil:
		writeInternalError(w, "reading the approval", err)
		return
	}
	if org, _ := existing.Context["org"].(string); org != principal.Org && !s.allow.acrossOrgs(principal) {
		writeError(w, http.StatusNotFound, "approval not found")
		return
	}
	rec := previewOf(existing.Context)
	if rec.state == "" {
		writeError(w, http.StatusNotFound, "this approval records no preview")
		return
	}
	dto := approvalPreviewDTO{ApprovalID: existing.ApprovalID, State: rec.state, ToolCallDigest: toolCallDigestOf(existing.Context)}
	if rec.state != PreviewSealed {
		writeJSON(w, http.StatusOK, dto)
		return
	}
	dto.Digest, dto.Ruleset = rec.digest, rec.ruleset
	if !existing.Pending() {
		writeError(w, http.StatusGone, "the approval is decided and its preview was deleted")
		return
	}
	ps, ok := s.store.(store.PreviewStore)
	if !ok {
		writeError(w, http.StatusGone, "the preview has expired or was not kept")
		return
	}
	kept, err := ps.GetPreview(r.Context(), id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusGone, "the preview has expired or was not kept")
		return
	case err != nil:
		writeInternalError(w, "reading the preview", err)
		return
	}
	if kept.Digest != rec.digest {
		log.Printf("wardryx: the kept preview of approval %s is not the one its hold records; not served", id)
		writeError(w, http.StatusGone, "the preview has expired or was not kept")
		return
	}
	dto.Suite = kept.Suite
	dto.Sealed = base64.StdEncoding.EncodeToString(kept.Sealed)
	dto.ExpiresAt = kept.ExpiresAt.UTC().Format(time.RFC3339)
	writeJSON(w, http.StatusOK, dto)
}

// WatchPreviews removes expired sealed previews once a minute until ctx ends.
// An expired preview is never served whether or not this has run; this only
// keeps the table from holding ciphertext past its time.
func (s *Server) WatchPreviews(ctx context.Context) {
	ps, ok := s.store.(store.PreviewStore)
	if !ok {
		return
	}
	t := time.NewTicker(previewPurgeEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = ps.PurgePreviews(ctx)
		}
	}
}
