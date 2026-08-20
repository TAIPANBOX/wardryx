package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/store"
)

// /v1/status exists because /v1/policies answers a narrower question than it
// looks like it does, and the difference is the most damaging thing a posture
// check can get wrong.
//
// /v1/policies lists the STORE's operator-managed rules only. A deployment
// whose rules come from a -policy file sees an empty list there while every one
// of those rules is being enforced on /v1/decide. A console reading only that
// list says "no policies, everything is allowed", which reports enforcement as
// OFF while it is ON. An operator who disproves that warning once stops
// trusting the others beside it.
//
// It was at 60%. This is the case that matters and it was the untested one.

func TestStatusSeparatesFileLoadedRulesFromStoreManagedOnes(t *testing.T) {
	s := newTestServer(t)

	// The fixture server carries one file-loaded policy and an empty store,
	// which is exactly the deployment shape /v1/policies misreports.
	rec := doRequest(t, s.Handler(), http.MethodGet, "/v1/status", viewerKey, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	got := decodeBody[statusDTO](t, rec)

	if got.BasePolicies == 0 {
		t.Error("the file-loaded rules must be counted; reporting zero here is the " +
			"claim that nothing is enforced, on a deployment that is enforcing")
	}
	if got.StorePolicies != 0 {
		t.Errorf("store policies = %d, want 0 on a fresh store", got.StorePolicies)
	}
	if got.EffectivePolicies != got.BasePolicies+got.StorePolicies {
		t.Errorf("effective = %d, want base+store = %d",
			got.EffectivePolicies, got.BasePolicies+got.StorePolicies)
	}
	if got.EffectivePolicies == 0 {
		t.Error("zero effective policies is the ONE reading that means everything is " +
			"allowed, and it must not be produced by a deployment that enforces")
	}
	if got.PolicyVersion == "" {
		t.Error("status must carry the version every decision carries, or the two " +
			"cannot be compared")
	}
}

func TestAPolicyWrittenThroughTheAPIIsAddedToTheFileLoadedOnesNotSubstituted(t *testing.T) {
	s := newTestServer(t)

	before := decodeBody[statusDTO](t,
		doRequest(t, s.Handler(), http.MethodGet, "/v1/status", viewerKey, nil))

	rec := doRequest(t, s.Handler(), http.MethodPut, "/v1/policies/added-by-api", adminKey, map[string]any{
		"target":    "agent://acme.example/ops/*",
		"deny_tool": []string{"shell_exec"},
	})
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("writing a policy: status %d: %s", rec.Code, rec.Body.String())
	}

	after := decodeBody[statusDTO](t,
		doRequest(t, s.Handler(), http.MethodGet, "/v1/status", viewerKey, nil))

	// The property the whole layering exists for: an API write ADDS to the
	// file-loaded base. If base dropped, an operator's own file rules would
	// have been silently deleted by somebody using the API.
	if after.BasePolicies != before.BasePolicies {
		t.Errorf("file-loaded rules went from %d to %d across an API write; an API "+
			"write must never be able to remove a rule loaded from a file",
			before.BasePolicies, after.BasePolicies)
	}
	if after.StorePolicies != before.StorePolicies+1 {
		t.Errorf("store rules went from %d to %d, want one more",
			before.StorePolicies, after.StorePolicies)
	}
	if after.EffectivePolicies != after.BasePolicies+after.StorePolicies {
		t.Errorf("effective %d does not equal base %d plus store %d",
			after.EffectivePolicies, after.BasePolicies, after.StorePolicies)
	}
}

func TestComputePolicySetLayersStoredRulesOnTopOfTheBaseAndLosesNeither(t *testing.T) {
	t.Parallel()

	base := []policy.Policy{
		{Name: "from-file", Target: "agent://acme.example/*", DenyTool: []string{"shell_exec"}},
	}
	st := store.NewMemory()
	if err := st.PutPolicy(context.Background(), "from-store", policy.Policy{
		Name: "from-store", Target: "agent://acme.example/ops/*", MaxSteps: 3,
	}, time.Now()); err != nil {
		t.Fatalf("seed the store: %v", err)
	}

	set, err := ComputePolicySet(context.Background(), st, base)
	if err != nil {
		t.Fatalf("ComputePolicySet: %v", err)
	}

	names := map[string]bool{}
	for _, p := range set.Policies() {
		names[p.Name] = true
	}
	for _, want := range []string{"from-file", "from-store"} {
		if !names[want] {
			t.Errorf("%q is missing from the effective set: %v", want, names)
		}
	}
}

func TestComputePolicySetWithAnEmptyStoreIsStillTheBase(t *testing.T) {
	t.Parallel()

	// The deployment shape that /v1/policies misreports. The effective set must
	// be the file rules, not nothing.
	base := []policy.Policy{
		{Name: "from-file", Target: "agent://acme.example/*", DenyTool: []string{"shell_exec"}},
	}
	set, err := ComputePolicySet(context.Background(), store.NewMemory(), base)
	if err != nil {
		t.Fatalf("ComputePolicySet: %v", err)
	}
	if got := len(set.Policies()); got != 1 {
		t.Errorf("effective set has %d policies, want the one loaded from the file", got)
	}
}
