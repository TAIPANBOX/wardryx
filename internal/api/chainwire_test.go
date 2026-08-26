package api

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/store"
)

// Found by a planted mutant, not by review. Hardcoding `ChainProven: true` in
// handleDecide survived the whole suite: every existing API test either sends
// no chain or uses a policy with no chain rule, so nothing observed the field
// at all.
//
// That is the failure that looks exactly like the feature working. The rule is
// configured, the policy is loaded, the decision comes back Allow, and the
// reason it came back Allow is that the HTTP layer told the PDP a proof was
// verified when nobody verified anything.

func chainServer(t *testing.T) *Server {
	t.Helper()
	set, err := policy.Compile([]policy.Policy{{
		Name:                "delegation-must-be-proved",
		Target:              "agent://acme.example/*",
		DenyIfChainUnproven: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]Principal{adminKey: {Org: "acme", Role: RoleAdmin}}
	return New(pdp.New(set, []byte(testHMAC)), store.NewMemory(), nil, nil,
		keys, []byte(testHMAC), false, set.Policies())
}

func decisionFor(t *testing.T, srv *Server, dto decideRequestDTO) decideResponseDTO {
	t.Helper()
	rec := doRequest(t, srv.Handler(), http.MethodPost, "/v1/decide", adminKey, dto)
	if rec.Code != http.StatusOK {
		t.Fatalf("decide returned %d: %s", rec.Code, rec.Body)
	}
	var out decideResponseDTO
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTheWireCarriesWhetherAnybodyVerifiedTheProof(t *testing.T) {
	srv := chainServer(t)
	chain := []string{"user://acme.example/alice", "agent://acme.example/bot"}

	unproven := decisionFor(t, srv, decideRequestDTO{
		AgentID: "agent://acme.example/bot", RunID: "r1", OnBehalfOf: chain,
	})
	if unproven.Decision != "deny" {
		t.Fatalf("a caller that said nothing was treated as having verified: %+v", unproven)
	}

	proven := decisionFor(t, srv, decideRequestDTO{
		AgentID: "agent://acme.example/bot", RunID: "r1", OnBehalfOf: chain,
		ChainProven: true,
	})
	if proven.Decision != "allow" {
		t.Fatalf("a caller that verified was refused: %+v", proven)
	}
}

func TestAnAbsentChainProvenMeansNotVerified(t *testing.T) {
	// The half that matters for a fleet mid-upgrade. Every enforcement point
	// that has not been taught to verify keeps sending what it always sent,
	// and a default of true would make all of them look like they verify. The
	// safe default is the one that refuses.
	srv := chainServer(t)
	var dto decideRequestDTO
	raw := []byte(`{"agent_id":"agent://acme.example/bot","run_id":"r1",` +
		`"on_behalf_of":["user://acme.example/alice","agent://acme.example/bot"]}`)
	if err := json.Unmarshal(raw, &dto); err != nil {
		t.Fatal(err)
	}
	if dto.ChainProven {
		t.Fatal("a request that never mentions chain_proven decoded as verified")
	}
	if got := decisionFor(t, srv, dto); got.Decision != "deny" {
		t.Fatalf("%+v", got)
	}
}
