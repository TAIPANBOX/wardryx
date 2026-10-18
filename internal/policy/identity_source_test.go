package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

// require_identity_source is a list of the identity sources a policy accepts.
// These tests hold how it is read from a file: a value that is not one of the
// three sources is refused at load, and the order of the list does not change
// the PolicyVersion every decision names.

const identityHead = "name: support\ntarget: \"agent://acme.example/support/*\"\n"

func TestAnUnlistedIdentitySourceIsRefusedAtLoad(t *testing.T) {
	_, err := loadDoc(t, "typo.yaml", identityHead+"require_identity_source: [agnet-token]\n")
	if err == nil {
		t.Fatal("a require_identity_source naming a value that is not an identity source loaded; a typo would silently accept nothing")
	}
	if !strings.Contains(err.Error(), "require_identity_source") || !strings.Contains(err.Error(), "agnet-token") {
		t.Fatalf("the refusal does not name the field and the value: %v", err)
	}
}

func TestEveryListedIdentitySourceLoads(t *testing.T) {
	for _, doc := range []string{
		identityHead + "require_identity_source: [agent-token]\n",
		identityHead + "require_identity_source: [agent-token, client-key]\n",
		identityHead + "require_identity_source: [none]\n",
	} {
		if _, err := loadDoc(t, "ok.yaml", doc); err != nil {
			t.Fatalf("a valid require_identity_source did not load:\n%s\n%v", doc, err)
		}
	}
}

func TestTheOrderOfTheSourceListDoesNotChangeThePolicyVersion(t *testing.T) {
	a, err := loadDoc(t, "a.yaml", identityHead+"require_identity_source: [client-key, agent-token]\n")
	if err != nil {
		t.Fatalf("load a: %v", err)
	}
	b, err := loadDoc(t, "b.yaml", identityHead+"require_identity_source: [agent-token, client-key]\n")
	if err != nil {
		t.Fatalf("load b: %v", err)
	}
	if a.Version() != b.Version() {
		t.Fatalf("the same two sources in another order give another version: %s vs %s", a.Version(), b.Version())
	}
}

func TestAPolicyWithoutTheRequirementKeepsItsVersion(t *testing.T) {
	plain, err := loadDoc(t, "plain.yaml", identityHead)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// The field is absent from the marshalled policy, so the digest of a policy
	// that never mentions it is what it was before the field existed.
	out, err := json.Marshal(plain.Policies())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(out), "require_identity_source") {
		t.Fatal("a policy that sets no requirement marshals the field, which would change its PolicyVersion")
	}
}
