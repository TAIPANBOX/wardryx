package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/pdp"
	"github.com/TAIPANBOX/wardryx/internal/policy"
	"github.com/TAIPANBOX/wardryx/internal/store"
)

// Finding F-023 of the 2026-10-17 review: the bearer key store was a map keyed
// by the raw configured key, and authenticate looked the presented bearer up in
// it. These tests hold the store to what the invariant asks: no stored key is
// a raw secret, every role still authenticates with its own key, and a key that
// is almost right is refused.

// One bearer per role. Long enough that a one-byte change is an easy near miss.
const (
	storeAdminSecret    = "bearer-secret-admin-7f3a9c"
	storeViewerSecret   = "bearer-secret-viewer-21be08"
	storePEPSecret      = "bearer-secret-pep-c04d55"
	storeCrossOrgSecret = "bearer-secret-cross-9e6a71"
)

func storeKeySpec() string {
	return storeAdminSecret + ":acme:admin," +
		storeViewerSecret + ":acme:viewer," +
		storePEPSecret + ":acme:pep," +
		storeCrossOrgSecret + ":globex:cross-org-admin"
}

// storeServer builds the server the way serve does: ParseKeys, then New.
func storeServer(t *testing.T, spec string) *Server {
	t.Helper()
	keys, warnings := ParseKeys(spec, false)
	if len(warnings) != 0 {
		t.Fatalf("ParseKeys warned: %v", warnings)
	}
	set, err := policy.Compile(nil)
	if err != nil {
		t.Fatalf("policy.Compile: %v", err)
	}
	return New(pdp.New(set, []byte(testHMAC)), store.NewMemory(), nil, nil,
		keys, []byte(testHMAC), false, nil)
}

func TestTheKeyStoreHoldsNoRawSecret(t *testing.T) {
	srv := storeServer(t, storeKeySpec())
	secrets := []string{storeAdminSecret, storeViewerSecret, storePEPSecret, storeCrossOrgSecret}
	if len(srv.keys) != len(secrets) {
		t.Fatalf("the key store holds %d keys, want %d", len(srv.keys), len(secrets))
	}
	for stored := range srv.keys {
		for _, secret := range secrets {
			if stored == secret {
				t.Fatalf("the key store holds a configured bearer in the clear (%d bytes): "+
					"a key must be stored under its digest, not its value", len(secret))
			}
		}
	}
}

func TestEveryRoleStillAuthenticatesWithItsKey(t *testing.T) {
	srv := storeServer(t, storeKeySpec())
	h := srv.Handler()

	// GET /v1/status is bearer-only: every role may read it.
	for name, secret := range map[string]string{
		"admin":           storeAdminSecret,
		"viewer":          storeViewerSecret,
		"pep":             storePEPSecret,
		"cross-org-admin": storeCrossOrgSecret,
	} {
		if rec := doRequest(t, h, http.MethodGet, "/v1/status", secret, nil); rec.Code != http.StatusOK {
			t.Errorf("%s: GET /v1/status = %d, want 200: %s", name, rec.Code, rec.Body)
		}
	}

	// GET /v1/policies is admin-only. An admin and a cross-org admin pass the
	// role check; a viewer and an enforcement point authenticate and are refused
	// as not admin, which is a 403, never a 401.
	for _, tc := range []struct {
		name   string
		secret string
		want   int
	}{
		{"admin", storeAdminSecret, http.StatusOK},
		{"viewer", storeViewerSecret, http.StatusForbidden},
		{"pep", storePEPSecret, http.StatusForbidden},
		{"cross-org-admin", storeCrossOrgSecret, http.StatusOK},
	} {
		if rec := doRequest(t, h, http.MethodGet, "/v1/policies", tc.secret, nil); rec.Code != tc.want {
			t.Errorf("%s: GET /v1/policies = %d, want %d: %s", tc.name, rec.Code, tc.want, rec.Body)
		}
	}
}

func TestANearMissKeyIsRefusedWith401(t *testing.T) {
	srv := storeServer(t, storeKeySpec())
	h := srv.Handler()

	// The exact key goes first, so every refusal below is about the presented
	// bytes and not about a server that refuses everything.
	if rec := doRequest(t, h, http.MethodGet, "/v1/status", storeAdminSecret, nil); rec.Code != http.StatusOK {
		t.Fatalf("the exact admin key = %d, want 200: %s", rec.Code, rec.Body)
	}

	last := len(storeAdminSecret) - 1
	nearMiss := map[string]string{
		"one byte off at the end":        storeAdminSecret[:last] + "x",
		"one byte off at the start":      "x" + storeAdminSecret[1:],
		"the same prefix, shorter":       storeAdminSecret[:last-2],
		"the same prefix, longer":        storeAdminSecret + "0",
		"the prefix alone, three bytes":  storeAdminSecret[:3],
		"upper case of the whole secret": strings.ToUpper(storeAdminSecret),
		"another role's key, one byte off": storeViewerSecret[:len(storeViewerSecret)-1] + "x",
	}
	for name, presented := range nearMiss {
		if rec := doRequest(t, h, http.MethodGet, "/v1/status", presented, nil); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: GET /v1/status = %d, want 401", name, rec.Code)
		}
	}
}
