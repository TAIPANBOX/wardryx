package api

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// These tests hold features/strict-policy-write.feature: a policy write refuses
// a field it does not know. Before this change the PUT body was decoded with
// json.Decoder's default, which drops an unknown key without a word. A rule
// spelled wrong (deny_tolls for deny_tool) was stored without that rule, the
// PUT answered 200, and the call the rule was meant to deny was allowed.

// The scenario "A PUT with a misspelled rule is refused, and the rule is not
// silently dropped". Measured on 84c0779 before the change: this PUT answered
// 200. After the change it answers 400 that names the field and does not echo
// the value, and nothing is stored.
func TestAPutWithAMisspelledRuleIsRefusedAndNothingIsStored(t *testing.T) {
	srv := newTestServer(t)
	const path = "/v1/policies/treasury-no-wires"
	body := `{"name":"treasury-no-wires","target":"agent://acme.example/treasury/*","deny_tolls":["send_wire_transfer"]}`
	rec := doRaw(t, srv.Handler(), http.MethodPut, path, adminKey, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT status = %d, body = %s; want 400: a misspelled rule must not be stored with the rule silently gone", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "deny_tolls") {
		t.Errorf("the 400 does not name the unknown field: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "send_wire_transfer") {
		t.Errorf("the 400 echoes a value of the refused body: %s", rec.Body.String())
	}
	if got := doRequest(t, srv.Handler(), http.MethodGet, path, adminKey, nil).Code; got != http.StatusNotFound {
		t.Fatalf("GET after the refused PUT = %d, want 404: a refused body stores nothing", got)
	}
}

// The scenario "A policy read by GET can be written back unchanged". id and
// updated_at are what GET emits beyond the policy's own fields. They are
// accepted on input and ignored, so a copy of a GET body is a valid PUT body,
// and the policy it writes is the policy it read.
func TestAGetBodyWrittenBackUnchangedIsAccepted(t *testing.T) {
	srv := newTestServer(t)
	const path = "/v1/policies/treasury-limits"
	put := `{"name":"treasury-limits","target":"agent://acme.example/treasury/*","deny_tool":["send_wire_transfer"],"require_human_above_usd":250,"max_steps":9}`
	if rec := doRaw(t, srv.Handler(), http.MethodPut, path, adminKey, put); rec.Code != http.StatusOK {
		t.Fatalf("first PUT status = %d, body = %s; want 200", rec.Code, rec.Body.String())
	}
	first := doRequest(t, srv.Handler(), http.MethodGet, path, adminKey, nil)
	if first.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body = %s", first.Code, first.Body.String())
	}
	if rec := doRaw(t, srv.Handler(), http.MethodPut, path, adminKey, first.Body.String()); rec.Code != http.StatusOK {
		t.Fatalf("PUT of a GET body written back unchanged: status = %d, body = %s; want 200: id and updated_at are read-only and must be accepted", rec.Code, rec.Body.String())
	}
	second := doRequest(t, srv.Handler(), http.MethodGet, path, adminKey, nil)
	a := decodeBody[map[string]any](t, first)
	b := decodeBody[map[string]any](t, second)
	delete(a, "updated_at")
	delete(b, "updated_at")
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("the policy after the write-back differs from the one read:\n before: %v\n after:  %v", a, b)
	}
}

// The scenario "The read-only fields of a PUT body do not choose what is
// stored". The id in the body does not move the policy (the URL names it), and
// the updated_at in the body is not stored (the server stamps the write).
func TestTheReadOnlyFieldsOfAPutBodyAreIgnored(t *testing.T) {
	srv := newTestServer(t)
	const path = "/v1/policies/treasury-ids"
	body := `{"id":"someone-else","updated_at":"1999-01-01T00:00:00Z","name":"treasury-ids","target":"agent://acme.example/treasury/*","deny_tool":["send_wire_transfer"]}`
	if rec := doRaw(t, srv.Handler(), http.MethodPut, path, adminKey, body); rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, body = %s; want 200", rec.Code, rec.Body.String())
	}
	got := decodeBody[map[string]any](t, doRequest(t, srv.Handler(), http.MethodGet, path, adminKey, nil))
	if got["id"] != "treasury-ids" {
		t.Errorf("stored id = %v, want treasury-ids: the URL names the policy, not the body", got["id"])
	}
	if got["updated_at"] == "1999-01-01T00:00:00Z" {
		t.Errorf("the body's updated_at was stored: %v", got["updated_at"])
	}
	if code := doRequest(t, srv.Handler(), http.MethodGet, "/v1/policies/someone-else", adminKey, nil).Code; code != http.StatusNotFound {
		t.Errorf("GET /v1/policies/someone-else = %d, want 404: the body's id stored a policy under another name", code)
	}
}

// The scenario "An unknown key inside a hold rule is refused on a PUT too". The
// hold rule has its own decoder, which already refused its unknown keys; this
// holds that claim on the PUT path as well.
func TestAnUnknownKeyInsideAHoldRuleIsRefusedOnPut(t *testing.T) {
	srv := newTestServer(t)
	const path = "/v1/policies/treasury-hold"
	body := `{"name":"treasury-hold","target":"agent://acme.example/treasury/*","hold_if_signal":{"name":"action.risk_class","values":["destructive"],"min_probability":0.8,"on_match":"deny"}}`
	rec := doRaw(t, srv.Handler(), http.MethodPut, path, adminKey, body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT status = %d, body = %s; want 400: a hold rule with a deny-shaped key must be refused", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "on_match") {
		t.Errorf("the 400 does not name the unknown key: %s", rec.Body.String())
	}
	if got := doRequest(t, srv.Handler(), http.MethodGet, path, adminKey, nil).Code; got != http.StatusNotFound {
		t.Fatalf("GET after the refused PUT = %d, want 404", got)
	}
}
