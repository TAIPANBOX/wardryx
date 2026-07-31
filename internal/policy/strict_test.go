package policy

import "testing"

// A misspelled policy field must be a hard error, not a silently dropped rule.
//
// This is the most dangerous shape of mistake this package can make. A policy
// with `deny_tools` instead of `deny_tool` parses, compiles, matches its
// agents, and denies nothing, while the decision reads "allowed: request
// satisfies all matched policy rules". The operator sees a loaded policy, a
// matched agent and an allow, and concludes the guardrail works. An enforcement
// control that forgets is worse than no control, because it is believed.
func TestYAMLTypoInFieldNameIsAnError(t *testing.T) {
	src := []byte("name: typo\ntarget: \"agent://x.example/**\"\ndeny_tools:\n  - shell_exec\n")
	if _, err := decodeYAML(src); err == nil {
		t.Fatal("a policy with deny_tools (a typo for deny_tool) loaded cleanly. " +
			"It matches agents and denies nothing, and the operator is told the " +
			"request satisfies all matched rules.")
	}
}

func TestJSONTypoInFieldNameIsAnError(t *testing.T) {
	src := []byte(`{"name":"typo","target":"agent://x.example/**","deny_tools":["shell_exec"]}`)
	if _, err := decodeJSON(src); err == nil {
		t.Fatal("a JSON policy with an unknown field loaded cleanly")
	}
}

func TestUnknownFieldInsideAListIsAnError(t *testing.T) {
	// The list shape is right and one element is not. Falling through to the
	// single-document decode here would report "cannot unmarshal !!seq", which
	// hides the real problem behind a type error.
	src := []byte("- name: a\n  target: \"agent://x.example/**\"\n- name: b\n  target: \"agent://y.example/**\"\n  max_step: 3\n")
	_, err := decodeYAML(src)
	if err == nil {
		t.Fatal("a list policy with an unknown field in one element loaded cleanly")
	}
	if !isUnknownFieldError(err) {
		t.Errorf("the error should name the unknown field, got: %v", err)
	}
}

func TestKnownFieldsStillLoad(t *testing.T) {
	// The other half: strictness must not reject anything legitimate.
	src := []byte("name: ok\ntarget: \"agent://x.example/**\"\ndeny_tool:\n  - shell_exec\n" +
		"allow_domains:\n  - example.com\nrequire_human_above_usd: 5\ndeny_above_usd: 50\n" +
		"max_steps: 20\ndeny_if_unattested: true\n")
	got, err := decodeYAML(src)
	if err != nil {
		t.Fatalf("a policy using every documented field failed to load: %v", err)
	}
	if len(got) != 1 || len(got[0].DenyTool) != 1 {
		t.Fatalf("policy did not decode as expected: %+v", got)
	}
}
