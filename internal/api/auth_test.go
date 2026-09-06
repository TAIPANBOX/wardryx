package api

import (
	"strings"
	"testing"
)

func TestParseKeysOrgAndRole(t *testing.T) {
	keys, _ := ParseKeys("a:acme,b:globex:viewer", false)
	if keys["a"] != (Principal{Org: "acme", Role: RoleAdmin}) {
		t.Errorf("a = %+v, want acme/admin (default role)", keys["a"])
	}
	if keys["b"] != (Principal{Org: "globex", Role: RoleViewer}) {
		t.Errorf("b = %+v, want globex/viewer", keys["b"])
	}
}

// TestParseKeysEmptySpecYieldsDevKey pins the OPT-IN half of the new
// contract: with allowDevkey true, an empty spec still yields the
// convenience devkey, exactly as ParseKeys always behaved before W1. The
// name is kept (rather than renamed to something like
// "...WithAllowDevkeyYieldsDevKey") because the fixture it guards, an empty
// WARDRYX_KEYS, is unchanged; what changed is that this outcome now requires
// an explicit flag rather than being the unconditional default.
func TestParseKeysEmptySpecYieldsDevKey(t *testing.T) {
	keys, _ := ParseKeys("", true)
	if len(keys) != 1 {
		t.Fatalf("len = %d, want 1", len(keys))
	}
	if keys["devkey"] != (Principal{Org: "default", Role: RoleAdmin}) {
		t.Errorf("devkey = %+v, want default/admin", keys["devkey"])
	}
}

func TestParseKeysSkipsMalformedEntries(t *testing.T) {
	keys, _ := ParseKeys("nokey, :noorg , good:org", false)
	if len(keys) != 1 {
		t.Fatalf("len = %d, want 1: %+v", len(keys), keys)
	}
	if _, ok := keys["good"]; !ok {
		t.Errorf("keys = %+v, want \"good\" present", keys)
	}
}

func TestParseKeysWhitespaceIsTrimmed(t *testing.T) {
	keys, _ := ParseKeys(" a : acme : viewer ", false)
	if keys["a"] != (Principal{Org: "acme", Role: RoleViewer}) {
		t.Errorf("a = %+v, want acme/viewer", keys["a"])
	}
}

// TestParseKeysAllMalformedYieldsDevKey is the "every entry malformed" sibling
// of the empty-spec case above, same opt-in requirement.
func TestParseKeysAllMalformedYieldsDevKey(t *testing.T) {
	keys, _ := ParseKeys("nokey,,:noorg", true)
	if len(keys) != 1 || keys["devkey"].Org != "default" {
		t.Errorf("keys = %+v, want just the devkey fallback", keys)
	}
}

// ------------------------------------------------------------------
// W1: the security-critical half. Before this, ParseKeys ALWAYS installed
// devkey -> default/admin when WARDRYX_KEYS was unset or entirely malformed,
// unconditionally, on whatever address -addr bound (":8090", every
// interface, by default). stack-k8s GOTCHAS 20 records the consequence: a
// self-labelled pod turning a policy `deny` into `allow` against a wardryx
// instance nobody had configured on purpose.
// ------------------------------------------------------------------

// TestNoKeysAndNoOptInAuthenticatesNobody is the fail-closed default this
// whole finding is about: with no valid WARDRYX_KEYS entries and no explicit
// WARDRYX_ALLOW_DEVKEY opt-in, ParseKeys must return an EMPTY map, not the
// devkey fallback. An empty map means requireAuth's map lookup misses for
// every bearer token, including "devkey" itself, so every /v1 route answers
// 401.
func TestNoKeysAndNoOptInAuthenticatesNobody(t *testing.T) {
	for _, spec := range []string{"", "nokey,,:noorg", "   "} {
		keys, _ := ParseKeys(spec, false)
		if len(keys) != 0 {
			t.Errorf("ParseKeys(%q, false) = %+v, want an empty map: nobody should authenticate "+
				"without an explicit WARDRYX_ALLOW_DEVKEY opt-in", spec, keys)
		}
		if _, ok := keys["devkey"]; ok {
			t.Errorf("ParseKeys(%q, false) installed the devkey fallback without allowDevkey", spec)
		}
	}
}

// TestParseKeysNormalSpecUnaffectedByAllowDevkeyFlag: allowDevkey must only
// ever affect the EMPTY/all-malformed case. A real, non-empty spec parses
// identically either way, and must never gain an extra "devkey" entry
// alongside real keys (mirrors tokenfuse-cloud's
// normal_spec_unaffected_by_allow_devkey_flag).
func TestParseKeysNormalSpecUnaffectedByAllowDevkeyFlag(t *testing.T) {
	withFlag, _ := ParseKeys("a:acme", true)
	withoutFlag, _ := ParseKeys("a:acme", false)
	if len(withFlag) != 1 || len(withoutFlag) != 1 {
		t.Fatalf("withFlag = %+v, withoutFlag = %+v, want exactly one entry each", withFlag, withoutFlag)
	}
	if _, ok := withFlag["devkey"]; ok {
		t.Error("allowDevkey=true injected a devkey entry alongside a real key")
	}
	if withFlag["a"] != withoutFlag["a"] {
		t.Errorf("a = %+v with the flag, %+v without: a real spec must parse identically either way",
			withFlag["a"], withoutFlag["a"])
	}
}

// The runServe-level decisions (refuse to start, warn about a routable
// bind, warn an unused WARDRYX_ALLOW_DEVKEY) are tested in
// cmd/wardryx/main_test.go against startupKeyPosture, the factored helper
// runServe consults: that is where bindWarning and the refusal message
// live, alongside runServe itself.

// A typo'd role ("admni" for "admin") is not rejected by ParseKeys: it is
// stored exactly as given, and requireAdmin's strict p.Role != RoleAdmin
// check then locks that key out of every admin-only route (POST
// /v1/approvals/{id}/decide, every /v1/policies route) while leaving it
// fully usable on every requireAuth-only route, since authenticate never
// inspects Role at all. That is fail-closed and therefore not a bypass, but
// it used to be silent: nothing at parse time said the operator had
// provisioned a key that looks admin-shaped in config and is not. These
// tests pin the fix: ParseKeys' second return value names the key and the
// unknown role for every entry whose role is neither RoleAdmin nor
// RoleViewer, so serve can warn about it at startup instead of an operator
// discovering the lockout from a 403 later.
func TestParseKeysUnknownRoleWarns(t *testing.T) {
	t.Run("an unknown role is stored as given and produces one warning naming the key and the role", func(t *testing.T) {
		keys, warnings := ParseKeys("a:acme:admni", false)
		if keys["a"] != (Principal{Org: "acme", Role: "admni"}) {
			t.Errorf("a = %+v, want acme/admni stored as-is (fails closed on admin routes, not silently corrected)", keys["a"])
		}
		if len(warnings) != 1 {
			t.Fatalf("warnings = %v, want exactly 1", warnings)
		}
		if !strings.Contains(warnings[0], `"a"`) || !strings.Contains(warnings[0], `"admni"`) {
			t.Errorf("warning = %q, want it to name the key \"a\" and the unknown role \"admni\"", warnings[0])
		}
	})

	t.Run("admin and viewer roles produce no warnings", func(t *testing.T) {
		_, warnings := ParseKeys("a:acme,b:globex:viewer,c:initech:admin", false)
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want none for admin/viewer/default-to-admin", warnings)
		}
	})

	t.Run("the empty-spec devkey fallback produces no warning", func(t *testing.T) {
		_, warnings := ParseKeys("", true)
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want none for the devkey fallback", warnings)
		}
	})

	t.Run("multiple unknown roles each produce their own warning", func(t *testing.T) {
		_, warnings := ParseKeys("a:acme:admni,b:globex:veiwer", false)
		if len(warnings) != 2 {
			t.Fatalf("warnings = %v, want exactly 2", warnings)
		}
	})
}
