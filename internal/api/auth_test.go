package api

import (
	"strings"
	"testing"
)

func TestParseKeysOrgAndRole(t *testing.T) {
	keys, _ := ParseKeys("a:acme,b:globex:viewer")
	if keys["a"] != (Principal{Org: "acme", Role: RoleAdmin}) {
		t.Errorf("a = %+v, want acme/admin (default role)", keys["a"])
	}
	if keys["b"] != (Principal{Org: "globex", Role: RoleViewer}) {
		t.Errorf("b = %+v, want globex/viewer", keys["b"])
	}
}

func TestParseKeysEmptySpecYieldsDevKey(t *testing.T) {
	keys, _ := ParseKeys("")
	if len(keys) != 1 {
		t.Fatalf("len = %d, want 1", len(keys))
	}
	if keys["devkey"] != (Principal{Org: "default", Role: RoleAdmin}) {
		t.Errorf("devkey = %+v, want default/admin", keys["devkey"])
	}
}

func TestParseKeysSkipsMalformedEntries(t *testing.T) {
	keys, _ := ParseKeys("nokey, :noorg , good:org")
	if len(keys) != 1 {
		t.Fatalf("len = %d, want 1: %+v", len(keys), keys)
	}
	if _, ok := keys["good"]; !ok {
		t.Errorf("keys = %+v, want \"good\" present", keys)
	}
}

func TestParseKeysWhitespaceIsTrimmed(t *testing.T) {
	keys, _ := ParseKeys(" a : acme : viewer ")
	if keys["a"] != (Principal{Org: "acme", Role: RoleViewer}) {
		t.Errorf("a = %+v, want acme/viewer", keys["a"])
	}
}

func TestParseKeysAllMalformedYieldsDevKey(t *testing.T) {
	keys, _ := ParseKeys("nokey,,:noorg")
	if len(keys) != 1 || keys["devkey"].Org != "default" {
		t.Errorf("keys = %+v, want just the devkey fallback", keys)
	}
}

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
		keys, warnings := ParseKeys("a:acme:admni")
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
		_, warnings := ParseKeys("a:acme,b:globex:viewer,c:initech:admin")
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want none for admin/viewer/default-to-admin", warnings)
		}
	})

	t.Run("the empty-spec devkey fallback produces no warning", func(t *testing.T) {
		_, warnings := ParseKeys("")
		if len(warnings) != 0 {
			t.Errorf("warnings = %v, want none for the devkey fallback", warnings)
		}
	})

	t.Run("multiple unknown roles each produce their own warning", func(t *testing.T) {
		_, warnings := ParseKeys("a:acme:admni,b:globex:veiwer")
		if len(warnings) != 2 {
			t.Fatalf("warnings = %v, want exactly 2", warnings)
		}
	})
}
