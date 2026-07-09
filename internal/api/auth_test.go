package api

import "testing"

func TestParseKeysOrgAndRole(t *testing.T) {
	keys := ParseKeys("a:acme,b:globex:viewer")
	if keys["a"] != (Principal{Org: "acme", Role: RoleAdmin}) {
		t.Errorf("a = %+v, want acme/admin (default role)", keys["a"])
	}
	if keys["b"] != (Principal{Org: "globex", Role: RoleViewer}) {
		t.Errorf("b = %+v, want globex/viewer", keys["b"])
	}
}

func TestParseKeysEmptySpecYieldsDevKey(t *testing.T) {
	keys := ParseKeys("")
	if len(keys) != 1 {
		t.Fatalf("len = %d, want 1", len(keys))
	}
	if keys["devkey"] != (Principal{Org: "default", Role: RoleAdmin}) {
		t.Errorf("devkey = %+v, want default/admin", keys["devkey"])
	}
}

func TestParseKeysSkipsMalformedEntries(t *testing.T) {
	keys := ParseKeys("nokey, :noorg , good:org")
	if len(keys) != 1 {
		t.Fatalf("len = %d, want 1: %+v", len(keys), keys)
	}
	if _, ok := keys["good"]; !ok {
		t.Errorf("keys = %+v, want \"good\" present", keys)
	}
}

func TestParseKeysWhitespaceIsTrimmed(t *testing.T) {
	keys := ParseKeys(" a : acme : viewer ")
	if keys["a"] != (Principal{Org: "acme", Role: RoleViewer}) {
		t.Errorf("a = %+v, want acme/viewer", keys["a"])
	}
}

func TestParseKeysAllMalformedYieldsDevKey(t *testing.T) {
	keys := ParseKeys("nokey,,:noorg")
	if len(keys) != 1 || keys["devkey"].Org != "default" {
		t.Errorf("keys = %+v, want just the devkey fallback", keys)
	}
}
