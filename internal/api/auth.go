package api

import "strings"

// RoleAdmin and RoleViewer are the two roles a bearer key can carry.
// RoleAdmin is required for POST /v1/approvals/{id}/decide; every other
// authenticated endpoint accepts either role.
const (
	RoleAdmin  = "admin"
	RoleViewer = "viewer"
)

// Principal is who a bearer key belongs to: an organization and a role.
// Mirrors the Cloud plane's key convention (tokenfuse/crates/cloud/src/keys.rs
// parse_keys), reimplemented here in Go for the same wire format, minus the
// Cloud-only plan-tier segment Wardryx has no use for.
type Principal struct {
	Org  string
	Role string
}

// ParseKeys parses "key:org[:role],key:org[:role],...". Entries missing a
// key or an org are skipped. The role segment is optional and defaults to
// RoleAdmin when absent, matching the Rust implementation's default: a bare
// "key:org" key gets full access unless explicitly downgraded to viewer.
//
// With no valid entries (including an empty spec, WARDRYX_KEYS unset), a
// single dev key "devkey" -> default/admin is returned, so the service is
// usable out of the box in development.
func ParseKeys(spec string) map[string]Principal {
	keys := make(map[string]Principal)
	for _, pair := range strings.Split(spec, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		parts := strings.Split(pair, ":")
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		org := strings.TrimSpace(parts[1])
		if key == "" || org == "" {
			continue
		}
		role := RoleAdmin
		if len(parts) >= 3 {
			if r := strings.TrimSpace(parts[2]); r != "" {
				role = r
			}
		}
		keys[key] = Principal{Org: org, Role: role}
	}
	if len(keys) == 0 {
		keys["devkey"] = Principal{Org: "default", Role: RoleAdmin}
	}
	return keys
}
