package api

import (
	"fmt"
	"strings"
)

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
// Fails closed by default. With no valid entries (an empty spec, WARDRYX_KEYS
// unset, or every entry malformed) and allowDevkey false, ParseKeys returns
// an EMPTY map: nobody authenticates, and every /v1 route answers 401. The
// insecure "devkey" -> default/admin fallback exists only for a local,
// loopback-only development run and is inserted ONLY when the caller
// explicitly opts in via allowDevkey, mirroring the Cloud plane's
// TOKENFUSE_CLOUD_ALLOW_DEVKEY (tokenfuse/crates/cloud/src/keys.rs
// parse_keys). It is never a silent default: before this, an unset or
// malformed WARDRYX_KEYS installed the built-in devkey admin credential on
// whatever address -addr bound (":8090", every interface, by default), which
// is exactly the misconfiguration stack-k8s GOTCHAS 20 records turning a
// `deny` into an `allow` from a self-labelled pod. Callers must only ever set
// allowDevkey from an explicit operator opt-in (WARDRYX_ALLOW_DEVKEY), never
// as a silent default.
//
// ParseKeys never rejects a role outside {RoleAdmin, RoleViewer}: it stores
// whatever string followed the second colon exactly as given, so a lookup
// against it fails closed rather than being silently upgraded to something
// that was never asked for. That is the right default, but on its own it is
// also silent: requireAuth never inspects Role, so a key with an unknown role
// like "admni" (typo for "admin") authenticates and works on every ordinary
// route, and only requireAdmin's strict equality check locks it out, on
// every admin-only route, of an operation the config looks like it granted.
// The second return value is one warning per entry whose role is neither
// RoleAdmin nor RoleViewer, naming the key and the role, so a caller (serve)
// can print it at startup rather than leaving the gap for a 403 to reveal
// later.
func ParseKeys(spec string, allowDevkey bool) (map[string]Principal, []string) {
	keys := make(map[string]Principal)
	var warnings []string
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
		if role != RoleAdmin && role != RoleViewer {
			warnings = append(warnings, fmt.Sprintf(
				"wardryx: key %q has unknown role %q (want %q or %q); it is stored as given and will authenticate normally but requireAdmin will reject it on every admin-only route",
				key, role, RoleAdmin, RoleViewer))
		}
		keys[key] = Principal{Org: org, Role: role}
	}
	if len(keys) == 0 && allowDevkey {
		keys["devkey"] = Principal{Org: "default", Role: RoleAdmin}
	}
	return keys, warnings
}
