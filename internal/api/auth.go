package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// The roles a bearer key can carry.
//
// RoleAdmin decides approvals and writes policies of its own org; with more
// than one org in WARDRYX_KEYS it reaches nothing of another org's, and a
// policy or an approval that belongs to no org needs RoleCrossOrgAdmin.
// RoleCrossOrgAdmin is an admin across every org. RoleViewer reads its org's
// approvals and the status. RolePEP is an enforcement point (the gateway, its
// MCP broker, the egress plane): it asks /v1/decide and /v1/filter-tools for
// the agents it authenticated, and reads what a viewer reads.
//
// Which agents a key may ask for is speaksFor's rule; see it.
const (
	RoleAdmin         = "admin"
	RoleViewer        = "viewer"
	RolePEP           = "pep"
	RoleCrossOrgAdmin = "cross-org-admin"
)

// Principal is who a bearer key belongs to: an organization, a role and,
// optionally, the agents it may speak for. Mirrors the Cloud plane's key
// convention (tokenfuse/crates/cloud/src/keys.rs parse_keys), reimplemented
// here in Go for the same wire format; the fourth segment, which the Cloud
// plane reads as a site, is here the list of agents.
type Principal struct {
	Org  string
	Role string
	// Agents are the agent patterns this key may speak for, in a policy
	// Target's glob syntax ("agent://acme.example/*" or an exact id), joined
	// by "|" exactly as the WARDRYX_KEYS entry listed them after trimming.
	// Empty when the entry lists none, and then the role decides (speaksFor).
	// A string rather than a slice so a Principal stays a comparable value.
	Agents string
	// KeyFP identifies which key authenticated the request: keyFingerprint of
	// the presented bearer key, set by authenticate. It is never the key
	// itself, so it is safe to record in an audit event.
	KeyFP string
}

// agentPatterns returns the patterns Agents holds, in the order listed.
func (p Principal) agentPatterns() []string {
	if p.Agents == "" {
		return nil
	}
	return strings.Split(p.Agents, "|")
}

// isAdmin reports whether the role may use the admin-only routes.
func (p Principal) isAdmin() bool { return p.Role == RoleAdmin || p.Role == RoleCrossOrgAdmin }

// knownRole reports whether a role is one this service gives meaning to.
func knownRole(role string) bool {
	switch role {
	case RoleAdmin, RoleViewer, RolePEP, RoleCrossOrgAdmin:
		return true
	}
	return false
}

// orgsOf returns the orgs the keys belong to, leaving out cross-org admins,
// which belong to every org rather than to their own: adding one never turns
// a single-org deployment into a multi-org one.
func orgsOf(keys map[string]Principal) map[string]bool {
	orgs := map[string]bool{}
	for _, p := range keys {
		if p.Role != RoleCrossOrgAdmin {
			orgs[p.Org] = true
		}
	}
	return orgs
}

// KeyPosture says, one line per key, what WARDRYX_KEYS leaves a key unable to
// do that its operator may expect it to: a key that speaks for no agent, and,
// with more than one org, the fact that an admin is confined to its own org.
// serve prints these at start, so a 403 on /v1/decide is never the first an
// operator hears of it. Keys are named by fingerprint, never by value.
func KeyPosture(keys map[string]Principal) []string {
	orgs := orgsOf(keys)
	single := len(orgs) <= 1
	var out []string
	for key, p := range keys {
		if p.Agents != "" {
			continue
		}
		switch {
		case p.Role == RoleViewer:
			out = append(out, fmt.Sprintf(
				"wardryx: key %s (org %q, role viewer) lists no agent, so /v1/decide and /v1/filter-tools answer it 403: give it role pep if it is an enforcement point, or list the agents it speaks for (key:org:role:agent://example.org/*)",
				keyFingerprint(key), p.Org))
		case !single && (p.Role == RolePEP || p.Role == RoleAdmin):
			out = append(out, fmt.Sprintf(
				"wardryx: key %s (org %q, role %s) lists no agent and WARDRYX_KEYS names %d orgs, so it speaks for no agent: wardryx cannot tell which agents are its org's; list them (key:org:role:agent://example.org/*)",
				keyFingerprint(key), p.Org, p.Role, len(orgs)))
		}
	}
	if !single {
		out = append(out, fmt.Sprintf(
			"wardryx: WARDRYX_KEYS names %d orgs: an admin key decides approvals and changes policies of its own org only; a policy or an approval with no org needs a %s key",
			len(orgs), RoleCrossOrgAdmin))
	}
	sort.Strings(out)
	return out
}

// keyFingerprint is the first 16 hex characters of SHA-256 over the bytes of
// a bearer key. An operator recovers it with
// printf %s "$KEY" | shasum -a 256 | cut -c1-16, so the audit record can be
// matched to a key without the record ever holding one.
func keyFingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:16]
}

// ParseKeys parses "key:org[:role[:agents]],...". Entries missing a key or an
// org are skipped. The role segment is optional and defaults to RoleAdmin when
// absent, matching the Rust implementation's default: a bare "key:org" key
// gets full access unless explicitly downgraded to viewer. The agents segment
// is everything after the third colon (an agent id holds colons of its own):
// agent patterns separated by "|", each trimmed, blanks dropped. An entry of
// three segments or fewer parses exactly as it did before agents existed.
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
		parts := strings.SplitN(pair, ":", 4)
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
		if !knownRole(role) {
			warnings = append(warnings, fmt.Sprintf(
				"wardryx: key %q has unknown role %q (want %q, %q, %q or %q); it is stored as given and will authenticate normally but requireAdmin will reject it on every admin-only route, and it speaks for an agent only if its entry lists one",
				key, role, RoleAdmin, RoleViewer, RolePEP, RoleCrossOrgAdmin))
		}
		var agents []string
		if len(parts) == 4 {
			for _, a := range strings.Split(parts[3], "|") {
				if a = strings.TrimSpace(a); a != "" {
					agents = append(agents, a)
				}
			}
		}
		keys[key] = Principal{Org: org, Role: role, Agents: strings.Join(agents, "|")}
	}
	if len(keys) == 0 && allowDevkey {
		// The local development key: one org, so as an admin it speaks for any
		// agent and is the cross-org admin of a deployment with no other org.
		keys["devkey"] = Principal{Org: "default", Role: RoleAdmin}
	}
	return keys, warnings
}

// allowance is what New compiles from the keys once: whether there is one org,
// and each listed key's patterns as matchers.
type allowance struct {
	singleOrg bool
	globs     map[string][]*regexp.Regexp // keyed by Principal.Agents
}

func newAllowance(keys map[string]Principal) allowance {
	a := allowance{singleOrg: len(orgsOf(keys)) <= 1, globs: map[string][]*regexp.Regexp{}}
	for _, p := range keys {
		if p.Agents != "" {
			a.globs[p.Agents] = compileAgents(p)
		}
	}
	return a
}

func compileAgents(p Principal) []*regexp.Regexp {
	var out []*regexp.Regexp
	for _, pat := range p.agentPatterns() {
		if re, err := policy.CompileGlob(pat); err == nil {
			out = append(out, re)
		}
	}
	return out
}

// speaksFor is the binding between a key and the agent a request names
// (F-001 of the 2026-10-17 review). A key whose entry lists agents speaks for
// exactly the agents its patterns match, whatever its role. A key that lists
// none speaks for:
//
//   - any agent, as a cross-org admin;
//   - any agent of its own org, as an enforcement point (pep) or an admin. The
//     enforcement point authenticated the agent before it asked; an admin can
//     rewrite the rules that decide, so binding it buys nothing. Wardryx knows
//     which agents are an org's only when every key belongs to one org, where
//     every agent is: with more than one org, such a key speaks for none until
//     its entry lists them;
//   - no agent, as a viewer or a role this service does not know.
func (a allowance) speaksFor(p Principal, agentID string) bool {
	if p.Agents != "" {
		globs, ok := a.globs[p.Agents]
		if !ok {
			globs = compileAgents(p)
		}
		for _, re := range globs {
			if re.MatchString(agentID) {
				return true
			}
		}
		return false
	}
	switch p.Role {
	case RoleCrossOrgAdmin:
		return true
	case RolePEP, RoleAdmin:
		return a.singleOrg
	}
	return false
}

// acrossOrgs reports whether a principal may act on what belongs to no org,
// or to another org: a cross-org admin, or the admin of the only org there is.
func (a allowance) acrossOrgs(p Principal) bool {
	return p.Role == RoleCrossOrgAdmin || (p.Role == RoleAdmin && a.singleOrg)
}
