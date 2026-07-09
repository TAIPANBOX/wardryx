// Package policy loads declarative access policies for the Wardryx Policy
// Decision Point and compiles them into an in-memory matcher.
//
// A policy is a small YAML or JSON document that targets a set of agents by
// an agent:// glob and constrains what those agents may do: which tools are
// denied outright, which domains its declared tools may reach, how many
// steps a run may take, whether the agent must carry a live attestation,
// and the spend level above which a human must approve the action. Loading
// and compiling is entirely deterministic: no LLM, no network call, and no
// randomness anywhere in this package, matching Idryx's rule that the
// decision path stays deterministic and auditable.
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Policy is one declarative rule. Target is an agent:// glob ("*" matches
// any run of characters, including "/"; "?" matches exactly one character).
// Every other field is optional; its zero value means "this policy imposes
// no constraint of that kind."
type Policy struct {
	// Name identifies the policy in Reason strings and logs. Defaults to
	// Target when left empty.
	Name string `yaml:"name,omitempty" json:"name,omitempty"`
	// Target is the agent:// glob this policy applies to. Required.
	Target string `yaml:"target" json:"target"`
	// DenyTool lists tool names this policy refuses outright.
	DenyTool []string `yaml:"deny_tool,omitempty" json:"deny_tool,omitempty"`
	// AllowDomains lists network destinations the agent may reach. Enforced
	// by internal/pdp's Decide against the request's declared Domains: any
	// entry in Domains that is absent from AllowDomains denies the request.
	// A request that declares no Domains is not restricted by this field --
	// AllowDomains only ever restricts domains the caller actually declared
	// (see internal/pdp doc comment). Full runtime tool-egress enforcement
	// (stopping a tool from actually reaching an undeclared domain) is an
	// enforcement point's job, not this field's: AllowDomains only governs
	// what the caller declares up front.
	AllowDomains []string `yaml:"allow_domains,omitempty" json:"allow_domains,omitempty"`
	// RequireHumanAboveUSD is the estimated-cost threshold above which a
	// human must approve the action. Zero (the default) means "no
	// threshold": Decide never holds solely because this field is unset.
	RequireHumanAboveUSD float64 `yaml:"require_human_above_usd,omitempty" json:"require_human_above_usd,omitempty"`
	// MaxSteps caps how many steps a run may take. Enforced by
	// internal/pdp's Decide against the request's declared Steps: once
	// Steps reaches or exceeds MaxSteps, the request denies. Zero (the
	// default) means "no cap": Decide never denies solely because this
	// field is unset.
	MaxSteps int `yaml:"max_steps,omitempty" json:"max_steps,omitempty"`
	// DenyIfUnattested denies any request from an agent with no live
	// attestation (attestation method "" or "none").
	DenyIfUnattested bool `yaml:"deny_if_unattested,omitempty" json:"deny_if_unattested,omitempty"`
}

// compiled pairs a normalized Policy with its compiled glob matcher.
type compiled struct {
	Policy
	re *regexp.Regexp
}

// Set is a compiled, immutable policy set: safe for concurrent use by many
// goroutines (the HTTP API decides many requests against one loaded Set).
type Set struct {
	policies []compiled
	version  string
}

// Version returns the Set's PolicyVersion: a short, stable sha256 hex digest
// of the normalized policy set. Two Sets compiled from the same rules,
// regardless of source file order or field order, always report the same
// Version; any rule change changes it.
func (s *Set) Version() string { return s.version }

// Match returns every policy in s whose Target glob matches agentID, in a
// deterministic order (sorted by target, then name). A nil or empty Set
// (Empty()) matches nothing, which is intentional: with no policy in force,
// Decide's documented "otherwise allow" fallthrough is what governs.
func (s *Set) Match(agentID string) []Policy {
	if s == nil {
		return nil
	}
	var out []Policy
	for _, c := range s.policies {
		if c.re.MatchString(agentID) {
			out = append(out, c.Policy)
		}
	}
	return out
}

// Len reports how many policies are loaded.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.policies)
}

// Empty returns a Set with no policies loaded: every agent matches zero
// policies, so Decide allows everything (no rule can fire). Its Version is
// the well-defined hash of an empty policy list, stable across calls.
func Empty() *Set {
	set, err := Compile(nil)
	if err != nil {
		// Compile(nil) never errors: there are no policies to fail
		// validation or glob compilation.
		panic(fmt.Sprintf("policy: Empty: unexpected error: %v", err))
	}
	return set
}

// Load reads every policy document reachable from path and compiles them
// into a Set.
//
// path is, in order of precedence:
//  1. empty -- Load returns Empty(), the zero-policy set;
//  2. an existing directory -- every "*.yaml", "*.yml", and "*.json" file
//     directly inside it (non-recursive) is read, in sorted-path order;
//  3. a glob pattern such as "policies/*.yaml";
//  4. otherwise tried as a literal file path, so a genuinely missing input
//     produces a clear I/O error rather than a silently empty policy set.
//
// Unlike Idryx's tolerant ingest connectors, a malformed policy file is a
// hard error: Load aborts and returns it rather than silently loading a
// smaller rule set than the operator intended. A security control that
// silently drops a rule because of a YAML typo is worse than one that
// refuses to start.
func Load(path string) (*Set, error) {
	if path == "" {
		return Empty(), nil
	}
	files, err := resolve(path)
	if err != nil {
		return nil, err
	}
	var all []Policy
	for _, f := range files {
		data, err := os.ReadFile(f) // #nosec G304 -- f comes from an operator-supplied CLI flag/env var/glob/directory listing, not untrusted input
		if err != nil {
			return nil, fmt.Errorf("policy: read %s: %w", f, err)
		}
		docs, err := decode(f, data)
		if err != nil {
			return nil, fmt.Errorf("policy: parse %s: %w", f, err)
		}
		all = append(all, docs...)
	}
	return Compile(all)
}

// resolve expands path into the list of policy files to read, per Load's
// documented precedence.
func resolve(path string) ([]string, error) {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		var matches []string
		for _, pat := range []string{"*.yaml", "*.yml", "*.json"} {
			m, err := filepath.Glob(filepath.Join(path, pat))
			if err != nil {
				return nil, fmt.Errorf("policy: bad directory %q: %w", path, err)
			}
			matches = append(matches, m...)
		}
		sort.Strings(matches)
		return matches, nil
	}
	matches, err := filepath.Glob(path)
	if err != nil {
		return nil, fmt.Errorf("policy: bad glob %q: %w", path, err)
	}
	if len(matches) == 0 {
		// Not a glob (or one that matched nothing): try it as a literal
		// path so a genuinely missing file still produces a clear error.
		matches = []string{path}
	}
	sort.Strings(matches)
	return matches, nil
}

// decode parses one policy file, dispatching on its extension. A file may
// hold either a single policy document or a YAML/JSON array of policies.
func decode(path string, data []byte) ([]Policy, error) {
	switch ext := strings.ToLower(filepath.Ext(path)); ext {
	case ".yaml", ".yml":
		return decodeYAML(data)
	case ".json":
		return decodeJSON(data)
	default:
		return nil, fmt.Errorf("unsupported policy file extension %q (want .yaml, .yml, or .json)", ext)
	}
}

func decodeJSON(data []byte) ([]Policy, error) {
	var list []Policy
	if err := json.Unmarshal(data, &list); err == nil {
		return list, nil
	}
	var one Policy
	if err := json.Unmarshal(data, &one); err != nil {
		return nil, err
	}
	return []Policy{one}, nil
}

func decodeYAML(data []byte) ([]Policy, error) {
	var list []Policy
	if err := yaml.Unmarshal(data, &list); err == nil {
		return list, nil
	}
	var one Policy
	if err := yaml.Unmarshal(data, &one); err != nil {
		return nil, err
	}
	return []Policy{one}, nil
}

// Compile normalizes and validates policies, compiles each Target glob, and
// returns the resulting Set. Compile(nil) returns a valid, empty Set.
func Compile(policies []Policy) (*Set, error) {
	norm := normalize(policies)

	out := make([]compiled, 0, len(norm))
	for _, p := range norm {
		if err := validate(p); err != nil {
			return nil, err
		}
		re, err := compileGlob(p.Target)
		if err != nil {
			return nil, fmt.Errorf("policy %q: %w", p.Name, err)
		}
		out = append(out, compiled{Policy: p, re: re})
	}
	return &Set{policies: out, version: computeVersion(norm)}, nil
}

func validate(p Policy) error {
	if p.Target == "" {
		return fmt.Errorf("policy %q: target is required", p.Name)
	}
	if p.RequireHumanAboveUSD < 0 {
		return fmt.Errorf("policy %q: require_human_above_usd must not be negative", p.Name)
	}
	if p.MaxSteps < 0 {
		return fmt.Errorf("policy %q: max_steps must not be negative", p.Name)
	}
	return nil
}

// normalize returns a defensive copy of policies with Name defaulted, and
// DenyTool/AllowDomains deduplicated, sorted, and stripped of blank entries,
// then sorts the policies themselves by (target, name). The result is
// deterministic regardless of the input's source-file or field order, which
// is what makes computeVersion stable across equivalent policy sets.
func normalize(policies []Policy) []Policy {
	out := make([]Policy, len(policies))
	for i, p := range policies {
		np := p
		np.DenyTool = sortedUnique(p.DenyTool)
		np.AllowDomains = sortedUnique(p.AllowDomains)
		if np.Name == "" {
			np.Name = np.Target
		}
		out[i] = np
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func sortedUnique(ss []string) []string {
	if len(ss) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

// computeVersion is PolicyVersion: a short, stable sha256 hex digest of the
// normalized policy set's canonical JSON form. policies must already be
// normalize()'d so that equivalent sets always serialize identically.
func computeVersion(policies []Policy) string {
	if policies == nil {
		policies = []Policy{}
	}
	b, err := json.Marshal(policies)
	if err != nil {
		// Policy only holds strings, a float64, an int, and a bool: it
		// always marshals.
		panic(fmt.Sprintf("policy: marshal normalized set: %v", err))
	}
	sum := sha256.Sum256(b)
	const shortLen = 12 // hex characters (48 bits): short like a git abbreviated hash, long enough to be collision-safe for one operator's policy history
	return hex.EncodeToString(sum[:])[:shortLen]
}

// compileGlob turns an agent:// glob into an anchored regular expression.
// "*" matches any run of characters (including "/"), "?" matches exactly
// one character, and every other character matches itself literally.
func compileGlob(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, fmt.Errorf("empty target glob")
	}
	escaped := regexp.QuoteMeta(pattern)
	escaped = strings.ReplaceAll(escaped, `\*`, `.*`)
	escaped = strings.ReplaceAll(escaped, `\?`, `.`)
	re, err := regexp.Compile("^" + escaped + "$")
	if err != nil {
		return nil, fmt.Errorf("invalid target glob %q: %w", pattern, err)
	}
	return re, nil
}
