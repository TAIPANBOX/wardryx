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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TAIPANBOX/agent-stack-go/chain"
	"io"
	"math"
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
	// human must approve the action. A pointer, not a float64, so an
	// operator can say "zero" and be believed: nil (the field absent from
	// the file or the PUT body) means "no threshold", and Decide never
	// holds solely because this field is unset; a non-nil zero means "hold
	// on any priced call at all", a real and useful threshold, not the
	// absence of one.
	//
	// @decided 2026-09-27: before this, the field was a plain float64 with
	// yaml/json ",omitempty", so an explicit zero and an absent field
	// decoded to the identical Go value and could never be told apart: a
	// policy meaning "require approval above zero" silently behaved as "no
	// threshold at all". Making zero a real, distinguishable value (rather
	// than refusing it at load and PUT) keeps that policy sentence
	// sayable, matches this field's own documented contract ("holds any
	// action whose cost exceeds the threshold", and a threshold of zero is
	// a threshold), and matches how DenyAboveUSD's sibling field on an
	// approval_token, MaxCostUSD, already treats zero (README's approval
	// token section: "0 is deliberately never treated as no ceiling").
	// Refusing zero outright was rejected: since every currently-valid
	// policy file that simply never mentions this field also decodes to
	// the Go zero value, "refuse an explicit zero" is only expressible at
	// all once presence is tracked, at which point there is no reason left
	// to forbid the one value operators asked for over "no restriction".
	RequireHumanAboveUSD *float64 `yaml:"require_human_above_usd,omitempty" json:"require_human_above_usd,omitempty"`
	// DenyAboveUSD is a hard, non-approvable cost ceiling: internal/pdp's
	// Decide denies any action whose estimated cost exceeds it outright, and
	// no approval_token -- however validly minted -- can ever turn that deny
	// into an allow. This is deliberately stronger than RequireHumanAboveUSD,
	// which only holds pending a human's approval: DenyAboveUSD instead marks
	// a line no human approval is trusted to cross at all. A policy commonly
	// sets both, with DenyAboveUSD above RequireHumanAboveUSD, to get an
	// approvable band between them and a hard ceiling above it; when a
	// request exceeds both, the hard ceiling wins and require_human_above_usd
	// is never reached (see internal/pdp's Decide doc comment for the exact
	// rule order).
	//
	// A pointer for the same reason as RequireHumanAboveUSD, and this is the
	// field the defect measured 2026-09-27 was found on: a PUT of
	// {"deny_above_usd":0} answered 200, the stored policy echoed back with
	// no deny_above_usd field at all, and the next priced call through the
	// enforcement point was allowed, because the old float64 could not tell
	// "deny everything above zero" from "no ceiling was ever set". nil means
	// "no hard ceiling", exactly as before; a non-nil zero denies any action
	// whose cost is more than zero, "everything priced" being exactly what
	// an operator writing deny_above_usd: 0 asked for.
	DenyAboveUSD *float64 `yaml:"deny_above_usd,omitempty" json:"deny_above_usd,omitempty"`
	// MaxSteps caps how many steps a run may take. Enforced by
	// internal/pdp's Decide against the request's declared Steps: once
	// Steps reaches or exceeds MaxSteps, the request denies. Zero (the
	// default) means "no cap": Decide never denies solely because this
	// field is unset.
	MaxSteps int `yaml:"max_steps,omitempty" json:"max_steps,omitempty"`
	// DenyIfUnattested denies any request from an agent with no live
	// attestation (attestation method "" or "none").
	DenyIfUnattested bool `yaml:"deny_if_unattested,omitempty" json:"deny_if_unattested,omitempty"`
	// DenyIfChainUnproven denies a request whose delegation chain is present
	// and was not PROVED (agent-passport SPEC 5.2).
	//
	// Until 2026-08-26 a chain was a list of names an agent typed into a
	// header: this service validated its shape and believed its contents.
	// With vouchryx issuing RFC 8693 tokens and enforcement points verifying
	// them, a policy can finally require the difference.
	//
	// It is about a chain that IS present. An agent acting autonomously is
	// not delegating and has nothing to prove, so this rule does not fire on
	// it; the rule for "must be acting for somebody" is
	// [Policy.RequireRootPrincipal], and the two are separate precisely so an
	// operator can say either without saying both.
	DenyIfChainUnproven bool `yaml:"deny_if_chain_unproven,omitempty" json:"deny_if_chain_unproven,omitempty"`
	// MaxChainDepth caps how many entries a delegation chain may carry.
	//
	// agent-passport SPEC 5.1 already caps every chain at chain.MaxDepth (32)
	// stack-wide and this service refuses a longer one independent of policy.
	// This is a policy saying a LOWER number: a support bot three delegations
	// deep is a fan-out somebody should have to justify. Zero (the default)
	// means no cap, consistent with MaxSteps.
	MaxChainDepth int `yaml:"max_chain_depth,omitempty" json:"max_chain_depth,omitempty"`
	// RequireRootPrincipal is a glob the chain's ROOT must match, in the same
	// syntax as Target.
	//
	// The root is the first entry (SPEC 5), usually a human. A policy setting
	// this is saying "this agent only ever acts for X", and an EMPTY chain has
	// no root, so it denies: without that, an agent satisfies the rule by
	// dropping its chain and having nothing to check. Empty (the default)
	// means no requirement.
	RequireRootPrincipal string `yaml:"require_root_principal,omitempty" json:"require_root_principal,omitempty"`
	// HoldIfSignal holds a request that carries a matching typed signal (for
	// example, a tool call a classifier says is destructive with probability
	// 0.8 or more). It can only ever produce a hold: a signal is a
	// probability about the world, and a probability must never refuse an
	// action by itself. See SignalRule.
	//
	// Nil, the default, imposes nothing. A policy without it is byte for byte
	// what it was before this field existed, PolicyVersion included.
	HoldIfSignal *SignalRule `yaml:"hold_if_signal,omitempty" json:"hold_if_signal,omitempty"`
	// DenyIfSignal is not a rule. It exists so that a policy which tries to
	// make a signal refuse something is refused at load and at PUT with a
	// sentence saying why, in a decoder that is strict about unknown fields
	// (a policy file) and in one that is not (the policy-as-code API), instead
	// of being silently dropped by the second. Any value, even false, is
	// refused. It never survives into a compiled Set.
	DenyIfSignal any `yaml:"deny_if_signal,omitempty" json:"deny_if_signal,omitempty"`
}

// SignalRule is the body of hold_if_signal: hold when a signal named Name
// carries one of Values with probability at least MinProbability.
//
// Name, Values and MinProbability are all required, and MinProbability is a
// pointer so that an absent threshold can be refused rather than read as zero,
// which would hold on a coin flip. Any other key is refused with a sentence
// saying that a signal can only hold, so no spelling of "...and deny" (a
// decision, action or on_match key) can ride along unread.
type SignalRule struct {
	// Name is the signal this rule reads, e.g. "action.risk_class".
	Name string `yaml:"name" json:"name"`
	// Values are the signal values that hold, e.g. destructive.
	Values []string `yaml:"values" json:"values"`
	// MinProbability is the lowest probability that holds, in [0, 1].
	MinProbability *float64 `yaml:"min_probability" json:"min_probability"`
}

// signalRuleKeys are the only keys hold_if_signal has.
var signalRuleKeys = map[string]bool{"name": true, "values": true, "min_probability": true}

func refuseSignalRuleKey(key string) error {
	return fmt.Errorf("hold_if_signal has no key %q: a signal can only hold, never deny, so the rule takes exactly name, values and min_probability", key)
}

// UnmarshalJSON refuses any key a hold-only rule does not have, in the strict
// and the non-strict decoder alike.
func (r *SignalRule) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("hold_if_signal must be an object with name, values and min_probability: %w", err)
	}
	for k := range raw {
		if !signalRuleKeys[k] {
			return refuseSignalRuleKey(k)
		}
	}
	type plain SignalRule
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*r = SignalRule(p)
	return nil
}

// UnmarshalYAML is UnmarshalJSON's twin for a YAML policy file.
func (r *SignalRule) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("hold_if_signal must be a mapping with name, values and min_probability")
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if k := n.Content[i].Value; !signalRuleKeys[k] {
			return refuseSignalRuleKey(k)
		}
	}
	type plain SignalRule
	var p plain
	if err := n.Decode(&p); err != nil {
		return err
	}
	*r = SignalRule(p)
	return nil
}

// validate checks a rule on its own terms.
func (r *SignalRule) validate(policyName string) error {
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("policy %q: hold_if_signal.name is required", policyName)
	}
	if len(r.Values) == 0 {
		return fmt.Errorf("policy %q: hold_if_signal.values is required: a rule that lists no value could never hold", policyName)
	}
	for _, v := range r.Values {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("policy %q: hold_if_signal.values must not contain a blank value", policyName)
		}
	}
	if r.MinProbability == nil {
		return fmt.Errorf("policy %q: hold_if_signal.min_probability is required: a rule with no threshold would hold on any probability", policyName)
	}
	if p := *r.MinProbability; math.IsNaN(p) || p < 0 || p > 1 {
		return fmt.Errorf("policy %q: hold_if_signal.min_probability must be a number between 0 and 1", policyName)
	}
	return nil
}

func (r *SignalRule) clone() *SignalRule {
	if r == nil {
		return nil
	}
	c := *r
	c.Values = sortedUnique(r.Values)
	c.MinProbability = cloneUSD(r.MinProbability)
	return &c
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

// Policies returns every policy in s, in the same normalized, deterministic
// order Compile produced (sorted by target, then name). Unlike Match, this
// is unfiltered -- the inverse of Compile, useful for a caller that loaded
// a Set and now needs to recombine its rules with more policies from
// another source before recompiling. Wardryx's internal/api policy-as-code
// routes use this to layer store-managed policies on top of a fixed
// file-loaded base (see Server.recomputePolicySet): the file-loaded Set's
// Policies() plus the store's current rows, recompiled together on every
// write, so an API write can never make the file-loaded rules disappear.
func (s *Set) Policies() []Policy {
	if s == nil {
		return nil
	}
	out := make([]Policy, len(s.policies))
	for i, c := range s.policies {
		out[i] = c.Policy
	}
	return out
}

// RequiresHumanApproval reports whether any loaded policy sets a
// require_human_above_usd threshold at all, including an explicit zero
// (which holds on any priced call), i.e. whether Decide can ever produce a
// hold for this Set. main uses it at startup to warn when
// WARDRYX_APPROVAL_SECRET is empty but a hold could actually occur: without
// the secret, the approvals-decide grant path fails closed (internal/api,
// internal/approval.ErrNoSecret) rather than minting an approval_token.
func (s *Set) RequiresHumanApproval() bool {
	if s == nil {
		return false
	}
	for _, c := range s.policies {
		// A hold_if_signal rule is the other way a hold can happen, and a hold
		// with no approval secret cannot be granted: the warning is owed to
		// both.
		if c.RequireHumanAboveUSD != nil || c.HoldIfSignal != nil {
			return true
		}
	}
	return false
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

// isUnknownFieldError reports whether err is a decoder complaining about a
// field name it does not recognize, as opposed to a shape mismatch.
//
// The distinction matters because both decoders try the list shape first and
// fall through to the single-document shape. A single document legitimately
// fails the list attempt with a type error, so falling through is correct
// there. A LIST carrying an unknown field must not fall through: the second
// attempt would fail with "cannot unmarshal !!seq into policy.Policy", which
// hides a misspelled field behind a shape error and sends the reader looking in
// the wrong place.
func isUnknownFieldError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// gopkg.in/yaml.v3 with KnownFields: "field X not found in type ..."
	// encoding/json with DisallowUnknownFields: "unknown field \"X\""
	// hold_if_signal's own decoders refuse a key a hold-only rule does not have
	// (see SignalRule): that is the same finding as an unknown field, and must
	// not fall through to the single-document attempt either.
	return strings.Contains(msg, "not found in type") || strings.Contains(msg, "unknown field") ||
		strings.Contains(msg, "hold_if_signal has no key")
}

// strictJSON and strictYAML refuse a field the Policy struct does not declare.
//
// Without this, a misspelled field is silently dropped. A policy written with
// `deny_tools` instead of `deny_tool` parses, compiles, matches its agents and
// denies nothing, while the decision reads "allowed: request satisfies all
// matched policy rules". The operator sees a loaded policy, a matched agent and
// an allow, and concludes the guardrail works. An enforcement control that
// forgets is worse than no control, because it is believed.
func strictJSON(data []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(into)
}

func strictYAML(data []byte, into any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(into); err != nil {
		if errors.Is(err, io.EOF) {
			return nil // an empty document is an empty policy set, not an error
		}
		return err
	}
	return nil
}

func decodeJSON(data []byte) ([]Policy, error) {
	var list []Policy
	err := strictJSON(data, &list)
	if err == nil {
		return list, nil
	}
	if isUnknownFieldError(err) {
		return nil, err
	}
	var one Policy
	if err := strictJSON(data, &one); err != nil {
		return nil, err
	}
	return []Policy{one}, nil
}

func decodeYAML(data []byte) ([]Policy, error) {
	var list []Policy
	err := strictYAML(data, &list)
	if err == nil {
		return list, nil
	}
	if isUnknownFieldError(err) {
		return nil, err
	}
	var one Policy
	if err := strictYAML(data, &one); err != nil {
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
	if p.RequireHumanAboveUSD != nil && *p.RequireHumanAboveUSD < 0 {
		return fmt.Errorf("policy %q: require_human_above_usd must not be negative", p.Name)
	}
	if p.DenyAboveUSD != nil && *p.DenyAboveUSD < 0 {
		return fmt.Errorf("policy %q: deny_above_usd must not be negative", p.Name)
	}
	if p.MaxSteps < 0 {
		return fmt.Errorf("policy %q: max_steps must not be negative", p.Name)
	}
	if p.MaxChainDepth < 0 {
		return fmt.Errorf("policy %q: max_chain_depth must not be negative", p.Name)
	}
	if p.MaxChainDepth > chain.MaxDepth {
		// A cap above the stack-wide one can never fire, and a rule that can
		// never fire reads as a control and is not. SPEC 5.1 refuses a longer
		// chain before any policy is consulted.
		return fmt.Errorf(
			"policy %q: max_chain_depth %d is above the stack-wide cap of %d, so it could never fire",
			p.Name, p.MaxChainDepth, chain.MaxDepth)
	}
	if p.DenyIfSignal != nil {
		return fmt.Errorf("policy %q: deny_if_signal is refused: a signal is a probability, and a probability can only hold an action for a person, never deny it; use hold_if_signal", p.Name)
	}
	if p.HoldIfSignal != nil {
		if err := p.HoldIfSignal.validate(p.Name); err != nil {
			return err
		}
	}
	if p.RequireRootPrincipal != "" {
		if _, err := compileGlob(p.RequireRootPrincipal); err != nil {
			return fmt.Errorf("policy %q: require_root_principal %q is not a valid glob: %w",
				p.Name, p.RequireRootPrincipal, err)
		}
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
		np.RequireHumanAboveUSD = cloneUSD(p.RequireHumanAboveUSD)
		np.DenyAboveUSD = cloneUSD(p.DenyAboveUSD)
		np.HoldIfSignal = p.HoldIfSignal.clone()
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

// cloneUSD returns a fresh pointer holding the same value as p, or nil if p
// is nil. normalize's defensive copy already gives every Policy its own
// DenyTool/AllowDomains backing arrays (invariant 11's read side: a copy
// of a struct is not a copy of what it points at); RequireHumanAboveUSD and
// DenyAboveUSD are pointers for the same presence-tracking reason a slice
// is a reference, so they get the same treatment here rather than being
// the one field left aliased to the caller's own copy.
func cloneUSD(p *float64) *float64 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
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

// MatchesGlob reports whether `value` matches `pattern` in the same syntax
// Target uses.
//
// Exported because the PDP matches a chain's ROOT against
// [Policy.RequireRootPrincipal], and a second glob implementation over there
// would be two answers to "does this pattern match", which is the same class of
// drift a second signature verifier would be.
func MatchesGlob(pattern, value string) bool {
	re, err := compileGlob(pattern)
	if err != nil {
		// A pattern that does not compile was refused at validate time, so
		// reaching here means the set was built without validation. Matching
		// nothing is the safe answer: a rule that matches nothing denies,
		// because every caller of this treats "no match" as a refusal.
		return false
	}
	return re.MatchString(value)
}
