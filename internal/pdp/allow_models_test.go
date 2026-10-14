package pdp

import (
	"encoding/json"
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/TAIPANBOX/wardryx/internal/approval"
	"github.com/TAIPANBOX/wardryx/internal/policy"
)

// A policy may name the models its agents may use (allow_models). An agent that
// switches to a model its policy does not name is refused, on every call, and
// no decision under such a policy is offered for reuse: an enforcement point's
// decision cache is keyed by agent and tool set, not by model, so a cached allow
// for one model would otherwise answer a call naming another.

const fleetAgent = "agent://acme.example/fleet/bot1"

// modelPolicy decodes a policy from the JSON an operator writes, so the test
// reads allow_models exactly as a policy file or a PUT states it.
func modelPolicy(t *testing.T, name string, models ...string) policy.Policy {
	t.Helper()
	doc := map[string]any{"name": name, "target": "agent://acme.example/fleet/*"}
	if models != nil {
		doc["allow_models"] = models
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	var p policy.Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("the policy %s did not decode: %v", raw, err)
	}
	return p
}

func modelCall(model string) DecideRequest {
	return DecideRequest{AgentID: fleetAgent, RunID: "run-1", ToolNames: []string{"search"}, Model: model}
}

func TestAModelTheListDoesNotNameIsDenied(t *testing.T) {
	e := allowEngine(t, modelPolicy(t, "fleet", "claude-sonnet-*", "gpt-6-mini"))
	cases := []struct {
		model, want string
	}{
		{"claude-sonnet-5-5", Allow},
		{"claude-sonnet-", Allow}, // * matches the empty run
		{"gpt-6-mini", Allow},
		{"claude-opus-5", Deny},
		{"gpt-6-mini-2026", Deny},   // a name is matched whole, not as a prefix
		{"Claude-Sonnet-5-5", Deny}, // exact: folding case would widen an allow-list
		{" claude-sonnet-5-5", Deny},
		{"unknown", Deny}, // what TokenFuse sends for a call that names no model
		{"claude-sonnet-5\x00", Deny},
		{"claude-sonnet-5\nopus", Deny},
		{"claude-sonnet-\xff", Deny},
		{strings.Repeat("a", 4096), Deny},
		{"claude-sonnet-" + strings.Repeat("a", 4096), Allow},
	}
	for _, c := range cases {
		got := e.Decide(modelCall(c.model))
		if got.Decision != c.want {
			t.Errorf("model %.40q: %s (%s), want %s", c.model, got.Decision, got.Reason, c.want)
			continue
		}
		if got.Decision == Deny {
			want := `model ` + quoteModel(c.model) + ` is not in the allow_models of policy "fleet" (target agent://acme.example/fleet/*)`
			if got.Reason != want {
				t.Errorf("model %.40q: reason %q, want %q", c.model, got.Reason, want)
			}
			if strings.ContainsAny(got.Reason, "\n\x00") {
				t.Errorf("model %.40q: the reason carries a raw control character: %q", c.model, got.Reason)
			}
		}
	}
}

// quoteModel is how a reason prints a model: Go-quoted, so a control
// character in it is escaped, never written raw into a log line.
func quoteModel(m string) string { return strconv.Quote(m) }

// No list, an empty list, or a list with only other agents' policies restricts
// nothing: an empty list read as deny-all would refuse every model of every
// policy written before the key existed.
func TestNoAllowModelsMeansNoRestriction(t *testing.T) {
	for name, p := range map[string]policy.Policy{
		"absent": modelPolicy(t, "fleet"),
		"empty":  modelPolicy(t, "fleet", []string{}...),
	} {
		if got := allowEngine(t, p).Decide(modelCall("claude-opus-5")); got.Decision != Allow {
			t.Errorf("%s list: %s (%s), want allow", name, got.Decision, got.Reason)
		}
	}
	other := modelPolicy(t, "other", "claude-haiku-*")
	other.Target = "agent://acme.example/other/*"
	if got := allowEngine(t, other).Decide(modelCall("claude-opus-5")); got.Decision != Allow {
		t.Errorf("a list on another agent's policy: %s (%s), want allow", got.Decision, got.Reason)
	}
}

// A model call that names no model is refused under a list. TokenFuse sends
// the body's model field as it is, so a body with "model": "" reaches the
// decision as an empty model, and an upstream that fills in a default would
// otherwise serve whatever model it likes. A body with no model at all arrives
// as "unknown", which a list refuses like any unlisted name.
func TestAModelCallThatNamesNoModelIsRefused(t *testing.T) {
	e := allowEngine(t, modelPolicy(t, "fleet", "claude-sonnet-*"))
	for _, m := range []string{"", "   ", "\t"} {
		got := e.Decide(modelCall(m))
		want := `model ` + quoteModel(m) + ` is not in the allow_models of policy "fleet" (target agent://acme.example/fleet/*)`
		if got.Decision != Deny || got.Reason != want {
			t.Errorf("a model call with model %q: %s (%s), want deny %q", m, got.Decision, got.Reason, want)
		}
	}
}

// Only a model call is judged. A request that carries a tool_call is a tool
// decision (TokenFuse's MCP broker sends the call and an empty model), and a
// request that sends no model at all is not about a model call (scopyx's
// egress checks send agent, run and domains only): allow_models does not judge
// either, whatever its model field says, the way allow_domains does not judge
// a request that declares no domain.
func TestOnlyAModelCallIsJudgedByAllowModels(t *testing.T) {
	e := allowEngine(t, modelPolicy(t, "fleet", "claude-sonnet-*"))
	cases := map[string]DecideRequest{
		"an egress check, no model sent": {AgentID: fleetAgent, RunID: "run-1", Domains: []string{"api.example.com"}, ModelAbsent: true},
		"a tool call with an empty model": {AgentID: fleetAgent, RunID: "run-1", ToolNames: []string{"search"},
			ToolCall: &ToolCall{Name: "search", Target: "mcp://search"}},
		"a tool call naming a refused model": {AgentID: fleetAgent, RunID: "run-1", ToolNames: []string{"search"}, Model: "claude-opus-5",
			ToolCall: &ToolCall{Name: "search", Target: "mcp://search"}},
	}
	for name, req := range cases {
		if got := e.Decide(req); got.Decision != Allow {
			t.Errorf("%s: %s (%s), want allow: allow_models judges model calls only", name, got.Decision, got.Reason)
		}
	}
	// The control: the same egress request that does send a model is a model
	// call, and its empty model is refused.
	sent := cases["an egress check, no model sent"]
	sent.ModelAbsent = false
	if got := e.Decide(sent); got.Decision != Deny {
		t.Fatalf("control: a request that sends an empty model is %s (%s), want deny", got.Decision, got.Reason)
	}
}

// Every matched list applies: a model must be named by each of them.
func TestTwoModelListsNarrowEachOther(t *testing.T) {
	a := modelPolicy(t, "a", "claude-*")
	b := modelPolicy(t, "b", "claude-sonnet-*", "gpt-*")
	e := allowEngine(t, a, b)
	if got := e.Decide(modelCall("claude-sonnet-5")); got.Decision != Allow {
		t.Fatalf("a model both lists name: %s (%s)", got.Decision, got.Reason)
	}
	if got := e.Decide(modelCall("claude-opus-5")); got.Decision != Deny || !strings.Contains(got.Reason, `policy "b"`) {
		t.Fatalf("a model only the first list names: %s (%s), want a deny naming policy b", got.Decision, got.Reason)
	}
	if got := e.Decide(modelCall("gpt-6")); got.Decision != Deny || !strings.Contains(got.Reason, `policy "a"`) {
		t.Fatalf("a model only the second list names: %s (%s), want a deny naming policy a", got.Decision, got.Reason)
	}
}

// The rule sits before the cost gate, so no approval can lift it: a person
// approving a costly call approves its price, not a model the policy refuses.
func TestAnApprovalDoesNotLiftAModelDenial(t *testing.T) {
	p := modelPolicy(t, "fleet", "claude-sonnet-*")
	p.RequireHumanAboveUSD = f64(1)
	e := allowEngine(t, p)
	req := modelCall("claude-opus-5")
	req.EstCostUSD = 5
	tok, _, err := approval.MintApprovalToken([]byte("signal-test-secret"), req.AgentID, req.RunID, req.ToolNames, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	req.ApprovalToken = tok
	if got := e.Decide(req); got.Decision != Deny || !strings.Contains(got.Reason, "allow_models") || got.ApprovalTokenRequired {
		t.Fatalf("an approved costly call on a refused model: %s (%s) tokenRequired=%v, want the model deny", got.Decision, got.Reason, got.ApprovalTokenRequired)
	}
	// The control: the same token lifts the cost hold for a model the list names.
	ok := req
	ok.Model = "claude-sonnet-5"
	if got := e.Decide(ok); got.Decision != Allow {
		t.Fatalf("control: the token no longer lifts the cost hold: %s (%s)", got.Decision, got.Reason)
	}
}

// The model is per request: the same agent and tool set may name another model
// on the next call. So nothing decided under the rule may be cached by a cache
// keyed on agent and tool set.
func TestAnAllowModelsDecisionIsNeverCacheable(t *testing.T) {
	e := allowEngine(t, modelPolicy(t, "fleet", "claude-sonnet-*"))
	for name, req := range map[string]DecideRequest{
		"an allowed model":           modelCall("claude-sonnet-5"),
		"a refused model":            modelCall("claude-opus-5"),
		"a request with no model":    modelCall(""),
		"an egress call, no model":   {AgentID: fleetAgent, RunID: "r", Domains: []string{"x.example"}, ModelAbsent: true},
		"a tool call, no model":      {AgentID: fleetAgent, RunID: "r", ToolNames: []string{"search"}, ToolCall: &ToolCall{Name: "search"}},
		"an allowed model, no tools": {AgentID: fleetAgent, RunID: "r", Model: "claude-sonnet-5"},
	} {
		if got := e.Decide(req); got.Cacheable {
			t.Errorf("%s (%s): marked cacheable", name, got.Decision)
		}
	}
	if got := allowEngine(t, modelPolicy(t, "fleet")).Decide(modelCall("claude-opus-5")); !got.Cacheable {
		t.Error("control: a policy without allow_models stopped being cacheable")
	}
}

// The property under the tests above, swept: over random policy sets and
// requests, allow_models denies exactly the requests whose model some matched
// non-empty list does not name, and changes nothing else. Each decision is
// compared with the same policies without the lists, and the match is
// recomputed here by a glob matcher written independently of the PDP's. 200
// seeds, so a counterexample is a number somebody can rerun.
func TestAllowModelsDeniesExactlyTheUnlistedModelsOverRandomPolicies(t *testing.T) {
	patterns := []string{"claude-sonnet-*", "claude-*", "gpt-6-mini", "gpt-?-mini", "*-mini", "gemini-*-pro", "unknown", "*"}
	models := []string{"claude-sonnet-5-5", "claude-opus-5", "gpt-6-mini", "gpt-7-mini", "gpt-6-mini-x", "gemini-3-pro", "gemini-pro",
		"unknown", "", "  ", "Claude-Sonnet-5", "claude-sonnet-5\x01", "llama-4", "gpt-66-mini", "o4-mini"}
	refused, allowedUnderList := 0, 0
	for seed := int64(1); seed <= 200; seed++ {
		r := rand.New(rand.NewSource(seed))
		// Each policy twice: with its list, and the same policy without one.
		var pols, ref []policy.Policy
		var lists [][]string
		for i, n := 0, 1+r.Intn(2); i < n; i++ {
			var list []string
			if r.Intn(4) != 0 {
				list = []string{}
				for k := r.Intn(4); k > 0; k-- {
					list = append(list, patterns[r.Intn(len(patterns))])
				}
			}
			name := string(rune('a' + i))
			with, without := modelPolicy(t, name, list...), modelPolicy(t, name)
			if r.Intn(3) == 0 {
				with.DenyTool, without.DenyTool = []string{"shell"}, []string{"shell"}
			}
			if r.Intn(3) == 0 {
				c := float64(r.Intn(10))
				with.RequireHumanAboveUSD, without.RequireHumanAboveUSD = f64(c), f64(c)
			}
			if r.Intn(3) == 0 {
				s := 1 + r.Intn(4)
				with.MaxSteps, without.MaxSteps = s, s
			}
			pols, ref, lists = append(pols, with), append(ref, without), append(lists, list)
		}
		e, base := sweptSet(t, seed, pols), sweptSet(t, seed, ref)

		req := modelCall(models[r.Intn(len(models))])
		if r.Intn(3) == 0 {
			req.ToolNames = []string{"shell"}
		}
		// One request in five is not a model call: an egress check that sends
		// no model, or a tool call. allow_models judges neither.
		switch r.Intn(10) {
		case 0:
			req.ModelAbsent = true
		case 1:
			req.ToolCall = &ToolCall{Name: "search", Target: "mcp://search"}
		}
		judged := !req.ModelAbsent && req.ToolCall == nil
		req.EstCostUSD = float64(r.Intn(15))
		req.Steps = r.Intn(5)

		got, want := e.Decide(req), base.Decide(req)
		listed, nonEmpty := true, 0
		for _, list := range lists {
			if len(list) == 0 {
				continue
			}
			nonEmpty++
			if judged && !anyGlob(list, req.Model) {
				listed = false
			}
		}
		if nonEmpty > 0 && got.Cacheable {
			t.Fatalf("seed %d: a decision under allow_models was cacheable", seed)
		}
		if listed {
			if nonEmpty > 0 {
				allowedUnderList++
			}
			if got.Decision != want.Decision || got.Reason != want.Reason || got.ApprovalTokenRequired != want.ApprovalTokenRequired {
				t.Fatalf("seed %d: model %q is listed (or no list applies) and the decision changed: %s (%s) -> %s (%s)", seed, req.Model, want.Decision, want.Reason, got.Decision, got.Reason)
			}
			continue
		}
		refused++
		if got.Decision != Deny {
			t.Fatalf("seed %d: model %q is not listed and was %s (%s)", seed, req.Model, got.Decision, got.Reason)
		}
		// Of the rules this sweep sets, only deny_tool runs before the model
		// rule, and its reason starts with the tool's name.
		if strings.HasPrefix(want.Reason, "tool ") && want.Decision == Deny {
			if got.Reason != want.Reason {
				t.Fatalf("seed %d: the model rule overtook a tool deny: %q -> %q", seed, want.Reason, got.Reason)
			}
		} else if !strings.Contains(got.Reason, "allow_models") {
			t.Fatalf("seed %d: model %q refused with a reason that does not name allow_models: %q", seed, req.Model, got.Reason)
		}
	}
	t.Logf("%d of 200 requests refused for their model, %d allowed past a list", refused, allowedUnderList)
	if refused < 30 || allowedUnderList < 20 {
		t.Fatalf("the sweep refused %d and let %d through a list: it measured too little", refused, allowedUnderList)
	}
}

func sweptSet(t *testing.T, seed int64, pols []policy.Policy) *Engine {
	t.Helper()
	set, err := policy.Compile(pols)
	if err != nil {
		t.Fatalf("seed %d: %v", seed, err)
	}
	return New(set, []byte("signal-test-secret"))
}

// anyGlob is the test's own reading of the glob syntax Target uses: "*" any
// run of characters, "?" exactly one, everything else itself. A blank model, or
// one with a control character or invalid UTF-8, matches nothing.
func anyGlob(patterns []string, model string) bool {
	if strings.TrimSpace(model) == "" || !utf8.ValidString(model) || strings.IndexFunc(model, func(r rune) bool { return r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) }) >= 0 {
		return false
	}
	for _, p := range patterns {
		if glob(p, model) {
			return true
		}
	}
	return false
}

func glob(p, s string) bool {
	if p == "" {
		return s == ""
	}
	switch p[0] {
	case '*':
		for i := 0; i <= len(s); i++ {
			if glob(p[1:], s[i:]) {
				return true
			}
		}
		return false
	case '?':
		if s == "" {
			return false
		}
		_, n := utf8.DecodeRuneInString(s)
		return glob(p[1:], s[n:])
	default:
		return s != "" && s[0] == p[0] && glob(p[1:], s[1:])
	}
}
