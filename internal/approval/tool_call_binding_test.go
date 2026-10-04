package approval

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/store"
)

// An approval is for the call a person read: name, target and arguments. These
// tests hold the digest, the token that carries it and the verification that
// compares it.

var bindSecret = []byte("bind-test-secret")

const (
	bindAgent = "agent://x/bot"
	bindRun   = "run-1"
)

var bindTools = []string{"s3.delete_object"}

func digestOf(args string) string {
	return ToolCallDigest("s3.delete_object", "s3://prod-backups", []byte(args), false)
}

func boundToken(t *testing.T, digest string) string {
	t.Helper()
	tok, _, err := MintApprovalTokenForCall(bindSecret, bindAgent, bindRun, bindTools, 100, digest, DefaultTTL)
	if err != nil {
		t.Fatalf("MintApprovalTokenForCall: %v", err)
	}
	return tok
}

func verifyFor(tok, digest string) error {
	return VerifyApprovalTokenForCall(bindSecret, tok, bindAgent, bindRun, bindTools, 100, digest)
}

// resign signs claims exactly as Mint does, so a test can hand the verifier a
// token that is well signed and wrong in one respect.
func resign(t *testing.T, c map[string]any) string {
	t.Helper()
	body, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	return payload + "." + sign(bindSecret, payload)
}

func claimsMap(t *testing.T, tok string) map[string]any {
	t.Helper()
	payload, _, _ := strings.Cut(tok, ".")
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// --- the digest ---

func TestTheDigestSeparatesEveryPartOfTheCall(t *testing.T) {
	base := ToolCallDigest("s3.delete_object", "s3://prod-backups", []byte(`{"k":1}`), false)
	if base != ToolCallDigest("s3.delete_object", "s3://prod-backups", []byte(`{"k":1}`), false) {
		t.Fatal("the digest is not deterministic")
	}
	if !validToolCallDigest(base) {
		t.Fatalf("%q is not a lowercase hex sha-256", base)
	}
	others := map[string]string{
		"name":      ToolCallDigest("s3.delete_bucket", "s3://prod-backups", []byte(`{"k":1}`), false),
		"target":    ToolCallDigest("s3.delete_object", "s3://prod-other", []byte(`{"k":1}`), false),
		"arguments": ToolCallDigest("s3.delete_object", "s3://prod-backups", []byte(`{"k":2}`), false),
		"truncated": ToolCallDigest("s3.delete_object", "s3://prod-backups", []byte(`{"k":1}`), true),
	}
	for part, d := range others {
		if d == base {
			t.Errorf("changing only the %s leaves the digest unchanged", part)
		}
	}
}

// Plain concatenation would make these one call.
func TestTheDigestCannotBeForgedByMovingBytesBetweenNameAndTarget(t *testing.T) {
	a := ToolCallDigest("ab", "c", nil, false)
	b := ToolCallDigest("a", "bc", nil, false)
	c := ToolCallDigest("abc", "", nil, false)
	if a == b || b == c || a == c {
		t.Fatalf("name and target are not delimited: %s %s %s", a, b, c)
	}
}

// Absent arguments, null and an empty object are three byte strings, the same
// three arguments_sha256 already tells apart. Equal meaning, different bytes:
// refused, never wrongly granted.
func TestTheDigestIsOverTheArgumentBytesAsReceived(t *testing.T) {
	seen := map[string]string{}
	for _, args := range []string{"", "null", "{}", "{ }", `{"a":1}`, `{ "a": 1 }`} {
		d := ToolCallDigest("t", "x", []byte(args), false)
		if prev, dup := seen[d]; dup {
			t.Errorf("arguments %q and %q share a digest", prev, args)
		}
		seen[d] = args
	}
	if ArgumentsSHA256([]byte(`{"a":1}`)) == ArgumentsSHA256([]byte(`{ "a":1}`)) {
		t.Error("the argument hash the events record is not over the exact bytes")
	}
}

// --- verification ---

func TestATokenBoundToACallVerifiesForThatCallOnly(t *testing.T) {
	a := digestOf(`{"bucket":"prod-backups"}`)
	b := digestOf(`{"bucket":"prod-customers"}`)
	tok := boundToken(t, a)

	if err := verifyFor(tok, a); err != nil {
		t.Fatalf("the approved call is refused: %v", err)
	}
	if err := verifyFor(tok, b); !errors.Is(err, ErrTokenToolCall) {
		t.Fatalf("another call of the same tool = %v, want ErrTokenToolCall", err)
	}
	if err := verifyFor(tok, ""); !errors.Is(err, ErrTokenToolCall) {
		t.Fatalf("a request with no tool call = %v, want ErrTokenToolCall", err)
	}
	// The legacy entry point is the no-tool-call contract and so refuses too.
	if err := VerifyApprovalToken(bindSecret, tok, bindAgent, bindRun, bindTools, 100); !errors.Is(err, ErrTokenToolCall) {
		t.Fatalf("VerifyApprovalToken on a bound token = %v, want ErrTokenToolCall", err)
	}
}

func TestTheRefusalNeverCarriesADigest(t *testing.T) {
	a, b := digestOf(`{"a":1}`), digestOf(`{"a":2}`)
	err := verifyFor(boundToken(t, a), b)
	if err == nil || strings.Contains(err.Error(), a) || strings.Contains(err.Error(), b) {
		t.Fatalf("the refusal %v names a digest", err)
	}
}

func TestEveryOtherBindingStillAppliesToABoundToken(t *testing.T) {
	d := digestOf(`{"a":1}`)
	tok := boundToken(t, d)
	if err := VerifyApprovalTokenForCall(bindSecret, tok, "agent://x/other", bindRun, bindTools, 100, d); !errors.Is(err, ErrTokenBinding) {
		t.Errorf("other agent = %v", err)
	}
	if err := VerifyApprovalTokenForCall(bindSecret, tok, bindAgent, "run-2", bindTools, 100, d); !errors.Is(err, ErrTokenBinding) {
		t.Errorf("other run = %v", err)
	}
	if err := VerifyApprovalTokenForCall(bindSecret, tok, bindAgent, bindRun, []string{"other"}, 100, d); !errors.Is(err, ErrTokenBinding) {
		t.Errorf("other tool set = %v", err)
	}
	if err := VerifyApprovalTokenForCall(bindSecret, tok, bindAgent, bindRun, bindTools, 100.01, d); !errors.Is(err, ErrTokenCostExceeded) {
		t.Errorf("over the ceiling = %v", err)
	}
	expired, _, _ := MintApprovalTokenForCall(bindSecret, bindAgent, bindRun, bindTools, 100, d, -time.Second)
	if err := VerifyApprovalTokenForCall(bindSecret, expired, bindAgent, bindRun, bindTools, 100, d); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("expired = %v", err)
	}
	if err := VerifyApprovalTokenForCall([]byte("another-secret"), tok, bindAgent, bindRun, bindTools, 100, d); !errors.Is(err, ErrTokenSignature) {
		t.Errorf("other secret = %v", err)
	}
}

// Every token minted before this change, and every token minted for a hold
// whose request carried no tool call, is this shape.
func TestALegacyTokenOnARequestWithNoToolCallIsAcceptedAsBefore(t *testing.T) {
	legacy, _, err := MintApprovalToken(bindSecret, bindAgent, bindRun, bindTools, 100, DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	c := claimsMap(t, legacy)
	for _, k := range []string{"v", "tcd"} {
		if _, ok := c[k]; ok {
			t.Fatalf("a token minted for no call carries %q: the old format is not kept: %v", k, c)
		}
	}
	if err := verifyFor(legacy, ""); err != nil {
		t.Fatalf("a legacy token on a request with no tool call = %v, want nil", err)
	}
	if err := VerifyApprovalToken(bindSecret, legacy, bindAgent, bindRun, bindTools, 100); err != nil {
		t.Fatalf("VerifyApprovalToken = %v, want nil", err)
	}
}

// Granted with no call in view, so nobody was shown one: it binds what it
// always did, and a digest nobody computed is not invented for it.
func TestALegacyTokenOnARequestThatNowCarriesACallBindsWhatItAlwaysDid(t *testing.T) {
	legacy, _, _ := MintApprovalToken(bindSecret, bindAgent, bindRun, bindTools, 100, DefaultTTL)
	if err := verifyFor(legacy, digestOf(`{"a":1}`)); err != nil {
		t.Fatalf("= %v, want nil", err)
	}
}

// The exact claims JSON a build before this change wrote, hand signed.
func TestATokenInTheExactPreChangeFormatStillVerifies(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
		`{"agent_id":%q,"run_id":%q,"tools":["s3.delete_object"],"max_cost_usd":100,"exp":%d,"nonce":"0123456789abcdef"}`,
		bindAgent, bindRun, time.Now().Add(time.Minute).Unix())))
	tok := payload + "." + sign(bindSecret, payload)
	if err := verifyFor(tok, ""); err != nil {
		t.Fatalf("a pre-change token = %v, want nil", err)
	}
}

func TestMintingABoundTokenRefusesAMalformedDigestAndNoSecret(t *testing.T) {
	for _, bad := range []string{"abc", strings.Repeat("g", 64), strings.ToUpper(digestOf("x")), digestOf("x") + "0"} {
		if _, _, err := MintApprovalTokenForCall(bindSecret, bindAgent, bindRun, bindTools, 1, bad, DefaultTTL); !errors.Is(err, ErrToolCallContext) {
			t.Errorf("digest %q minted: %v", bad, err)
		}
	}
	if _, _, err := MintApprovalTokenForCall(nil, bindAgent, bindRun, bindTools, 1, digestOf("x"), DefaultTTL); !errors.Is(err, ErrNoSecret) {
		t.Errorf("no secret = %v, want ErrNoSecret", err)
	}
}

// --- hostile tokens: refused, never a panic, never an allow ---

func TestHostileTokensAreRefusedWithoutPanic(t *testing.T) {
	d := digestOf(`{"a":1}`)
	other := digestOf(`{"a":2}`)
	good := boundToken(t, d)
	base := func() map[string]any {
		m := claimsMap(t, good)
		return m
	}
	with := func(k string, v any) map[string]any { m := base(); m[k] = v; return m }
	without := func(k string) map[string]any { m := base(); delete(m, k); return m }

	tampered := func() string {
		payload, sig, _ := strings.Cut(good, ".")
		raw, _ := base64.RawURLEncoding.DecodeString(payload)
		raw = []byte(strings.Replace(string(raw), d, other, 1))
		return base64.RawURLEncoding.EncodeToString(raw) + "." + sig
	}()

	cases := []struct {
		name string
		tok  string
		want error
	}{
		{"digest edited, signature kept", tampered, ErrTokenSignature},
		{"digest replaced and re-signed", resign(t, with("tcd", other)), ErrTokenToolCall},
		{"digest stripped and re-signed, version kept", resign(t, without("tcd")), ErrTokenMalformed},
		{"digest and version stripped, re-signed, as a legacy token", resign(t, without("v")), ErrTokenVersion},
		{"version 1", resign(t, with("v", 1)), ErrTokenVersion},
		{"version 3", resign(t, with("v", 3)), ErrTokenVersion},
		{"version negative", resign(t, with("v", -2)), ErrTokenVersion},
		{"version huge", resign(t, with("v", 1<<40)), ErrTokenVersion},
		{"version a string", resign(t, with("v", "2")), ErrTokenMalformed},
		{"version a fraction", resign(t, with("v", 2.5)), ErrTokenMalformed},
		{"version null with a digest", resign(t, with("v", nil)), ErrTokenVersion},
		{"digest empty", resign(t, with("tcd", "")), ErrTokenMalformed},
		{"digest short", resign(t, with("tcd", d[:63])), ErrTokenMalformed},
		{"digest long", resign(t, with("tcd", d+"0")), ErrTokenMalformed},
		{"digest upper case", resign(t, with("tcd", strings.ToUpper(d))), ErrTokenMalformed},
		{"digest not hex", resign(t, with("tcd", strings.Repeat("z", 64))), ErrTokenMalformed},
		{"digest a number", resign(t, with("tcd", 7)), ErrTokenMalformed},
		{"digest an array", resign(t, with("tcd", []string{d})), ErrTokenMalformed},
		{"claims not an object", func() string {
			p := base64.RawURLEncoding.EncodeToString([]byte(`[1,2]`))
			return p + "." + sign(bindSecret, p)
		}(), ErrTokenMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := verifyFor(c.tok, d)
			if err == nil {
				t.Fatal("a hostile token verified")
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("= %v, want %v", err, c.want)
			}
		})
	}
}

// A token that is only version 0 but carries a digest is not something this
// package mints; it must not be read as "legacy, no digest to check".
func TestALegacyVersionTokenCarryingADigestIsRefusedNotTreatedAsUnbound(t *testing.T) {
	m := claimsMap(t, boundToken(t, digestOf("x")))
	delete(m, "v")
	tok := resign(t, m)
	for _, presented := range []string{"", digestOf("x"), digestOf("y")} {
		if err := verifyFor(tok, presented); !errors.Is(err, ErrTokenVersion) {
			t.Errorf("presented %q: %v, want ErrTokenVersion", presented, err)
		}
	}
}

func TestEveryPrefixOfATokenAndRandomBytesAreRefusedWithoutPanic(t *testing.T) {
	d := digestOf("x")
	tok := boundToken(t, d)
	for i := 0; i < len(tok); i++ {
		if err := verifyFor(tok[:i], d); err == nil {
			t.Fatalf("a %d-byte prefix of a token verified", i)
		}
	}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 500; i++ {
		b := make([]byte, rng.Intn(120))
		rng.Read(b)
		_ = verifyFor(string(b), d)
		_ = verifyFor(base64.RawURLEncoding.EncodeToString(b)+"."+strings.Repeat("0", 64), d)
	}
}

// --- the grant ---

func TestGrantingAHoldThatCarriedACallBindsTheTokenToIt(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := digestOf(`{"a":1}`)
	held, err := Request(ctx, st, bindAgent, bindRun, bindTools, map[string]any{
		"est_cost_usd": 100.0,
		ContextKeyToolCall: map[string]any{
			"name": "s3.delete_object", "target": "s3://prod-backups", "arguments_truncated": false, ContextKeyDigest: d,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, tok, err := Decide(ctx, st, bindSecret, held.ApprovalID, "grant", "alice", DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyFor(tok, d); err != nil {
		t.Fatalf("the granted call is refused: %v", err)
	}
	if err := verifyFor(tok, digestOf(`{"a":2}`)); !errors.Is(err, ErrTokenToolCall) {
		t.Fatalf("another call = %v, want ErrTokenToolCall", err)
	}
}

func TestAHoldWithADamagedCallDigestIsNotGrantedUnboundAndStaysPending(t *testing.T) {
	damaged := map[string]map[string]any{
		"no digest":        {"name": "s3.delete_object"},
		"digest empty":     {"name": "s3.delete_object", ContextKeyDigest: ""},
		"digest malformed": {"name": "s3.delete_object", ContextKeyDigest: "abc"},
		"digest a number":  {"name": "s3.delete_object", ContextKeyDigest: 5},
	}
	for name, tc := range damaged {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			st := store.NewMemory()
			held, err := Request(ctx, st, bindAgent, bindRun, bindTools, map[string]any{ContextKeyToolCall: tc})
			if err != nil {
				t.Fatal(err)
			}
			_, tok, err := Decide(ctx, st, bindSecret, held.ApprovalID, "grant", "alice", DefaultTTL)
			if !errors.Is(err, ErrToolCallContext) || tok != "" {
				t.Fatalf("Decide = %q, %v; want no token and ErrToolCallContext", tok, err)
			}
			still, _ := st.GetApproval(ctx, held.ApprovalID)
			if !still.Pending() {
				t.Fatal("the refused grant left the approval decided")
			}
		})
	}
	// A context where tool_call is not even a map is the same refusal.
	ctx := context.Background()
	st := store.NewMemory()
	held, _ := Request(ctx, st, bindAgent, bindRun, bindTools, map[string]any{ContextKeyToolCall: "s3.delete_object"})
	if _, _, err := Decide(ctx, st, bindSecret, held.ApprovalID, "grant", "alice", DefaultTTL); !errors.Is(err, ErrToolCallContext) {
		t.Fatalf("a non-map tool_call = %v, want ErrToolCallContext", err)
	}
}

func TestGrantingAHoldThatCarriedNoCallMintsTheOldFormat(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	held, _ := Request(ctx, st, bindAgent, bindRun, bindTools, map[string]any{"est_cost_usd": 100.0})
	_, tok, err := Decide(ctx, st, bindSecret, held.ApprovalID, "grant", "alice", DefaultTTL)
	if err != nil {
		t.Fatal(err)
	}
	c := claimsMap(t, tok)
	if _, ok := c["tcd"]; ok {
		t.Fatalf("an unbound hold minted a digest: %v", c)
	}
	if err := verifyFor(tok, ""); err != nil {
		t.Fatal(err)
	}
}

func TestDenyingAHoldNeedsNoDigest(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	held, _ := Request(ctx, st, bindAgent, bindRun, bindTools, map[string]any{ContextKeyToolCall: map[string]any{"name": "x"}})
	if _, tok, err := Decide(ctx, st, bindSecret, held.ApprovalID, "deny", "alice", DefaultTTL); err != nil || tok != "" {
		t.Fatalf("deny = %q, %v", tok, err)
	}
}

// --- what holds the rest of the binding in place ---

// The digest is compared in constant time, as the signature is, and neither
// with == or !=. The behaviour is identical either way, so a behavioural test
// cannot hold this; the source can.
func TestTheSignatureAndTheDigestAreComparedInConstantTime(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "approval.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if x, ok := d.(*ast.FuncDecl); ok && x.Name.Name == "VerifyApprovalTokenForCall" {
			fn = x
		}
	}
	if fn == nil {
		t.Fatal("VerifyApprovalTokenForCall not found: this test measured nothing")
	}
	equalCalls := 0
	var plain []string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "hmac" && sel.Sel.Name == "Equal" {
					equalCalls++
				}
			}
		case *ast.BinaryExpr:
			// Comparing with the empty string asks whether a value is present,
			// which reveals nothing about its content.
			if lit, ok := x.Y.(*ast.BasicLit); ok && lit.Value == `""` {
				return true
			}
			if x.Op == token.EQL || x.Op == token.NEQ {
				for _, side := range []ast.Expr{x.X, x.Y} {
					text := exprText(side)
					if strings.Contains(text, "ToolCallDigest") || text == "sig" || text == "want" || text == "toolCallDigest" {
						plain = append(plain, text)
					}
				}
			}
		}
		return true
	})
	if equalCalls < 2 {
		t.Errorf("hmac.Equal is called %d times in VerifyApprovalTokenForCall, want the signature and the digest (2)", equalCalls)
	}
	if len(plain) > 0 {
		t.Errorf("a secret-derived value is compared with == or !=: %v", plain)
	}
}

func exprText(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return exprText(x.X) + "." + x.Sel.Name
	}
	return ""
}

// The decision path must hand the verifier the call. VerifyApprovalToken and
// MintApprovalToken stand for "no tool call"; a production caller that used
// either would be asking the unbound question about a call it holds.
func TestNoProductionCodeOutsideThisPackageUsesTheUnboundEntryPoints(t *testing.T) {
	root := filepath.Join("..", "..")
	re := regexp.MustCompile(`approval\.(VerifyApprovalToken|MintApprovalToken)\(`)
	scanned, offenders := 0, []string{}
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		scanned++
		b, _ := os.ReadFile(p)
		if re.Match(b) {
			offenders = append(offenders, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 10 {
		t.Fatalf("scanned %d Go files from %s: this test measured nothing", scanned, root)
	}
	if len(offenders) > 0 {
		t.Fatalf("production code asks the unbound question: %v", offenders)
	}
}
