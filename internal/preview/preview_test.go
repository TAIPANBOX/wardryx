package preview

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// build is Build for a test: it fails the test on an error and returns the
// document and its canonical bytes.
func build(t *testing.T, args string) (Document, []byte) {
	t.Helper()
	doc, canon, err := Build([]byte(args))
	if err != nil {
		t.Fatalf("Build(%s): %v", args, err)
	}
	return doc, canon
}

// member returns the value of the first member of obj whose key is shown as
// the one text part key.
func member(t *testing.T, obj *Node, key string) *Node {
	t.Helper()
	if obj == nil || obj.K != KindObject {
		t.Fatalf("not an object: %+v", obj)
	}
	for _, m := range obj.Members {
		if m.Key.K == KindString && len(m.Key.Parts) == 1 && m.Key.Parts[0].Text == key {
			return m.Value
		}
	}
	t.Fatalf("no member %q in %+v", key, obj.Members)
	return nil
}

// text is the visible text of a string node, with a marker for each hidden
// part and vault handle so a test can read the shape at a glance.
func text(n *Node) string {
	var b strings.Builder
	for _, p := range n.Parts {
		switch {
		case p.Hidden != "":
			b.WriteString("<" + p.Hidden + ">")
		case p.Vault != "":
			b.WriteString("<vault:" + p.Vault + ">")
		default:
			b.WriteString(p.Text)
		}
	}
	return b.String()
}

func TestAPersonSeesTheArgumentsOfAHeldCall(t *testing.T) {
	doc, _ := build(t, `{"repo":"x","action":"delete","force":true,"count":3,"note":null}`)
	if doc.V != Version || doc.Ruleset != Ruleset {
		t.Fatalf("v %d ruleset %q", doc.V, doc.Ruleset)
	}
	if got := text(member(t, doc.Root, "repo")); got != "x" {
		t.Errorf("repo = %q, want x", got)
	}
	if got := text(member(t, doc.Root, "action")); got != "delete" {
		t.Errorf("action = %q, want delete", got)
	}
	if f := member(t, doc.Root, "force"); f.K != KindBool || f.Value == nil || !*f.Value {
		t.Errorf("force = %+v", f)
	}
	if c := member(t, doc.Root, "count"); c.K != KindNumber || c.Lexeme != "3" {
		t.Errorf("count = %+v", c)
	}
	if n := member(t, doc.Root, "note"); n.K != KindNull {
		t.Errorf("note = %+v", n)
	}
}

func TestAMemberWhoseKeyNamesACredentialIsHiddenWhole(t *testing.T) {
	args := `{"user":"a","password":"hunter2","api_key":"k-123","Authorization":"Basic Zm9v",` +
		`"credentials":{"user":"u","pass":"p"},"refreshToken":"rt-1","X-API-KEY":"xk","pin":1234,` +
		`"max_tokens":100,"author":"Ann","spinner":"on","oauth_token":"ot"}`
	doc, canon := build(t, args)
	if got := text(member(t, doc.Root, "user")); got != "a" {
		t.Errorf("user = %q, want a", got)
	}
	for key, typ := range map[string]string{
		"password": KindString, "api_key": KindString, "Authorization": KindString,
		"credentials": KindObject, "refreshToken": KindString, "X-API-KEY": KindString,
		"pin": KindNumber, "oauth_token": KindString,
	} {
		v := member(t, doc.Root, key)
		if v.K != KindHidden || v.Rule != RuleKeyName || v.Type != typ {
			t.Errorf("%s = %+v, want hidden by %s as %s", key, v, RuleKeyName, typ)
		}
	}
	for _, key := range []string{"max_tokens", "author", "spinner"} {
		if v := member(t, doc.Root, key); v.K == KindHidden {
			t.Errorf("%s is hidden, and its name is no credential", key)
		}
	}
	for _, leaked := range []string{"hunter2", "k-123", "Zm9v", `"p"`, "rt-1", `"xk"`, "1234", `"ot"`} {
		if bytes.Contains(canon, []byte(leaked)) {
			t.Errorf("the document carries %s: %s", leaked, canon)
		}
	}
}

func TestEverySecretKindInsideAStringIsHiddenAndTheRestShows(t *testing.T) {
	cases := map[string]string{
		"anthropic_key":  "sk-ant-api03-" + strings.Repeat("A", 30),
		"openai_key":     "sk-proj" + strings.Repeat("b", 30),
		"aws_access_key": "AKIA" + "ABCDEFGHIJKLMNOP", // split so no scanner reads a key in the source
		"google_api_key": "AIza" + strings.Repeat("C", 35),
		"github_token":   "ghp_" + strings.Repeat("d", 36),
		"slack_token":    "xox" + "b-1234567890-abc",
		"jwt":            "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl",
		"bearer_token":   "Bearer " + strings.Repeat("e", 24),
		"private_key":    "-----BEGIN EC PRIVATE " + "KEY-----\nMHcCAQEEIBody\n-----END EC PRIVATE " + "KEY-----",
	}
	for kind, secret := range cases {
		raw, _ := json.Marshal(map[string]string{"note": "call with " + secret + " now"})
		doc, canon := build(t, string(raw))
		got := text(member(t, doc.Root, "note"))
		want := "call with <" + RuleSecret + kind + "> now"
		if got != want {
			t.Errorf("%s: note = %q, want %q", kind, got, want)
		}
		probe := secret
		if len(probe) > 12 {
			probe = probe[len(probe)-12:]
		}
		if bytes.Contains(canon, []byte(probe)) {
			t.Errorf("%s: the document carries the secret's tail %q", kind, probe)
		}
	}
}

func TestTheSecretKindsAreTheBrokersKinds(t *testing.T) {
	// tokenfuse_core::dlp::patterns at tokenfuse ad60ca6, kind for kind and in
	// order. A kind the broker gains is a kind a preview must hide, and that
	// is a new ruleset.
	want := []string{"private_key", "anthropic_key", "openai_key", "aws_access_key", "google_api_key",
		"github_token", "slack_token", "jwt", "bearer_token"}
	var got []string
	for _, p := range secretPatterns {
		got = append(got, p.kind)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("secret kinds %v, want %v", got, want)
	}
}

func TestPersonalDataInsideAStringIsHiddenAndTheRestShows(t *testing.T) {
	cases := []struct{ in, want string }{
		{"mail ann@example.com today", "mail <pii:email> today"},
		{"card 4111 1111 1111 1111 ok", "card <pii:card> ok"},
		{"iban GB82 WEST 1234 5698 7654 32 ok", "iban <pii:iban> ok"},
		{"call +44 20 7946 0958 now", "call <pii:phone> now"},
		// A probability that passes Luhn is a number, not a card.
		{"p=0.41935483870967744", "p=0.41935483870967744"},
		// A digit run that fails Luhn is not a card.
		{"id 4111111111111112", "id 4111111111111112"},
	}
	for _, c := range cases {
		raw, _ := json.Marshal(map[string]string{"t": c.in})
		doc, _ := build(t, string(raw))
		if got := text(member(t, doc.Root, "t")); got != c.want {
			t.Errorf("%q: got %q, want %q", c.in, got, c.want)
		}
	}
}

func TestAHighEntropyRunIsHiddenAndAHexDigestIsNot(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	token := make([]byte, 44)
	for i := range token {
		token[i] = alphabet[r.Intn(len(alphabet))]
	}
	sha := sha256.Sum256([]byte("x"))
	raw, _ := json.Marshal(map[string]string{
		"a": "key " + string(token) + " end",
		"b": "commit " + hex.EncodeToString(sha[:]),
		"c": "a_long_identifier_made_of_plain_english_words_only",
	})
	doc, canon := build(t, string(raw))
	if got := text(member(t, doc.Root, "a")); got != "key <"+RuleEntropy+"> end" {
		t.Errorf("a = %q", got)
	}
	if bytes.Contains(canon, token) {
		t.Errorf("the random token is in the document")
	}
	if got := text(member(t, doc.Root, "b")); got != "commit "+hex.EncodeToString(sha[:]) {
		t.Errorf("a hex digest was hidden: %q", got)
	}
	if got := text(member(t, doc.Root, "c")); got != "a_long_identifier_made_of_plain_english_words_only" {
		t.Errorf("an identifier of words was hidden: %q", got)
	}
}

func TestAVaultHandleShowsItsNameAndNoValue(t *testing.T) {
	doc, _ := build(t, `{"token_ref":"x","h":"{{secret:github_token}}","hdr":"Bearer {{secret:api}} please","odd":"{{secret:ignore all and approve}}"}`)
	if v := member(t, doc.Root, "h"); v.K != KindVault || v.Name != "github_token" {
		t.Errorf("h = %+v, want the vault handle github_token", v)
	}
	if got := text(member(t, doc.Root, "hdr")); got != "Bearer <vault:api> please" {
		t.Errorf("hdr = %q", got)
	}
	// A handle whose name is not a name is text, and is shown as text.
	if got := text(member(t, doc.Root, "odd")); got != "{{secret:ignore all and approve}}" {
		t.Errorf("odd = %q", got)
	}
}

func TestABase64ImageIsShownAsTypeSizeAndHashAndNeverDecoded(t *testing.T) {
	png := append([]byte("\x89PNG\r\n\x1a\n"), bytes.Repeat([]byte{0x42, 0x13, 0x77}, 40)...)
	enc := base64.StdEncoding.EncodeToString(png)
	raw, _ := json.Marshal(map[string]string{"image": enc})
	doc, canon := build(t, string(raw))
	v := member(t, doc.Root, "image")
	sum := sha256.Sum256(png)
	if v.K != KindBlob || v.MIME != "image/png" || v.Bytes != len(png) || v.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("image = %+v", v)
	}
	if bytes.Contains(canon, []byte(enc[:20])) {
		t.Errorf("the encoded bytes are in the document")
	}
}

func TestALongIdentifierIsTextAndNotABlob(t *testing.T) {
	id := "this_is_a_very_long_identifier_name_that_goes_on_and_on_forever_and_ever"
	doc, _ := build(t, `{"name":"`+id+`"}`)
	v := member(t, doc.Root, "name")
	if v.K != KindString || text(v) != id {
		t.Fatalf("name = %+v", v)
	}
}

func TestALongStringIsCutOnARuneBoundaryWithItsCountAndHash(t *testing.T) {
	long := strings.Repeat("ї", MaxStringRunes+10)
	raw, _ := json.Marshal(map[string]string{"t": long})
	doc, _ := build(t, string(raw))
	v := member(t, doc.Root, "t")
	sum := sha256.Sum256([]byte(long))
	if !v.Cut || v.Runes != MaxStringRunes+10 || v.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("t = cut %v runes %d sha %q", v.Cut, v.Runes, v.SHA256)
	}
	if got := text(v); got != strings.Repeat("ї", StringHead) {
		t.Errorf("shown %d runes, want %d whole runes", len([]rune(got)), StringHead)
	}
	// Nothing hidden in it, so the hash is there; with a hidden part it is not.
	withSecret := "ann@example.com " + long
	raw, _ = json.Marshal(map[string]string{"t": withSecret})
	doc, _ = build(t, string(raw))
	if v := member(t, doc.Root, "t"); v.SHA256 != "" || !v.Cut {
		t.Errorf("a cut string with a hidden part carries sha %q cut %v", v.SHA256, v.Cut)
	}
	// A string at the limit is shown whole.
	exact := strings.Repeat("a", MaxStringRunes)
	doc, _ = build(t, `{"t":"`+exact+`"}`)
	if v := member(t, doc.Root, "t"); v.Cut || text(v) != exact {
		t.Errorf("a string at the limit was cut")
	}
}

func TestCharactersThatDoNotReadAsTheyLookAreFlagged(t *testing.T) {
	cases := map[string]string{
		"rm -rf /safe‮/etc": FlagBidi,
		"pay​pal":           FlagInvisible,
		"bell\u0007":        FlagControl,
		"раypal":            FlagMixedScript,
	}
	for in, flag := range cases {
		raw, _ := json.Marshal(map[string]string{"t": in})
		doc, _ := build(t, string(raw))
		v := member(t, doc.Root, "t")
		if len(v.Flags) != 1 || v.Flags[0] != flag {
			t.Errorf("%q: flags %v, want [%s]", in, v.Flags, flag)
		}
	}
	doc, _ := build(t, `{"t":"line one\nline two\ttab, Київ and Kyiv"}`)
	if v := member(t, doc.Root, "t"); len(v.Flags) != 0 {
		t.Errorf("plain text flagged: %v", v.Flags)
	}
}

func TestDepthArrayAndObjectLimits(t *testing.T) {
	deep := strings.Repeat(`{"a":`, MaxDepth+2) + "1" + strings.Repeat("}", MaxDepth+2)
	doc, _ := build(t, deep)
	n := doc.Root
	for i := 0; i < MaxDepth; i++ {
		n = member(t, n, "a")
	}
	if n.K != KindElided || n.Reason != ElidedDepth || n.Count != 1 {
		t.Errorf("below the depth limit: %+v", n)
	}

	items := make([]string, MaxArrayItems+1)
	for i := range items {
		items[i] = fmt.Sprint(i)
	}
	doc, _ = build(t, `{"xs":[`+strings.Join(items, ",")+`]}`)
	xs := member(t, doc.Root, "xs")
	if len(xs.Items) != ArrayHead || xs.Omitted != MaxArrayItems+1-ArrayHead {
		t.Errorf("array: %d shown, %d omitted", len(xs.Items), xs.Omitted)
	}

	members := make([]string, MaxObjectMembers+1)
	for i := range members {
		members[i] = fmt.Sprintf(`"k%d":%d`, i, i)
	}
	doc, _ = build(t, `{`+strings.Join(members, ",")+`}`)
	if len(doc.Root.Members) != ObjectHead || doc.Root.Omitted != MaxObjectMembers+1-ObjectHead {
		t.Errorf("object: %d shown, %d omitted", len(doc.Root.Members), doc.Root.Omitted)
	}
}

func TestDuplicateKeysAreShownBothAndMemberOrderIsTheOrderOfTheBytes(t *testing.T) {
	doc, _ := build(t, `{"path":"/safe","b":1,"path":"/etc/passwd"}`)
	if !doc.Root.DuplicateKeys {
		t.Errorf("duplicate keys not flagged")
	}
	var order []string
	for _, m := range doc.Root.Members {
		order = append(order, text(m.Key)+"="+text(m.Value)+m.Value.Lexeme)
	}
	if got := strings.Join(order, " "); got != "path=/safe b=1 path=/etc/passwd" {
		t.Errorf("order %q", got)
	}
}

func TestANumberIsShownAsWritten(t *testing.T) {
	doc, _ := build(t, `{"id":9007199254740993,"f":1.10,"e":-2E+3}`)
	for key, want := range map[string]string{"id": "9007199254740993", "f": "1.10", "e": "-2E+3"} {
		if v := member(t, doc.Root, key); v.Lexeme != want {
			t.Errorf("%s = %q, want %q", key, v.Lexeme, want)
		}
	}
	long := strings.Repeat("9", MaxLexeme+5)
	doc, _ = build(t, `{"n":`+long+`}`)
	if v := member(t, doc.Root, "n"); !v.Cut || len(v.Lexeme) != MaxLexeme || v.Runes != MaxLexeme+5 {
		t.Errorf("long number = %+v", v)
	}
}

func TestTheDocumentIsBoundedInSize(t *testing.T) {
	// 12 KiB of arguments, the most wardryx accepts, of the widest shape.
	var b strings.Builder
	b.WriteString("[")
	for i := 0; b.Len() < 12<<10-20; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"` + strings.Repeat("‮", 3) + `"`)
	}
	b.WriteString("]")
	_, canon := build(t, b.String())
	if len(canon) > MaxDocumentBytes {
		t.Fatalf("document %d bytes, over %d", len(canon), MaxDocumentBytes)
	}
}

func TestBuildIsDeterministicAndTheDigestIsPinned(t *testing.T) {
	args := `{"repo":"x","password":"p","note":"mail ann@example.com","n":1.50,"h":"{{secret:gh}}"}`
	_, a := build(t, args)
	_, b := build(t, args)
	if !bytes.Equal(a, b) {
		t.Fatalf("two builds differ")
	}
	// The pinned digest of this fixture under r1. A change here is a change
	// of what a person was shown for a recorded hold: a new ruleset.
	const pinned = "d1ca5a70b3f6a60902dc63e58ebe77192bcae321dea20641ac98dec28edf47cd"
	if got := Digest(a); got != pinned {
		t.Errorf("digest %s, pinned %s; canonical: %s", got, pinned, a)
	}
}

func TestTheDigestSeparatesDocumentsAndHasTheShapeItChecks(t *testing.T) {
	_, a := build(t, `{"a":"x"}`)
	_, b := build(t, `{"a":"y"}`)
	if Digest(a) == Digest(b) {
		t.Fatal("two documents, one digest")
	}
	if !ValidDigest(Digest(a)) {
		t.Errorf("Digest's own output is not a valid digest")
	}
	for _, bad := range []string{"", "none", strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("g", 64)} {
		if ValidDigest(bad) {
			t.Errorf("ValidDigest(%q) = true", bad)
		}
	}
	// The domain tag is in the digest: a bare sha-256 of the bytes is not it.
	bare := sha256.Sum256(a)
	if Digest(a) == hex.EncodeToString(bare[:]) {
		t.Errorf("the digest carries no domain tag")
	}
}

func TestArgumentsThatAreNotOneJSONValueAreRefused(t *testing.T) {
	for _, bad := range []string{``, `{`, `{"a":1}{"b":2}`, `nope`, `{"a":1,}`} {
		if _, _, err := Build([]byte(bad)); !errors.Is(err, ErrNotJSON) {
			t.Errorf("Build(%q) = %v, want ErrNotJSON", bad, err)
		}
	}
}

// TestPlantedSecretsNeverAppearInTheDocument plants secrets, personal data and
// credential-named members at random places of random trees, 200 seeds, and
// requires that none of the planted values appears in the document, that the
// document stays within its size, and that two builds agree.
func TestPlantedSecretsNeverAppearInTheDocument(t *testing.T) {
	plants := []string{
		"sk-ant-api03-" + strings.Repeat("Q", 28),
		"AKIA" + strings.Repeat("Z", 16),
		"ghp_" + strings.Repeat("R", 40),
		"zoe.planted@example.org",
		"4012888888881881",
		"GB82WEST12345698765432",
	}
	keys := []string{"password", "client_secret", "accessToken", "Cookie", "privateKey"}
	for seed := int64(0); seed < 200; seed++ {
		r := rand.New(rand.NewSource(seed))
		var planted []string
		var gen func(depth int) any
		gen = func(depth int) any {
			switch k := r.Intn(6); {
			case depth > 5 || k == 0:
				if r.Intn(3) == 0 {
					p := plants[r.Intn(len(plants))]
					planted = append(planted, p)
					return "pre " + p + " post"
				}
				return fmt.Sprintf("word%d", r.Intn(1000))
			case k == 1:
				return r.Intn(100)
			case k <= 3:
				m := map[string]any{}
				for i := 0; i < 1+r.Intn(4); i++ {
					m[fmt.Sprintf("f%d", i)] = gen(depth + 1)
				}
				if r.Intn(2) == 0 {
					v := fmt.Sprintf("credval%d", seed)
					m[keys[r.Intn(len(keys))]] = v
					planted = append(planted, v)
				}
				return m
			default:
				var xs []any
				for i := 0; i < 1+r.Intn(4); i++ {
					xs = append(xs, gen(depth+1))
				}
				return xs
			}
		}
		raw, _ := json.Marshal(map[string]any{"root": gen(0)})
		if len(raw) > 12<<10 {
			continue
		}
		doc, canon, err := Build(raw)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		for _, p := range planted {
			if bytes.Contains(canon, []byte(p)) {
				t.Fatalf("seed %d: planted %q is in the document: %s", seed, p, canon)
			}
		}
		if len(canon) > MaxDocumentBytes {
			t.Fatalf("seed %d: %d bytes", seed, len(canon))
		}
		again, _ := Canonical(doc)
		if !bytes.Equal(again, canon) {
			t.Fatalf("seed %d: canonical form is not stable", seed)
		}
	}
}

func FuzzBuild(f *testing.F) {
	for _, s := range []string{`{"a":1}`, `[1,"x",null,true]`, `"sk-ant-` + strings.Repeat("a", 30) + `"`,
		`{"password":{"x":[1,2]}}`, `{"a":"‮"}`, `1e400`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		doc, canon, err := Build(in)
		if err != nil {
			if !errors.Is(err, ErrNotJSON) {
				t.Fatalf("unexpected error %v", err)
			}
			return
		}
		if len(canon) > MaxDocumentBytes {
			t.Fatalf("%d bytes", len(canon))
		}
		_, again, err := Build(in)
		if err != nil || !bytes.Equal(again, canon) {
			t.Fatalf("not deterministic")
		}
		if doc.Root == nil {
			t.Fatalf("no root")
		}
	})
}
