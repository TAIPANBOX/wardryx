package previewseal

import (
	"bytes"
	"crypto/hpke"
	"errors"
	"math/rand"
	"strings"
	"testing"

	"github.com/TAIPANBOX/wardryx/internal/preview"
)

func docFor(t *testing.T, args string) ([]byte, string) {
	t.Helper()
	_, canon, err := preview.Build([]byte(args))
	if err != nil {
		t.Fatal(err)
	}
	return canon, preview.Digest(canon)
}

func keys(t *testing.T, kem hpke.KEM) (hpke.PrivateKey, *Recipient) {
	t.Helper()
	privText, recText, err := GenerateKey(kem)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParsePrivateKey(privText)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseRecipient(recText)
	if err != nil {
		t.Fatal(err)
	}
	if r.String() != recText {
		t.Fatalf("recipient text does not round-trip")
	}
	return k, r
}

func TestASealedPreviewOpensOnlyUnderTheConsoleKeyAndItsBinding(t *testing.T) {
	for name, kem := range map[string]hpke.KEM{"hybrid": KEMHybrid, "x25519": KEMX25519} {
		t.Run(name, func(t *testing.T) {
			doc, pvd := docFor(t, `{"repo":"x","action":"delete"}`)
			k, r := keys(t, kem)
			b := Binding{Org: "acme", ToolCallDigest: strings.Repeat("a", 64), PreviewDigest: pvd, Ruleset: preview.Ruleset}
			sealed, err := Seal(r, b, doc)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(sealed, []byte("delete")) {
				t.Fatal("the ciphertext carries the plaintext")
			}
			got, err := Open(k, b, sealed)
			if err != nil || !bytes.Equal(got, doc) {
				t.Fatalf("open: %v", err)
			}
			// Another org, another call, another ruleset: it does not open.
			for _, other := range []Binding{
				{Org: "other", ToolCallDigest: b.ToolCallDigest, PreviewDigest: pvd, Ruleset: b.Ruleset},
				{Org: b.Org, ToolCallDigest: strings.Repeat("b", 64), PreviewDigest: pvd, Ruleset: b.Ruleset},
				{Org: b.Org, ToolCallDigest: b.ToolCallDigest, PreviewDigest: pvd, Ruleset: "r0"},
			} {
				if _, err := Open(k, other, sealed); !errors.Is(err, ErrSeal) {
					t.Errorf("opened under %+v: %v", other, err)
				}
			}
			// Another key: it does not open.
			k2, _ := keys(t, kem)
			if _, err := Open(k2, b, sealed); !errors.Is(err, ErrSeal) {
				t.Errorf("opened under another key: %v", err)
			}
		})
	}
}

func TestAPreviewDigestThatIsNotTheDocumentsIsRefusedBothWays(t *testing.T) {
	doc, pvd := docFor(t, `{"a":1}`)
	_, other := docFor(t, `{"a":2}`)
	k, r := keys(t, KEMHybrid)
	if _, err := Seal(r, Binding{Org: "o", ToolCallDigest: "t", PreviewDigest: other, Ruleset: "r1"}, doc); !errors.Is(err, ErrSeal) {
		t.Errorf("sealed a document under another document's digest: %v", err)
	}
	// A ciphertext made with a binding whose digest lies opens, and Open
	// refuses it for the digest. Made by hand: Seal would refuse to make it.
	b := Binding{Org: "o", ToolCallDigest: "t", PreviewDigest: other, Ruleset: "r1"}
	sealed, err := hpke.Seal(r.pk, kdf, aead, Info(b), doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(k, b, sealed); !errors.Is(err, ErrMismatch) {
		t.Errorf("Open = %v, want ErrMismatch", err)
	}
	_ = pvd
}

func TestTheInfoCannotBeForgedByMovingBytesBetweenFields(t *testing.T) {
	a := Info(Binding{Org: "ab", ToolCallDigest: "c", PreviewDigest: "d", Ruleset: "r1"})
	b := Info(Binding{Org: "a", ToolCallDigest: "bc", PreviewDigest: "d", Ruleset: "r1"})
	if bytes.Equal(a, b) {
		t.Fatal("moving a byte from org to the call digest kept the info")
	}
}

func TestOnlyTheTwoAllowedKEMsAreAccepted(t *testing.T) {
	for _, bad := range []string{
		"", "hpke:", "hpke:0020", "hpke:zzzz:AAAA", "hpke:0010:AAAA", "hpke:0020:!!!",
		"ssh-ed25519 AAAA", "hpke-private:0020:AAAA",
	} {
		if _, err := ParseRecipient(bad); err == nil {
			t.Errorf("ParseRecipient(%q) accepted", bad)
		}
	}
	if _, _, err := GenerateKey(hpke.MLKEM768()); err == nil {
		t.Errorf("a key under a KEM outside the list was generated")
	}
	// A generated key's default is the hybrid KEM.
	_, r := keys(t, KEMHybrid)
	if !strings.HasPrefix(r.String(), "hpke:647a:") || r.Suite() != "kem=0x647a,kdf=0x0001,aead=0x0003" {
		t.Errorf("recipient %q suite %q", r.String()[:12], r.Suite())
	}
}

func TestHostileCiphertextsAreRefusedWithoutPanic(t *testing.T) {
	doc, pvd := docFor(t, `{"a":"b"}`)
	k, r := keys(t, KEMX25519)
	b := Binding{Org: "o", ToolCallDigest: "t", PreviewDigest: pvd, Ruleset: "r1"}
	sealed, err := Seal(r, b, doc)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(sealed); i++ {
		if _, err := Open(k, b, sealed[:i]); err == nil {
			t.Fatalf("a prefix of %d bytes opened", i)
		}
	}
	rnd := rand.New(rand.NewSource(1))
	for i := 0; i < 200; i++ {
		junk := make([]byte, rnd.Intn(200))
		rnd.Read(junk)
		if _, err := Open(k, b, junk); err == nil {
			t.Fatal("random bytes opened")
		}
		flipped := append([]byte{}, sealed...)
		flipped[rnd.Intn(len(flipped))] ^= 1 << uint(rnd.Intn(8))
		if _, err := Open(k, b, flipped); err == nil {
			t.Fatal("a flipped bit opened")
		}
	}
}
