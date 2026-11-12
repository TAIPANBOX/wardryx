// Package previewseal seals a preview Document (internal/preview) to the
// console's preview key, so that what wardryx keeps of a held call's arguments
// is ciphertext only the console can open (CLAUDE.md invariant 51).
//
// HPKE, RFC 9180, base mode, from the standard library's crypto/hpke. The KEM
// is the recipient key's: ML-KEM-768 with X25519 (the default a key generated
// here gets, so a ciphertext kept in a backup stays closed to a later quantum
// computer), or DHKEM(X25519). KDF HKDF-SHA256, AEAD ChaCha20-Poly1305.
//
// The HPKE info binds a ciphertext to the hold it was made for: the org, the
// call's digest, the preview's digest and the ruleset. A ciphertext moved to
// another hold opens only if that hold names the same org, call and preview,
// and then it is the same Document. Open checks the digest of what it opened
// against the one the hold names, so a ciphertext that opens but is not the
// Document the hold records is refused.
package previewseal

import (
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/TAIPANBOX/wardryx/internal/preview"
)

// infoDomain separates this HPKE context from any other.
const infoDomain = "wardryx/preview-seal/v1"

// The text forms of the two keys: a prefix, the KEM id in hex, and the key
// bytes as base64url.
const (
	recipientPrefix = "hpke:"
	privatePrefix   = "hpke-private:"
)

var (
	kdf  = hpke.HKDFSHA256()
	aead = hpke.ChaCha20Poly1305()
)

// KEMHybrid is ML-KEM-768 with X25519, the KEM a generated key gets.
var KEMHybrid = hpke.MLKEM768X25519()

// KEMX25519 is DHKEM(X25519, HKDF-SHA256), accepted for a console whose HPKE
// library has no hybrid KEM yet.
var KEMX25519 = hpke.DHKEM(ecdh.X25519())

// allowed are the KEMs a key may name. Anything else is refused at start.
func allowed(id uint16) (hpke.KEM, bool) {
	switch id {
	case KEMHybrid.ID():
		return KEMHybrid, true
	case KEMX25519.ID():
		return KEMX25519, true
	}
	return nil, false
}

// ErrSeal is a preview that could not be sealed or opened. The text after it
// names the reason and never quotes a key or a ciphertext.
var ErrSeal = errors.New("previewseal")

// ErrMismatch is a ciphertext that opened to a Document whose digest is not
// the one the hold names.
var ErrMismatch = errors.New("previewseal: the opened preview is not the one the hold names")

// Recipient is the console's public preview key.
type Recipient struct {
	pk hpke.PublicKey
}

// ParseRecipient reads WARDRYX_PREVIEW_RECIPIENT: "hpke:<kem id>:<base64url key>".
func ParseRecipient(text string) (*Recipient, error) {
	kem, b, err := parseKey(text, recipientPrefix)
	if err != nil {
		return nil, err
	}
	pk, err := kem.NewPublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("%w: the recipient key does not parse for its KEM", ErrSeal)
	}
	return &Recipient{pk: pk}, nil
}

// String is the recipient's text form.
func (r *Recipient) String() string { return keyText(recipientPrefix, r.pk.KEM().ID(), r.pk.Bytes()) }

// Suite names the ciphersuite a ciphertext for this recipient uses, as the
// three RFC 9180 ids.
func (r *Recipient) Suite() string { return suite(r.pk.KEM().ID()) }

func suite(kemID uint16) string {
	return fmt.Sprintf("kem=0x%04x,kdf=0x%04x,aead=0x%04x", kemID, kdf.ID(), aead.ID())
}

// ParsePrivateKey reads the console's private preview key.
func ParsePrivateKey(text string) (hpke.PrivateKey, error) {
	kem, b, err := parseKey(text, privatePrefix)
	if err != nil {
		return nil, err
	}
	k, err := kem.NewPrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("%w: the private key does not parse for its KEM", ErrSeal)
	}
	return k, nil
}

// GenerateKey makes a preview key pair under kem and returns the private key's
// text form and the recipient's.
func GenerateKey(kem hpke.KEM) (private, recipient string, err error) {
	if _, ok := allowed(kem.ID()); !ok {
		return "", "", fmt.Errorf("%w: KEM 0x%04x is not allowed", ErrSeal, kem.ID())
	}
	k, err := kem.GenerateKey()
	if err != nil {
		return "", "", fmt.Errorf("%w: generate: %v", ErrSeal, err)
	}
	b, err := k.Bytes()
	if err != nil {
		return "", "", fmt.Errorf("%w: serialize: %v", ErrSeal, err)
	}
	return keyText(privatePrefix, kem.ID(), b), keyText(recipientPrefix, kem.ID(), k.PublicKey().Bytes()), nil
}

// Binding is what a ciphertext is bound to.
type Binding struct {
	Org            string
	ToolCallDigest string
	PreviewDigest  string
	Ruleset        string
}

// Info is the HPKE info for b: the domain tag, then each field with an 8-byte
// length prefix, so no field's bytes can be moved into its neighbour.
func Info(b Binding) []byte {
	out := []byte(infoDomain)
	for _, f := range []string{b.Org, b.ToolCallDigest, b.PreviewDigest, b.Ruleset} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(f)))
		out = append(out, n[:]...)
		out = append(out, f...)
	}
	return out
}

// Seal encrypts a canonical Document to r under b. The result is the HPKE
// encapsulated key followed by the ciphertext.
func Seal(r *Recipient, b Binding, document []byte) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: no recipient", ErrSeal)
	}
	if preview.Digest(document) != b.PreviewDigest {
		return nil, fmt.Errorf("%w: the document is not the one the binding names", ErrSeal)
	}
	ct, err := hpke.Seal(r.pk, kdf, aead, Info(b), document)
	if err != nil {
		return nil, fmt.Errorf("%w: seal: %v", ErrSeal, err)
	}
	return ct, nil
}

// Open decrypts a sealed Document under b and checks that its digest is the
// one b names.
func Open(k hpke.PrivateKey, b Binding, sealed []byte) ([]byte, error) {
	doc, err := hpke.Open(k, kdf, aead, Info(b), sealed)
	if err != nil {
		return nil, fmt.Errorf("%w: the ciphertext does not open under this key and binding", ErrSeal)
	}
	if preview.Digest(doc) != b.PreviewDigest {
		return nil, ErrMismatch
	}
	return doc, nil
}

func keyText(prefix string, id uint16, b []byte) string {
	return fmt.Sprintf("%s%04x:%s", prefix, id, base64.RawURLEncoding.EncodeToString(b))
}

func parseKey(text, prefix string) (hpke.KEM, []byte, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(text), prefix)
	if !ok {
		return nil, nil, fmt.Errorf("%w: a preview key starts with %q", ErrSeal, prefix)
	}
	idText, keyB64, ok := strings.Cut(rest, ":")
	if !ok || len(idText) != 4 {
		return nil, nil, fmt.Errorf("%w: a preview key is %s<4 hex digits of KEM id>:<base64url>", ErrSeal, prefix)
	}
	id, err := strconv.ParseUint(idText, 16, 16)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: the KEM id is not hex", ErrSeal)
	}
	kem, ok := allowed(uint16(id))
	if !ok {
		return nil, nil, fmt.Errorf("%w: KEM 0x%04x is not allowed (0x%04x or 0x%04x)", ErrSeal, id, KEMHybrid.ID(), KEMX25519.ID())
	}
	b, err := base64.RawURLEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: the key is not base64url without padding", ErrSeal)
	}
	return kem, b, nil
}
