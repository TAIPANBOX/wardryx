// Package preview builds what a person deciding a held tool call is shown of
// its arguments (CLAUDE.md invariant 51).
//
// The input is the argument bytes exactly as wardryx received them: the same
// bytes approval.ArgumentsSHA256 hashes and approval.ToolCallDigest binds a
// grant to. So the call a person reads and the call a token is bound to are one
// call by construction, never by a second parse of something else.
//
// The output is a Document: a tree of typed nodes, never text and never markup.
// Before anything is put in it the rules of Ruleset run over every key and every
// string (rules.go): a member whose key names a credential is hidden whole, a
// secret or a piece of personal data inside a string is hidden as a part of that
// string, a long high-entropy run is hidden, and a vault handle is shown by name.
// A hidden value carries the rule and its JSON type and nothing else: no length
// and no hash, because a hash of a short secret is found by trying them all.
//
// Everything here is a pure function of its input. No clock, no randomness, no
// network (scripts/decision-path-purity.sh holds the imports), and no map is
// iterated, so the same bytes give the same Document and the same Digest on
// every run and every machine. A new rule is a new Ruleset, never an edit of an
// old one: a hold records the ruleset it was built under, so an old preview can
// always be rebuilt.
package preview

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// Ruleset names the rules this package applies. Recorded in a hold beside the
// digest, so a person and an auditor can tell which rules hid what.
const Ruleset = "r1"

// Version is the Document's own format version.
const Version = 1

// digestDomain separates a preview digest from every other sha-256 in the
// estate, as approval.ToolCallDigest's tag does for a call's.
const digestDomain = "wardryx/preview/v1"

// The fixed limits of r1. Changing any of them is a new ruleset.
const (
	// MaxDepth is the deepest level of nesting shown; a container below it is
	// an elided node with the number of members it held.
	MaxDepth = 8
	// MaxArrayItems is the longest array shown whole; a longer one shows its
	// first ArrayHead items and how many were left out.
	MaxArrayItems = 50
	ArrayHead     = 20
	// MaxObjectMembers is the largest object shown whole; a larger one shows
	// its first ObjectHead members and how many were left out.
	MaxObjectMembers = 100
	ObjectHead       = 50
	// MaxStringRunes is the longest string shown whole; a longer one shows
	// its first StringHead runes, its full rune count, and its sha-256 when
	// nothing in it was hidden.
	MaxStringRunes = 512
	StringHead     = 256
	// MaxLexeme is the longest number lexeme shown whole.
	MaxLexeme = 64
	// BlobMinChars is the shortest string read as an encoded binary value.
	BlobMinChars = 64
	// MaxDocumentBytes caps the canonical Document. A Document over it is
	// replaced by one whose root says it was too large.
	MaxDocumentBytes = 16 << 10
	// shownBudget bounds the text shown across the whole tree, in bytes, so a
	// wide tree of long strings stops early rather than at the hard cap.
	shownBudget = 12 << 10
)

// Kinds of node.
const (
	KindObject = "object"
	KindArray  = "array"
	KindString = "string"
	KindNumber = "number"
	KindBool   = "bool"
	KindNull   = "null"
	KindHidden = "hidden"
	KindVault  = "vault_handle"
	KindBlob   = "blob"
	KindElided = "elided"
)

// Reasons a node was elided.
const (
	ElidedDepth = "depth"
	ElidedSize  = "size"
)

// Document is what a person is shown of one call's arguments.
type Document struct {
	V       int    `json:"v"`
	Ruleset string `json:"ruleset"`
	Root    *Node  `json:"root"`
}

// Node is one value of the tree. Which fields are set depends on K. The field
// order is the canonical order: Canonical marshals this struct, never a map.
type Node struct {
	K string `json:"k"`
	// object
	Members []Member `json:"members,omitempty"`
	// DuplicateKeys is set when one key appears more than once in an object:
	// a reader of the arguments may take the first or the last, so a person
	// sees both.
	DuplicateKeys bool `json:"duplicate_keys,omitempty"`
	// array
	Items []*Node `json:"items,omitempty"`
	// object and array: how many members or items are not shown.
	Omitted int `json:"omitted,omitempty"`
	// string
	Parts []Part `json:"parts,omitempty"`
	// Runes is the rune count of the whole string as received.
	Runes int `json:"runes,omitempty"`
	// Cut says the string is longer than what Parts shows.
	Cut bool `json:"cut,omitempty"`
	// SHA256 is the sha-256 of the whole string, set only for a cut string in
	// which nothing was hidden.
	SHA256 string `json:"sha256,omitempty"`
	// Flags name characters in the shown text that do not read as they look.
	Flags []string `json:"flags,omitempty"`
	// number
	Lexeme string `json:"lexeme,omitempty"`
	// bool
	Value *bool `json:"value,omitempty"`
	// hidden
	Rule string `json:"rule,omitempty"`
	Type string `json:"type,omitempty"`
	// vault_handle
	Name string `json:"name,omitempty"`
	// blob
	Bytes int    `json:"bytes,omitempty"`
	MIME  string `json:"mime,omitempty"`
	// elided
	Reason string `json:"reason,omitempty"`
	Count  int    `json:"count,omitempty"`
}

// Member is one key and value of an object. The key is a node of its own,
// because a key is text an agent wrote and the rules run over it too.
type Member struct {
	Key   *Node `json:"key"`
	Value *Node `json:"value"`
}

// Part is one piece of a string: visible text, a hidden span, or a vault
// handle inside a longer string. Exactly one field is set.
type Part struct {
	Text   string `json:"text,omitempty"`
	Hidden string `json:"hidden,omitempty"`
	Vault  string `json:"vault,omitempty"`
}

// Flags a string node can carry.
const (
	FlagControl     = "control"
	FlagBidi        = "bidi"
	FlagInvisible   = "invisible"
	FlagMixedScript = "mixed_script"
	FlagReplacement = "replacement"
)

// ErrNotJSON is arguments that are not one JSON value. wardryx refuses such a
// tool call before this runs (pdp.ValidateToolCall), so here it is a defect,
// reported as a preview that could not be built and never as a verdict.
var ErrNotJSON = errors.New("preview: the arguments are not one JSON value")

// Build makes the Document for one call's argument bytes and returns it with
// its canonical bytes. It fails only on bytes that are not one JSON value.
func Build(args []byte) (Document, []byte, error) {
	root, err := parse(args)
	if err != nil {
		return Document{}, nil, err
	}
	b := &builder{budget: shownBudget}
	doc := Document{V: Version, Ruleset: Ruleset, Root: b.node(root, 0)}
	canon, err := Canonical(doc)
	if err != nil {
		return Document{}, nil, err
	}
	if len(canon) > MaxDocumentBytes {
		doc.Root = &Node{K: KindElided, Reason: ElidedSize, Count: 1}
		if canon, err = Canonical(doc); err != nil {
			return Document{}, nil, err
		}
	}
	return doc, canon, nil
}

// Canonical is the one byte form of a Document: encoding/json over the structs
// above, whose field order is fixed and which hold no map.
func Canonical(doc Document) ([]byte, error) {
	return json.Marshal(doc)
}

// Digest is the value a person's decision names (pvd): a sha-256 over a fixed
// domain tag, then the canonical Document with an 8-byte length prefix.
func Digest(canonical []byte) string {
	h := sha256.New()
	h.Write([]byte(digestDomain))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(canonical)))
	h.Write(n[:])
	h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil))
}

// ValidDigest reports whether s has the shape Digest returns.
func ValidDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// --- parsing, in the order of the bytes ---

// raw is a parsed JSON value that keeps what a map would lose: member order,
// duplicate keys, and a number's lexeme.
type raw struct {
	kind    string
	members []rawMember
	items   []raw
	str     string
	lexeme  string
	boolean bool
}

type rawMember struct {
	key   string
	value raw
}

// parse reads one JSON value token by token. encoding/json's Token keeps
// object members in the order they were written, which a decode into a map
// would not, and UseNumber keeps the number as written.
func parse(args []byte) (raw, error) {
	if !json.Valid(args) {
		return raw{}, ErrNotJSON
	}
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return raw{}, ErrNotJSON
	}
	if _, err := dec.Token(); err != io.EOF {
		return raw{}, ErrNotJSON
	}
	return v, nil
}

func parseValue(dec *json.Decoder) (raw, error) {
	tok, err := dec.Token()
	if err != nil {
		return raw{}, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			v := raw{kind: KindObject}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return raw{}, err
				}
				key, ok := kt.(string)
				if !ok {
					return raw{}, ErrNotJSON
				}
				val, err := parseValue(dec)
				if err != nil {
					return raw{}, err
				}
				v.members = append(v.members, rawMember{key: key, value: val})
			}
			if _, err := dec.Token(); err != nil {
				return raw{}, err
			}
			return v, nil
		case '[':
			v := raw{kind: KindArray}
			for dec.More() {
				item, err := parseValue(dec)
				if err != nil {
					return raw{}, err
				}
				v.items = append(v.items, item)
			}
			if _, err := dec.Token(); err != nil {
				return raw{}, err
			}
			return v, nil
		}
		return raw{}, ErrNotJSON
	case string:
		return raw{kind: KindString, str: t}, nil
	case json.Number:
		return raw{kind: KindNumber, lexeme: string(t)}, nil
	case bool:
		return raw{kind: KindBool, boolean: t}, nil
	case nil:
		return raw{kind: KindNull}, nil
	}
	return raw{}, ErrNotJSON
}

// jsonType is the JSON type a hidden node names.
func jsonType(v raw) string { return v.kind }

// count is how many values a container holds, for an elided node.
func count(v raw) int {
	switch v.kind {
	case KindObject:
		return len(v.members)
	case KindArray:
		return len(v.items)
	}
	return 1
}

// --- building ---

type builder struct {
	// budget is what is left of shownBudget.
	budget int
}

func (b *builder) spend(n int) { b.budget -= n }

func (b *builder) node(v raw, depth int) *Node {
	if b.budget <= 0 {
		return &Node{K: KindElided, Reason: ElidedSize, Count: count(v)}
	}
	b.spend(16)
	switch v.kind {
	case KindObject:
		if depth >= MaxDepth {
			return &Node{K: KindElided, Reason: ElidedDepth, Count: count(v)}
		}
		n := &Node{K: KindObject, Members: []Member{}}
		seen := map[string]bool{}
		for _, m := range v.members {
			if seen[m.key] {
				n.DuplicateKeys = true
			}
			seen[m.key] = true
		}
		shown := v.members
		if len(shown) > MaxObjectMembers {
			n.Omitted = len(shown) - ObjectHead
			shown = shown[:ObjectHead]
		}
		for _, m := range shown {
			key := b.stringNode(m.key)
			var val *Node
			if rule := hiddenKeyRule(m.key); rule != "" {
				val = &Node{K: KindHidden, Rule: rule, Type: jsonType(m.value)}
			} else {
				val = b.node(m.value, depth+1)
			}
			n.Members = append(n.Members, Member{Key: key, Value: val})
		}
		return n
	case KindArray:
		if depth >= MaxDepth {
			return &Node{K: KindElided, Reason: ElidedDepth, Count: count(v)}
		}
		n := &Node{K: KindArray, Items: []*Node{}}
		shown := v.items
		if len(shown) > MaxArrayItems {
			n.Omitted = len(shown) - ArrayHead
			shown = shown[:ArrayHead]
		}
		for _, it := range shown {
			n.Items = append(n.Items, b.node(it, depth+1))
		}
		return n
	case KindString:
		return b.stringNode(v.str)
	case KindNumber:
		lex := v.lexeme
		if utf8.RuneCountInString(lex) > MaxLexeme {
			lex = lex[:MaxLexeme]
			b.spend(len(lex))
			return &Node{K: KindNumber, Lexeme: lex, Cut: true, Runes: len(v.lexeme)}
		}
		b.spend(len(lex))
		return &Node{K: KindNumber, Lexeme: lex}
	case KindBool:
		val := v.boolean
		return &Node{K: KindBool, Value: &val}
	}
	return &Node{K: KindNull}
}

// stringNode applies the string rules, in order: a whole vault handle, a whole
// encoded binary value, then the spans found inside (secrets, vault handles,
// personal data, high entropy), then the cut.
func (b *builder) stringNode(s string) *Node {
	if name, ok := wholeVaultHandle(s); ok {
		b.spend(len(name))
		return &Node{K: KindVault, Name: name}
	}
	if blob, ok := asBlob(s); ok {
		return blob
	}
	spans := findSpans(s)
	n := &Node{K: KindString, Runes: utf8.RuneCountInString(s)}
	if n.Runes == 0 {
		n.Parts = []Part{}
		return n
	}
	n.Parts, n.Cut = partsOf(s, spans, StringHead, n.Runes > MaxStringRunes)
	if n.Cut && len(spans) == 0 {
		sum := sha256.Sum256([]byte(s))
		n.SHA256 = hex.EncodeToString(sum[:])
	}
	for _, p := range n.Parts {
		b.spend(len(p.Text) + len(p.Vault))
	}
	n.Flags = flagsOf(n.Parts)
	return n
}
