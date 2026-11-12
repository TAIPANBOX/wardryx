package preview

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The rules of r1, each named by the id a hidden node or part carries.
const (
	// RuleKeyName hides a member whose key names a credential, whole,
	// whatever its type.
	RuleKeyName = "key_name"
	// RuleSecret prefixes the kind of a secret found inside a string.
	RuleSecret = "secret:"
	// RulePII prefixes the kind of personal data found inside a string.
	RulePII = "pii:"
	// RuleEntropy hides a long run that reads as random.
	RuleEntropy = "high_entropy"
)

// --- rule 1: the key names a credential ---

// credentialWords are the words that make a key name a credential. A key is cut
// into words (separators, a lower-to-upper change, a letter-to-digit change),
// and a word, two adjacent words joined, or the whole key joined is looked up
// here. Whole words and not substrings: "author", "spinner" and "max_tokens"
// name no credential, "auth", "pin" and "access_token" do.
var credentialWords = map[string]bool{
	"password": true, "passwd": true, "pwd": true, "passphrase": true,
	"secret": true, "secrets": true, "token": true, "apikey": true,
	"authorization": true, "auth": true, "cookie": true, "cookies": true,
	"setcookie": true, "privatekey": true, "clientsecret": true,
	"accesskey": true, "secretkey": true, "session": true, "sessionid": true,
	"credential": true, "credentials": true, "bearer": true, "signature": true,
	"otp": true, "pin": true, "cvv": true, "cvc": true, "ssn": true, "jwt": true,
}

// hiddenKeyRule returns RuleKeyName when key names a credential, else "".
func hiddenKeyRule(key string) string {
	words := keyWords(key)
	if len(words) == 0 {
		return ""
	}
	if credentialWords[strings.Join(words, "")] {
		return RuleKeyName
	}
	for i, w := range words {
		if credentialWords[w] {
			return RuleKeyName
		}
		if i+1 < len(words) && credentialWords[w+words[i+1]] {
			return RuleKeyName
		}
	}
	return ""
}

// keyWords cuts a key into lower-case words.
func keyWords(key string) []string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	var prev rune
	for i, r := range key {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case i > 0 && unicode.IsUpper(r) && unicode.IsLower(prev):
			flush()
			cur = append(cur, r)
		case i > 0 && unicode.IsDigit(r) != unicode.IsDigit(prev) && (unicode.IsLetter(prev) || unicode.IsDigit(prev)):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
		prev = r
	}
	flush()
	return words
}

// --- rule 2: secrets, the same set the TokenFuse broker's DLP scans for ---

// secretPatterns mirror tokenfuse_core::dlp::patterns, kind for kind and in the
// same order (more specific first). Parity is a test here
// (TestTheSecretKindsAreTheBrokersKinds) and a cross-repository check in
// estate-gates.
var secretPatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"private_key", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"anthropic_key", regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{20,}`)},
	{"openai_key", regexp.MustCompile(`sk-[A-Za-z0-9_\-]{20,}`)},
	{"aws_access_key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"google_api_key", regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`)},
	{"github_token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`)},
	{"slack_token", regexp.MustCompile(`xox[baprs]-[A-Za-z0-9\-]{10,}`)},
	{"jwt", regexp.MustCompile(`eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+`)},
	{"bearer_token", regexp.MustCompile(`Bearer\s+[A-Za-z0-9._\-]{20,}`)},
}

// privateKeyBlock widens a private key header to the whole PEM block when its
// end line is there, so the key material after the header is hidden too.
var privateKeyBlock = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)

// --- rule 3: personal data, the same set as the broker's PII masks ---

var (
	emailPattern = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	cardPattern  = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)
	phonePattern = regexp.MustCompile(`\+\d(?:[ ()\-]?\d){6,14}\b`)
	ibanStart    = regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}`)
)

// ibanLengths is the ISO 13616 registry as tokenfuse_core::dlp's IBAN_LENGTHS
// holds it.
var ibanLengths = map[string]int{
	"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
	"BH": 22, "BI": 27, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24,
	"DE": 22, "DJ": 27, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18,
	"FK": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27,
	"GT": 28, "HN": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26,
	"IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20,
	"LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20,
	"MR": 27, "MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23, "PK": 24,
	"PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33, "SA": 24,
	"SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SO": 23, "ST": 25,
	"SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
	"YE": 30,
}

// --- rule 4: high entropy ---

// entropyRun is a run that could be an encoded key: base64 and base64url
// characters. A run of at least entropyMinRun of them whose Shannon entropy is
// at least entropyMinBits bits a character is hidden. Hex tops out at 4 bits a
// character, so a commit id or a sha-256 stays visible by construction.
var entropyRun = regexp.MustCompile(`[A-Za-z0-9+/=_\-]+`)

const (
	entropyMinRun  = 40
	entropyMinBits = 4.5
)

// --- rule 5: vault handles ---

// vaultHandle is the broker's {{secret:NAME}} handle with a NAME a person can
// read. A handle whose name is anything else is plain text, and the other
// rules run over it.
var vaultHandle = regexp.MustCompile(`\{\{secret:([A-Za-z0-9_.\-]{1,64})\}\}`)

func wholeVaultHandle(s string) (string, bool) {
	m := vaultHandle.FindStringSubmatchIndex(s)
	if m == nil || m[0] != 0 || m[1] != len(s) {
		return "", false
	}
	return s[m[2]:m[3]], true
}

// --- spans ---

// span is a piece of a string that is not shown as text.
type span struct {
	start, end int
	hidden     string // the rule, for a hidden span
	vault      string // the name, for a vault handle
	class      int    // lower wins an overlap
}

// The classes, in the order an overlap is settled: a secret wins over
// everything, a vault handle over personal data and entropy, personal data
// over entropy.
const (
	classSecret = iota
	classVault
	classPII
	classEntropy
)

// findSpans finds every span of s, settled so that no two overlap: the lower
// class wins, then the earlier start, then the longer span.
func findSpans(s string) []span {
	var all []span
	for _, m := range privateKeyBlock.FindAllStringIndex(s, -1) {
		all = append(all, span{start: m[0], end: m[1], hidden: RuleSecret + "private_key", class: classSecret})
	}
	for _, p := range secretPatterns {
		for _, m := range p.re.FindAllStringIndex(s, -1) {
			all = append(all, span{start: m[0], end: m[1], hidden: RuleSecret + p.kind, class: classSecret})
		}
	}
	for _, m := range vaultHandle.FindAllStringSubmatchIndex(s, -1) {
		all = append(all, span{start: m[0], end: m[1], vault: s[m[2]:m[3]], class: classVault})
	}
	for _, m := range ibans(s) {
		all = append(all, span{start: m[0], end: m[1], hidden: RulePII + "iban", class: classPII})
	}
	for _, m := range emailPattern.FindAllStringIndex(s, -1) {
		all = append(all, span{start: m[0], end: m[1], hidden: RulePII + "email", class: classPII})
	}
	for _, m := range cardPattern.FindAllStringIndex(s, -1) {
		if partOfADecimal(s, m[0], m[1]) {
			continue
		}
		digits := digitsOf(s[m[0]:m[1]])
		if allSameDigit(digits) || !luhnValid(digits) {
			continue
		}
		all = append(all, span{start: m[0], end: m[1], hidden: RulePII + "card", class: classPII})
	}
	for _, m := range phonePattern.FindAllStringIndex(s, -1) {
		all = append(all, span{start: m[0], end: m[1], hidden: RulePII + "phone", class: classPII})
	}
	for _, m := range entropyRun.FindAllStringIndex(s, -1) {
		if m[1]-m[0] >= entropyMinRun && shannon(s[m[0]:m[1]]) >= entropyMinBits {
			all = append(all, span{start: m[0], end: m[1], hidden: RuleEntropy, class: classEntropy})
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		if a.class != b.class {
			return a.class < b.class
		}
		if a.start != b.start {
			return a.start < b.start
		}
		return a.end > b.end
	})
	var kept []span
	for _, c := range all {
		overlaps := false
		for _, k := range kept {
			if c.start < k.end && k.start < c.end {
				overlaps = true
				break
			}
		}
		if !overlaps {
			kept = append(kept, c)
		}
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].start < kept[j].start })
	return kept
}

// partsOf turns s and its spans into parts. When cut is asked for, visible
// text stops after head runes, on a rune boundary, and the second result says
// whether anything was left out. Hidden spans and vault handles count no runes.
func partsOf(s string, spans []span, head int, cut bool) ([]Part, bool) {
	var parts []Part
	left := head
	pos := 0
	addText := func(t string) bool {
		if t == "" {
			return true
		}
		if !cut {
			parts = append(parts, Part{Text: t})
			return true
		}
		if left <= 0 {
			return false
		}
		if n := utf8.RuneCountInString(t); n <= left {
			parts = append(parts, Part{Text: t})
			left -= n
			return true
		}
		i, taken := 0, 0
		for taken < left {
			_, size := utf8.DecodeRuneInString(t[i:])
			i += size
			taken++
		}
		parts = append(parts, Part{Text: t[:i]})
		left = 0
		return false
	}
	for _, sp := range spans {
		if !addText(s[pos:sp.start]) {
			return parts, true
		}
		if cut && left <= 0 {
			return parts, true
		}
		if sp.vault != "" {
			parts = append(parts, Part{Vault: sp.vault})
		} else {
			parts = append(parts, Part{Hidden: sp.hidden})
		}
		pos = sp.end
	}
	if !addText(s[pos:]) {
		return parts, true
	}
	return parts, false
}

// --- encoded binary values ---

// magic is the fixed table a blob's type is read from, by its first bytes.
var magic = []struct {
	prefix []byte
	mime   string
}{
	{[]byte("\x89PNG\r\n\x1a\n"), "image/png"},
	{[]byte("\xff\xd8\xff"), "image/jpeg"},
	{[]byte("GIF87a"), "image/gif"},
	{[]byte("GIF89a"), "image/gif"},
	{[]byte("%PDF-"), "application/pdf"},
	{[]byte("PK\x03\x04"), "application/zip"},
	{[]byte("\x1f\x8b"), "application/gzip"},
	{[]byte("\x7fELF"), "application/x-elf"},
	{[]byte("\xcf\xfa\xed\xfe"), "application/x-mach-binary"},
	{[]byte("\xfe\xed\xfa\xcf"), "application/x-mach-binary"},
	{[]byte("MZ"), "application/x-msdownload"},
}

var base64Whole = regexp.MustCompile(`^[A-Za-z0-9+/_\-]+={0,2}$`)

// asBlob reads a whole string of at least BlobMinChars base64 or base64url
// characters that decodes as a blob: its decoded size, its type by the table
// above, and the sha-256 of the decoded bytes. What it decodes to is never
// shown. A string that is text a person would read (it decodes but is not, or
// it does not decode) is not a blob.
func asBlob(s string) (*Node, bool) {
	if len(s) < BlobMinChars || !base64Whole.MatchString(s) {
		return nil, false
	}
	var dec []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		if dec, err = enc.DecodeString(s); err == nil {
			break
		}
	}
	if err != nil || len(dec) == 0 {
		return nil, false
	}
	mime := ""
	for _, m := range magic {
		if bytes.HasPrefix(dec, m.prefix) {
			mime = m.mime
			break
		}
	}
	// A long identifier made of words is base64 by alphabet and decodes to
	// noise. It is read as text unless its first bytes name a type or the
	// string itself reads as random, as encoded bytes do and words do not.
	if mime == "" {
		if shannon(s) < entropyMinBits {
			return nil, false
		}
		mime = "application/octet-stream"
	}
	sum := sha256.Sum256(dec)
	return &Node{K: KindBlob, Bytes: len(dec), MIME: mime, SHA256: hex.EncodeToString(sum[:])}, true
}

// --- flags ---

// flagsOf names what in the shown text does not read as it looks, in a fixed
// order.
func flagsOf(parts []Part) []string {
	var control, bidi, invisible, mixed, replacement bool
	for _, p := range parts {
		if p.Text == "" {
			continue
		}
		for _, r := range p.Text {
			switch {
			case r == utf8.RuneError:
				replacement = true
			case isBidi(r):
				bidi = true
			case isInvisible(r):
				invisible = true
			case unicode.IsControl(r) && r != '\n' && r != '\t':
				control = true
			}
		}
		if mixedScript(p.Text) {
			mixed = true
		}
	}
	var out []string
	if control {
		out = append(out, FlagControl)
	}
	if bidi {
		out = append(out, FlagBidi)
	}
	if invisible {
		out = append(out, FlagInvisible)
	}
	if mixed {
		out = append(out, FlagMixedScript)
	}
	if replacement {
		out = append(out, FlagReplacement)
	}
	return out
}

func isBidi(r rune) bool {
	return r == 0x061C || r == 0x200E || r == 0x200F || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

func isInvisible(r rune) bool {
	switch r {
	case 0x00AD, 0x034F, 0x180E, 0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF:
		return true
	}
	return r >= 0xE0000 && r <= 0xE007F
}

// mixedScript reports a word that mixes Latin with Cyrillic or Greek, the shape
// of a lookalike: "раypal" reads as a name it is not.
func mixedScript(t string) bool {
	var latin, cyrillic, greek bool
	check := func() bool {
		n := 0
		for _, b := range []bool{latin, cyrillic, greek} {
			if b {
				n++
			}
		}
		latin, cyrillic, greek = false, false, false
		return n > 1
	}
	for _, r := range t {
		if !unicode.IsLetter(r) {
			if check() {
				return true
			}
			continue
		}
		switch {
		case unicode.Is(unicode.Latin, r):
			latin = true
		case unicode.Is(unicode.Cyrillic, r):
			cyrillic = true
		case unicode.Is(unicode.Greek, r):
			greek = true
		}
	}
	return check()
}

// --- helpers mirrored from tokenfuse_core::dlp ---

// ibans finds IBANs, compact or in groups of four, upper case only, gated by
// the country's length and the mod-97 check, as scan_ibans does.
func ibans(s string) [][2]int {
	var out [][2]int
	for _, m := range ibanStart.FindAllStringIndex(s, -1) {
		start := m[0]
		n, ok := ibanLengths[s[start:start+2]]
		if !ok {
			continue
		}
		var compact []byte
		i := start
		for len(compact) < n && i < len(s) {
			b := s[i]
			if isUpperDigit(b) {
				compact = append(compact, b)
				i++
			} else if b == ' ' && len(compact) > 0 && i+1 < len(s) && isUpperDigit(s[i+1]) {
				i++
			} else {
				break
			}
		}
		if len(compact) < n || (i < len(s) && isAlnum(s[i])) {
			continue
		}
		if ibanChecksum(compact) {
			out = append(out, [2]int{start, i})
		}
	}
	return out
}

func isUpperDigit(b byte) bool { return b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' }
func isAlnum(b byte) bool {
	return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' || b >= '0' && b <= '9'
}

func ibanChecksum(compact []byte) bool {
	re := append(append([]byte{}, compact[4:]...), compact[:4]...)
	rem := 0
	for _, c := range re {
		var v int
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
			rem = (rem*10 + v) % 97
		case c >= 'A' && c <= 'Z':
			v = int(c-'A') + 10
			rem = (rem*100 + v) % 97
		default:
			return false
		}
	}
	return rem == 1
}

// partOfADecimal is tokenfuse's invariant 110: a digit run that is the
// fraction or the integer part of a decimal number is not a card.
func partOfADecimal(s string, start, end int) bool {
	fraction := start >= 1 && s[start-1] == '.' && (start < 2 || !isLetter(s[start-2]))
	integer := end+1 < len(s) && s[end] == '.' && s[end+1] >= '0' && s[end+1] <= '9'
	return fraction || integer
}

func isLetter(b byte) bool { return b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' }

func digitsOf(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func allSameDigit(d string) bool {
	if d == "" {
		return false
	}
	return strings.Count(d, d[:1]) == len(d)
}

func luhnValid(d string) bool {
	if d == "" {
		return false
	}
	sum, double := 0, false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

// shannon is the Shannon entropy of s in bits a byte. s is ASCII here (the
// run's alphabet), so a byte is a character.
func shannon(s string) float64 {
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}
