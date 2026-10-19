// Package agenttoken verifies an agent's own access token (RFC 9068, typ
// at+jwt, issued by vouchryx) for the decision point (CLAUDE.md invariant 13).
//
// It holds a key set and a revocation list it was given, and checks a token
// against them with the library's own relayed-token verifier, which is every
// agent-token check except the proof: the proof belongs to the enforcement
// point that sees it. Nothing is fetched at decision time. Sources are polled
// by Run, and a request reads only what was last installed.
package agenttoken

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
)

// Config is what WARDRYX_AGENT_TOKEN_* names. An empty Issuer means verification
// is not configured; New refuses a configuration that is only partly there.
type Config struct {
	Issuer        string
	Audiences     []string
	JWKSURL       string
	JWKSFile      string
	RevocationURL string
	// DoorOrigins are the scheme://host:port origins of the doors whose DPoP
	// proofs are accepted. Required with the issuer.
	DoorOrigins []string
	// ProofOptional lets a token without a proof verify. The zero value requires
	// the proof.
	ProofOptional bool
	// ProofMaxAge is how far a proof's iat may sit from now, either way. Zero
	// takes the default of 60 seconds; the largest allowed is 300.
	ProofMaxAge time.Duration
}

// ErrInvalid is what every refusal of a token is, to a caller. The check that
// failed is wrapped beside it for the operator's log and never reaches the
// caller.
var ErrInvalid = errors.New("agenttoken: the token did not verify")

// Verified is what a verified token says about the agent it was issued for.
type Verified struct {
	Subject   string
	JTI       string
	IssuedAt  int64
	ExpiresAt int64
	// JKT is the thumbprint the token is bound to (cnf.jkt).
	JKT string
}

// ErrProofRequired is a token presented with no DPoP proof, when proofs are
// required.
var ErrProofRequired = errors.New("agenttoken: the token was presented with no DPoP proof")

// ErrProof is a DPoP proof that did not verify for the token it accompanies.
var ErrProof = errors.New("agenttoken: the DPoP proof did not verify")

const (
	// maxKeySetBytes bounds a key set body. A vouchryx set is a few hundred bytes.
	maxKeySetBytes = 64 << 10
	// maxCached bounds the verified-token cache. A full cache stops caching
	// rather than evicting a live entry.
	maxCached = 4096
	// fetchTimeout bounds one poll of a source.
	fetchTimeout = 10 * time.Second
)

// Verifier checks tokens against the sources it holds.
type Verifier struct {
	cfg    Config
	client *http.Client
	revs   *delegation.Revocations // nil when no revocation list is configured

	mu         sync.RWMutex
	keys       delegation.Set
	keysJSON   string // the installed set, for the change check
	generation uint64 // bumped whenever the installed key set changes
	cache      map[string]cacheEntry
	fromURL    []delegation.JWK // the last set the URL served
	fromFile   []delegation.JWK // the last set the file held
}

// cacheEntry is a token that verified: its claims, kept until its exp, and the
// key-set generation it verified under. A cached entry is never used after the
// set it verified under has changed.
type cacheEntry struct {
	v          Verified
	generation uint64
	exp        int64
}

// New builds a verifier from its configuration. It refuses a configuration that
// names an issuer without audiences, a key source, or a usable URL, so a
// process never runs with a verifier that checks less than it was asked to.
func New(cfg Config, client *http.Client) (*Verifier, error) {
	cfg.Issuer = strings.TrimSpace(cfg.Issuer)
	if cfg.Issuer == "" {
		return nil, errors.New("WARDRYX_AGENT_TOKEN_ISSUER is empty: an agent token needs the issuer its iss must name")
	}
	var auds []string
	for _, a := range cfg.Audiences {
		if a = strings.TrimSpace(a); a != "" {
			auds = append(auds, a)
		}
	}
	if len(auds) == 0 {
		return nil, errors.New("WARDRYX_AGENT_TOKEN_AUDIENCES names no audience: an agent token must name the resource it is for")
	}
	cfg.Audiences = auds
	if cfg.JWKSURL == "" && cfg.JWKSFile == "" {
		return nil, errors.New("WARDRYX_AGENT_TOKEN_JWKS_URL or WARDRYX_AGENT_TOKEN_JWKS_FILE must name where the key set comes from")
	}
	for name, raw := range map[string]string{"WARDRYX_AGENT_TOKEN_JWKS_URL": cfg.JWKSURL, "WARDRYX_AGENT_TOKEN_REVOCATION_URL": cfg.RevocationURL} {
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("%s must be an absolute http or https URL", name)
		}
	}
	if client == nil {
		client = &http.Client{
			Timeout: fetchTimeout,
			// A source is fetched from the one address configured, and never
			// from one a redirect names.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	v := &Verifier{cfg: cfg, client: client, cache: map[string]cacheEntry{}}
	if cfg.RevocationURL != "" {
		v.revs = delegation.NewRevocations(delegation.DefaultRevocationMaxAge, delegation.FailClosed)
	}
	return v, nil
}

// Load installs the key set before the first request. It fails when no key set
// is loaded: a verifier with no keys would refuse every token, and an operator
// should hear that at start, not from every caller. The revocation list is
// fetched too, but a failure there is not a reason to stop: until it is
// fetched, FailClosed refuses every token.
func (v *Verifier) Load(ctx context.Context) error {
	err := v.Refresh(ctx)
	v.mu.RLock()
	n := len(v.keys.Keys)
	v.mu.RUnlock()
	if n == 0 {
		return fmt.Errorf("no agent-token key set loaded: %w", err)
	}
	return nil
}

// Refresh polls every source once. A source that fails keeps what it had, and
// the errors are joined; a key set that is malformed is refused whole, as a
// whole set, never partly installed.
func (v *Verifier) Refresh(ctx context.Context) error {
	var errs []error
	if v.cfg.JWKSURL != "" {
		set, err := v.fetchURL(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("the key set URL: %w", err))
		} else {
			v.mu.Lock()
			v.fromURL = set
			v.mu.Unlock()
		}
	}
	if v.cfg.JWKSFile != "" {
		set, err := readKeyFile(v.cfg.JWKSFile)
		if err != nil {
			errs = append(errs, fmt.Errorf("the key set file: %w", err))
		} else {
			v.mu.Lock()
			v.fromFile = set
			v.mu.Unlock()
		}
	}
	if err := v.install(); err != nil {
		errs = append(errs, err)
	}
	if v.revs != nil {
		if err := v.revs.Refresh(ctx, v.client, v.cfg.RevocationURL, time.Now()); err != nil {
			errs = append(errs, fmt.Errorf("the revocation list: %w", err))
		}
	}
	return errors.Join(errs...)
}

// Run refreshes the sources every interval until ctx ends, and reports each
// failed refresh once. A failed refresh keeps the sources it had.
func (v *Verifier) Run(ctx context.Context, every time.Duration, report func(error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := v.Refresh(ctx); err != nil && report != nil {
				report(err)
			}
		}
	}
}

// CheckProof checks the DPoP proof that accompanies a verified token. Scaffold:
// accepts every proof, which is what the decision did before proofs.
func (v *Verifier) CheckProof(proof, token string, bound Verified, now time.Time) error {
	return nil
}

// Verify checks a token at the given time. Every refusal is ErrInvalid, and the
// reason is wrapped for the log only.
func (v *Verifier) Verify(token string, now time.Time) (Verified, error) {
	alg, ok := headerAlg(token)
	if !ok || alg != "ES256" {
		return Verified{}, fmt.Errorf("%w: the algorithm is not ES256", ErrInvalid)
	}

	digest := sha256.Sum256([]byte(token))
	key := hex.EncodeToString(digest[:])
	v.mu.RLock()
	hit, cached := v.cache[key]
	fresh := cached && hit.generation == v.generation && now.Unix() < hit.exp
	keys, gen := v.keys, v.generation
	v.mu.RUnlock()

	if fresh {
		// A cached token is still asked the revocation question every time: a
		// revocation takes effect at the next call, not at the token's exp.
		if v.revoked(hit.v.JTI, hit.v.Subject, hit.v.IssuedAt, now) {
			return Verified{}, fmt.Errorf("%w: the token is on the revocation list", ErrInvalid)
		}
		return hit.v, nil
	}

	var lastErr error
	var out Verified
	for _, aud := range v.cfg.Audiences {
		a, err := delegation.VerifyRelayedAccess(token, delegation.AccessOptions{
			Keys:     keys,
			Issuer:   v.cfg.Issuer,
			Audience: aud,
			Now:      now,
			Revoked:  func(jti, subject string, iat int64) bool { return v.revoked(jti, subject, iat, now) },
		})
		if err == nil {
			out = Verified{Subject: a.Subject, JTI: a.JTI, IssuedAt: a.IssuedAt, ExpiresAt: a.ExpiresAt}
			lastErr = nil
			break
		}
		lastErr = err
	}
	if lastErr != nil {
		return Verified{}, fmt.Errorf("%w: %v", ErrInvalid, lastErr)
	}
	if nbf, ok := notBefore(token); ok && now.Unix()+int64(delegation.AgentTokenLeeway/time.Second) < nbf {
		return Verified{}, fmt.Errorf("%w: the token is not valid until later", ErrInvalid)
	}

	v.mu.Lock()
	if v.generation == gen && len(v.cache) < maxCached {
		v.cache[key] = cacheEntry{v: out, generation: gen, exp: out.ExpiresAt}
	}
	v.mu.Unlock()
	return out, nil
}

// revoked answers the revocation question for one token. With no list
// configured there is nothing to ask, and no token is revoked by it.
func (v *Verifier) revoked(jti, subject string, issuedAt int64, now time.Time) bool {
	if v.revs == nil {
		return false
	}
	return v.revs.Check(jti, subject, issuedAt, now).Revoked
}

// install recomputes the key set from both sources. A kid that two sources
// name with different keys refuses the install, rather than choosing one.
func (v *Verifier) install() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	byKid := map[string]delegation.JWK{}
	var merged []delegation.JWK
	for _, src := range [][]delegation.JWK{v.fromURL, v.fromFile} {
		for _, k := range src {
			if prev, ok := byKid[k.Kid]; ok {
				if prev.X != k.X || prev.Y != k.Y {
					return fmt.Errorf("kid %q is in both key sources with different keys: keeping the set held", k.Kid)
				}
				continue
			}
			byKid[k.Kid] = k
			merged = append(merged, k)
		}
	}
	set := delegation.Set{Keys: merged}
	raw, err := json.Marshal(set)
	if err != nil {
		return err
	}
	if string(raw) != v.keysJSON {
		v.keys = set
		v.keysJSON = string(raw)
		v.generation++
		v.cache = map[string]cacheEntry{}
	}
	return nil
}

func (v *Verifier) fetchURL(ctx context.Context) ([]delegation.JWK, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("answered %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxKeySetBytes+1))
	if err != nil {
		return nil, err
	}
	return parseKeySet(body)
}

func readKeyFile(path string) ([]delegation.JWK, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the operator names this file in WARDRYX_AGENT_TOKEN_JWKS_FILE; reading it is the point
	if err != nil {
		return nil, err
	}
	if len(raw) > maxKeySetBytes {
		return nil, errors.New("the file is larger than the key set limit")
	}
	return parseKeySet(raw)
}

// parseKeySet reads a JWK set and refuses it whole unless every key is an EC
// P-256 key with a kid and both coordinates. ES256 is the only algorithm a
// token may use (Verify), so a key of another curve could never verify one.
func parseKeySet(raw []byte) ([]delegation.JWK, error) {
	if len(raw) > maxKeySetBytes {
		return nil, errors.New("the key set is larger than the limit")
	}
	var set delegation.Set
	if err := json.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("not a JWK set: %w", err)
	}
	if len(set.Keys) == 0 {
		return nil, errors.New("the key set holds no keys")
	}
	seen := map[string]bool{}
	for _, k := range set.Keys {
		switch {
		case k.Kty != "EC" || k.Crv != "P-256":
			return nil, fmt.Errorf("kid %q is not an EC P-256 key", k.Kid)
		case k.Kid == "" || seen[k.Kid]:
			return nil, errors.New("a key has no kid, or a kid that repeats")
		case k.X == "" || k.Y == "":
			return nil, fmt.Errorf("kid %q has no coordinates", k.Kid)
		}
		seen[k.Kid] = true
	}
	return set.Keys, nil
}

// headerAlg reads the JWS header's alg. It reads without trusting anything: the
// caller uses the value only to refuse a token whose alg is not ES256 before
// the library runs.
func headerAlg(token string) (string, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return "", false
	}
	return h.Alg, true
}

// notBefore reads a token's nbf. It is called only on a token the library has
// verified, so the payload it reads is one the issuer signed.
func notBefore(token string) (int64, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return 0, false
	}
	var c struct {
		NBF *int64 `json:"nbf"`
	}
	if err := json.Unmarshal(raw, &c); err != nil || c.NBF == nil {
		return 0, false
	}
	return *c.NBF, true
}
