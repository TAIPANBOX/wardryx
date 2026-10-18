// Package keyryx is wardryx's client for Keyryx's custody role: the signing
// route for approval tokens and the cached JWKS that verifies them. It is the
// only place in this module that speaks HTTP to Keyryx. Nothing on the decision
// path imports it (CLAUDE.md invariant 26), and internal/approval sees only the
// interfaces this package implements.
//
// The key is the one Keyryx's custody role holds for wardryx's approval tokens
// (KeyName). Keyryx signs at grant time, at human rate, and verifiers never ask
// it per decision: they keep the set Refresh last verified, and keep using it
// while Keyryx is unreachable (CLAUDE.md invariant 41).
package keyryx

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// KeyName is the Keyryx key that signs approval tokens.
const KeyName = "wardryx-approval"

// Purpose is the purpose wardryx names on every sign request. Keyryx records it
// in its use log.
const Purpose = "approval"

const (
	httpTimeout  = 5 * time.Second
	maxBodyBytes = 64 << 10
	rawSigLen    = 64
)

var (
	errNoActiveKey = errors.New("keyryx: no active key for the approval signer")
	errBadAnswer   = errors.New("keyryx: the answer is not an ES256 signature")
)

// Client calls Keyryx's sign route and inventory.
type Client struct {
	base       string
	socket     bool
	credential string
	http       *http.Client
}

// NewClient returns a client for base: an http or https URL, or unix:///path for
// a unix socket. credential is the bearer key sent over http. A socket needs
// none, since Keyryx knows its caller by the socket it was reached on.
func NewClient(base, credential string) (*Client, error) {
	c := &Client{credential: credential}
	c.http = &http.Client{Timeout: httpTimeout, CheckRedirect: refuseRedirect}
	if path, ok := strings.CutPrefix(base, "unix://"); ok {
		if path == "" {
			return nil, errors.New("keyryx: the socket path is empty")
		}
		c.socket = true
		c.base = "http://keyryx"
		c.http.Transport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}}
		return c, nil
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("keyryx: the URL is neither http, https nor unix://")
	}
	c.base = strings.TrimRight(base, "/")
	return c, nil
}

// refuseRedirect stops the client at the first redirect. A redirected request
// would carry the credential to whatever host the redirect names.
func refuseRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

// Current returns the kid of the key Keyryx is signing with now, read from its
// inventory. Two active keys under one name are refused: which one signs would
// then be a guess.
func (c *Client) Current(ctx context.Context) (string, error) {
	body, err := c.do(ctx, http.MethodGet, "/v1/keys", nil, false)
	if err != nil {
		return "", err
	}
	var inv struct {
		Keys []struct {
			Name  string `json:"name"`
			Kid   string `json:"kid"`
			State string `json:"state"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &inv); err != nil {
		return "", fmt.Errorf("keyryx: inventory: %w", err)
	}
	kid, active := "", 0
	for _, k := range inv.Keys {
		if k.Name == KeyName && k.State == "active" {
			kid = k.Kid
			active++
		}
	}
	switch {
	case active == 0 || kid == "":
		return "", errNoActiveKey
	case active > 1:
		return "", fmt.Errorf("keyryx: %d active keys under %s", active, KeyName)
	}
	return kid, nil
}

// Sign has Keyryx sign input with its current key. It returns that key's kid and
// the raw ES256 signature, r || s, 64 bytes.
func (c *Client) Sign(ctx context.Context, input []byte) (string, []byte, error) {
	body, err := json.Marshal(map[string]string{
		"statement_b64": base64.StdEncoding.EncodeToString(input),
		"purpose":       Purpose,
	})
	if err != nil {
		return "", nil, err
	}
	out, err := c.do(ctx, http.MethodPost, "/v1/keys/"+KeyName+"/sign", body, true)
	if err != nil {
		return "", nil, err
	}
	var ans struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		Sig string `json:"signature_b64"`
	}
	if err := json.Unmarshal(out, &ans); err != nil {
		return "", nil, errBadAnswer
	}
	sig, err := base64.StdEncoding.DecodeString(ans.Sig)
	if ans.Alg != "ES256" || ans.Kid == "" || err != nil || len(sig) != rawSigLen {
		return "", nil, errBadAnswer
	}
	return ans.Kid, sig, nil
}

// do performs one request and returns the body of a 200 answer. A non-200
// status is an error that names the status and nothing from the body.
func (c *Client) do(ctx context.Context, method, path string, body []byte, authenticate bool) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authenticate && !c.socket && c.credential != "" {
		req.Header.Set("Authorization", "Bearer "+c.credential)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keyryx: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keyryx: %s %s answered %d", method, path, resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
}

// Cache holds the verified keys of KeyName as Keyryx's JWKS published them.
type Cache struct {
	client *Client
	mu     sync.RWMutex
	keys   map[string]*ecdsa.PublicKey
}

// NewCache returns an empty cache that refreshes through c.
func NewCache(c *Client) *Cache {
	return &Cache{client: c, keys: map[string]*ecdsa.PublicKey{}}
}

// Refresh fetches the set and replaces the cache with it. A failed fetch, or a
// set in which any member does not verify, leaves the cache as it was: Keyryx
// unreachable never empties the keys a verifier already trusts.
func (c *Cache) Refresh(ctx context.Context) error {
	body, err := c.client.do(ctx, http.MethodGet, "/v1/jwks/"+KeyName, nil, false)
	if err != nil {
		return err
	}
	keys, err := parseSet(body)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.keys = keys
	c.mu.Unlock()
	return nil
}

// Key returns the verified public key Keyryx published under kid.
func (c *Cache) Key(kid string) (*ecdsa.PublicKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	k, ok := c.keys[kid]
	return k, ok
}

// Run refreshes the cache now and then every interval until ctx ends. Each
// failed refresh goes to report, which may be nil.
func (c *Cache) Run(ctx context.Context, interval time.Duration, report func(error)) {
	refresh := func() {
		if err := c.Refresh(ctx); err != nil && report != nil {
			report(err)
		}
	}
	refresh()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			refresh()
		}
	}
}

// parseSet reads a JWKS whole or not at all. Every member must be a P-256 key
// that lies on the curve, whose kid is its RFC 7638 thumbprint, and no kid may
// appear twice.
func parseSet(body []byte) (map[string]*ecdsa.PublicKey, error) {
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("keyryx: jwks: %w", err)
	}
	out := make(map[string]*ecdsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" || (k.Alg != "" && k.Alg != "ES256") || (k.Use != "" && k.Use != "sig") {
			return nil, errors.New("keyryx: jwks: a member is not an ES256 signing key")
		}
		pub, err := p256Key(k.X, k.Y)
		if err != nil {
			return nil, err
		}
		if k.Kid == "" || k.Kid != thumbprint(pub) {
			return nil, errors.New("keyryx: jwks: a kid is not the thumbprint of its key")
		}
		if _, dup := out[k.Kid]; dup {
			return nil, errors.New("keyryx: jwks: a kid appears twice")
		}
		out[k.Kid] = pub
	}
	return out, nil
}

// p256Key decodes base64url coordinates and checks the point is on the curve,
// by the crypto/ecdh parser, which refuses a point that is not.
func p256Key(xs, ys string) (*ecdsa.PublicKey, error) {
	x, errX := base64.RawURLEncoding.DecodeString(xs)
	y, errY := base64.RawURLEncoding.DecodeString(ys)
	if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
		return nil, errors.New("keyryx: jwks: a coordinate is not 32 bytes")
	}
	point := append(append([]byte{4}, x...), y...)
	if _, err := ecdh.P256().NewPublicKey(point); err != nil {
		return nil, errors.New("keyryx: jwks: a point is not on P-256")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
}

// thumbprint is the RFC 7638 thumbprint of a P-256 key: the SHA-256 of its
// required members in lexicographic order, base64url without padding.
func thumbprint(k *ecdsa.PublicKey) string {
	x, y := make([]byte, 32), make([]byte, 32)
	k.X.FillBytes(x)
	k.Y.FillBytes(y)
	js := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`,
		base64.RawURLEncoding.EncodeToString(x), base64.RawURLEncoding.EncodeToString(y))
	sum := sha256.Sum256([]byte(js))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
