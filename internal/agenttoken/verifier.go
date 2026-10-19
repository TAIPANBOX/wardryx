// Package agenttoken verifies an agent's own access token (RFC 9068, typ
// at+jwt, issued by vouchryx) for the decision point. It holds a key set and a
// revocation list it was given, and checks a relayed token against them. It
// makes no call at decision time: the sources are polled on a timer, and a
// request reads only what was last installed.
//
// Scaffold: nothing is verified yet. Verify refuses every token, so the tests
// that expect a valid token to verify fail on their assertions.
package agenttoken

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Config is what WARDRYX_AGENT_TOKEN_* names. An empty Issuer means verification
// is not configured.
type Config struct {
	Issuer        string
	Audiences     []string
	JWKSURL       string
	JWKSFile      string
	RevocationURL string
}

// ErrInvalid is what every refusal of a token is, to a caller: which check
// failed is written to the operator's log, never to the caller.
var ErrInvalid = errors.New("agenttoken: the token did not verify")

// Verified is what a verified token says about the agent it was issued for.
type Verified struct {
	Subject   string
	JTI       string
	ExpiresAt int64
}

// Verifier checks tokens against the sources it holds.
type Verifier struct {
	cfg Config
}

// New builds a verifier from its configuration. Scaffold: nothing is checked.
func New(cfg Config, client *http.Client) (*Verifier, error) {
	return &Verifier{cfg: cfg}, nil
}

// Load installs the key set and the revocation list once, before the first
// request. Scaffold: installs nothing.
func (v *Verifier) Load(ctx context.Context) error {
	return nil
}

// Refresh polls the sources once and installs what they hold. A source that
// fails keeps the one it had. Scaffold: installs nothing and reports no error.
func (v *Verifier) Refresh(ctx context.Context) error {
	return nil
}

// Run refreshes the sources every interval until ctx ends. Scaffold: returns.
func (v *Verifier) Run(ctx context.Context, every time.Duration, report func(error)) {}

// Verify checks a token at the given time. Scaffold: refuses every token.
func (v *Verifier) Verify(token string, now time.Time) (Verified, error) {
	return Verified{}, ErrInvalid
}
