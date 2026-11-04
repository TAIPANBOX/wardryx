package manifest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TAIPANBOX/agent-stack-go/v2/delegation"
)

// The built binary, started the way an operator starts it, with a real key set
// on disk and tokens and proofs made here. Nothing below reaches into the code:
// a test that holds these helpers reads what a caller reads.

const (
	liveKey      = "live-bearer-made-up-for-this-test"
	liveIssuer   = "https://vouchryx.example"
	liveAudience = "https://wardryx.example"
	liveKid      = "k-live"
	liveDoor     = "https://pep.example"
	liveHTU      = "https://pep.example/v1/tools/call"
	liveAgent    = "agent://acme.example/support/bot1"
)

// liveKeys is an issuer key, the key set file that publishes it, and the key the
// agent holds.
type liveKeys struct {
	issuer, holder *ecdsa.PrivateKey
	jwks           string
}

func newLiveKeys(t testing.TB) liveKeys {
	t.Helper()
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	holder, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(delegation.Set{Keys: []delegation.JWK{delegation.FromPublic(&issuer.PublicKey, liveKid)}})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return liveKeys{issuer: issuer, holder: holder, jwks: file}
}

func signCompact(t testing.TB, key *ecdsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	enc := base64.RawURLEncoding
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	input := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	digest := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + enc.EncodeToString(sig)
}

func (k liveKeys) token(t testing.TB) string {
	t.Helper()
	jkt, err := delegation.Thumbprint(delegation.FromPublic(&k.holder.PublicKey, ""))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	return signCompact(t, k.issuer, map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": liveKid}, map[string]any{
		"iss": liveIssuer, "sub": liveAgent, "client_id": liveAgent, "aud": liveAudience,
		"iat": now, "exp": now + 300, "jti": randomID(t), "cnf": map[string]any{"jkt": jkt},
	})
}

func (k liveKeys) proof(t testing.TB, token string) string {
	t.Helper()
	raw, err := json.Marshal(delegation.FromPublic(&k.holder.PublicKey, ""))
	if err != nil {
		t.Fatal(err)
	}
	var jwk map[string]any
	if err := json.Unmarshal(raw, &jwk); err != nil {
		t.Fatal(err)
	}
	return signCompact(t, k.holder, map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}, map[string]any{
		"htm": "POST", "htu": liveHTU, "iat": time.Now().Unix(), "jti": randomID(t),
		"ath": delegation.AccessTokenHash(token),
	})
}

func randomID(t testing.TB) string {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(raw)
}

func buildServe(t testing.TB) string {
	t.Helper()
	r, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "wardryx")
	build := exec.Command("go", "build", "-o", bin, "./cmd/wardryx")
	build.Dir = r
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building wardryx: %v\n%s", err, out)
	}
	return bin
}

// instance is one running wardryx.
type instance struct {
	addr string
	cmd  *exec.Cmd
	out  *syncBuffer
}

// startServe starts the binary and waits for /healthz. An empty dsn is the
// in-memory store.
func startServe(t testing.TB, bin string, k liveKeys, dsn string) *instance {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "serve", "-addr", addr)
	cmd.Env = []string{
		"WARDRYX_KEYS=" + liveKey + ":acme:pep",
		"WARDRYX_AGENT_TOKEN_ISSUER=" + liveIssuer,
		"WARDRYX_AGENT_TOKEN_AUDIENCES=" + liveAudience,
		"WARDRYX_AGENT_TOKEN_JWKS_FILE=" + k.jwks,
		"WARDRYX_AGENT_TOKEN_DOOR_ORIGINS=" + liveDoor,
	}
	if dsn != "" {
		cmd.Env = append(cmd.Env, "WARDRYX_DB="+dsn)
	}
	out := &syncBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting it: %v", err)
	}
	in := &instance{addr: addr, cmd: cmd, out: out}
	t.Cleanup(in.stop)
	client := &http.Client{Timeout: 2 * time.Second}
	for i := 0; i < 100; i++ {
		resp, err := client.Get("http://" + addr + "/healthz")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return in
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("it never answered /healthz; its output was:\n%s", out.String())
	return nil
}

func (in *instance) stop() {
	if in.cmd.Process == nil {
		return
	}
	_ = in.cmd.Process.Kill()
	_, _ = in.cmd.Process.Wait()
}

// decide posts one decide and returns the status and the body. An empty token
// sends none.
func (in *instance) decide(t testing.TB, token, proof string) (int, string) {
	t.Helper()
	body := map[string]any{"agent_id": liveAgent, "run_id": "live-run"}
	if token != "" {
		body["agent_token"] = token
		body["agent_dpop_proof"] = proof
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://"+in.addr+"/v1/decide", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+liveKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST /v1/decide: %v", err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, buf.String()
}

// wantAllow and wantRefused say what a caller must have read.
func wantAllow(t testing.TB, what string, code int, body string) {
	t.Helper()
	if code != http.StatusOK || !strings.Contains(body, `"allow"`) {
		t.Fatalf("%s: status %d, body %s, want 200 allow", what, code, body)
	}
	t.Logf("%s: %d allow", what, code)
}

func wantRefused(t testing.TB, what string, wantCode int, reason string, code int, body string) {
	t.Helper()
	if code != wantCode || !strings.Contains(body, reason) {
		t.Fatalf("%s: status %d, body %s, want %d %s", what, code, body, wantCode, reason)
	}
	t.Logf("%s: %d %s", what, code, reason)
}

// With no database the record is per process, and that is a limit named rather
// than closed: one proof is accepted once by each instance, and each said at
// start what it costs. This pins the limit, so a change to it is seen.
func TestWithoutADatabaseTheRecordIsPerProcessAndTheStartSaysSo(t *testing.T) {
	if testing.Short() {
		t.Skip("starts two processes")
	}
	bin := buildServe(t)
	k := newLiveKeys(t)
	first, second := startServe(t, bin, k, ""), startServe(t, bin, k, "")
	tok := k.token(t)
	proof := k.proof(t, tok)
	code, body := first.decide(t, tok, proof)
	wantAllow(t, "the first instance", code, body)
	code, body = second.decide(t, tok, proof)
	wantAllow(t, "the second instance, which shares nothing with the first", code, body)
	code, body = first.decide(t, tok, proof)
	wantRefused(t, "the first instance again", http.StatusForbidden, "agent_token_proof_invalid", code, body)
	for name, in := range map[string]*instance{"first": first, "second": second} {
		if out := in.out.String(); !strings.Contains(out, "DPoP proof") || !strings.Contains(out, "WARDRYX_DB") {
			t.Errorf("the %s instance did not say at start that the record is per process:\n%s", name, out)
		}
	}
}
