// Package enrich asks an outside service for a typed signal about a pending
// tool call, so the policy engine can read it. It is OUTSIDE the decision
// path on purpose: internal/pdp, internal/policy and internal/replay never
// import it (scripts/decision-path-purity.sh holds that), so a decision is a
// pure function of the request it is handed and a replay can reproduce it
// with the service unreachable.
//
// # Fail-open on the signal, and why that is the safe direction
//
// Any failure here (a timeout, a refused connection, a 500, an `unanswered`
// answer, a body that is not what was asked for) is NO SIGNAL, never a guess
// and never a refusal. That is safe because of what a signal can do: it can
// add a hold and nothing else (policy.Policy.HoldIfSignal). Absent, the call
// is decided exactly as it would have been before this package existed.
// Failing closed would hold every call whenever the classifier is down.
//
// The one thing that must never happen is the failure being read as an answer,
// so every failure path returns the zero Signal and false, and the tests
// plant exactly that fault.
package enrich

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/TAIPANBOX/wardryx/internal/pdp"
)

const (
	// SignalName is the template id asked and the name of the signal produced.
	SignalName = "action.risk_class"
	// Source is stamped on every signal this package produces, so an auditor
	// can tell a signal wardryx asked for from one a caller supplied.
	Source = "typryx"
	// DefaultTimeout is the sub-budget for one ask. The enforcement point
	// calling /v1/decide has its own timeout; this one is carved out of it so
	// a slow classifier costs a bounded amount of every call, not the call.
	DefaultTimeout = 150 * time.Millisecond
	// MaxTimeout is the ceiling a configured timeout may not pass: a
	// misconfigured minute would hold every decision for a minute whenever
	// the classifier hangs.
	MaxTimeout = 5 * time.Second

	askPath          = "/v1/ask"
	keyHeader        = "X-Typryx-Key"
	maxResponseBytes = 64 << 10
)

// The reasons an ask gave no signal. One counter and one log line per class.
const (
	ReasonTimeout     = "timeout"
	ReasonUnreachable = "unreachable"
	ReasonCanceled    = "canceled"
	ReasonHTTP4xx     = "http_4xx"
	ReasonHTTP5xx     = "http_5xx"
	ReasonHTTPOther   = "http_other"
	ReasonUnanswered  = "unanswered"
	ReasonMalformed   = "malformed"
	// ReasonArgumentsTruncated: the enforcement point could not send the
	// arguments, so nothing was asked.
	ReasonArgumentsTruncated = "arguments_truncated"
)

// Stats counts what enrichment did since the process started.
type Stats struct {
	// Asked is how many times typryx was asked.
	Asked int64 `json:"asked"`
	// Signalled is how many asks produced a signal.
	Signalled int64 `json:"signalled"`
	// NoSignal counts the asks that produced none, by reason.
	NoSignal map[string]int64 `json:"no_signal"`
}

// Typryx asks a typryx deployment to classify a tool call under the
// action.risk_class template. Safe for concurrent use.
type Typryx struct {
	endpoint string
	key      string
	timeout  time.Duration
	client   *http.Client

	asked     atomic.Int64
	signalled atomic.Int64

	mu       sync.Mutex
	noSignal map[string]int64
	logged   map[string]bool
}

// NewTypryx builds the client for the typryx deployment at rawURL (its base
// URL, e.g. http://typryx:4320). key is the X-Typryx-Key credential, or "" for
// a deployment that needs none. A zero timeout means DefaultTimeout.
//
// The URL must be absolute http or https with a host and no userinfo, query or
// fragment, the shape typryx itself demands of the URLs it is given. Errors
// never contain the key.
func NewTypryx(rawURL, key string, timeout time.Duration) (*Typryx, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("must be an absolute http or https URL with a host")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("must not carry userinfo, a query or a fragment")
	}
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	if timeout < 0 || timeout > MaxTimeout {
		return nil, fmt.Errorf("timeout must be greater than zero and at most %s", MaxTimeout)
	}
	if badKey(key) {
		return nil, errors.New("the typryx key must be one line of printable text")
	}
	endpoint := strings.TrimRight(u.String(), "/") + askPath
	return &Typryx{
		endpoint: endpoint,
		key:      key,
		timeout:  timeout,
		client: &http.Client{
			Transport: &http.Transport{
				// No environment proxy: the key and the tool call go to the
				// URL the operator named and nowhere else.
				Proxy:                 nil,
				MaxIdleConns:          4,
				IdleConnTimeout:       30 * time.Second,
				ResponseHeaderTimeout: timeout,
			},
			// A redirect is a reply, not a destination: following one would
			// carry the key to a host the operator never named.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		noSignal: map[string]int64{},
		logged:   map[string]bool{},
	}, nil
}

func badKey(k string) bool {
	for _, r := range k {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// ReadKeyFile reads the credential from path, trimmed. The file is read once,
// at start; its contents are never logged and never appear in an error.
func ReadKeyFile(path string) (string, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- path is operator configuration (WARDRYX_TYPRYX_KEY_FILE), read once at start
	if err != nil {
		return "", fmt.Errorf("cannot read the key file: %w", err)
	}
	k := strings.TrimSpace(string(b))
	if k == "" {
		return "", errors.New("the key file is empty")
	}
	if badKey(k) {
		return "", errors.New("the key file must hold one line of printable text")
	}
	return k, nil
}

// Timeout is the sub-budget in force.
func (t *Typryx) Timeout() time.Duration { return t.timeout }

// askBody is the whole request: the template and exactly the three fields its
// `fields` names. Nothing else about the call or the agent is sent.
type askBody struct {
	Template string   `json:"template"`
	State    askState `json:"state"`
}

type askState struct {
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
	Target    string          `json:"target"`
}

// askAnswer is the part of typryx's answer this package reads.
type askAnswer struct {
	AnswerID      string             `json:"answer_id"`
	Template      string             `json:"template"`
	Type          string             `json:"type"`
	Answer        json.RawMessage    `json:"answer"`
	Probabilities map[string]float64 `json:"probabilities"`
	Unanswered    bool               `json:"unanswered"`
}

// Enrich asks typryx about one tool call. The bool is false whenever there is
// no signal, for any reason; the reason is counted and, once per class,
// logged. It returns within the configured timeout plus scheduling slack.
func (t *Typryx) Enrich(ctx context.Context, call pdp.ToolCall) (pdp.Signal, bool) {
	// The enforcement point could not send the arguments. A classification of
	// a tool name alone is a guess, and a guess must never look like an answer:
	// nothing is asked and there is no signal.
	if call.ArgumentsTruncated {
		t.noSignalFor(ReasonArgumentsTruncated)
		return pdp.Signal{}, false
	}
	t.asked.Add(1)

	args := call.Arguments
	if len(args) == 0 || string(args) == "null" {
		args = json.RawMessage(`{}`)
	}
	payload, err := json.Marshal(askBody{
		Template: SignalName,
		State:    askState{Tool: call.Name, Arguments: args, Target: call.Target},
	})
	if err != nil {
		t.noSignalFor(ReasonMalformed)
		return pdp.Signal{}, false
	}

	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(payload))
	if err != nil {
		t.noSignalFor(ReasonUnreachable)
		return pdp.Signal{}, false
	}
	req.Header.Set("Content-Type", "application/json")
	if t.key != "" {
		req.Header.Set(keyHeader, t.key)
	}

	resp, err := t.client.Do(req)
	if err != nil {
		t.noSignalFor(classify(ctx, err))
		return pdp.Signal{}, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		switch {
		case resp.StatusCode >= 400 && resp.StatusCode < 500:
			t.noSignalFor(ReasonHTTP4xx)
		case resp.StatusCode >= 500:
			t.noSignalFor(ReasonHTTP5xx)
		default:
			t.noSignalFor(ReasonHTTPOther)
		}
		return pdp.Signal{}, false
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		t.noSignalFor(classify(ctx, err))
		return pdp.Signal{}, false
	}
	if len(raw) > maxResponseBytes {
		t.noSignalFor(ReasonMalformed)
		return pdp.Signal{}, false
	}
	return t.read(raw)
}

// read turns typryx's answer into a signal, or into no signal. Every shape
// that is not a clean answer to the question asked is "malformed": the wrong
// template, a type other than choice, an answer that is not one of the
// probabilities it came with, a probability outside [0, 1].
func (t *Typryx) read(raw []byte) (pdp.Signal, bool) {
	var a askAnswer
	if err := json.Unmarshal(raw, &a); err != nil {
		t.noSignalFor(ReasonMalformed)
		return pdp.Signal{}, false
	}
	if a.Unanswered {
		t.noSignalFor(ReasonUnanswered)
		return pdp.Signal{}, false
	}
	if a.Template != SignalName || a.Type != "choice" {
		t.noSignalFor(ReasonMalformed)
		return pdp.Signal{}, false
	}
	var value string
	if err := json.Unmarshal(a.Answer, &value); err != nil || value == "" {
		t.noSignalFor(ReasonMalformed)
		return pdp.Signal{}, false
	}
	p, ok := a.Probabilities[value]
	if !ok {
		t.noSignalFor(ReasonMalformed)
		return pdp.Signal{}, false
	}
	sig := pdp.Signal{Name: SignalName, Value: value, Probability: p, Source: Source, AnswerID: a.AnswerID}
	if err := pdp.ValidateSignals([]pdp.Signal{sig}); err != nil {
		t.noSignalFor(ReasonMalformed)
		return pdp.Signal{}, false
	}
	t.signalled.Add(1)
	t.recovered()
	return sig, true
}

// classify names why a request failed before an answer arrived.
func classify(ctx context.Context, err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		return ReasonTimeout
	case errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled):
		return ReasonCanceled
	default:
		return ReasonUnreachable
	}
}

// noSignalFor counts a failed ask and, the first time this reason class shows
// up since typryx last answered, says so in the log. The line names the class
// and nothing the request or the response carried.
func (t *Typryx) noSignalFor(class string) {
	t.mu.Lock()
	t.noSignal[class]++
	first := !t.logged[class]
	t.logged[class] = true
	t.mu.Unlock()
	if first {
		log.Printf("wardryx: no risk signal from typryx (%s); calls are decided without it, and further asks that fail the same way are counted at /v1/status, not logged again until typryx answers", class)
	}
}

// recovered forgets which classes were logged, so a later failure after a
// working stretch is told again. In memory on purpose, like the store outage.
func (t *Typryx) recovered() {
	t.mu.Lock()
	if len(t.logged) > 0 {
		t.logged = map[string]bool{}
	}
	t.mu.Unlock()
}

// Stats is a snapshot of the counters.
func (t *Typryx) Stats() Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	by := make(map[string]int64, len(t.noSignal))
	for k, v := range t.noSignal {
		by[k] = v
	}
	return Stats{Asked: t.asked.Load(), Signalled: t.signalled.Load(), NoSignal: by}
}
