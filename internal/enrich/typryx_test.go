package enrich

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TAIPANBOX/wardryx/internal/pdp"
)

// These tests stand a fake typryx up with httptest and make it misbehave in
// every way a real one can. The property under all of them: whatever typryx
// does, the result is either a clean signal built from a clean answer, or NO
// signal. A failure read as an answer is the one thing that must never happen,
// because a made-up "destructive" would hold a call nobody classified.

const goodAnswer = `{"answer_id":"ans-42","template":"action.risk_class","template_version":"abc","type":"choice","answer":"destructive","probabilities":{"read_only":0.01,"reversible_change":0.02,"destructive":0.95,"external_send":0.01,"financial":0.01},"backend":"jev","model":"m","latency_ms":3,"held_back_fields":0}`

var testCall = pdp.ToolCall{
	Name:      "s3.delete_object",
	Arguments: json.RawMessage(`{"bucket":"prod-backups","key":"2026/db.dump"}`),
	Target:    "s3://prod-backups",
}

// fake serves handler and returns a client pointed at it.
func fake(t *testing.T, key string, timeout time.Duration, handler http.HandlerFunc) (*Typryx, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := NewTypryx(srv.URL, key, timeout)
	if err != nil {
		t.Fatalf("NewTypryx: %v", err)
	}
	return c, srv
}

func answer(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}
}

// captureLog redirects the standard logger for one test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func TestItAsksTheRiskClassTemplateWithOnlyTheThreeFieldsAndTheKey(t *testing.T) {
	var gotPath, gotMethod, gotKey, gotType string
	var gotBody []byte
	c, _ := fake(t, "k-123", time.Second, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod, gotKey, gotType = r.URL.Path, r.Method, r.Header.Get("X-Typryx-Key"), r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, goodAnswer)
	})
	sig, ok := c.Enrich(context.Background(), testCall)
	if !ok {
		t.Fatal("a clean answer produced no signal")
	}
	want := pdp.Signal{Name: "action.risk_class", Value: "destructive", Probability: 0.95, Source: "typryx", AnswerID: "ans-42"}
	if sig != want {
		t.Fatalf("signal = %+v, want %+v", sig, want)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/ask" {
		t.Errorf("asked %s %s, want POST /v1/ask", gotMethod, gotPath)
	}
	if gotKey != "k-123" {
		t.Errorf("X-Typryx-Key = %q", gotKey)
	}
	if !strings.HasPrefix(gotType, "application/json") {
		t.Errorf("Content-Type = %q", gotType)
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal(gotBody, &body); err != nil {
		t.Fatalf("request body is not JSON: %v", err)
	}
	if len(body) != 2 || string(body["template"]) != `"action.risk_class"` {
		t.Fatalf("request body = %s, want exactly template and state", gotBody)
	}
	var state map[string]json.RawMessage
	if err := json.Unmarshal(body["state"], &state); err != nil {
		t.Fatalf("state is not an object: %v", err)
	}
	if len(state) != 3 {
		t.Errorf("state carries %d fields, want tool, arguments, target: %s", len(state), body["state"])
	}
	if string(state["tool"]) != `"s3.delete_object"` || string(state["target"]) != `"s3://prod-backups"` ||
		string(state["arguments"]) != `{"bucket":"prod-backups","key":"2026/db.dump"}` {
		t.Errorf("state = %s", body["state"])
	}
}

func TestNoKeyHeaderIsSentWhenNoKeyIsConfigured(t *testing.T) {
	var has bool
	c, _ := fake(t, "", time.Second, func(w http.ResponseWriter, r *http.Request) {
		_, has = r.Header["X-Typryx-Key"]
		_, _ = io.WriteString(w, goodAnswer)
	})
	if _, ok := c.Enrich(context.Background(), testCall); !ok {
		t.Fatal("no signal")
	}
	if has {
		t.Fatal("an X-Typryx-Key header was sent with no key configured")
	}
}

func TestACallWithNoArgumentsIsAskedWithAnEmptyObject(t *testing.T) {
	var gotBody []byte
	c, _ := fake(t, "", time.Second, func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, goodAnswer)
	})
	if _, ok := c.Enrich(context.Background(), pdp.ToolCall{Name: "list_files"}); !ok {
		t.Fatal("no signal")
	}
	if !strings.Contains(string(gotBody), `"arguments":{}`) || !strings.Contains(string(gotBody), `"target":""`) {
		t.Fatalf("body = %s", gotBody)
	}
}

// Everything that is not a clean answer. Each must be no signal, counted under
// the reason it names, and none may leak a made-up value.
func TestAnythingButACleanAnswerIsNoSignalAndIsCountedByReason(t *testing.T) {
	huge := strings.Repeat("x", maxResponseBytes+10)
	cases := []struct {
		name    string
		handler http.HandlerFunc
		reason  string
	}{
		{"http 500", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }, ReasonHTTP5xx},
		{"http 503", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }, ReasonHTTP5xx},
		{"http 401", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }, ReasonHTTP4xx},
		{"http 404", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }, ReasonHTTP4xx},
		{"http 429", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(429) }, ReasonHTTP4xx},
		{"a 500 that still carries a destructive body", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
			_, _ = io.WriteString(w, goodAnswer)
		}, ReasonHTTP5xx},
		{"unanswered", answer(`{"answer_id":"a","template":"action.risk_class","type":"choice","unanswered":true,"reason":"timeout"}`), ReasonUnanswered},
		{"unanswered beside a destructive answer", answer(strings.Replace(goodAnswer, `"type":"choice"`, `"type":"choice","unanswered":true`, 1)), ReasonUnanswered},
		{"not JSON", answer(`<html>502 bad gateway</html>`), ReasonMalformed},
		{"empty body", answer(``), ReasonMalformed},
		{"a JSON array", answer(`[]`), ReasonMalformed},
		{"null", answer(`null`), ReasonMalformed},
		{"trailing garbage after the JSON", answer(goodAnswer + `{"x":`), ReasonMalformed},
		{"an answer that is a number", answer(strings.Replace(goodAnswer, `"answer":"destructive"`, `"answer":3`, 1)), ReasonMalformed},
		{"an empty answer", answer(strings.Replace(goodAnswer, `"answer":"destructive"`, `"answer":""`, 1)), ReasonMalformed},
		{"no answer at all", answer(strings.Replace(goodAnswer, `"answer":"destructive",`, ``, 1)), ReasonMalformed},
		{"an answer that is not one of the probabilities", answer(strings.Replace(goodAnswer, `"answer":"destructive"`, `"answer":"banana"`, 1)), ReasonMalformed},
		{"no probabilities", answer(`{"answer_id":"a","template":"action.risk_class","type":"choice","answer":"destructive"}`), ReasonMalformed},
		{"a probability above one", answer(strings.Replace(goodAnswer, `"destructive":0.95`, `"destructive":1.5`, 1)), ReasonMalformed},
		{"a negative probability", answer(strings.Replace(goodAnswer, `"destructive":0.95`, `"destructive":-0.2`, 1)), ReasonMalformed},
		{"a probability that is a string", answer(strings.Replace(goodAnswer, `"destructive":0.95`, `"destructive":"high"`, 1)), ReasonMalformed},
		{"another template's answer", answer(strings.Replace(goodAnswer, `"template":"action.risk_class"`, `"template":"request.complexity"`, 1)), ReasonMalformed},
		{"a score where a choice was asked", answer(strings.Replace(goodAnswer, `"type":"choice"`, `"type":"score"`, 1)), ReasonMalformed},
		{"an answer id with a control character", answer(strings.Replace(goodAnswer, `"ans-42"`, `"a\nb"`, 1)), ReasonMalformed},
		{"an answer id over the cap", answer(strings.Replace(goodAnswer, `"ans-42"`, `"`+strings.Repeat("a", 300)+`"`, 1)), ReasonMalformed},
		{"a body over the read cap", answer(huge), ReasonMalformed},
		{"a redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://127.0.0.1:1/elsewhere", http.StatusFound)
		}, ReasonHTTPOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			captureLog(t)
			c, _ := fake(t, "", time.Second, tc.handler)
			sig, ok := c.Enrich(context.Background(), testCall)
			if ok || sig != (pdp.Signal{}) {
				t.Fatalf("a failure was read as an answer: %+v ok=%v", sig, ok)
			}
			st := c.Stats()
			if st.Asked != 1 || st.Signalled != 0 || st.NoSignal[tc.reason] != 1 {
				t.Fatalf("stats = %+v, want one ask, no signal, reason %q", st, tc.reason)
			}
		})
	}
}

func TestATyprxThatTimesOutIsNoSignalWithinTheBudget(t *testing.T) {
	captureLog(t)
	release := make(chan struct{})
	c, _ := fake(t, "", 60*time.Millisecond, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
		_, _ = io.WriteString(w, goodAnswer) // would be destructive, if anyone were still listening
	})
	// Registered after fake, so it runs before the server's own Close: a
	// handler still waiting is released first and Close cannot block on it.
	t.Cleanup(func() { close(release) })
	start := time.Now()
	sig, ok := c.Enrich(context.Background(), testCall)
	elapsed := time.Since(start)
	if ok || sig != (pdp.Signal{}) {
		t.Fatalf("a timeout was read as an answer: %+v", sig)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("a 60ms budget took %s", elapsed)
	}
	if n := c.Stats().NoSignal[ReasonTimeout]; n != 1 {
		t.Fatalf("timeout counted %d times, want 1 (stats %+v)", n, c.Stats())
	}
}

func TestAnUnreachableTyprxIsNoSignal(t *testing.T) {
	captureLog(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	c, err := NewTypryx(url, "", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if sig, ok := c.Enrich(context.Background(), testCall); ok || sig != (pdp.Signal{}) {
		t.Fatalf("a refused connection was read as an answer: %+v", sig)
	}
	if n := c.Stats().NoSignal[ReasonUnreachable]; n != 1 {
		t.Fatalf("stats = %+v", c.Stats())
	}
}

func TestACallerThatGaveUpIsCountedAsCanceledNotAsTyprxFailing(t *testing.T) {
	captureLog(t)
	c, _ := fake(t, "", time.Second, answer(goodAnswer))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok := c.Enrich(ctx, testCall); ok {
		t.Fatal("a canceled ask produced a signal")
	}
	if n := c.Stats().NoSignal[ReasonCanceled]; n != 1 {
		t.Fatalf("stats = %+v", c.Stats())
	}
}

// A redirect is a reply, not a destination. Following it would carry the key
// to a host the operator never named.
func TestARedirectIsNotFollowedAndTheKeyGoesNowhereElse(t *testing.T) {
	captureLog(t)
	var elsewhere atomic.Int64
	var leakedKey atomic.Value
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		leakedKey.Store(r.Header.Get("X-Typryx-Key"))
		_, _ = io.WriteString(w, goodAnswer)
	}))
	t.Cleanup(other.Close)
	c, _ := fake(t, "the-key", time.Second, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/v1/ask", http.StatusTemporaryRedirect)
	})
	if _, ok := c.Enrich(context.Background(), testCall); ok {
		t.Fatal("a redirect produced a signal")
	}
	if elsewhere.Load() != 0 {
		t.Fatalf("the redirect was followed %d time(s), key seen there: %v", elsewhere.Load(), leakedKey.Load())
	}
}

func TestAReasonIsLoggedOncePerClassUntilTyprxAnswersAgain(t *testing.T) {
	buf := captureLog(t)
	var mode atomic.Value
	mode.Store("500")
	c, _ := fake(t, "", time.Second, func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load() {
		case "500":
			w.WriteHeader(500)
		case "garbage":
			_, _ = io.WriteString(w, "nope")
		default:
			_, _ = io.WriteString(w, goodAnswer)
		}
	})
	lines := func() int { return strings.Count(buf.String(), "no risk signal from typryx") }

	for i := 0; i < 5; i++ {
		c.Enrich(context.Background(), testCall)
	}
	if lines() != 1 {
		t.Fatalf("five 500s logged %d lines, want 1:\n%s", lines(), buf)
	}
	mode.Store("garbage")
	for i := 0; i < 3; i++ {
		c.Enrich(context.Background(), testCall)
	}
	if lines() != 2 {
		t.Fatalf("a second reason class should log once more, got %d lines:\n%s", lines(), buf)
	}
	mode.Store("ok")
	if _, ok := c.Enrich(context.Background(), testCall); !ok {
		t.Fatal("recovery produced no signal")
	}
	mode.Store("500")
	c.Enrich(context.Background(), testCall)
	if lines() != 3 {
		t.Fatalf("a failure after a working stretch should be told again, got %d lines:\n%s", lines(), buf)
	}
	if st := c.Stats(); st.NoSignal[ReasonHTTP5xx] != 6 || st.NoSignal[ReasonMalformed] != 3 || st.Signalled != 1 || st.Asked != 10 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestTheKeyNeverReachesTheLogOrTheStats(t *testing.T) {
	buf := captureLog(t)
	const marker = "SEKRET-KEY-MARKER-77"
	c, _ := fake(t, marker, time.Second, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) })
	c.Enrich(context.Background(), testCall)
	stats, _ := json.Marshal(c.Stats())
	if strings.Contains(buf.String(), marker) || strings.Contains(string(stats), marker) {
		t.Fatalf("the key reached the log or the stats:\nlog: %s\nstats: %s", buf, stats)
	}
}

func TestNewTypryxRefusesWhatItCannotUseSafely(t *testing.T) {
	good := []string{"http://typryx:4320", "https://typryx.internal", "http://127.0.0.1:4320/", "http://host/prefix/"}
	for _, u := range good {
		if _, err := NewTypryx(u, "", 0); err != nil {
			t.Errorf("%q refused: %v", u, err)
		}
	}
	bad := map[string]string{
		"empty":         "",
		"no scheme":     "typryx:4320",
		"ftp":           "ftp://typryx",
		"no host":       "http://",
		"userinfo":      "http://user:pass@typryx",
		"a query":       "http://typryx?x=1",
		"a fragment":    "http://typryx#x",
		"a relative":    "/v1/ask",
		"a javascript:": "javascript:alert(1)",
	}
	for name, u := range bad {
		if _, err := NewTypryx(u, "", 0); err == nil {
			t.Errorf("%s: %q accepted", name, u)
		}
	}
	if _, err := NewTypryx("http://typryx", "", -time.Second); err == nil {
		t.Error("a negative timeout accepted")
	}
	if _, err := NewTypryx("http://typryx", "", MaxTimeout+time.Millisecond); err == nil {
		t.Error("a timeout over the ceiling accepted")
	}
	if _, err := NewTypryx("http://typryx", "bad\nkey", 0); err == nil {
		t.Error("a key with a newline accepted: that is header injection")
	}
	c, err := NewTypryx("http://typryx:4320/prefix/", "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if c.endpoint != "http://typryx:4320/prefix/v1/ask" {
		t.Errorf("endpoint = %q", c.endpoint)
	}
	if c.Timeout() != DefaultTimeout {
		t.Errorf("zero timeout = %s, want the default %s", c.Timeout(), DefaultTimeout)
	}
}

func TestTheKeyFileIsTrimmedAndANonsenseOneIsRefusedWithoutEchoingIt(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	k, err := ReadKeyFile(write("good", "  abc123\n"))
	if err != nil || k != "abc123" {
		t.Fatalf("ReadKeyFile = %q, %v", k, err)
	}
	for name, content := range map[string]string{"empty": "", "blank": " \n\t ", "two lines": "FIRSTLINESECRET\nSECONDLINE"} {
		_, err := ReadKeyFile(write(name, content))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), "FIRSTLINESECRET") || strings.Contains(err.Error(), "SECONDLINE") {
			t.Errorf("%s: the error echoes the file's content: %v", name, err)
		}
	}
	if _, err := ReadKeyFile(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing file accepted")
	}
}

func TestConcurrentAsksAreSafe(t *testing.T) {
	captureLog(t)
	c, _ := fake(t, "", time.Second, answer(goodAnswer))
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := c.Enrich(context.Background(), testCall); !ok {
				t.Error("no signal")
			}
		}()
	}
	wg.Wait()
	if st := c.Stats(); st.Asked != 25 || st.Signalled != 25 {
		t.Fatalf("stats = %+v", st)
	}
}

// tokenfuse sends arguments_truncated when the arguments were too large to
// send. There is then nothing to classify, and asking about a tool name alone
// would be a guess dressed as an answer: no ask, no signal, counted by reason.
func TestACallWhoseArgumentsWereTruncatedIsNotAskedAbout(t *testing.T) {
	captureLog(t)
	var asks atomic.Int64
	c, _ := fake(t, "", time.Second, func(w http.ResponseWriter, r *http.Request) {
		asks.Add(1)
		_, _ = io.WriteString(w, goodAnswer)
	})
	sig, ok := c.Enrich(context.Background(), pdp.ToolCall{Name: "s3.delete_object", Target: "s3://b", ArgumentsTruncated: true})
	if ok || sig != (pdp.Signal{}) {
		t.Fatalf("a truncated call produced a signal: %+v", sig)
	}
	if asks.Load() != 0 {
		t.Fatalf("typryx was asked %d time(s)", asks.Load())
	}
	if st := c.Stats(); st.Asked != 0 || st.NoSignal[ReasonArgumentsTruncated] != 1 {
		t.Fatalf("stats = %+v, want no ask and one %q", st, ReasonArgumentsTruncated)
	}
}
