package otel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func testSpan() Span {
	return Span{
		AgentID:       "agent://acme.example/support/bot",
		RunID:         "run-1",
		Decision:      "allow",
		Reason:        "no matching deny rule",
		PolicyVersion: "v3",
		ToolNames:     []string{"read_ticket", "reply"},
		TimestampNs:   1_700_000_000_000_000_000,
	}
}

// --- New: endpoint normalization, mirroring TokenFuse's OtelSink::new ---

func TestNewNormalizesEndpoint(t *testing.T) {
	cases := map[string]string{
		"http://h:4318":            "http://h:4318/v1/traces",
		"http://h:4318/":           "http://h:4318/v1/traces",
		"http://h:4318/v1/traces":  "http://h:4318/v1/traces",
		"http://h:4318/v1/traces/": "http://h:4318/v1/traces",
	}
	for in, want := range cases {
		if got := New(in).url; got != want {
			t.Errorf("New(%q).url = %q, want %q", in, got, want)
		}
	}
}

// --- buildPayload: pure, deterministic, unit-tested without HTTP ---

func TestBuildPayloadShape(t *testing.T) {
	v := buildPayload(testSpan(), "wardryx")
	span := payloadSpan(t, v)

	if span["name"] != "policy.decide" {
		t.Errorf("name = %v, want policy.decide", span["name"])
	}
	if span["kind"] != 2 {
		t.Errorf("kind = %v, want 2 (SERVER)", span["kind"])
	}
	traceID, _ := span["traceId"].(string)
	spanID, _ := span["spanId"].(string)
	if len(traceID) != 32 {
		t.Errorf("traceId = %q, want 32 hex chars", traceID)
	}
	if len(spanID) != 16 {
		t.Errorf("spanId = %q, want 16 hex chars", spanID)
	}

	attrs := spanAttributes(t, span)
	for _, key := range []string{
		"wardryx.agent_id", "wardryx.run_id", "wardryx.decision",
		"wardryx.reason", "wardryx.policy_version", "wardryx.tool_names",
	} {
		if !hasAttr(attrs, key) {
			t.Errorf("attributes missing %q: %+v", key, attrs)
		}
	}
}

func TestBuildPayloadOmitsEmptyOptionalAttributes(t *testing.T) {
	span := Span{
		AgentID:     "agent://acme.example/bot",
		RunID:       "run-1",
		Decision:    "deny",
		TimestampNs: 1,
	}
	attrs := spanAttributes(t, payloadSpan(t, buildPayload(span, "wardryx")))
	for _, key := range []string{"wardryx.reason", "wardryx.policy_version", "wardryx.tool_names"} {
		if hasAttr(attrs, key) {
			t.Errorf("attributes unexpectedly present: %q", key)
		}
	}
}

func TestBuildPayloadServiceNameOnResource(t *testing.T) {
	v := buildPayload(testSpan(), "wardryx")
	resourceSpans, _ := v["resourceSpans"].([]map[string]any)
	resource, _ := resourceSpans[0]["resource"].(map[string]any)
	attrs, _ := resource["attributes"].([]map[string]any)
	if len(attrs) != 1 || attrs[0]["key"] != "service.name" {
		t.Fatalf("resource attributes = %+v, want one service.name entry", attrs)
	}
	value, _ := attrs[0]["value"].(map[string]any)
	if value["stringValue"] != "wardryx" {
		t.Errorf("service.name = %v, want wardryx", value["stringValue"])
	}
}

func TestSameRunSharesTraceID(t *testing.T) {
	a := testSpan()
	a.Decision = "hold"
	a.TimestampNs = 1
	b := testSpan()
	b.Decision = "allow"
	b.TimestampNs = 2

	ta := payloadSpan(t, buildPayload(a, "wardryx"))["traceId"]
	tb := payloadSpan(t, buildPayload(b, "wardryx"))["traceId"]
	if ta != tb {
		t.Errorf("traceId a=%v b=%v, want equal (same run_id)", ta, tb)
	}
}

func TestDifferentRunsGetDifferentTraceIDs(t *testing.T) {
	a := testSpan()
	a.RunID = "run-1"
	b := testSpan()
	b.RunID = "run-2"

	ta := payloadSpan(t, buildPayload(a, "wardryx"))["traceId"]
	tb := payloadSpan(t, buildPayload(b, "wardryx"))["traceId"]
	if ta == tb {
		t.Errorf("traceId should differ for different run_ids, both = %v", ta)
	}
}

func TestRepeatedDecisionsForSameRunGetDifferentSpanIDs(t *testing.T) {
	// A run held, then later allowed once approved: same trace, distinct spans.
	hold := testSpan()
	hold.Decision = "hold"
	hold.TimestampNs = 1
	allow := testSpan()
	allow.Decision = "allow"
	allow.TimestampNs = 2

	sHold := payloadSpan(t, buildPayload(hold, "wardryx"))
	sAllow := payloadSpan(t, buildPayload(allow, "wardryx"))
	if sHold["traceId"] != sAllow["traceId"] {
		t.Fatalf("expected shared traceId, got %v vs %v", sHold["traceId"], sAllow["traceId"])
	}
	if sHold["spanId"] == sAllow["spanId"] {
		t.Errorf("expected distinct spanId for hold vs allow, both = %v", sHold["spanId"])
	}
}

func TestBuildPayloadDeterministic(t *testing.T) {
	span := testSpan()
	a, _ := json.Marshal(buildPayload(span, "wardryx"))
	b, _ := json.Marshal(buildPayload(span, "wardryx"))
	if string(a) != string(b) {
		t.Errorf("buildPayload not deterministic for the same span")
	}
}

// --- Exporter.Export: fire-and-forget over real HTTP ---

func TestExportPostsToConfiguredEndpoint(t *testing.T) {
	var (
		mu       sync.Mutex
		gotPath  string
		gotCT    string
		gotBody  map[string]any
		received = make(chan struct{})
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath = r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		close(received)
	}))
	defer server.Close()

	exp := New(server.URL)
	exp.Export(testSpan())

	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the exported span to be posted")
	}

	mu.Lock()
	defer mu.Unlock()
	if gotPath != "/v1/traces" {
		t.Errorf("path = %q, want /v1/traces", gotPath)
	}
	if gotCT != "application/json" {
		t.Errorf("content-type = %q, want application/json", gotCT)
	}
	if _, ok := gotBody["resourceSpans"]; !ok {
		t.Errorf("posted body missing resourceSpans: %+v", gotBody)
	}
}

func TestExportDoesNotBlockCaller(t *testing.T) {
	// A server that never responds within the test's patience -- Export
	// must still return immediately, proving it never blocks on the POST.
	block := make(chan struct{})
	defer close(block)
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		<-block
	}))
	defer server.Close()

	exp := New(server.URL)
	done := make(chan struct{})
	go func() {
		exp.Export(testSpan())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("Export blocked the caller instead of firing the POST in the background")
	}
}

func TestExportSurvivesUnreachableEndpoint(t *testing.T) {
	// Nothing listening on this port: Export must not panic and must
	// return promptly regardless of what the background goroutine does.
	exp := New("http://127.0.0.1:1")
	done := make(chan struct{})
	go func() {
		exp.Export(testSpan())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("Export did not return promptly against an unreachable endpoint")
	}
}

// payloadSpan drills into buildPayload's nested shape down to the one span
// it always produces, failing the test loudly if the shape is wrong rather
// than panicking on a bad type assertion.
func payloadSpan(t *testing.T, v map[string]any) map[string]any {
	t.Helper()
	resourceSpans, ok := v["resourceSpans"].([]map[string]any)
	if !ok || len(resourceSpans) != 1 {
		t.Fatalf("resourceSpans = %#v, want exactly one entry", v["resourceSpans"])
	}
	scopeSpans, ok := resourceSpans[0]["scopeSpans"].([]map[string]any)
	if !ok || len(scopeSpans) != 1 {
		t.Fatalf("scopeSpans = %#v, want exactly one entry", resourceSpans[0]["scopeSpans"])
	}
	spans, ok := scopeSpans[0]["spans"].([]map[string]any)
	if !ok || len(spans) != 1 {
		t.Fatalf("spans = %#v, want exactly one entry", scopeSpans[0]["spans"])
	}
	return spans[0]
}

// spanAttributes extracts a span's "attributes" list, failing loudly if the
// shape is wrong.
func spanAttributes(t *testing.T, span map[string]any) []map[string]any {
	t.Helper()
	attrs, ok := span["attributes"].([]map[string]any)
	if !ok {
		t.Fatalf("attributes = %#v, want []map[string]any", span["attributes"])
	}
	return attrs
}

// hasAttr reports whether attrs contains an entry with the given key
// (buildPayload's attrStr shape: {"key": ..., "value": {...}}).
func hasAttr(attrs []map[string]any, key string) bool {
	for _, a := range attrs {
		if a["key"] == key {
			return true
		}
	}
	return false
}
