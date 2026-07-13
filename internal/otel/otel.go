// Package otel exports one OTLP/HTTP-JSON span per Wardryx decision
// (allow/deny/hold), mirroring TokenFuse's own OTLP exporter
// (tokenfuse/crates/gateway/src/otel.rs): a hand-rolled POST to
// <endpoint>/v1/traces built directly against the OTLP/HTTP JSON wire
// format, not a full OpenTelemetry SDK. Fire-and-forget, so it never blocks
// the /v1/decide path it describes, and a no-op unless WARDRYX_OTLP_ENDPOINT
// is set (see internal/config.Config.OTLPEndpoint).
//
// Every decision for one run_id shares a trace id (derived from run_id
// alone), so a run's allow/hold/allow sequence shows up as one trace in
// Grafana/Datadog/Honeycomb, matching TokenFuse's per-run trace grouping.
// The derivation is Wardryx-internal (SHA-256, not TokenFuse's Rust
// DefaultHasher, which has no portable Go equivalent), so it is stable
// across Wardryx restarts but does not itself merge into the same trace as
// TokenFuse's own spans for that run_id -- cross-service trace correlation
// would need a shared trace-id derivation across the stack, a larger,
// separate change than this exporter.
package otel

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Span is everything about one /v1/decide outcome worth exporting. Kept
// separate from internal/api's DTOs so this package has no dependency on
// api, and separate from time.Now() so BuildPayload stays pure and
// testable: the caller supplies TimestampNs (see Exporter.Export).
type Span struct {
	AgentID       string
	RunID         string
	Decision      string // pdp.Allow | pdp.Deny | pdp.Hold ("allow"/"deny"/"hold")
	Reason        string
	PolicyVersion string
	ToolNames     []string
	// TimestampNs is the decision's wall-clock time, Unix nanoseconds.
	TimestampNs int64
}

// Exporter posts one OTLP/HTTP-JSON span per Export call to a configured
// OTLP endpoint. The zero value is not usable; construct with New.
type Exporter struct {
	client  *http.Client
	url     string
	service string
}

// New builds an Exporter for endpoint, normalizing it to end in
// "/v1/traces" the same way TokenFuse's OtelSink::new does.
func New(endpoint string) *Exporter {
	base := strings.TrimRight(endpoint, "/")
	url := base
	if !strings.HasSuffix(base, "/v1/traces") {
		url = base + "/v1/traces"
	}
	return &Exporter{
		// A bounded timeout so an unresponsive collector cannot leak
		// goroutines/connections indefinitely; Export already runs off the
		// request path, so this only protects the exporter's own
		// background work, never a caller.
		client:  &http.Client{Timeout: 5 * time.Second},
		url:     url,
		service: "wardryx",
	}
}

// Export posts span's OTLP payload in a new goroutine and returns
// immediately. Best-effort: a marshal failure, dial failure, or non-2xx
// response is dropped silently, matching TokenFuse's own OtelSink and this
// codebase's agent-event exporter -- telemetry delivery never fails or
// delays the /v1/decide call it describes.
func (e *Exporter) Export(span Span) {
	payload, err := json.Marshal(buildPayload(span, e.service))
	if err != nil {
		return
	}
	go func() {
		req, err := http.NewRequest(http.MethodPost, e.url, bytes.NewReader(payload))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := e.client.Do(req)
		if err != nil {
			return
		}
		_ = resp.Body.Close()
	}()
}

// buildPayload builds the OTLP/HTTP-JSON resourceSpans payload for one
// decision. Pure and deterministic given the same span and service --
// unit-tested directly, no HTTP involved, mirroring TokenFuse's otlp_json.
func buildPayload(span Span, service string) map[string]any {
	nanos := strconv.FormatInt(span.TimestampNs, 10)

	spanAttrs := []map[string]any{
		attrStr("wardryx.agent_id", span.AgentID),
		attrStr("wardryx.run_id", span.RunID),
		attrStr("wardryx.decision", span.Decision),
	}
	if span.Reason != "" {
		spanAttrs = append(spanAttrs, attrStr("wardryx.reason", span.Reason))
	}
	if span.PolicyVersion != "" {
		spanAttrs = append(spanAttrs, attrStr("wardryx.policy_version", span.PolicyVersion))
	}
	if len(span.ToolNames) > 0 {
		spanAttrs = append(spanAttrs, attrStr("wardryx.tool_names", strings.Join(span.ToolNames, ",")))
	}

	return map[string]any{
		"resourceSpans": []map[string]any{
			{
				"resource": map[string]any{
					"attributes": []map[string]any{attrStr("service.name", service)},
				},
				"scopeSpans": []map[string]any{
					{
						"scope": map[string]any{"name": "wardryx"},
						"spans": []map[string]any{
							{
								"traceId": traceID(span.RunID),
								"spanId":  spanID(span.AgentID, span.RunID, span.Decision, span.TimestampNs),
								"name":    "policy.decide",
								// SERVER: /v1/decide is an inbound request
								// Wardryx handles, not an outbound call it
								// makes (contrast TokenFuse's own CLIENT
								// span for its outbound LLM call).
								"kind":              2,
								"startTimeUnixNano": nanos,
								"endTimeUnixNano":   nanos,
								"attributes":        spanAttrs,
							},
						},
					},
				},
			},
		},
	}
}

func attrStr(key, value string) map[string]any {
	return map[string]any{"key": key, "value": map[string]any{"stringValue": value}}
}

// traceID derives a 16-byte (32 hex char) OTLP trace id from run_id alone,
// so every decision belonging to the same run shares one trace.
func traceID(runID string) string {
	sum := sha256.Sum256([]byte("wardryx-trace|" + runID))
	return hex.EncodeToString(sum[:16])
}

// spanID derives an 8-byte (16 hex char) OTLP span id. Folding in decision
// and timestamp (not just agent/run id) keeps repeated decisions for the
// same run -- e.g. hold, then a later allow once approved -- from
// colliding on the same span id.
func spanID(agentID, runID, decision string, timestampNs int64) string {
	sum := sha256.Sum256(
		[]byte("wardryx-span|" + agentID + "|" + runID + "|" + decision + "|" + strconv.FormatInt(timestampNs, 10)),
	)
	return hex.EncodeToString(sum[:8])
}
