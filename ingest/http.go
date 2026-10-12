// Package ingest defines the shared check model (Status, Result) and the
// canary adapters that inject into HTTP-based ingestion endpoints.
package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/Brava-Security/ghost-telemetry-check/canary"
)

// Status grades a check finding.
type Status int

const (
	Pass Status = iota // auth enforced
	Warn               // hardening gap, no confirmed exposure
	Fail               // unauthenticated event accepted
)

func (s Status) String() string {
	switch s {
	case Pass:
		return "pass"
	case Warn:
		return "warn"
	case Fail:
		return "fail"
	}
	return fmt.Sprintf("status(%d)", int(s))
}

// Result is one graded finding from a check module.
type Result struct {
	Check       string
	Evidence    string
	Remediation string
	Status      Status
}

// Ingestor injects a canary into a target endpoint, verifies through the
// product API that the marker landed, and purges it where the product API
// allows.
type Ingestor interface {
	Name() string
	// Inject delivers the canary unauthenticated; nil error = accepted.
	Inject(ctx context.Context, c canary.Canary) error
	Verify(ctx context.Context, c canary.Canary) (bool, error)
	Purge(ctx context.Context, c canary.Canary) error
}

const injectTimeout = 10 * time.Second

// rejection marks an HTTP response where the endpoint processed the request
// and refused the unauthenticated event. It is distinct from transport
// failures (dial, DNS, TLS, timeout), which abort the check without a
// grade — an unreachable endpoint must never read as secure.
type rejection struct{ msg string }

func (r rejection) Error() string { return r.msg }

// httpIngestor is the shared shape of the HTTP-based adapters: it posts a
// vendor-specific canary payload to the ingest endpoint. Sources whose port
// carries no product search/delete API verify and purge manually.
type httpIngestor struct {
	name         string
	endpoint     string // ingest base URL
	endpointPath string // path appended to endpoint; "" if endpoint is the full URL
	contentType  string
	payload      func(c canary.Canary) ([]byte, error)
	api          string // product API base; "" if the ingest port has none
	searchPath   string
	purgePath    string
	check        string // Result.Check
	hardening    string // Result.Remediation when the canary is accepted
	client       *http.Client
}

func newHTTPIngestor(name string) *httpIngestor {
	return &httpIngestor{
		name: name,
		// Redirects are not followed: a 3xx is not an acceptance of the
		// event, so it grades as a rejection, not a pass-through to
		// wherever the endpoint points the client.
		client: &http.Client{
			Timeout: injectTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// jsonCanary is the semantically inert event body every adapter embeds the
// marker in.
func jsonCanary(c canary.Canary) map[string]any {
	return map[string]any{
		"message":  c.Marker,
		"tool":     "ghost-telemetry-check",
		"severity": "info",
	}
}

// markerQuery matches the canary marker in the message field.
func markerQuery(c canary.Canary) map[string]any {
	return map[string]any{"query": map[string]any{"match_phrase": map[string]any{"message": c.Marker}}}
}

// Name identifies the adapter in reports.
func (h *httpIngestor) Name() string { return h.name }

// target resolves the full ingest URL, propagating a malformed base.
func (h *httpIngestor) target() (string, error) {
	u, err := url.Parse(h.endpoint)
	if err != nil {
		return "", fmt.Errorf("%s: parsing endpoint: %w", h.name, err)
	}
	if h.endpointPath == "" {
		return u.String(), nil
	}
	return u.JoinPath(h.endpointPath).String(), nil
}

// Inject posts the canary without credentials. Acceptance of an
// unauthenticated event is itself the finding, so any 2xx counts as
// accepted and any other status is a rejection.
func (h *httpIngestor) Inject(ctx context.Context, c canary.Canary) error {
	body, err := h.payload(c)
	if err != nil {
		return fmt.Errorf("%s: encoding canary: %w", h.name, err)
	}
	target, err := h.target()
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%s: building request: %w", h.name, err)
	}
	req.Header.Set("Content-Type", h.contentType)
	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", h.name, err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) // keep the connection reusable
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return rejection{msg: fmt.Sprintf("%s: endpoint rejected unauthenticated event: HTTP %d", h.name, resp.StatusCode)}
	}
	return nil
}

// CanVerify reports whether the ingest port carries a product search API
// the agent can verify and purge through. HEC-class source ports do not:
// agent mode surfaces their manual-search guidance instead of treating the
// missing API as a failure.
func (h *httpIngestor) CanVerify() bool { return h.api != "" }

// Verify searches the product API for the marker. HTTP source ports
// (HEC, in_http, fluent-bit http, Cribl) expose no search API, so
// verification is the agent-side manual search named in the returned error.
func (h *httpIngestor) Verify(ctx context.Context, c canary.Canary) (bool, error) {
	if h.api == "" {
		return false, fmt.Errorf("%s: ingest port has no product search API; search downstream for %s", h.name, c.Marker)
	}
	body, err := json.Marshal(markerQuery(c))
	if err != nil {
		return false, fmt.Errorf("%s: encoding search: %w", h.name, err)
	}
	return h.postJSON(ctx, h.searchPath, body)
}

// Purge deletes the canary via the product API where one exists; otherwise it
// tells the operator what to search for and delete by hand.
func (h *httpIngestor) Purge(ctx context.Context, c canary.Canary) error {
	if h.api == "" {
		return fmt.Errorf("%s: product API has no delete; manual purge: search %s", h.name, c.Marker)
	}
	body, err := json.Marshal(markerQuery(c))
	if err != nil {
		return fmt.Errorf("%s: encoding delete query: %w", h.name, err)
	}
	return h.deleteByQuery(ctx, h.purgePath, body)
}

// Check runs one canary cycle and grades it. A refused (HTTP-rejected)
// unauthenticated event means auth is enforced (Pass); an accepted one means
// the endpoint ingests events from anyone who can reach it (Fail). Transport
// errors (dial, DNS, TLS, timeout) are returned ungraded — an unreachable
// endpoint is not evidence of security.
func (h *httpIngestor) Check(ctx context.Context, c canary.Canary) (Result, error) {
	err := h.Inject(ctx, c)
	if err != nil {
		var rej rejection
		if !errors.As(err, &rej) {
			return Result{}, fmt.Errorf("%s: check aborted: %w", h.name, err)
		}
		return Result{
			Check:       h.check,
			Evidence:    fmt.Sprintf("unauthenticated event rejected: %v", err),
			Remediation: "none: authentication is enforced",
			Status:      Pass,
		}, nil
	}
	evidence := "unauthenticated event accepted (HTTP 2xx)"
	if found, verr := h.Verify(ctx, c); verr != nil {
		evidence += fmt.Sprintf("; verify: %v", verr)
	} else if found {
		evidence += "; marker located via product search"
	} else {
		evidence += "; marker not found via product search"
	}
	remediation := h.hardening
	if h.api == "" {
		remediation += fmt.Sprintf("; manual purge: search %s", c.Marker)
	}
	return Result{Check: h.check, Evidence: evidence, Remediation: remediation, Status: Fail}, nil
}

func (h *httpIngestor) postJSON(ctx context.Context, path string, body []byte) (bool, error) {
	req, err := h.request(ctx, http.MethodPost, h.api, path, body)
	if err != nil {
		return false, err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("%s: %w", h.name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return false, fmt.Errorf("%s: HTTP %d", h.name, resp.StatusCode)
	}
	// Elasticsearch 7+ response shape.
	var out struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, fmt.Errorf("%s: decoding search response: %w", h.name, err)
	}
	return out.Hits.Total.Value > 0, nil
}

func (h *httpIngestor) deleteByQuery(ctx context.Context, path string, body []byte) error {
	req, err := h.request(ctx, http.MethodPost, h.api, path, body)
	if err != nil {
		return err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", h.name, err)
	}
	defer resp.Body.Close()
	// _delete_by_query returns 200 with per-shard failures or a timeout
	// flag; the status code alone does not mean the marker is gone.
	var out struct {
		Failures []any `json:"failures"`
		TimedOut bool  `json:"timed_out"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("%s: decoding delete response: %w", h.name, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s: HTTP %d", h.name, resp.StatusCode)
	}
	if out.TimedOut || len(out.Failures) > 0 {
		return fmt.Errorf("%s: delete_by_query incomplete (timed_out=%v, %d shard failures)", h.name, out.TimedOut, len(out.Failures))
	}
	return nil
}

func (h *httpIngestor) request(ctx context.Context, method, base, path string, body []byte) (*http.Request, error) {
	u, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("%s: parsing product API base: %w", h.name, err)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.JoinPath(path).String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%s: building request: %w", h.name, err)
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

// NewHEC returns an adapter for a Splunk HTTP Event Collector (port 8088).
// The HEC data port has no search or delete API: findings on it carry a
// manual-purge note.
func NewHEC(endpoint string) *httpIngestor {
	h := newHTTPIngestor("hec")
	h.endpoint = endpoint
	h.endpointPath = "/services/collector/event"
	h.contentType = "application/json"
	h.payload = func(c canary.Canary) ([]byte, error) {
		return json.Marshal(map[string]any{
			"event":      jsonCanary(c),
			"sourcetype": "_json",
		})
	}
	h.check = "Splunk HEC accepts only authenticated events"
	h.hardening = "enable HEC token authentication"
	return h
}

// NewFluentd returns an adapter for a fluentd in_http source (port 8888).
// in_http expects a JSON array by default.
func NewFluentd(endpoint string) *httpIngestor {
	h := newHTTPIngestor("fluentd")
	h.endpoint = endpoint
	h.contentType = "application/json"
	h.payload = func(c canary.Canary) ([]byte, error) {
		return json.Marshal([]any{jsonCanary(c)})
	}
	h.check = "fluentd in_http accepts only authenticated events"
	h.hardening = "add shared_key/user authentication to the in_http source (HF-fluentd-1)"
	return h
}

// NewFluentBit returns an adapter for a fluent-bit HTTP input (port 9880).
func NewFluentBit(endpoint string) *httpIngestor {
	h := newHTTPIngestor("fluentbit")
	h.endpoint = endpoint
	h.contentType = "application/json"
	h.payload = func(c canary.Canary) ([]byte, error) {
		return json.Marshal(jsonCanary(c))
	}
	h.check = "fluent-bit HTTP input accepts only authenticated events"
	h.hardening = "enable TLS and authentication on the HTTP input (HF-fluentbit-1)"
	return h
}

// NewCribl returns an adapter for a Cribl Stream HTTP source (port 10080).
func NewCribl(endpoint string) *httpIngestor {
	h := newHTTPIngestor("cribl")
	h.endpoint = endpoint
	h.contentType = "application/json"
	h.payload = func(c canary.Canary) ([]byte, error) {
		return json.Marshal(jsonCanary(c))
	}
	h.check = "Cribl HTTP source accepts only authenticated events"
	h.hardening = "add authentication to the Cribl HTTP source"
	return h
}

// NewElastic returns an adapter that bulk-indexes into the brava-research
// index (NDJSON) and verifies/purges through the Elasticsearch product API.
func NewElastic(endpoint string) *httpIngestor {
	h := newHTTPIngestor("elastic")
	h.endpoint = endpoint
	h.endpointPath = "/brava-research/_bulk"
	h.contentType = "application/x-ndjson"
	h.api = endpoint
	h.searchPath = "/brava-research/_search"
	h.purgePath = "/brava-research/_delete_by_query"
	h.payload = func(c canary.Canary) ([]byte, error) {
		meta, err := json.Marshal(map[string]any{"index": map[string]any{"_index": "brava-research"}})
		if err != nil {
			return nil, err
		}
		doc, err := json.Marshal(jsonCanary(c))
		if err != nil {
			return nil, err
		}
		return append(append(meta, '\n'), append(doc, '\n')...), nil
	}
	h.check = "Elasticsearch bulk API accepts only authenticated events"
	h.hardening = "enable Elasticsearch security (HF-elastic-1)"
	return h
}
