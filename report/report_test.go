package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Brava-Security/ghost-telemetry-check/ingest"
)

func TestExitCodeFailDominates(t *testing.T) {
	res := []ingest.Result{{Status: ingest.Pass}, {Status: ingest.Warn}, {Status: ingest.Fail}}
	if code := ExitCode(res); code != 2 {
		t.Fatalf("want 2, got %d", code)
	}
}

func TestExitCode(t *testing.T) {
	tests := []struct {
		name string
		res  []ingest.Result
		want int
	}{
		{"empty is pass", nil, 0},
		{"all pass", []ingest.Result{{Status: ingest.Pass}, {Status: ingest.Pass}}, 0},
		{"warn only", []ingest.Result{{Status: ingest.Pass}, {Status: ingest.Warn}}, 1},
		{"fail only", []ingest.Result{{Status: ingest.Fail}}, 2},
		{"fail beats warn", []ingest.Result{{Status: ingest.Warn}, {Status: ingest.Fail}}, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExitCode(tc.res); got != tc.want {
				t.Fatalf("want %d, got %d", tc.want, got)
			}
		})
	}
}

func TestRenderTable(t *testing.T) {
	res := []ingest.Result{
		{Check: "http-canary", Evidence: "endpoint rejected unauthenticated event", Remediation: "https://brava.io/docs", Status: ingest.Pass},
		{Check: "audit-secrets", Evidence: "token in audit log", Remediation: "rotate it", Status: ingest.Warn},
		{Check: "syslog-canary", Evidence: "accepted event", Remediation: "enable TLS+auth", Status: ingest.Fail},
	}
	var buf bytes.Buffer
	if err := RenderTable(&buf, res); err != nil {
		t.Fatalf("RenderTable: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"STATUS", "CHECK", "EVIDENCE", "REMEDIATION", "PASS", "WARN", "FAIL", "http-canary", "syslog-canary", "rotate it"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
}

func TestRenderTableEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderTable(&buf, nil); err != nil {
		t.Fatalf("RenderTable: %v", err)
	}
	if !strings.Contains(buf.String(), "STATUS") {
		t.Errorf("empty input should still print header, got:\n%s", buf.String())
	}
}

func TestRenderJSON(t *testing.T) {
	res := []ingest.Result{
		{Check: "http-canary", Evidence: "e", Remediation: "r", Status: ingest.Fail},
	}
	var buf bytes.Buffer
	if err := RenderJSON(&buf, res, ""); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var doc struct {
		Results []struct {
			Check       string `json:"check"`
			Status      string `json:"status"`
			Evidence    string `json:"evidence"`
			Remediation string `json:"remediation"`
		} `json:"results"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON %q: %v", buf.String(), err)
	}
	if len(doc.Results) != 1 {
		t.Fatalf("want 1 result, got %d", len(doc.Results))
	}
	r := doc.Results[0]
	if r.Check != "http-canary" || r.Status != "fail" || r.Evidence != "e" || r.Remediation != "r" {
		t.Errorf("bad result: %+v", r)
	}
}

func TestRenderJSONEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(&buf, nil, ""); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if strings.TrimSpace(buf.String()) != `{"results":[]}` {
		t.Errorf("want empty results JSON, got %q", buf.String())
	}
}

// Finding 3: the JSON envelope carries the probe run's canary marker so a
// CI pipeline can pass it to `agent --marker`; empty marker is omitted.
func TestRenderJSONCarriesCanaryMarker(t *testing.T) {
	res := []ingest.Result{{Check: "c", Evidence: "e", Remediation: "r", Status: ingest.Warn}}
	var buf bytes.Buffer
	if err := RenderJSON(&buf, res, "BRAVA-CHECK-f5067650-7d2f-44c1-873b-3b970d47b88d"); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	var doc struct {
		CanaryMarker string `json:"canary_marker"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON %q: %v", buf.String(), err)
	}
	if doc.CanaryMarker != "BRAVA-CHECK-f5067650-7d2f-44c1-873b-3b970d47b88d" {
		t.Fatalf("canary_marker = %q", doc.CanaryMarker)
	}
	buf.Reset()
	if err := RenderJSON(&buf, res, ""); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if strings.Contains(buf.String(), "canary_marker") {
		t.Fatalf("empty marker must be omitted, got %q", buf.String())
	}
}
