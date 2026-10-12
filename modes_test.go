package main

// End-to-end wiring tests: real local listeners exercise the actual adapters
// through Run, per Ruling R4 (the campaign lab stack is gated; local
// listeners stand in for the vendor endpoints).

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// statusServer stands in for a vendor ingest port: every request gets the
// given status. 200 = tokenless source, 401 = token'd HEC.
func statusServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// elasticMock stands in for the Elasticsearch product API. searchBody, when
// non-nil, captures the marker query so tests can assert what was searched.
func elasticMock(t *testing.T, hits int, deleteOK bool, searchBody *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/brava-research/_search":
			if searchBody != nil {
				*searchBody = string(b)
			}
			fmt.Fprintf(w, `{"hits":{"total":{"value":%d}}}`, hits)
		case "/brava-research/_delete_by_query":
			if deleteOK {
				fmt.Fprint(w, `{"took":1,"timed_out":false,"failures":[]}`)
			} else {
				fmt.Fprint(w, `{"took":1,"timed_out":true,"failures":[]}`)
			}
		default: // the _bulk ingest port accepts the canary
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// shodanMock stands in for the Shodan API: 200 = indexed, 404 = not indexed.
func shodanMock(t *testing.T, status int, gotPath *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gotPath != nil {
			*gotPath = r.URL.Path
		}
		if status == http.StatusNotFound {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		fmt.Fprint(w, `{"data":[{"port":514}],"last_update":"2026-08-31T10:00:00"}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestProbeOpenSourceFailsAndNotesManualPurge(t *testing.T) {
	srv := statusServer(t, http.StatusOK) // tokenless source accepts anyone
	var out strings.Builder
	code := Run([]string{"probe", "--target", srv.URL, "--adapter", "cribl"}, &out)
	if code != exitFail {
		t.Fatalf("open listener must fail (exit 2), got %d\n%s", code, out.String())
	}
	s := out.String()
	if !strings.Contains(s, "FAIL") || !strings.Contains(s, "unauthenticated event accepted") {
		t.Fatalf("missing fail row:\n%s", s)
	}
	// Cribl's ingest port has no delete API: the row must say what to purge.
	if !strings.Contains(s, "manual purge") {
		t.Fatalf("missing manual purge note:\n%s", s)
	}
}

func TestProbeAuthenticatedHECPasses(t *testing.T) {
	srv := statusServer(t, http.StatusUnauthorized) // token'd HEC
	var out strings.Builder
	code := Run([]string{"probe", "--target", srv.URL, "--adapter", "hec"}, &out)
	if code != exitPass {
		t.Fatalf("401 listener must pass (exit 0), got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "PASS") || !strings.Contains(out.String(), "rejected") {
		t.Fatalf("missing pass row:\n%s", out.String())
	}
}

func TestProbeElasticAutoPurgesAcceptedCanary(t *testing.T) {
	srv := elasticMock(t, 1, true, nil) // canary accepted, search finds it, delete works
	var out strings.Builder
	code := Run([]string{"probe", "--target", srv.URL, "--adapter", "elastic"}, &out)
	if code != exitFail {
		t.Fatalf("accepted canary must fail (exit 2), got %d\n%s", code, out.String())
	}
	s := out.String()
	if !strings.Contains(s, "marker located via product search") {
		t.Fatalf("missing verify evidence:\n%s", s)
	}
	if !strings.Contains(s, "canary purged via product API") {
		t.Fatalf("missing auto-purge evidence:\n%s", s)
	}
}

func TestProbeSyslogUDPWarnsAndDefersToAgentMode(t *testing.T) {
	var out strings.Builder
	// Local loopback UDP write needs no listener: the transport is
	// fire-and-forget and that is exactly what the row must disclose.
	code := Run([]string{"probe", "--target", "udp://127.0.0.1:514"}, &out)
	if code != exitWarn {
		t.Fatalf("unverifiable syslog canary must warn (exit 1), got %d\n%s", code, out.String())
	}
	s := out.String()
	if !strings.Contains(s, "WARN") {
		t.Fatalf("missing warn row:\n%s", s)
	}
	if !strings.Contains(s, "verification requires agent mode") {
		t.Fatalf("missing agent-mode note:\n%s", s)
	}
}

func TestProbeMultipleTargetsEachGetARow(t *testing.T) {
	var out strings.Builder
	code := Run([]string{"probe", "--target", "udp://127.0.0.1:514,udp://127.0.0.1:12201"}, &out)
	if code != exitWarn {
		t.Fatalf("two unverifiable canaries must warn (exit 1), got %d\n%s", code, out.String())
	}
	if got := strings.Count(out.String(), "WARN"); got != 2 {
		t.Fatalf("want 2 warn rows, got %d:\n%s", got, out.String())
	}
}

func TestProbeHTTPTransportErrorAborts(t *testing.T) {
	var out strings.Builder
	// Port 1 on loopback is closed; an unreachable endpoint must abort, not
	// read as secure.
	code := Run([]string{"probe", "--target", "http://127.0.0.1:1", "--adapter", "hec"}, &out)
	if code != exitInternal {
		t.Fatalf("transport error must exit 3, got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "error:") {
		t.Fatalf("missing error line:\n%s", out.String())
	}
}

func TestProbeSyslogTCPTransportErrorAborts(t *testing.T) {
	var out strings.Builder
	code := Run([]string{"probe", "--target", "tcp://127.0.0.1:1", "--adapter", "syslog-tcp"}, &out)
	if code != exitInternal {
		t.Fatalf("transport error must exit 3, got %d\n%s", code, out.String())
	}
}

func TestProbeHonorsContextDeadline(t *testing.T) {
	old := targetTimeout
	targetTimeout = 150 * time.Millisecond
	t.Cleanup(func() { targetTimeout = old })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		time.Sleep(time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	var out strings.Builder
	start := time.Now()
	code := Run([]string{"probe", "--target", srv.URL, "--adapter", "cribl"}, &out)
	if code != exitInternal {
		t.Fatalf("hanging endpoint must abort (exit 3), got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "error:") {
		t.Fatalf("missing error line:\n%s", out.String())
	}
	if elapsed := time.Since(start); elapsed > 900*time.Millisecond {
		t.Fatalf("probe ignored its context deadline (took %v)", elapsed)
	}
}

func TestProbeJSONOutputParses(t *testing.T) {
	srv := statusServer(t, http.StatusUnauthorized)
	var out strings.Builder
	code := Run([]string{"probe", "--target", srv.URL, "--adapter", "hec", "--json"}, &out)
	if code != exitPass {
		t.Fatalf("want exit 0, got %d\n%s", code, out.String())
	}
	var doc struct {
		Results []struct {
			Check  string `json:"check"`
			Status string `json:"status"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(out.String()), &doc); err != nil {
		t.Fatalf("output is not parseable JSON: %v\n%s", err, out.String())
	}
	if len(doc.Results) != 1 || doc.Results[0].Status != "pass" {
		t.Fatalf("want one pass result, got %+v", doc.Results)
	}
}

func TestAgentVerifyFindsAndPurgesMarker(t *testing.T) {
	var body string
	srv := elasticMock(t, 1, true, &body)
	var out strings.Builder
	code := Run([]string{"agent", "--target", srv.URL, "--adapter", "elastic",
		"--marker", "BRAVA-CHECK-11111111-2222-3333-4444-555555555555"}, &out)
	if code != exitPass {
		t.Fatalf("found+purged marker must pass (exit 0), got %d\n%s", code, out.String())
	}
	s := out.String()
	if !strings.Contains(s, "PASS") || !strings.Contains(s, "purged via product API") {
		t.Fatalf("missing purged pass row:\n%s", s)
	}
	if !strings.Contains(body, "BRAVA-CHECK-11111111-2222-3333-4444-555555555555") {
		t.Fatalf("marker missing from product search: %s", body)
	}
}

func TestAgentAcceptsBareUUIDMarker(t *testing.T) {
	var body string
	srv := elasticMock(t, 0, true, &body)
	var out strings.Builder
	code := Run([]string{"agent", "--target", srv.URL, "--adapter", "elastic",
		"--marker", "11111111-2222-3333-4444-555555555555"}, &out)
	if code != exitPass {
		t.Fatalf("want exit 0, got %d\n%s", code, out.String())
	}
	if !strings.Contains(body, "BRAVA-CHECK-11111111-2222-3333-4444-555555555555") {
		t.Fatalf("bare UUID must be normalized to the full marker: %s", body)
	}
}

func TestAgentMarkerNotFoundPasses(t *testing.T) {
	srv := elasticMock(t, 0, true, nil)
	var out strings.Builder
	code := Run([]string{"agent", "--target", srv.URL, "--adapter", "elastic",
		"--marker", "BRAVA-CHECK-11111111-2222-3333-4444-555555555555"}, &out)
	if code != exitPass {
		t.Fatalf("nothing to purge must pass (exit 0), got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "not found via product search") {
		t.Fatalf("missing not-found evidence:\n%s", out.String())
	}
}

func TestAgentPurgeFailureFails(t *testing.T) {
	srv := elasticMock(t, 1, false, nil) // marker found, delete_by_query incomplete
	var out strings.Builder
	code := Run([]string{"agent", "--target", srv.URL, "--adapter", "elastic",
		"--marker", "BRAVA-CHECK-11111111-2222-3333-4444-555555555555"}, &out)
	if code != exitFail {
		t.Fatalf("found-but-not-purged marker must fail (exit 2), got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "purge failed") || !strings.Contains(out.String(), "FAIL") {
		t.Fatalf("missing purge-failure row:\n%s", out.String())
	}
}

func TestAgentHECPortCarriesManualSearchGuidance(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	var out strings.Builder
	code := Run([]string{"agent", "--target", srv.URL, "--adapter", "hec",
		"--marker", "BRAVA-CHECK-11111111-2222-3333-4444-555555555555"}, &out)
	if code != exitWarn {
		t.Fatalf("manual-search guidance must warn (exit 1), got %d\n%s", code, out.String())
	}
	s := out.String()
	if !strings.Contains(s, "no product search API") || !strings.Contains(s, "BRAVA-CHECK-11111111-2222-3333-4444-555555555555") {
		t.Fatalf("missing manual guidance with marker:\n%s", s)
	}
	if hits.Load() != 0 {
		t.Fatal("agent must not call the HEC ingest port; it has no product API")
	}
}

func TestAgentSyslogTargetIsManualNote(t *testing.T) {
	var out strings.Builder
	code := Run([]string{"agent", "--target", "udp://127.0.0.1:514",
		"--marker", "BRAVA-CHECK-11111111-2222-3333-4444-555555555555"}, &out)
	if code != exitWarn {
		t.Fatalf("unsupported syslog verify must warn (exit 1), got %d\n%s", code, out.String())
	}
	s := out.String()
	if !strings.Contains(s, "WARN") || !strings.Contains(s, "marker to search for: BRAVA-CHECK-11111111-2222-3333-4444-555555555555") {
		t.Fatalf("missing syslog manual note:\n%s", s)
	}
}

func TestAuditAggregatesConfigAndSecretFindings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "fluent.conf"),
		[]byte("<source>\n @type http\n port 8888\n bind 0.0.0.0\n</source>\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "collect.sh"),
		[]byte("curl https://collectors.us.sumologic.com/receiver/v1/http/ZVhhZmF1bHRJZDEyMzQ1Njc4OTA==\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	code := Run([]string{"audit", "--config", dir}, &out)
	if code != exitFail {
		t.Fatalf("no-auth config + leaked credential must fail (exit 2), got %d\n%s", code, out.String())
	}
	s := out.String()
	if !strings.Contains(s, "HF-fluentd-1") {
		t.Fatalf("missing config finding:\n%s", s)
	}
	if !strings.Contains(s, "HF-cloud-1") {
		t.Fatalf("missing secret finding:\n%s", s)
	}
}

func TestAuditCleanDirPasses(t *testing.T) {
	var out strings.Builder
	code := Run([]string{"audit", "--config", t.TempDir()}, &out)
	if code != exitPass {
		t.Fatalf("clean dir must pass (exit 0), got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "STATUS") {
		t.Fatalf("missing report header:\n%s", out.String())
	}
}

func TestShodanFlagWithoutKeyAbortsLoudly(t *testing.T) {
	t.Setenv("SHODAN_API_KEY", "")
	var out strings.Builder
	code := Run([]string{"probe", "--target", "udp://127.0.0.1:514", "--shodan"}, &out)
	if code != exitInternal {
		t.Fatalf("requested module without its key must abort (exit 3), got %d\n%s", code, out.String())
	}
	s := out.String()
	if !strings.Contains(s, "SHODAN_API_KEY") {
		t.Fatalf("missing key hint:\n%s", s)
	}
	// The probe rows still render; only the optional module aborted.
	if !strings.Contains(s, "verification requires agent mode") {
		t.Fatalf("probe row missing after shodan abort:\n%s", s)
	}
}

func TestShodanIndexedEndpointRendersWarnRow(t *testing.T) {
	var gotPath string
	srv := shodanMock(t, http.StatusOK, &gotPath)
	old := shodanAPIBase
	shodanAPIBase = srv.URL
	t.Cleanup(func() { shodanAPIBase = old })
	t.Setenv("SHODAN_API_KEY", "test-key")
	var out strings.Builder
	code := Run([]string{"probe", "--target", "udp://127.0.0.1:514", "--shodan"}, &out)
	if code != exitWarn {
		t.Fatalf("indexed endpoint must warn (exit 1), got %d\n%s", code, out.String())
	}
	s := out.String()
	if !strings.Contains(s, "Shodan index visibility") || !strings.Contains(s, "last seen 2026-08-31T10:00:00") {
		t.Fatalf("missing shodan warn row:\n%s", s)
	}
	if gotPath != "/shodan/host/127.0.0.1" {
		t.Fatalf("lookup must normalize the target to its IP, got path %q", gotPath)
	}
}

func TestShodanUnindexedEndpointRendersPassRow(t *testing.T) {
	srv := shodanMock(t, http.StatusNotFound, nil)
	old := shodanAPIBase
	shodanAPIBase = srv.URL
	t.Cleanup(func() { shodanAPIBase = old })
	t.Setenv("SHODAN_API_KEY", "test-key")
	var out strings.Builder
	code := Run([]string{"probe", "--target", "udp://127.0.0.1:514", "--shodan"}, &out)
	if code != exitWarn {
		t.Fatalf("syslog warn still dominates (exit 1), got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "not present in Shodan's index") {
		t.Fatalf("missing not-indexed pass row:\n%s", out.String())
	}
}
