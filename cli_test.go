package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProbeModeRejectsMissingTarget(t *testing.T) {
	var out strings.Builder
	code := Run([]string{"probe", "--target", ""}, &out)
	if code != 3 {
		t.Fatalf("want exit 3, got %d", code)
	}
	if !strings.Contains(out.String(), "--target is required") {
		t.Fatal("missing hint")
	}
}

// The shared flag set parses every flag for every mode (Task 1 contract);
// the probe run below exercises the full parse → wire path with only
// loopback traffic.
func TestProbeModeParsesAllFlags(t *testing.T) {
	var out strings.Builder
	code := Run([]string{"probe", "--target", "udp://127.0.0.1:514", "--config", "/etc/collectors", "--verbose"}, &out)
	if code != exitWarn {
		t.Fatalf("unverifiable syslog canary must warn (exit 1), got %d\n%s", code, out.String())
	}
	s := out.String()
	if !strings.Contains(s, "verification requires agent mode") {
		t.Fatalf("missing agent-mode note, got %q", s)
	}
	// The marker is the handoff token for agent mode: probe always prints it.
	if !strings.Contains(s, "canary marker: BRAVA-CHECK-") {
		t.Fatalf("missing marker line, got %q", s)
	}
}

func TestAgentModeRequiresMarker(t *testing.T) {
	var out strings.Builder
	code := Run([]string{"agent", "--target", "http://siem.example.com:9200"}, &out)
	if code != exitInternal {
		t.Fatalf("want exit 3, got %d", code)
	}
	if !strings.Contains(out.String(), "--marker is required") {
		t.Fatalf("missing hint, got %q", out.String())
	}
}

func TestAgentModeRejectsMissingTarget(t *testing.T) {
	var out strings.Builder
	code := Run([]string{"agent", "--marker", "BRAVA-CHECK-x"}, &out)
	if code != exitInternal {
		t.Fatalf("want exit 3, got %d", code)
	}
	if !strings.Contains(out.String(), "--target is required") {
		t.Fatalf("missing hint, got %q", out.String())
	}
}

func TestAuditModeScansGivenRoot(t *testing.T) {
	var out strings.Builder
	code := Run([]string{"audit", "--config", t.TempDir(), "--verbose"}, &out)
	if code != exitPass {
		t.Fatalf("empty config dir must pass (exit 0), got %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "STATUS") {
		t.Fatalf("missing report header, got %q", out.String())
	}
}

func TestUsageForMissingOrUnknownSubcommand(t *testing.T) {
	cases := [][]string{
		{},
		{"frobnicate"},
	}
	for _, args := range cases {
		var out strings.Builder
		code := Run(args, &out)
		if code != 3 {
			t.Fatalf("args %v: want exit 3, got %d", args, code)
		}
		for _, mode := range []string{"agent", "audit", "probe"} {
			if !strings.Contains(out.String(), mode) {
				t.Fatalf("args %v: usage missing subcommand %q, got %q", args, mode, out.String())
			}
		}
	}
}

func TestInvalidFlagIsReportedThroughWriter(t *testing.T) {
	var out strings.Builder
	code := Run([]string{"probe", "--nope"}, &out)
	if code != 3 {
		t.Fatalf("want exit 3, got %d", code)
	}
	// The Run interface exposes only stdout, so parse errors must surface
	// through it rather than os.Stderr.
	if !strings.Contains(out.String(), "not defined") {
		t.Fatalf("want flag error captured via writer, got %q", out.String())
	}
}

// Binding carry: the --shodan help text must disclose, verbatim, that this
// is the only check that puts the endpoint IP in a third-party data path.
func TestHelpCarriesHeuristicAndShodanDisclosure(t *testing.T) {
	var out strings.Builder
	if code := Run([]string{"probe", "-h"}, &out); code != exitPass {
		t.Fatalf("help must exit 0, got %d", code)
	}
	s := out.String()
	for _, want := range []string{"8088", "12201", "--adapter"} {
		if !strings.Contains(s, want) {
			t.Fatalf("help must state the port heuristic (missing %q):\n%s", want, s)
		}
	}
	const verbatim = "this module sends your endpoint IP to Shodan — the only check that does; default off"
	if !strings.Contains(s, verbatim) {
		t.Fatalf("--shodan help must carry the verbatim disclosure:\n%s", s)
	}
	var top strings.Builder
	if code := Run([]string{"--help"}, &top); code != exitPass {
		t.Fatalf("top-level help must exit 0, got %d", code)
	}
	if !strings.Contains(top.String(), "subcommands") {
		t.Fatalf("top-level help missing usage: %q", top.String())
	}
}

func TestAdapterSelectionByPort(t *testing.T) {
	cases := []struct{ target, want string }{
		{"http://siem.example.com:8088", "hec"},
		{"siem.example.com:8088", "hec"}, // bare host:port
		{"https://siem.example.com:8088", "hec"},
		{"siem.example.com:8888", "fluentd"},
		{"siem.example.com:9880", "fluentbit"},
		{"siem.example.com:10080", "cribl"},
		{"siem.example.com:9200", "elastic"},
		{"tcp://siem.example.com:514", "syslog-tcp"},
		{"udp://siem.example.com:514", "syslog-udp"},
		{"udp://siem.example.com:12201", "gelf"},
		{"siem.example.com:12201", "gelf"}, // bare GELF target defaults to UDP
	}
	for _, c := range cases {
		ad, err := adapterForTarget(c.target, "")
		if err != nil {
			t.Fatalf("%s: %v", c.target, err)
		}
		if ad.Name() != c.want {
			t.Fatalf("%s: want adapter %q, got %q", c.target, c.want, ad.Name())
		}
	}
}

func TestAdapterSelectionErrorsInsteadOfGuessing(t *testing.T) {
	cases := []struct {
		target, adapter, wantErr string
	}{
		{"siem.example.com:9999", "", "--adapter"},       // unknown port
		{"siem.example.com:514", "", "tcp://"},           // TCP/UDP ambiguity
		{"http://siem.example.com:514", "", "syslog"},    // syslog is not HTTP
		{"siem.example.com", "", "port"},                 // no port, no override
		{"gopher://siem.example.com:8088", "", "scheme"}, // unsupported scheme
		{"tcp://siem.example.com:12201", "", "UDP"},      // GELF here speaks UDP
		{"udp://siem.example.com:8088", "", "--adapter"}, // UDP scheme on an HTTP port
		{"siem.example.com:8088", "nope", "unknown --adapter"},
		{"siem.example.com:8088/api", "", "base address"},     // paths belong to adapters
		{"http://siem.example.com:8088", "syslog-udp", "UDP"}, // override/scheme mismatch
	}
	for _, c := range cases {
		_, err := adapterForTarget(c.target, c.adapter)
		if err == nil {
			t.Fatalf("%s (adapter %q): expected an error, never a silent guess", c.target, c.adapter)
		}
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Fatalf("%s (adapter %q): error %q must mention %q", c.target, c.adapter, err, c.wantErr)
		}
	}
}

func TestAdapterOverrideBeatsThePortHeuristic(t *testing.T) {
	ad, err := adapterForTarget("siem.example.com:8088", "cribl")
	if err != nil {
		t.Fatal(err)
	}
	if ad.Name() != "cribl" {
		t.Fatalf("override must win, got %q", ad.Name())
	}
	// An explicit adapter also resolves the port-514 TCP/UDP ambiguity.
	ad, err = adapterForTarget("siem.example.com:514", "syslog-tcp")
	if err != nil {
		t.Fatal(err)
	}
	if ad.Name() != "syslog-tcp" {
		t.Fatalf("override must win, got %q", ad.Name())
	}
}

// Finding 2: a typo'd or truncated --marker must never read as a clean
// "nothing to purge" PASS — a malformed marker is a usage error (exit 3).
func TestAgentModeRejectsMalformedMarker(t *testing.T) {
	var out strings.Builder
	code := Run([]string{"agent", "--target", "http://siem.example.com:9200", "--marker", "BRAVA-CHECK-typo"}, &out)
	if code != exitInternal {
		t.Fatalf("malformed marker must exit 3, got %d\n%s", code, out.String())
	}
	s := out.String()
	if !strings.Contains(s, "--marker") {
		t.Fatalf("missing marker hint, got %q", s)
	}
	if strings.Contains(s, "PASS") {
		t.Fatalf("malformed marker must never render a PASS row, got %q", s)
	}
}

// Finding 3: --json suppresses the text marker handoff line, so the JSON
// envelope must carry the marker (canary_marker) for CI pipelines to hand
// to `agent --marker`.
func TestProbeJSONCarriesCanaryMarker(t *testing.T) {
	var out strings.Builder
	code := Run([]string{"probe", "--target", "udp://127.0.0.1:514", "--json"}, &out)
	if code != exitWarn {
		t.Fatalf("unverifiable syslog canary must warn (exit 1), got %d\n%s", code, out.String())
	}
	var doc struct {
		CanaryMarker string `json:"canary_marker"`
		Results      []struct {
			Status string `json:"status"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(out.String()), &doc); err != nil {
		t.Fatalf("probe --json output is not valid JSON: %v\n%s", err, out.String())
	}
	if !strings.HasPrefix(doc.CanaryMarker, "BRAVA-CHECK-") || len(doc.CanaryMarker) != len("BRAVA-CHECK-")+36 {
		t.Fatalf("canary_marker missing or malformed: %q", doc.CanaryMarker)
	}
}
