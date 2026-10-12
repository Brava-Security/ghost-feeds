package audit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Brava-Security/ghost-telemetry-check/ingest"
)

func copyFixture(t *testing.T, name string) string {
	t.Helper()
	src := filepath.Join("testdata", name)
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, fixtureBase(name)), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// fixtureBase strips the -hardened suffix so the copied file keeps the
// vendor filename the patterns match on (fluent.conf, inputs.conf, ...).
func fixtureBase(name string) string {
	switch {
	case len(name) > len("-hardened.conf") && name[len(name)-len("-hardened.conf"):] == "-hardened.conf":
		return name[:len(name)-len("-hardened")] + ".conf"
	case name == "elasticsearch-hardened.yml":
		return "elasticsearch.yml"
	}
	return name
}

func findings(res []ingest.Result, id string) []ingest.Result {
	var out []ingest.Result
	for _, r := range res {
		if r.Remediation == id {
			out = append(out, r)
		}
	}
	return out
}

func TestAuditFlagsFluentdInHTTPNoAuth(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "fluent.conf"),
		[]byte("<source>\n @type http\n port 8888\n bind 0.0.0.0\n</source>\n"), 0o644)
	res, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range res {
		if r.Remediation == "HF-fluentd-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected HF-fluentd-1 finding, got %+v", res)
	}
}

func TestAuditFiresOnEachVendorFixture(t *testing.T) {
	cases := []struct {
		fixture string
		id      string
	}{
		{"fluent.conf", "HF-fluentd-1"},
		{"inputs.conf", "HF-splunk-1"},
		{"elasticsearch.yml", "HF-elastic-1"},
		{"fluent-bit.conf", "HF-fluentbit-1"},
	}
	for _, tc := range cases {
		res, err := Audit(copyFixture(t, tc.fixture))
		if err != nil {
			t.Fatalf("%s: %v", tc.fixture, err)
		}
		fs := findings(res, tc.id)
		if len(fs) != 1 {
			t.Fatalf("%s: want exactly 1 %s finding, got %+v", tc.fixture, tc.id, res)
		}
		if fs[0].Status == 0 { // ingest.Pass — audit findings are Warn or Fail
			t.Fatalf("%s: audit finding must not be Pass", tc.fixture)
		}
		if fs[0].Check == "" || fs[0].Evidence == "" {
			t.Fatalf("%s: finding missing Check/Evidence: %+v", tc.fixture, fs[0])
		}
	}
}

func TestAuditSilentOnHardenedFixtures(t *testing.T) {
	cases := []struct {
		fixture string
		id      string
	}{
		{"fluent-hardened.conf", "HF-fluentd-1"},
		{"inputs-hardened.conf", "HF-splunk-1"},
		{"elasticsearch-hardened.yml", "HF-elastic-1"},
		{"fluent-bit-hardened.conf", "HF-fluentbit-1"},
	}
	for _, tc := range cases {
		res, err := Audit(copyFixture(t, tc.fixture))
		if err != nil {
			t.Fatalf("%s: %v", tc.fixture, err)
		}
		if n := len(findings(res, tc.id)); n != 0 {
			t.Fatalf("%s: want 0 %s findings, got %d: %+v", tc.fixture, tc.id, n, res)
		}
	}
}

func TestAuditFluentdForwardWithoutAuth(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "fluent.conf"),
		[]byte("<source>\n @type forward\n port 24224\n</source>\n"), 0o644)
	res, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings(res, "HF-fluentd-1")) != 1 {
		t.Fatalf("expected HF-fluentd-1 for unauthenticated forward source, got %+v", res)
	}
}

func TestAuditNonexistentRoot(t *testing.T) {
	if _, err := Audit(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("expected error for missing root")
	}
}

func TestAuditNestedPathMatches(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "etc", "fluent")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(nested, "fluent.conf"),
		[]byte("<source>\n @type http\n</source>\n"), 0o644)
	res, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings(res, "HF-fluentd-1")) != 1 {
		t.Fatalf("expected nested fluent.conf to be scanned, got %+v", res)
	}
}

func TestAuditFluentBitInputNameHTTP(t *testing.T) {
	// Real fluent-bit syntax: [INPUT] block with Name http, no Host —
	// fluent-bit's default bind is 0.0.0.0, so this must fire.
	res, err := Audit(copyFixture(t, "fluent-bit.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings(res, "HF-fluentbit-1")) != 1 {
		t.Fatalf("want 1 HF-fluentbit-1 for Name http without Host, got %+v", res)
	}
}

func TestAuditFluentBitLoopbackStaysSilent(t *testing.T) {
	// Same http input, but bound to loopback — hardened fixture exercises
	// the pattern's silence semantics with an http input present.
	res, err := Audit(copyFixture(t, "fluent-bit-hardened.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(findings(res, "HF-fluentbit-1")); n != 0 {
		t.Fatalf("want 0 HF-fluentbit-1 for loopback http input, got %d: %+v", n, res)
	}
}

func TestAuditFluentdInlineSourceType(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "fluent.conf"),
		[]byte("<source @type http>\n port 8888\n bind 0.0.0.0\n</source>\n"), 0o644)
	res, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings(res, "HF-fluentd-1")) != 1 {
		t.Fatalf("expected HF-fluentd-1 for inline <source @type http>, got %+v", res)
	}
}

func TestAuditFluentdUnclosedSourceAtEOF(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "fluent.conf"),
		[]byte("<source>\n @type http\n port 8888\n"), 0o644)
	res, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings(res, "HF-fluentd-1")) != 1 {
		t.Fatalf("expected HF-fluentd-1 for unclosed http source at EOF, got %+v", res)
	}
}

func TestAuditFluentdTokenKeyBoundary(t *testing.T) {
	dir := t.TempDir()
	// "tokenize" is not an auth key: prefix matching must not treat it as one.
	os.WriteFile(filepath.Join(dir, "fluent.conf"),
		[]byte("<source>\n @type http\n tokenize true\n</source>\n"), 0o644)
	res, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings(res, "HF-fluentd-1")) != 1 {
		t.Fatalf("expected HF-fluentd-1 despite tokenize key, got %+v", res)
	}
}

func TestAuditFluentBitLegacyHTTPSection(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "fluent-bit.conf"),
		[]byte("[http]\n listen 0.0.0.0\n port 9880\n"), 0o644)
	res, err := Audit(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings(res, "HF-fluentbit-1")) != 1 {
		t.Fatalf("expected HF-fluentbit-1 for legacy [http] section, got %+v", res)
	}
}

// Finding 4: fluent-bit >=2.0 spells the http input's bind address `Listen`
// (default 0.0.0.0); the legacy 1.x option is `Host`. Both spellings must
// drive the loopback test, or a modern hardened config fires a false Warn.
func TestFluentBitListenKeyDrivesLoopbackTest(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    int // HF-fluentbit-1 findings
	}{
		{"listen loopback stays silent", "[INPUT]\n Name http\n Listen 127.0.0.1\n Port 9880\n", 0},
		{"legacy host loopback stays silent", "[INPUT]\n Name http\n Host 127.0.0.1\n Port 9880\n", 0},
		{"listen all interfaces fires", "[INPUT]\n Name http\n Listen 0.0.0.0\n Port 9880\n", 1},
		{"listen absent fires (default bind)", "[INPUT]\n Name http\n Port 9880\n", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "fluent-bit.conf"), []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			res, err := Audit(dir)
			if err != nil {
				t.Fatal(err)
			}
			if got := len(findings(res, "HF-fluentbit-1")); got != tc.want {
				t.Fatalf("want %d finding(s), got %d: %+v", tc.want, got, res)
			}
		})
	}
}
