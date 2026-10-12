package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Brava-Security/ghost-telemetry-check/ingest"
)

// copySecretFixture copies a file from testdata/secrets/ into a temp dir so
// the scan sees a clean root (Task 4 convention).
func copySecretFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "secrets", name))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestScanSecretsFlagsSumoURL(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "collect.sh"),
		[]byte("curl https://collectors.us.sumologic.com/receiver/v1/http/ZVhhZmF1bHRJZDEyMzQ1Njc4OTA==\n"), 0o644)
	res, _ := ScanSecrets(dir)
	if len(res) != 1 || res[0].Remediation != "HF-cloud-1" {
		t.Fatalf("got %+v", res)
	}
}

// Real Sumo deployments use 3-letter region suffixes (us2, eu2) — the
// flagship pattern must fire on those too, not just us/eu/de.
func TestScanSecretsFlagsSumoTwoCharAndThreeCharRegions(t *testing.T) {
	for _, host := range []string{
		"collectors.us.sumologic.com",
		"collectors.eu2.sumologic.com",
		"collectors.us2.sumologic.com",
		"collectors.sumologic.com", // no region is also valid
	} {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "collect.sh"),
			[]byte("curl https://"+host+"/receiver/v1/http/ZVhhZmF1bHRJZDEyMzQ1Njc4OTA==\n"), 0o644)
		res, err := ScanSecrets(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(res) != 1 || res[0].Remediation != "HF-cloud-1" {
			t.Fatalf("%s: got %+v", host, res)
		}
	}
}

// 2026-10-07 GitHub scan (docs/research/ghost-feeds/scan/regexes.yaml): the
// dominant real-world host shape is endpoint<N>.collection.<deployment>.
// sumologic.com — matched by neither the plan nor the pre-sync tool regex;
// all format-valid >=40-char token URLs in the sample sat on it.
func TestScanSecretsFlagsSumoEndpointCollectionHost(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "collect.sh"),
		[]byte("curl https://endpoint4.collection.us2.sumologic.com/receiver/v1/http/ZaVnC4dhaV3NlPxodY4AbCd\n"), 0o644)
	res, err := ScanSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Remediation != "HF-cloud-1" {
		t.Fatalf("got %+v", res)
	}
}

// Real Sumo tokens contain '-' (scan: ZaVnC4dhaV3N-lPxodY4...); a token
// class without it truncates the match at the first hyphen and drops the
// finding. Hyphen sits after 12 chars here, so a [A-Za-z0-9+/=] class alone
// never reaches the 16-char floor.
func TestScanSecretsFlagsSumoHyphenatedToken(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "collect.sh"),
		[]byte("curl https://collectors.us.sumologic.com/receiver/v1/http/ZaVnC4dhaV3N-lPxodY4AbCd\n"), 0o644)
	res, err := ScanSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Remediation != "HF-cloud-1" {
		t.Fatalf("got %+v", res)
	}
}

func TestRedactShortSecretFully(t *testing.T) {
	// 4-char preview would reveal 4 of 5 characters: short secrets must be
	// fully redacted.
	if got := redact("abcde"); got != "…" {
		t.Fatalf("want full redaction for short secret, got %q", got)
	}
}

func TestScanSecretsFlagsSentinelSharedKey(t *testing.T) {
	dir := t.TempDir()
	key := strings.Repeat("c2VudGluZWxLZXkyMDI2", 5) + "=="
	os.WriteFile(filepath.Join(dir, "agent.conf"),
		[]byte("SharedKey="+key+"\n"), 0o644)
	res, err := ScanSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Remediation != "HF-cloud-2" {
		t.Fatalf("got %+v", res)
	}
	if res[0].Status != ingest.Fail {
		t.Fatalf("severity must be Fail, got %v", res[0].Status)
	}
}

// HF-cloud-3 was re-pointed 2026-10-07 (docs/research/ghost-feeds/scan/
// regexes.yaml): real DCR JSON uses "immutableId" (dcr-<32hex>, an
// identifier), never "immutableKey" — the live Sentinel leak surface is
// the Entra client secret authenticating the DCR Logs Ingestion API
// (mechanisms/matrix.md). The client_id UUID sits next to the secret in
// every real config, so this test also proves identifier-shaped values are
// excluded and exactly the credential fires.
func TestScanSecretsFlagsEntraClientSecret(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ingest.env"),
		[]byte("AZURE_CLIENT_ID=550e8400-e29b-41d4-a716-446655440000\n"+
			"AZURE_CLIENT_SECRET=Cc3Dd~4Ee5.-Ff6Gg7Hh8Ii9Jj0Kk1_Ll2Mm3Nn4\n"), 0o644)
	res, err := ScanSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Remediation != "HF-cloud-3" {
		t.Fatalf("got %+v", res)
	}
}

// Identifier-shaped values adjacent to a client-secret keyword (tenant /
// client UUIDs, DCR immutableIds — all sit beside the real secret in Entra
// app configs) must NOT be flagged: they are IDs, not credentials.
func TestScanSecretsIgnoresIdentifierNoiseNearClientSecret(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "ingest.json"),
		[]byte(`{"tenant_id":"16b7e1a2-3c4d-5e6f-8a9b-0c1d2e3f4a5b","client_id":"550e8400-e29b-41d4-a716-446655440000","dcr_immutable_id":"dcr-1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d","client_secret":"<stored in Key Vault>"}`), 0o644)
	res, err := ScanSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 0 {
		t.Fatalf("expected silence, got %+v", res)
	}
}

// The pre-sync HF-cloud-3 keyed on "immutableKey" — a field that never
// appears in real DCR JSON; its substring surface is i18n/SDK noise. The
// re-pointed pattern must stay silent on it.
func TestScanSecretsIgnoresImmutableKeyI18nNoise(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "strings.json"),
		[]byte(`{"immutableKey":"d17b6b1e8a4f4b2c9d0e1f2a3b4c5d6e7f8a9b0c"}`), 0o644)
	res, err := ScanSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 0 {
		t.Fatalf("expected silence, got %+v", res)
	}
}

func TestScanSecretsFlagsDatadogKey(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "env"),
		[]byte("DD_API_KEY=1f2e3d4c5b6a79880716253443526170\n"), 0o644)
	res, err := ScanSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Remediation != "HF-cloud-4" {
		t.Fatalf("got %+v", res)
	}
}

// A bare 32-hex blob with no Datadog keyword nearby must NOT be flagged:
// this is the proof that keyword-adjacency is enforced in code (RE2 has no
// lookahead, so the keyword check cannot live in the regex).
func TestScanSecretsIgnoresBareHexWithoutKeyword(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "hash.txt"),
		[]byte("checksum: 1f2e3d4c5b6a79880716253443526170\n"), 0o644)
	res, err := ScanSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 0 {
		t.Fatalf("expected silence, got %+v", res)
	}
}

func TestScanSecretsFlagsChronicleServiceAccount(t *testing.T) {
	dir := t.TempDir()
	pem := strings.Repeat("MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", 6)
	os.WriteFile(filepath.Join(dir, "chronicle-sa.json"),
		[]byte(`{"type":"service_account","client_email":"sa@project.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\n`+pem+`\n-----END PRIVATE KEY-----\n"}`), 0o644)
	res, err := ScanSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Remediation != "HF-cloud-5" {
		t.Fatalf("got %+v", res)
	}
}

// Evidence must carry file:line plus a redacted preview (first 4 chars + … +
// length) — never the full credential.
func TestScanSecretsRedactsEvidence(t *testing.T) {
	dir := t.TempDir()
	full := "ZVhhZmF1bHRJZDEyMzQ1Njc4OTA=="
	os.WriteFile(filepath.Join(dir, "collect.sh"),
		[]byte("curl https://collectors.us.sumologic.com/receiver/v1/http/"+full+"\n"), 0o644)
	res, _ := ScanSecrets(dir)
	if len(res) != 1 {
		t.Fatalf("got %+v", res)
	}
	ev := res[0].Evidence
	if !strings.Contains(ev, "collect.sh:1") {
		t.Fatalf("missing file:line in %q", ev)
	}
	if !strings.Contains(ev, "ZVhh") || !strings.Contains(ev, fmt.Sprintf("len %d", len(full))) {
		t.Fatalf("missing redacted preview in %q", ev)
	}
	if strings.Contains(ev, full) {
		t.Fatalf("full credential leaked in evidence: %q", ev)
	}
}

func TestScanSecretsBenignFileStaysSilent(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "notes.txt"),
		[]byte("fluentd on port 8888, restart collector after patch\n"), 0o644)
	res, err := ScanSecrets(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 0 {
		t.Fatalf("expected silence, got %+v", res)
	}
}

func TestScanSecretsFiresOnEachFixture(t *testing.T) {
	for name, id := range map[string]string{
		"sumo-collect.sh":     "HF-cloud-1",
		"sentinel-agent.conf": "HF-cloud-2",
		"dcr.json":            "HF-cloud-3",
		"datadog.env":         "HF-cloud-4",
		"chronicle-sa.json":   "HF-cloud-5",
	} {
		t.Run(name, func(t *testing.T) {
			res, err := ScanSecrets(copySecretFixture(t, name))
			if err != nil {
				t.Fatal(err)
			}
			var found []ingest.Result
			for _, r := range res {
				if r.Remediation == id {
					found = append(found, r)
				}
			}
			if len(found) != 1 {
				t.Fatalf("want exactly one %s finding, got %+v", id, res)
			}
			if found[0].Status != ingest.Fail {
				t.Fatalf("severity must be Fail, got %v", found[0].Status)
			}
		})
	}
}

func TestScanSecretsNonexistentRoot(t *testing.T) {
	if _, err := ScanSecrets(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected error for nonexistent root")
	}
}
