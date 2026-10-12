package audit

import (
	"regexp"
)

// secretPattern matches a credential-shaped string in file contents.
// The regexes are format-only (shape of the secret itself); where the plan's
// Python-flavored "adjacent to keywords" semantics apply, the keyword check
// is performed in code (see keyNearby in secrets.go) because Go's RE2 has no
// lookahead/lookbehind.
//
// SOURCE OF TRUTH for these patterns is the campaign file
// docs/research/ghost-feeds/scan/regexes.yaml (main checkout — not on this
// branch). This table is synced 2026-10-07 to its `recommended` variants
// after the campaign's GitHub scan (scan/leaked-keys.md, "Divergences"):
// HF-cloud-1 host group + token charset; HF-cloud-3 re-pointed from the
// never-real "immutableKey" surface to the live Entra client-secret surface.
//
// ID mapping (agreed with the hardening matrix; Task 8 wiring depends on it):
//
//	HF-cloud-1  Sumo Logic HTTP receiver URL token
//	HF-cloud-2  Sentinel/Azure Monitor SharedKey (base64 workspace key) —
//	            legacy ingestion API retired 2026-09; archaeology value only
//	HF-cloud-3  Sentinel DCR Logs Ingestion Entra client secret (live path)
//	HF-cloud-4  Datadog API key (32-hex adjacent to DD_API_KEY)
//	HF-cloud-5  Chronicle service-account JSON (Google SA private key)
type secretPattern struct {
	ID   string // hardening-matrix ID, carried in Result.Remediation
	Name string // human label, used in Check and Evidence
	// Re matches the credential FORMAT only. Key, when non-nil, is a keyword
	// that must appear adjacent to the match (same line or within 64 bytes)
	// to suppress false positives on credential-shaped noise.
	Key *regexp.Regexp
	Re  *regexp.Regexp
	// Exclude, when non-nil, suppresses matches whose secret substring is
	// identifier-shaped rather than a credential (HF-cloud-3: tenant/client
	// UUIDs and DCR immutableIds sit beside the real secret in Entra app
	// configs; flagged as secrets they would be systematic false positives).
	Exclude *regexp.Regexp
	// Secret is the submatch index (0 = whole match) holding the credential
	// itself, used for the redacted preview and length. Sumo captures the
	// token in group 1 so the preview is the secret, not the URL around it.
	Secret int
	Msg    string
	Link   string
}

// secretPatterns is the credential pattern table. All findings are Fail:
// a leaked ingest credential means anyone who reads the file can inject.
var secretPatterns = []secretPattern{
	{
		ID:   "HF-cloud-1",
		Name: "Sumo Logic receiver URL token",
		// Key nil: the token IS the URL — self-contained credential, no
		// keyword adjacency needed (highest-visibility leak pattern).
		//
		// Host group `[a-z0-9.-]*sumologic.com` per regexes.yaml
		// `recommended`: the dominant real-world deployment shape is
		// endpoint<N>.collection.<deployment>.sumologic.com, which the
		// pre-sync `collectors(?:\.[a-z]{2}\d?)?` host never matched (all 10
		// format-valid >=40-char token URLs in the 2026-10-07 scan sat on
		// it). Token class carries '-' — empirical tokens contain hyphens
		// (ZaVnC4dhaV3N-l...); without it matches truncate at the first
		// hyphen and the finding is dropped. Floor 16, not the plan's 40:
		// observed real tokens run 16-120 chars, and the https scheme +
		// receiver path around the token is the credential context itself.
		Re:     regexp.MustCompile(`https://[a-z0-9.-]*sumologic\.com/receiver/v1/http/([A-Za-z0-9+/=-]{16,})`),
		Secret: 1,
		Msg:    "Sumo Logic HTTP receiver token leaked in a URL — anyone with the URL can ingest",
		Link:   "docs/research/ghost-feeds/report#sumo",
	},
	{
		ID:   "HF-cloud-2",
		Name: "Sentinel workspace SharedKey",
		Key:  regexp.MustCompile(`(?i)shared[\s_-]?key`),
		Re:   regexp.MustCompile(`\b[A-Za-z0-9+/]{40,}={0,2}`),
		Msg:  "Sentinel/Azure Monitor workspace SharedKey in a local file — rotate and move to a secret store",
		Link: "docs/research/ghost-feeds/report#sentinel",
	},
	{
		ID:   "HF-cloud-3",
		Name: "Sentinel DCR Logs Ingestion Entra client secret",
		// Re-pointed 2026-10-07 (regexes.yaml): real DCR JSON uses
		// "immutableId" (dcr-<32hex>), never "immutableKey" — that key's
		// substring surface was i18n/SDK noise. The immutableId is an
		// identifier (published verbatim in Azure's own rest-api-spec
		// examples), not a credential: the DCR Logs Ingestion API requires
		// Entra auth. The live Sentinel leak surface is the Entra client
		// secret itself (mechanisms/matrix.md) — lower false-positive
		// profile than keying on immutableId, which flags every copied
		// Azure example. Value shape per Microsoft Purview's "Microsoft
		// Entra client secret" entity: up to 40 chars of [a-z0-9_.~-],
		// case-insensitive; floor 32 to stay off shorter noise. Key
		// requires a client[-_ ]?secret keyword (env-var / JSON / Terraform
		// spellings) adjacent to the match.
		Key: regexp.MustCompile(`(?i)client[\s_-]?secret`),
		Re:  regexp.MustCompile(`\b[A-Za-z0-9_.~-]{32,}\b`),
		// Identifiers, not credentials: tenant/client/object UUIDs and
		// dcr-<32hex> immutableIds sit beside the keyword in every real
		// Entra app config — excluded so exactly the secret fires.
		Exclude: regexp.MustCompile(`(?i)^(?:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|dcr-[0-9a-f]{32})$`),
		Msg:     "Sentinel DCR Logs Ingestion API Entra client secret in a local file — rotate and move to a secret store",
		Link:    "docs/research/ghost-feeds/report#sentinel",
	},
	{
		ID:   "HF-cloud-4",
		Name: "Datadog API key",
		Key:  regexp.MustCompile(`(?i)dd_api_key|datadog[\s_-]?api[\s_-]?key`),
		Re:   regexp.MustCompile(`\b[0-9a-f]{32}\b`),
		Msg:  "Datadog API key in a local file — anyone with it can inject events",
		Link: "docs/research/ghost-feeds/report#datadog",
	},
	{
		ID:     "HF-cloud-5",
		Name:   "Chronicle service-account key",
		Re:     regexp.MustCompile(`(?s)"private_key"\s*:\s*"(-----BEGIN PRIVATE KEY-----[^"]{100,})"`),
		Secret: 1,
		Msg:    "Chronicle service-account private key in a local file — anyone with it can inject events",
		Link:   "docs/research/ghost-feeds/report#chronicle",
	},
}
