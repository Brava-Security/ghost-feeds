// Package audit scans SIEM/collector configuration trees for known
// no-authentication settings. Each finding cites a hardening-matrix ID
// (HF-<vendor>-<n>) from docs/research/ghost-feeds/report.
package audit

import (
	"regexp"

	"github.com/Brava-Security/ghost-telemetry-check/ingest"
)

// Pattern matches a single vendor misconfiguration. Sev is always Warn or
// Fail — the audit never emits Pass findings. Re is used for line/regex
// patterns; Match overrides it for block-structured formats (fluentd
// <source> blocks, fluent-bit [INPUT] sections).
type Pattern struct {
	ID    string // hardening-matrix ID, carried in Result.Remediation
	Glob  string // file glob relative to the scan root ("**/inputs.conf")
	Re    *regexp.Regexp
	Match func(p Pattern, path, content string) []ingest.Result
	Sev   ingest.Status
	Msg   string
	Link  string // hardening-matrix anchor
}

// patterns is the audit pattern table. IDs follow the hardening-matrix
// convention (HF-<vendor>-<n>); Task 5's credential patterns use the same
// convention (HF-cloud-1, ...).
var patterns = []Pattern{
	{
		ID:   "HF-splunk-1",
		Glob: "**/inputs.conf",
		Re:   regexp.MustCompile(`(?m)^\[splunktcp://\d+\]\s*$`),
		Sev:  ingest.Warn,
		Msg:  "raw splunktcp input present — verify SSL + shared-key",
		Link: "docs/research/ghost-feeds/report#splunk",
	},
	{
		ID:    "HF-fluentd-1",
		Glob:  "**/fluent.conf",
		Sev:   ingest.Fail,
		Msg:   "in_http/in_forward source without auth — anyone who can reach it can inject",
		Link:  "docs/research/ghost-feeds/report#fluentd",
		Match: parseSourceBlocks,
	},
	{
		ID:   "HF-elastic-1",
		Glob: "**/elasticsearch.yml",
		Re:   regexp.MustCompile(`(?m)^\s*xpack\.security\.enabled:\s*false`),
		Sev:  ingest.Fail,
		Msg:  "Elasticsearch security disabled",
		Link: "docs/research/ghost-feeds/report#elasticsearch",
	},
	{
		ID:    "HF-fluentbit-1",
		Glob:  "**/fluent-bit.conf",
		Sev:   ingest.Warn,
		Msg:   "fluent-bit http input bound to non-loopback interface — verify TLS + auth",
		Link:  "docs/research/ghost-feeds/report#fluentbit",
		Match: parseFluentBit,
	},
}
