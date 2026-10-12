package audit

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Brava-Security/ghost-telemetry-check/ingest"
)

// ScanSecrets walks root and reports local files containing
// credential-shaped strings (see secretPatterns). This module is
// LOCAL-ONLY: it reads files and matches patterns — it never makes a
// network call, and it never validates a found credential against any API.
// In the CLI, audit mode always runs this scan alongside the config audit:
// both are strictly local, and this scan never touches the network.
//
// Evidence carries file:line plus a REDACTED preview (first 4 chars + … +
// length) so findings never echo the full credential back into output that
// might itself be pasted into tickets or logs.
func ScanSecrets(root string) ([]ingest.Result, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("secrets: scan root %q: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("secrets: scan root %q is not a directory", root)
	}
	var results []ingest.Result
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		results = append(results, scanFile(path)...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("secrets: walking %q: %w", root, err)
	}
	return results, nil
}

// maxSecretFileSize caps how much of a file is scanned; larger files are
// skipped rather than read whole into memory.
const maxSecretFileSize = 10 << 20 // 10 MiB

// scanFile applies every secret pattern to one file. Files that look binary
// (contain NUL) are skipped: the patterns target text configs and scripts,
// and this avoids matching base64 inside binaries.
func scanFile(path string) []ingest.Result {
	content, err := os.ReadFile(path)
	if err != nil || len(content) > maxSecretFileSize {
		return nil
	}
	if bytes.IndexByte(content, 0) >= 0 {
		return nil
	}
	s := string(content)
	var results []ingest.Result
	for _, p := range secretPatterns {
		results = append(results, matchSecret(p, path, s)...)
	}
	return results
}

// matchSecret reports one finding per match of p in content. For patterns
// with a Key, the keyword must be adjacent to the match: on the same line,
// or within 64 bytes before/after it. This in-code check replaces the
// Python regex lookarounds used by the campaign's regexes.yaml, since Go's
// RE2 has no lookahead/lookbehind. Matches whose secret substring is
// identifier-shaped (p.Exclude, e.g. UUIDs and DCR immutableIds) are
// skipped: they are IDs, not credentials.
func matchSecret(p secretPattern, path, content string) []ingest.Result {
	var res []ingest.Result
	for _, loc := range p.Re.FindAllStringSubmatchIndex(content, -1) {
		if p.Key != nil && !keyNearby(content, loc, p.Key) {
			continue
		}
		secret := content[loc[2*p.Secret]:loc[2*p.Secret+1]]
		if p.Exclude != nil && p.Exclude.MatchString(secret) {
			continue
		}
		res = append(res, ingest.Result{
			Check: "secrets-scan: " + p.ID,
			Evidence: fmt.Sprintf("%s:%d: %s (%s, len %d) — %s",
				path, lineOf(content, loc[0]), p.Msg, redact(secret), len(secret), p.Link),
			Remediation: p.ID,
			Status:      ingest.Fail,
		})
	}
	return res
}

// keyNearby reports whether kw matches within the line containing the
// match, or within 64 bytes of either end of it (JSON spreads keys and
// values across lines, e.g. "api_key" on the line before the hex value).
func keyNearby(content string, loc []int, kw *regexp.Regexp) bool {
	lo := strings.LastIndexByte(content[:loc[0]], '\n')
	if lo < 0 {
		lo = 0
	}
	hi := strings.IndexByte(content[loc[1]:], '\n')
	if hi < 0 {
		hi = len(content)
	} else {
		hi += loc[1]
	}
	if kw.MatchString(content[lo:hi]) {
		return true
	}
	const near = 64
	lo2, hi2 := loc[0]-near, loc[1]+near
	if lo2 < 0 {
		lo2 = 0
	}
	if hi2 > len(content) {
		hi2 = len(content)
	}
	return kw.MatchString(content[lo2:hi2])
}

// lineOf returns the 1-based line number of byte offset i in content.
func lineOf(content string, i int) int {
	return strings.Count(content[:i], "\n") + 1
}

// redact renders a credential preview safe for reports: first 4 characters,
// an ellipsis, and the length. Never the full secret.
func redact(secret string) string {
	// Short secrets get no preview: showing 4 of 5 characters would
	// effectively reveal the whole credential.
	if len(secret) <= 8 {
		return "…"
	}
	return secret[:4] + "…"
}
