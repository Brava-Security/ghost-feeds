package audit

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Brava-Security/ghost-telemetry-check/ingest"
)

// Audit walks root and returns one Result per matched misconfiguration
// pattern. Remediation carries the hardening-matrix ID; Evidence carries
// the offending file and detail.
func Audit(root string) ([]ingest.Result, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("audit: scan root %q: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("audit: scan root %q is not a directory", root)
	}
	var results []ingest.Result
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		for _, p := range patterns {
			if globMatch(p.Glob, path) {
				results = append(results, matchFile(p, path)...)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("audit: walking %q: %w", root, err)
	}
	return results, nil
}

// globMatch supports the "**/<name>" globs in the pattern table: any path
// whose base name matches, at any depth under the root. stdlib
// path/filepath has no recursive glob, hence this helper.
func globMatch(glob, path string) bool {
	if !strings.HasPrefix(glob, "**/") {
		m, err := filepath.Match(glob, path)
		return err == nil && m
	}
	m, err := filepath.Match(strings.TrimPrefix(glob, "**/"), filepath.Base(path))
	return err == nil && m
}

// matchFile applies one pattern to one file.
func matchFile(p Pattern, path string) []ingest.Result {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil // unreadable file: skip, WalkDir already surfaced what it can
	}
	content := string(data)
	if p.Match != nil {
		return p.Match(p, path, content)
	}
	var results []ingest.Result
	for _, loc := range p.Re.FindAllStringIndex(content, -1) {
		line := firstLine(content[loc[0]:])
		results = append(results, finding(p, path, line))
	}
	return results
}

// key returns the first whitespace-delimited token of a config line,
// lowercased (config keys are case-insensitive in fluentd/fluent-bit).
func key(trimmed string) string {
	k, _, _ := strings.Cut(trimmed, " ")
	return strings.ToLower(k)
}

// parseSourceBlocks implements the HF-fluentd-1 check. The plan supersedes
// its illustrative single-regex approach with real parsing: scan
// <source>...</source> blocks and flag blocks whose @type is http or
// forward when they carry no per-source auth keys (shared_key / token).
// Fluentd also allows the plugin type inline in the opening directive
// (<source @type http>), so the opening line itself is scanned for @type.
func parseSourceBlocks(p Pattern, path, content string) []ingest.Result {
	var results []ingest.Result
	inBlock := false
	var blockStart int
	var blockType string
	var authed bool
	closeBlock := func() {
		if blockType != "" && !authed {
			results = append(results, finding(p, path,
				fmt.Sprintf("<source> (line %d) @type %s without shared_key/token", blockStart, blockType)))
		}
		blockType, authed = "", false
	}
	for i, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if !inBlock {
			if strings.HasPrefix(trimmed, "<source") && strings.HasSuffix(trimmed, ">") {
				inBlock, blockStart, blockType, authed = true, i+1, "", false
				opening := strings.TrimSuffix(trimmed, ">")
				if t := pluginType(opening); t != "" {
					blockType = t
				}
			}
			continue
		}
		if strings.HasPrefix(trimmed, "</source>") {
			closeBlock()
			inBlock = false
			continue
		}
		switch k := key(trimmed); k {
		case "@type":
			if t := pluginType(trimmed); t != "" {
				blockType = t
			} else {
				blockType = "-" // benign plugin type
			}
		case "shared_key", "token":
			authed = true
		}
	}
	if inBlock { // unclosed block at EOF: evaluate what was collected
		closeBlock()
	}
	return results
}

// pluginType returns "http" or "forward" when line assigns one of them to
// @type, "http"/"forward" itself for the risky plugins, "" otherwise.
func pluginType(line string) string {
	fields := strings.Fields(line)
	for i, f := range fields {
		if strings.EqualFold(f, "@type") && i+1 < len(fields) {
			switch strings.ToLower(fields[i+1]) {
			case "http", "forward":
				return strings.ToLower(fields[i+1])
			}
			return ""
		}
	}
	return ""
}

// parseFluentBit implements the HF-fluentbit-1 check. Real fluent-bit
// configs use INI-style sections: an [INPUT] block with `Name http` is the
// http input plugin, which binds 0.0.0.0 by default. We flag `Name http`
// inputs whose Host (fluent-bit 1.x) / Listen (fluent-bit >=2.0) is 0.0.0.0,
// ::, or absent (default bind), and stay silent for loopback addresses
// (127.0.0.1/localhost). The legacy literal `[http]` section form is kept
// for older configs.
func parseFluentBit(p Pattern, path, content string) []ingest.Result {
	var results []ingest.Result
	var section string
	var sectionStart int
	var name, host string
	closeSection := func() {
		if strings.EqualFold(name, "http") && !isLoopback(host) {
			results = append(results, finding(p, path,
				fmt.Sprintf("[INPUT] (line %d) Name http, bind %q (fluent-bit http input binds all interfaces by default)", sectionStart, host)))
		}
		if strings.EqualFold(section, "http") {
			results = append(results, finding(p, path,
				fmt.Sprintf("[http] section (line %d) — legacy http input form", sectionStart)))
		}
		section, name, host = "", "", ""
	}
	for i, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			closeSection()
			section, sectionStart = strings.ToLower(trimmed[1:len(trimmed)-1]), i+1
			continue
		}
		if section == "" {
			continue
		}
		k := key(trimmed)
		v := strings.TrimSpace(trimmed[len(k):])
		switch k {
		case "name":
			name = v
		case "host", "listen": // fluent-bit 1.x spells it Host; >=2.0 Listen (default 0.0.0.0)
			host = v
		}
	}
	closeSection() // EOF closes the final section
	return results
}

// isLoopback reports whether a fluent-bit Host/Listen value binds only
// loopback. Empty means fluent-bit's default bind (0.0.0.0), i.e. all
// interfaces.
func isLoopback(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

func finding(p Pattern, path, evidence string) ingest.Result {
	return ingest.Result{
		Check:       "config-audit: " + p.ID,
		Evidence:    fmt.Sprintf("%s: %s (%s) — %s", path, p.Msg, evidence, p.Link),
		Remediation: p.ID,
		Status:      p.Sev,
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimRight(s[:i], "\r")
	}
	return s
}
