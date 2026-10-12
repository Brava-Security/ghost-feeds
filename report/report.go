// Package report renders check results as a human-readable table or JSON
// and aggregates them into the CLI process exit code.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/Brava-Security/ghost-telemetry-check/ingest"
)

// Exit-code values follow the product contract and MUST stay numerically in
// sync with the exitPass/exitWarn/exitFail constants in the parent package's
// cli.go (they cannot be imported from here because cli.go is package main).
// Exit code 3 (internal error) belongs to the CLI layer, not to result
// aggregation, so it is intentionally absent from ExitCode.
const (
	codePass = 0
	codeWarn = 1
	codeFail = 2
)

// ExitCode aggregates results into the process exit code: 0 when all results
// pass (or there are none), 1 when any result is Warn with no Fail, and 2
// when any result is Fail. Fail dominates Warn.
func ExitCode(results []ingest.Result) int {
	worst := ingest.Pass
	for _, r := range results {
		if r.Status > worst {
			worst = r.Status
		}
	}
	switch worst {
	case ingest.Fail:
		return codeFail
	case ingest.Warn:
		return codeWarn
	default:
		return codePass
	}
}

// RenderTable writes a STATUS / CHECK / EVIDENCE / REMEDIATION table to w.
func RenderTable(w io.Writer, results []ingest.Result) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "STATUS\tCHECK\tEVIDENCE\tREMEDIATION"); err != nil {
		return err
	}
	for _, r := range results {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", strings.ToUpper(r.Status.String()), r.Check, r.Evidence, r.Remediation); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// jsonResult is the machine-readable projection of one ingest.Result.
type jsonResult struct {
	Check       string `json:"check"`
	Status      string `json:"status"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
}

// RenderJSON writes the results as a JSON object with a "results" array,
// where each status is the lowercase string form ("pass", "warn", "fail").
// canaryMarker carries the probe run's marker (empty for agent/audit runs)
// so a CI pipeline can hand it to `agent --marker`; empty is omitted.
// This is the output shape the CLI's --json flag uses for CI pipelines.
func RenderJSON(w io.Writer, results []ingest.Result, canaryMarker string) error {
	out := struct {
		CanaryMarker string       `json:"canary_marker,omitempty"`
		Results      []jsonResult `json:"results"`
	}{CanaryMarker: canaryMarker, Results: make([]jsonResult, 0, len(results))}
	for _, r := range results {
		out.Results = append(out.Results, jsonResult{
			Check:       r.Check,
			Status:      r.Status.String(),
			Evidence:    r.Evidence,
			Remediation: r.Remediation,
		})
	}
	enc := json.NewEncoder(w)
	return enc.Encode(out)
}
