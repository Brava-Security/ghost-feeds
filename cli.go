// Command ghost-telemetry-check is a free, customer-run security self-check that
// detects whether a SIEM ingestion endpoint accepts unauthenticated events:
// probe injects the canary from outside the perimeter, agent verifies and
// purges from inside, audit scans local collector configs. Zero telemetry:
// the only network calls go to customer-declared --target endpoints, plus
// the explicitly-enabled --shodan lookup.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/Brava-Security/ghost-telemetry-check/audit"
	"github.com/Brava-Security/ghost-telemetry-check/canary"
	"github.com/Brava-Security/ghost-telemetry-check/ingest"
	"github.com/Brava-Security/ghost-telemetry-check/report"
	"github.com/Brava-Security/ghost-telemetry-check/shodan"
)

// Exit codes are the tool's CI-facing contract: 0 pass, 1 warnings,
// 2 failures, 3 internal or usage error.
const (
	exitPass     = 0
	exitWarn     = 1
	exitFail     = 2
	exitInternal = 3
)

// targetTimeout bounds every network call the CLI makes, one deadline per
// target, so a hanging endpoint aborts its own check instead of hanging the
// run or eating the other targets' budgets.
var targetTimeout = 30 * time.Second

// defaultShodanAPI is where the optional --shodan lookup goes; the var
// wrapper lets tests point it at a local mock.
const defaultShodanAPI = "https://api.shodan.io"

var shodanAPIBase = defaultShodanAPI

// adapterHeuristic documents the port→adapter selection that --help states
// and adapterByPort applies; keep it in sync with portAdapter.
const adapterHeuristic = `adapter selection (probe/agent): the target's port picks the adapter —
  8088 splunk hec · 8888 fluentd in_http · 9880 fluent-bit http · 10080 cribl ·
  9200 elasticsearch · tcp://…:514 syslog-tcp · udp://…:514 syslog-udp · udp://…:12201 gelf
unknown ports are an error (the tool never silently guesses); --adapter overrides`

// portAdapter maps the well-known HTTP ingest ports to their adapters.
// Syslog ports (514, 12201) are handled case-by-case in adapterByPort
// because the URL scheme resolves their transport.
var portAdapter = map[string]string{
	"8088":  "hec",
	"8888":  "fluentd",
	"9880":  "fluentbit",
	"10080": "cribl",
	"9200":  "elastic",
}

// options carries the parsed CLI flags shared by every subcommand. Flags
// that a mode ignores (--config outside audit) still parse: one shared
// flag set is the Task 1 contract.
type options struct {
	target  string
	adapter string
	config  string
	marker  string
	shodan  bool
	json    bool
	verbose bool
}

// parseFlags parses the flags common to all subcommands. Parse errors and
// flag help go to stdout: Run's writer is the only output channel.
func parseFlags(name string, args []string, stdout io.Writer) (*options, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stdout)
	opts := &options{}
	fs.StringVar(&opts.target, "target", "", "comma-separated ingestion endpoints under test (probe/agent)")
	fs.StringVar(&opts.adapter, "adapter", "", "override the port heuristic: hec|fluentd|fluentbit|cribl|elastic|syslog-tcp|syslog-udp|gelf")
	fs.StringVar(&opts.config, "config", ".", "collector configuration root to audit (audit)")
	fs.StringVar(&opts.marker, "marker", "", "canary marker to verify and purge (agent); probe runs print it")
	// The disclosure below is a binding commitment: this module sends your endpoint IP to Shodan — the only check that does; default off
	fs.BoolVar(&opts.shodan, "shodan", false, "optional Shodan index lookup — this module sends your endpoint IP to Shodan — the only check that does; default off")
	fs.BoolVar(&opts.json, "json", false, "machine-readable JSON report for CI")
	fs.BoolVar(&opts.verbose, "verbose", false, "narrate target/adapter selection and the canary marker")
	fs.Usage = func() {
		fmt.Fprintf(stdout, "usage: ghost-telemetry-check %s [flags]\n\n%s\n\n", name, adapterHeuristic)
		fs.PrintDefaults()
	}
	err := fs.Parse(args)
	return opts, err
}

// usage prints the top-level CLI usage.
func usage(stdout io.Writer) {
	fmt.Fprintf(stdout, `usage: ghost-telemetry-check <subcommand> [flags]

subcommands:
  probe   inject the canary from outside the perimeter and grade acceptance
  agent   verify and purge canary markers from inside the perimeter
  audit   scan local collector configs for no-auth settings and leaked credentials

%s

examples:
  ghost-telemetry-check probe --target tcp://siem.example.com:514
  ghost-telemetry-check probe --target siem.example.com:8088 --shodan --json
  ghost-telemetry-check agent --target siem.example.com:9200 --marker BRAVA-CHECK-<uuid>
  ghost-telemetry-check audit --config /etc/collectors
`, adapterHeuristic)
}

// Run dispatches the subcommand in args and returns the process exit code.
func Run(args []string, stdout io.Writer) int {
	if len(args) == 0 {
		usage(stdout)
		return exitInternal
	}
	cmd, rest := args[0], args[1:]
	if cmd == "-h" || cmd == "--help" {
		usage(stdout)
		return exitPass // top-level help, same as subcommand -h
	}
	switch cmd {
	case "agent", "audit", "probe":
	default:
		usage(stdout)
		return exitInternal
	}
	opts, err := parseFlags(cmd, rest, stdout)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitPass // help was printed; nothing went wrong
		}
		return exitInternal
	}
	switch cmd {
	case "probe":
		return runProbe(opts, stdout)
	case "agent":
		return runAgent(opts, stdout)
	default:
		return runAudit(opts, stdout)
	}
}

// narrate prints verbose narration unless --json is set: JSON output must
// stay machine-parseable.
func (o *options) narrate(w io.Writer, msg string) {
	if o.verbose && !o.json {
		fmt.Fprintln(w, msg)
	}
}

// targets splits the comma-separated --target value, dropping empties.
func targets(raw string) []string {
	var out []string
	for _, t := range strings.Split(raw, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// finish renders the report and derives the exit code. Aborts (transport
// failures, invalid targets) print as error lines and force exit 3: an
// ungradable endpoint must never read as secure. marker is the probe run's
// canary marker ("" for agent/audit); under --json it rides in the report
// envelope's canary_marker field so the handoff token survives JSON mode.
func finish(stdout io.Writer, opts *options, results []ingest.Result, errs []string, marker string) int {
	for _, e := range errs {
		fmt.Fprintf(stdout, "error: %s\n", e)
	}
	var err error
	if opts.json {
		err = report.RenderJSON(stdout, results, marker)
	} else {
		err = report.RenderTable(stdout, results)
	}
	if err != nil {
		fmt.Fprintf(stdout, "error: rendering report: %v\n", err)
		return exitInternal
	}
	if len(errs) > 0 {
		return exitInternal
	}
	return report.ExitCode(results)
}

// checker is the HTTP-adapter check cycle (inject, grade, verify) that
// probe mode runs. Syslog-family adapters do not implement it: their
// transports cannot be graded from the probe side.
type checker interface {
	Check(ctx context.Context, c canary.Canary) (ingest.Result, error)
}

// canVerifier reports whether an adapter's ingest port carries a product
// search API. Agent mode uses it to tell designed manual-search guidance
// (HEC-class ports) apart from real failures.
type canVerifier interface {
	CanVerify() bool
}

// runProbe injects one canary per target from outside the perimeter, grades
// acceptance, and purges where the product API allows. Syslog-family
// targets are fire-and-forget: the canary is sent and verification defers
// to agent mode.
func runProbe(opts *options, stdout io.Writer) int {
	ts := targets(opts.target)
	if len(ts) == 0 {
		fmt.Fprintln(stdout, "--target is required")
		return exitInternal
	}
	c, err := canary.New()
	if err != nil {
		fmt.Fprintf(stdout, "error: %v\n", err)
		return exitInternal
	}
	var (
		results []ingest.Result
		errs    []string
	)
	for _, t := range ts {
		ad, err := adapterForTarget(t, opts.adapter)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		opts.narrate(stdout, fmt.Sprintf("probe %s via %s; marker %s", t, ad.Name(), c.Marker))
		ctx, cancel := context.WithTimeout(context.Background(), targetTimeout)
		res, err := probeTarget(ctx, ad, c)
		cancel()
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		results = append(results, res)
	}
	if opts.shodan {
		rows, serrs := shodanRows(ts)
		results = append(results, rows...)
		errs = append(errs, serrs...)
	}
	if !opts.json {
		// The marker is the handoff token for agent mode: the operator needs
		// it verbatim, on every run, not only in verbose mode.
		fmt.Fprintf(stdout, "canary marker: %s (pass to 'ghost-telemetry-check agent --marker' to verify and purge)\n", c.Marker)
	}
	return finish(stdout, opts, results, errs, c.Marker)
}

// probeTarget runs one canary cycle against one target.
func probeTarget(ctx context.Context, ad ingest.Ingestor, c canary.Canary) (ingest.Result, error) {
	if chk, ok := ad.(checker); ok {
		res, err := chk.Check(ctx, c)
		if err != nil {
			return ingest.Result{}, err
		}
		if res.Status == ingest.Fail {
			// The two-vantage model promises an automatic purge where the
			// product API allows one; where it does not (HEC-class ports),
			// Purge's error text is the manual-search instruction.
			pctx, pcancel := context.WithTimeout(context.Background(), targetTimeout)
			perr := ad.Purge(pctx, c)
			pcancel()
			if perr != nil {
				res.Evidence += fmt.Sprintf("; purge: %v", perr)
			} else {
				res.Evidence += "; canary purged via product API"
			}
		}
		return res, nil
	}
	// Syslog family (ErrUnsupported path): the send is unacknowledged, so
	// acceptance cannot be graded from here — an informational warn row,
	// never a failure and never a silent success.
	if err := ad.Inject(ctx, c); err != nil {
		return ingest.Result{}, err
	}
	return ingest.Result{
		Check: fmt.Sprintf("%s canary delivered unauthenticated", ad.Name()),
		Evidence: "canary sent without authentication over a fire-and-forget transport " +
			"(no acknowledgment); verification requires agent mode",
		Remediation: fmt.Sprintf("verify via agent mode or a SIEM search for %s; if the marker is present, "+
			"restrict the port to known senders and require TLS", c.Marker),
		Status: ingest.Warn,
	}, nil
}

// runAgent verifies and purges the marker through the product-API adapters
// from inside the perimeter. Probe never runs here: agent mode only reads
// and deletes.
func runAgent(opts *options, stdout io.Writer) int {
	ts := targets(opts.target)
	if len(ts) == 0 {
		fmt.Fprintln(stdout, "--target is required")
		return exitInternal
	}
	if opts.marker == "" {
		fmt.Fprintln(stdout, "--marker is required (the marker printed by your probe run)")
		return exitInternal
	}
	c, err := canaryFromMarker(opts.marker)
	if err != nil {
		fmt.Fprintf(stdout, "error: %v\n", err)
		return exitInternal
	}
	var (
		results []ingest.Result
		errs    []string
	)
	for _, t := range ts {
		ad, err := adapterForTarget(t, opts.adapter)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		opts.narrate(stdout, fmt.Sprintf("agent %s via %s; marker %s", t, ad.Name(), c.Marker))
		ctx, cancel := context.WithTimeout(context.Background(), targetTimeout)
		res, err := agentTarget(ctx, ad, c)
		cancel()
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		results = append(results, res)
	}
	if opts.shodan {
		rows, serrs := shodanRows(ts)
		results = append(results, rows...)
		errs = append(errs, serrs...)
	}
	return finish(stdout, opts, results, errs, "")
}

// markerUUID is the exact shape canary.New emits: lowercase hex, RFC 4122
// groups. Anything else in --marker is a typo or truncation, and a search
// for it would "find nothing" and report a false clean bill.
var markerUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// canaryFromMarker accepts the full marker (BRAVA-CHECK-<uuid>) or the bare
// UUID; the marker is what every adapter embeds and searches for. The UUID
// shape is validated so a typo'd marker is a usage error, not a
// nothing-to-purge false PASS.
func canaryFromMarker(m string) (canary.Canary, error) {
	u := strings.TrimSpace(m)
	u, _ = strings.CutPrefix(u, "BRAVA-CHECK-")
	if !markerUUID.MatchString(u) {
		return canary.Canary{}, fmt.Errorf("--marker %q is not a valid canary marker (want BRAVA-CHECK-<uuid> or the bare UUID, exactly as your probe run printed)", m)
	}
	return canary.FromUUID(u), nil
}

// agentTarget verifies and purges one target's marker.
func agentTarget(ctx context.Context, ad ingest.Ingestor, c canary.Canary) (ingest.Result, error) {
	// HEC-class ingest ports carry no product search API: the row is the
	// manual-search guidance (Warn), not an abort and not a failure.
	if cv, ok := ad.(canVerifier); ok && !cv.CanVerify() {
		_, verr := ad.Verify(ctx, c) // returns the guidance; makes no network call
		return ingest.Result{
			Check:       fmt.Sprintf("%s canary verification (manual)", ad.Name()),
			Evidence:    verr.Error(),
			Remediation: "search the product for the marker and delete matching events by hand",
			Status:      ingest.Warn,
		}, nil
	}
	found, err := ad.Verify(ctx, c)
	if err != nil {
		if errors.Is(err, ingest.ErrUnsupported) {
			// Syslog family: no product API is wired for these transports;
			// surface the manual instruction with the marker spelled out.
			return ingest.Result{
				Check:       fmt.Sprintf("%s canary verification (manual)", ad.Name()),
				Evidence:    fmt.Sprintf("%v; marker to search for: %s", err, c.Marker),
				Remediation: "search the SIEM for the marker and delete matching events by hand",
				Status:      ingest.Warn,
			}, nil
		}
		return ingest.Result{}, err
	}
	if !found {
		return ingest.Result{
			Check:       fmt.Sprintf("%s is free of the canary marker", ad.Name()),
			Evidence:    "marker not found via product search — nothing to purge",
			Remediation: "none",
			Status:      ingest.Pass,
		}, nil
	}
	if perr := ad.Purge(ctx, c); perr != nil {
		return ingest.Result{
			Check:       fmt.Sprintf("%s canary marker purged via product API", ad.Name()),
			Evidence:    fmt.Sprintf("marker located via product search; purge failed: %v", perr),
			Remediation: fmt.Sprintf("delete events matching %s via the product API", c.Marker),
			Status:      ingest.Fail,
		}, nil
	}
	return ingest.Result{
		Check:       fmt.Sprintf("%s canary marker purged via product API", ad.Name()),
		Evidence:    "marker located via product search and deleted via the product API",
		Remediation: "none",
		Status:      ingest.Pass,
	}, nil
}

// runAudit scans local collector configs for no-auth settings and leaked
// credentials. Strictly local: no network call of any kind.
func runAudit(opts *options, stdout io.Writer) int {
	if opts.shodan {
		fmt.Fprintln(stdout, "error: --shodan applies to probe/agent targets; audit is strictly local")
		return exitInternal
	}
	root := opts.config
	if root == "" {
		root = "."
	}
	opts.narrate(stdout, fmt.Sprintf("auditing %s: collector config patterns + local credential scan (no network)", root))
	cfg, err := audit.Audit(root)
	if err != nil {
		fmt.Fprintf(stdout, "error: config audit: %v\n", err)
		return exitInternal
	}
	secrets, err := audit.ScanSecrets(root)
	if err != nil {
		fmt.Fprintf(stdout, "error: credential scan: %v\n", err)
		return exitInternal
	}
	return finish(stdout, opts, append(cfg, secrets...), nil, "")
}

// shodanRows runs the OPTIONAL Shodan index lookup for each target host.
// This is the only code path that puts customer data in a third party's
// hands: it runs solely when --shodan is passed and requires a
// customer-provided SHODAN_API_KEY; anything else aborts loudly.
func shodanRows(ts []string) ([]ingest.Result, []string) {
	client := shodan.New(shodanAPIBase, "")
	var (
		rows []ingest.Result
		errs []string
	)
	for _, t := range ts {
		ti, err := parseTarget(t)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		host := ti.hostPort // host[:port]; Lookup strips the port and resolves DNS
		ctx, cancel := context.WithTimeout(context.Background(), targetTimeout)
		indexed, seen, err := client.Lookup(ctx, host)
		cancel()
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if indexed {
			rows = append(rows, ingest.Result{
				Check: fmt.Sprintf("Shodan index visibility of %s", host),
				Evidence: fmt.Sprintf("%s appears in Shodan's public scan index (last seen %s) — "+
					"attackers can find this endpoint", host, seen),
				Remediation: "restrict the endpoint to known sender addresses; internet-wide scanners already know it is there",
				Status:      ingest.Warn,
			})
			continue
		}
		rows = append(rows, ingest.Result{
			Check:       fmt.Sprintf("Shodan index visibility of %s", host),
			Evidence:    fmt.Sprintf("%s is not present in Shodan's index at lookup time", host),
			Remediation: "none",
			Status:      ingest.Pass,
		})
	}
	return rows, errs
}

// targetInfo is the normalized form of one --target value: an optional
// scheme plus host[:port], no path.
type targetInfo struct {
	scheme   string // "", "http", "https", "tcp", "udp"
	hostPort string
}

// parseTarget normalizes a --target value. A trailing "/" is tolerated;
// any other path, query, or fragment is rejected — request paths belong
// to the adapters, not to the operator.
func parseTarget(raw string) (targetInfo, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return targetInfo{}, errors.New("empty target")
	}
	var ti targetInfo
	rest := s
	if i := strings.Index(rest, "://"); i >= 0 {
		ti.scheme = strings.ToLower(rest[:i])
		rest = rest[i+3:]
		if rest == "" {
			return targetInfo{}, fmt.Errorf("target %q: no host after scheme", raw)
		}
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		if rest[i:] != "/" {
			return targetInfo{}, fmt.Errorf("target %q: pass the base address only (host[:port]) — request paths belong to the adapter", raw)
		}
		rest = rest[:i]
	}
	ti.hostPort = rest
	return ti, nil
}

// endpoint renders the HTTP base URL for the target, defaulting a bare
// host:port to plain HTTP (the ingest ports this tool probes are cleartext
// by default; https:// is honored when given).
func (ti targetInfo) endpoint() string {
	if ti.scheme == "" {
		return "http://" + ti.hostPort
	}
	return ti.scheme + "://" + ti.hostPort
}

// hostPortOf splits "host:port" with an all-digits port (IPv6 literals keep
// their brackets: the last colon is the separator).
func hostPortOf(s string) (host, port string, ok bool) {
	i := strings.LastIndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return "", "", false
	}
	port = s[i+1:]
	for _, r := range port {
		if r < '0' || r > '9' {
			return "", "", false
		}
	}
	return s[:i], port, true
}

// adapterForTarget resolves one --target value to an ingest adapter: the
// --adapter override when given, the port heuristic otherwise.
func adapterForTarget(raw, override string) (ingest.Ingestor, error) {
	ti, err := parseTarget(raw)
	if err != nil {
		return nil, err
	}
	if override != "" {
		return adapterByName(override, ti, raw)
	}
	return adapterByPort(ti, raw)
}

// adapterByPort implements the heuristic --help states: the well-known
// ingest port picks the adapter, with the URL scheme resolving syslog's
// TCP/UDP ambiguity. Anything else is an error with a hint.
func adapterByPort(ti targetInfo, raw string) (ingest.Ingestor, error) {
	_, port, hasPort := hostPortOf(ti.hostPort)
	switch ti.scheme {
	case "tcp", "udp":
		if !hasPort {
			return nil, fmt.Errorf("target %q: syslog-family targets need an explicit port (tcp://host:514, udp://host:514, udp://host:12201)", raw)
		}
		switch {
		case port == "514" && ti.scheme == "tcp":
			return ingest.NewSyslogTCP(ti.hostPort), nil
		case port == "514" && ti.scheme == "udp":
			return ingest.NewSyslogUDP(ti.hostPort), nil
		case port == "12201" && ti.scheme == "udp":
			return ingest.NewGELF(ti.hostPort), nil
		case port == "12201" && ti.scheme == "tcp":
			return nil, fmt.Errorf("target %q: the GELF adapter speaks UDP — use udp://host:12201 or a bare host:12201", raw)
		}
		return nil, fmt.Errorf("target %q: no known adapter for %s port %s — pass --adapter or use a port from the map in --help", raw, ti.scheme, port)
	case "http", "https", "":
		if port == "514" {
			if ti.scheme == "" {
				return nil, fmt.Errorf("target %q: port 514 is ambiguous between TCP and UDP syslog — pass tcp://host:514 or udp://host:514", raw)
			}
			return nil, fmt.Errorf("target %q: plain syslog is not HTTP — use tcp://host:514 or udp://host:514", raw)
		}
		if port == "12201" {
			if ti.scheme == "" {
				// GELF's common default is UDP (Graylog), so a bare
				// host:12201 is not ambiguous the way port 514 is.
				return ingest.NewGELF(ti.hostPort), nil
			}
			return nil, fmt.Errorf("target %q: the GELF adapter speaks UDP — use udp://host:12201 or a bare host:12201", raw)
		}
		if !hasPort {
			return nil, fmt.Errorf("target %q: cannot infer the adapter without a port — pass --adapter or a port from the map in --help (8088, 8888, 9880, 10080, 9200, 514, 12201)", raw)
		}
		name, known := portAdapter[port]
		if !known {
			return nil, fmt.Errorf("target %q: no known adapter for port %s — pass --adapter or use a port from the map in --help", raw, port)
		}
		return newHTTPAdapter(name, ti.endpoint())
	default:
		return nil, fmt.Errorf("target %q: unsupported scheme %q (use http://, https://, tcp:// or udp://)", raw, ti.scheme)
	}
}

// adapterByName applies the explicit --adapter override, validating that
// the target's scheme matches the adapter's transport.
func adapterByName(name string, ti targetInfo, raw string) (ingest.Ingestor, error) {
	switch name {
	case "hec", "fluentd", "fluentbit", "cribl", "elastic":
		switch ti.scheme {
		case "", "http", "https":
			return newHTTPAdapter(name, ti.endpoint())
		case "tcp", "udp":
			return nil, fmt.Errorf("--adapter %s speaks HTTP — drop the %s:// scheme or use http(s)://", name, ti.scheme)
		}
	case "syslog-tcp":
		if _, port, ok := hostPortOf(ti.hostPort); ok && port != "" {
			if ti.scheme == "" || ti.scheme == "tcp" {
				return ingest.NewSyslogTCP(ti.hostPort), nil
			}
			return nil, fmt.Errorf("--adapter syslog-tcp speaks TCP — pass tcp://host:514 or a bare host:514")
		}
		return nil, fmt.Errorf("target %q: syslog-tcp needs host:port (e.g. tcp://siem:514)", raw)
	case "syslog-udp":
		if _, port, ok := hostPortOf(ti.hostPort); ok && port != "" {
			if ti.scheme == "" || ti.scheme == "udp" {
				return ingest.NewSyslogUDP(ti.hostPort), nil
			}
			return nil, fmt.Errorf("--adapter syslog-udp speaks UDP — pass udp://host:514 or a bare host:514")
		}
		return nil, fmt.Errorf("target %q: syslog-udp needs host:port (e.g. udp://siem:514)", raw)
	case "gelf":
		if _, port, ok := hostPortOf(ti.hostPort); ok && port != "" {
			if ti.scheme == "" || ti.scheme == "udp" {
				return ingest.NewGELF(ti.hostPort), nil
			}
			return nil, fmt.Errorf("--adapter gelf speaks UDP here — pass udp://host:12201 or a bare host:12201")
		}
		return nil, fmt.Errorf("target %q: gelf needs host:port (e.g. udp://graylog:12201)", raw)
	}
	return nil, fmt.Errorf("unknown --adapter %q (known: hec, fluentd, fluentbit, cribl, elastic, syslog-tcp, syslog-udp, gelf)", name)
}

// newHTTPAdapter builds the named HTTP adapter for an endpoint.
func newHTTPAdapter(name, endpoint string) (ingest.Ingestor, error) {
	switch name {
	case "hec":
		return ingest.NewHEC(endpoint), nil
	case "fluentd":
		return ingest.NewFluentd(endpoint), nil
	case "fluentbit":
		return ingest.NewFluentBit(endpoint), nil
	case "cribl":
		return ingest.NewCribl(endpoint), nil
	case "elastic":
		return ingest.NewElastic(endpoint), nil
	}
	return nil, fmt.Errorf("unknown HTTP adapter %q", name)
}
