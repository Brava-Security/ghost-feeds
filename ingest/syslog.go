package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Brava-Security/ghost-telemetry-check/canary"
)

// Syslog-family transports are fire-and-forget at the probe side: there is
// no response to verify against, and this tool wires no vendor product API
// for them (the agent-mode HTTP adapters cover the ports that have one).
// Callers must treat ErrUnsupported as an informational "verify manually"
// note — not a failure, and not silent success.
var ErrUnsupported = errors.New("verification requires agent mode (product-API search), which syslog transports do not expose to this tool; search the SIEM for the marker and delete it manually")

// syslogIngestor is the shared shape of the syslog-family adapters: it frames
// the canary and ships it over TCP or UDP without any authentication.
type syslogIngestor struct {
	addr    string
	name    string
	network string // "tcp" or "udp"
	frame   func(c canary.Canary) []byte
}

// Name identifies the adapter in reports.
func (s *syslogIngestor) Name() string { return s.name }

// Inject dials the endpoint and writes one framed canary. On UDP the write is
// fire-and-forget: a nil return means the datagram left the probe, not that
// the receiver ingested it.
func (s *syslogIngestor) Inject(ctx context.Context, c canary.Canary) error {
	d := net.Dialer{Timeout: injectTimeout}
	conn, err := d.DialContext(ctx, s.network, s.addr)
	if err != nil {
		return fmt.Errorf("syslog dial: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if _, err := conn.Write(s.frame(c)); err != nil {
		return fmt.Errorf("syslog write: %w", err)
	}
	return nil
}

// Verify is not possible from the probe: UDP/TCP sends carry no response and
// the product search API is only reachable in agent mode.
func (s *syslogIngestor) Verify(ctx context.Context, c canary.Canary) (bool, error) {
	return false, fmt.Errorf("%s verify: %w", s.name, ErrUnsupported)
}

// Purge is not possible from the probe: deletion goes through the product API,
// which agent mode wires in.
func (s *syslogIngestor) Purge(ctx context.Context, c canary.Canary) error {
	return fmt.Errorf("%s purge: %w", s.name, ErrUnsupported)
}

// NewSyslogTCP returns an RFC 5424 syslog adapter over TCP (port 514),
// newline-delimited as receivers such as rsyslog expect.
func NewSyslogTCP(addr string) *syslogIngestor {
	return &syslogIngestor{addr: addr, name: "syslog-tcp", network: "tcp", frame: rfc5424Frame}
}

// NewSyslogUDP returns an RFC 5424 syslog adapter over UDP (port 514).
// Syslog UDP keeps each event in a single datagram; our frames are a few
// hundred bytes, far under the ~64KB UDP limit, so no chunking is needed.
func NewSyslogUDP(addr string) *syslogIngestor {
	return &syslogIngestor{addr: addr, name: "syslog-udp", network: "udp", frame: rfc5424Frame}
}

// NewGELF returns a GELF v1.1 adapter (Graylog, default UDP port 12201).
// Our payloads stay well under the ~8KB GELF chunk limit, so a single datagram
// suffices; chunked GELF adds no security signal here.
func NewGELF(addr string) *syslogIngestor {
	return &syslogIngestor{addr: addr, name: "gelf", network: "udp", frame: gelfFrame}
}

// rfc5424Frame builds one syslog line: local0.info (PRI 134), a stable
// hostname/appname pair for filtering, and the marker as the message.
func rfc5424Frame(c canary.Canary) []byte {
	// PRI 134 = facility local0 (16) * 8 + severity info (6)
	msg := fmt.Sprintf("<134>1 %s brava-res-%s brava-research - - %s\n",
		time.Now().UTC().Format(time.RFC3339), c.UUID, c.Marker)
	return []byte(msg)
}

// gelfFrame builds one GELF v1.1 message with the marker in both the
// human-visible short_message and a searchable _marker field.
func gelfFrame(c canary.Canary) []byte {
	b, err := json.Marshal(map[string]any{
		"version":       "1.1",
		"host":          "brava-res-" + c.UUID,
		"short_message": c.Marker,
		"level":         6, // info — matches the syslog severity above
		"_marker":       c.Marker,
	})
	if err != nil {
		// A map of strings and one int cannot fail to marshal; this is
		// unreachable belt-and-braces so the framer always returns bytes.
		return []byte(fmt.Sprintf(`{"version":"1.1","short_message":%q}`, c.Marker))
	}
	return b
}
