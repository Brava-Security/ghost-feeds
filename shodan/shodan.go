// Package shodan performs an OPTIONAL (default off, --shodan) lookup of the
// customer's endpoint IP in Shodan's public internet-scanning index, so they
// can learn their ingest endpoint is already visible to attackers.
//
// this module sends your endpoint IP to Shodan — the only check that does; default off
//
// Zero-telemetry promise: this package is the ONLY one in ghost-telemetry-check
// allowed network egress to a third party, and only when explicitly invoked
// with a customer-provided SHODAN_API_KEY (read from the environment). Every
// other check in the tool is direct, customer-local traffic. See the --shodan
// help text in the CLI for the same disclosure.
package shodan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Client queries the Shodan host index. baseURL is the Shodan API root
// (https://api.shodan.io), key the customer's SHODAN_API_KEY.
type Client struct {
	baseURL string
	key     string
	hc      *http.Client
	// lookupIP resolves hostnames to IPs; injectable for tests. Defaults to
	// the net package resolver (real DNS, honors ctx).
	lookupIP func(ctx context.Context, host string) ([]net.IP, error)
}

// New returns a Client for the given Shodan API base URL and API key. An
// empty key defers to the SHODAN_API_KEY environment variable at Lookup time.
func New(baseURL, key string) *Client {
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		key:     key,
		hc:      &http.Client{Timeout: 30 * time.Second},
		lookupIP: func(ctx context.Context, host string) ([]net.IP, error) {
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			ips := make([]net.IP, len(addrs))
			for i, a := range addrs {
				ips[i] = a.IP
			}
			return ips, nil
		},
	}
}

// errNoKey is returned when Lookup is invoked without an API key.
var errNoKey = errors.New("shodan: SHODAN_API_KEY not set; the optional Shodan lookup requires a customer-provided API key")

// hostResponse is the subset of Shodan's /shodan/host/{ip} response we use.
type hostResponse struct {
	// Data is non-empty when the IP has been observed by Shodan's scanners.
	Data []struct {
		Port int `json:"port"`
	} `json:"data"`
	// LastUpdate is when Shodan last scanned the IP, e.g. "2026-09-01T12:00:00".
	LastUpdate string `json:"last_update"`
}

// Lookup reports whether host (an IP literal, hostname, or host:port) appears
// in Shodan's index. The target is normalized to an IP first: a :port is
// stripped, and a hostname is resolved via DNS (preferring IPv4, Shodan's
// index granularity). indexed is true when the API returned scan data for the
// host. seen is the index entry's last_update timestamp, empty when absent —
// surfaced so the customer knows how stale the entry is. A 404 (no data) is
// not an error; it means the host is not indexed.
func (c *Client) Lookup(ctx context.Context, host string) (indexed bool, seen string, err error) {
	key := c.key
	if key == "" {
		key = os.Getenv("SHODAN_API_KEY") // customer-provided; read from the environment
	}
	if key == "" {
		return false, "", errNoKey
	}
	ip, err := c.targetIP(ctx, host)
	if err != nil {
		return false, "", err
	}
	u := c.baseURL + "/shodan/host/" + url.PathEscape(ip) + "?key=" + url.QueryEscape(key)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false, "", fmt.Errorf("shodan: build request: %w", err)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		// A transport failure surfaces as a *url.Error whose text embeds
		// the full request URL — including the ?key=<SHODAN_API_KEY> query.
		// Strip the query before wrapping so a refused connection, timeout,
		// or DNS failure can never print the customer's key into a CI log.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			uerr.URL = strings.SplitN(uerr.URL, "?", 2)[0]
		}
		return false, "", fmt.Errorf("shodan: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, "", nil // not indexed; Shodan has no data for this host
	}
	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("shodan: API returned status %d", resp.StatusCode)
	}
	var hr hostResponse
	if err := json.NewDecoder(resp.Body).Decode(&hr); err != nil {
		return false, "", fmt.Errorf("shodan: decode response: %w", err)
	}
	if len(hr.Data) == 0 {
		return false, "", nil
	}
	return true, hr.LastUpdate, nil
}

// targetIP normalizes host (IP literal, hostname, or host:port) to the IP
// Shodan should be queried for. Shodan's API only accepts IPs, so hostnames
// are resolved via DNS (first IPv4, else first address).
func (c *Client) targetIP(ctx context.Context, host string) (string, error) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h // strip :port; host was host:port (or [v6]:port)
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	ips, err := c.lookupIP(ctx, host)
	if err != nil {
		return "", fmt.Errorf("shodan: resolve %q: %w", host, err)
	}
	if len(ips) == 0 {
		return "", fmt.Errorf("shodan: resolve %q: no addresses", host)
	}
	for _, ip := range ips {
		if ip.To4() != nil {
			return ip.String(), nil // prefer IPv4
		}
	}
	return ips[0].String(), nil
}
