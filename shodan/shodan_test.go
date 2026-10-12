package shodan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestShodanLookupDisclosesThirdParty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ip": 167772160, "data": [{"port": 8088}]}`)
	}))
	defer srv.Close()
	s := New(srv.URL, "k")
	idx, seen, err := s.Lookup(context.Background(), "10.0.0.1")
	if err != nil || !idx {
		t.Fatalf("idx=%v err=%v", idx, err)
	}
	_ = seen
}

func TestShodanLookupNotIndexed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error": "No information available for that IP."}`)
	}))
	defer srv.Close()
	s := New(srv.URL, "k")
	idx, seen, err := s.Lookup(context.Background(), "10.0.0.1")
	if err != nil || idx {
		t.Fatalf("idx=%v err=%v seen=%q", idx, err, seen)
	}
}

func TestShodanLookupNoData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ip": 167772160, "data": []}`)
	}))
	defer srv.Close()
	s := New(srv.URL, "k")
	idx, _, err := s.Lookup(context.Background(), "10.0.0.1")
	if err != nil || idx {
		t.Fatalf("idx=%v err=%v", idx, err)
	}
}

func TestShodanLookupSeenTimestamp(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data": [{"port": 8088}], "last_update": "2026-09-01T12:00:00"}`)
	}))
	defer srv.Close()
	s := New(srv.URL, "k")
	idx, seen, err := s.Lookup(context.Background(), "10.0.0.1")
	if err != nil || !idx || seen != "2026-09-01T12:00:00" {
		t.Fatalf("idx=%v seen=%q err=%v", idx, seen, err)
	}
}

func TestShodanLookupSendsKeyAndHost(t *testing.T) {
	var gotPath, gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotKey = r.URL.Query().Get("key")
		fmt.Fprint(w, `{"data": [{"port": 8088}]}`)
	}))
	defer srv.Close()
	s := New(srv.URL, "k")
	if _, _, err := s.Lookup(context.Background(), "10.0.0.1"); err != nil {
		t.Fatalf("err=%v", err)
	}
	if gotPath != "/shodan/host/10.0.0.1" {
		t.Fatalf("path=%q", gotPath)
	}
	if gotKey != "k" {
		t.Fatalf("key=%q", gotKey)
	}
}

func TestShodanLookupServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	s := New(srv.URL, "k")
	idx, _, err := s.Lookup(context.Background(), "10.0.0.1")
	if err == nil || idx {
		t.Fatalf("idx=%v err=%v", idx, err)
	}
}

func TestShodanLookupRequiresAPIKey(t *testing.T) {
	s := New("http://example.invalid", "")
	idx, _, err := s.Lookup(context.Background(), "10.0.0.1")
	if err == nil || idx {
		t.Fatalf("idx=%v err=%v", idx, err)
	}
}

func TestShodanLookupContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New("http://example.invalid", "k")
	if _, _, err := s.Lookup(ctx, "10.0.0.1"); err == nil {
		t.Fatal("expected error for canceled context")
	}
}

func TestShodanLookupEnvKeyFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("key") != "envkey" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"data": [{"port": 8088}]}`)
	}))
	defer srv.Close()
	t.Setenv("SHODAN_API_KEY", "envkey")
	s := New(srv.URL, "") // no key via constructor: must read SHODAN_API_KEY
	idx, _, err := s.Lookup(context.Background(), "10.0.0.1")
	if err != nil || !idx {
		t.Fatalf("idx=%v err=%v", idx, err)
	}
}

func TestShodanLookupResolvesHostname(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		fmt.Fprint(w, `{"data": [{"port": 8088}]}`)
	}))
	defer srv.Close()
	s := New(srv.URL, "k")
	s.lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
		if host != "siem.example.com" {
			t.Errorf("resolved host=%q", host)
		}
		return []net.IP{net.ParseIP("192.0.2.10")}, nil
	}
	idx, _, err := s.Lookup(context.Background(), "siem.example.com")
	if err != nil || !idx {
		t.Fatalf("idx=%v err=%v", idx, err)
	}
	if gotPath != "/shodan/host/192.0.2.10" {
		t.Fatalf("path=%q", gotPath)
	}
}

func TestShodanLookupStripsPort(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		fmt.Fprint(w, `{"data": [{"port": 8088}]}`)
	}))
	defer srv.Close()
	s := New(srv.URL, "k")
	s.lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
		t.Errorf("resolver should not run for IP literal, got %q", host)
		return nil, nil
	}
	idx, _, err := s.Lookup(context.Background(), "10.0.0.1:8088")
	if err != nil || !idx {
		t.Fatalf("idx=%v err=%v", idx, err)
	}
	if gotPath != "/shodan/host/10.0.0.1" {
		t.Fatalf("path=%q", gotPath)
	}
}

func TestShodanLookupIPv6LiteralPassthrough(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		fmt.Fprint(w, `{"data": [{"port": 8088}]}`)
	}))
	defer srv.Close()
	s := New(srv.URL, "k")
	s.lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
		t.Errorf("resolver should not run for IP literal, got %q", host)
		return nil, nil
	}
	idx, _, err := s.Lookup(context.Background(), "2001:db8::1")
	if err != nil || !idx {
		t.Fatalf("idx=%v err=%v", idx, err)
	}
	if gotPath != "/shodan/host/2001:db8::1" {
		t.Fatalf("path=%q", gotPath)
	}
}

func TestShodanLookupPrefersIPv4(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		fmt.Fprint(w, `{"data": [{"port": 8088}]}`)
	}))
	defer srv.Close()
	s := New(srv.URL, "k")
	s.lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("192.0.2.20")}, nil
	}
	idx, _, err := s.Lookup(context.Background(), "dual.example.com")
	if err != nil || !idx {
		t.Fatalf("idx=%v err=%v", idx, err)
	}
	if gotPath != "/shodan/host/192.0.2.20" {
		t.Fatalf("path=%q", gotPath)
	}
}

func TestShodanLookupResolveFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no API call expected on DNS failure")
	}))
	defer srv.Close()
	s := New(srv.URL, "k")
	s.lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
		return nil, errors.New("no such host")
	}
	idx, _, err := s.Lookup(context.Background(), "siem.example.com")
	if err == nil || idx {
		t.Fatalf("idx=%v err=%v", idx, err)
	}
}

func TestShodanLookupResolverHonorsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New("http://example.invalid", "k")
	s.lookupIP = func(c context.Context, host string) ([]net.IP, error) {
		return nil, c.Err()
	}
	if _, _, err := s.Lookup(ctx, "siem.example.com"); err == nil {
		t.Fatal("expected error for canceled context")
	}
}

func TestShodanClientHasTimeout(t *testing.T) {
	s := New("http://example.invalid", "k")
	if s.hc.Timeout <= 0 {
		t.Fatalf("http client has no timeout: %v", s.hc.Timeout)
	}
}

// Finding 1: a transport-layer failure (refused connection, timeout, DNS)
// surfaces as a *url.Error whose text embeds the full request URL including
// the ?key=<SHODAN_API_KEY> query. The key must never reach the error the
// CLI prints into CI logs.
func TestShodanLookupRedactsKeyFromTransportError(t *testing.T) {
	s := New("http://127.0.0.1:1", "kryptonite-cat-key") // nothing listens on :1
	_, _, err := s.Lookup(context.Background(), "10.0.0.1")
	if err == nil {
		t.Fatal("want transport error, got nil")
	}
	if msg := err.Error(); strings.Contains(msg, "kryptonite-cat-key") {
		t.Fatalf("API key leaked in transport error: %s", msg)
	}
	if msg := err.Error(); !strings.Contains(msg, "shodan: request:") {
		t.Fatalf("missing request context: %s", msg)
	}
}
