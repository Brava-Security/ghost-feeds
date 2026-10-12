package ingest

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Brava-Security/ghost-telemetry-check/canary"
)

func testCanary() canary.Canary {
	return canary.FromUUID("11111111-2222-3333-4444-555555555555")
}

func TestHECRejectsAuthlessCanary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized) // token'd HEC
	}))
	defer srv.Close()
	h := NewHEC(srv.URL)
	if err := h.Inject(context.Background(), testCanary()); err == nil {
		t.Fatal("authless injection must fail on a token'd HEC")
	}
}

func TestOpenHTTPSourceAcceptsCanary(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // tokenless source
	}))
	defer srv.Close()
	h := NewCribl(srv.URL)
	if err := h.Inject(context.Background(), testCanary()); err != nil {
		t.Fatalf("open source should accept: %v", err)
	}
}

func TestCheckGradesRejectionAsPass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	res, err := NewHEC(srv.URL).Check(context.Background(), testCanary())
	if err != nil {
		t.Fatalf("rejected canary must grade, not error: %v", err)
	}
	if res.Status != Pass {
		t.Fatalf("rejected canary must grade Pass, got %v", res.Status)
	}
	if !strings.Contains(res.Evidence, "rejected") {
		t.Fatalf("evidence must explain the rejection, got %q", res.Evidence)
	}
}

func TestCheckGradesAcceptanceAsFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	res, err := NewCribl(srv.URL).Check(context.Background(), testCanary())
	if err != nil {
		t.Fatalf("accepted canary must grade, not error: %v", err)
	}
	if res.Status != Fail {
		t.Fatalf("accepted canary must grade Fail, got %v", res.Status)
	}
	if !strings.Contains(res.Remediation, "manual purge: search BRAVA-CHECK-11111111-2222-3333-4444-555555555555") {
		t.Fatalf("remediation must name the marker for manual purge, got %q", res.Remediation)
	}
}

func TestCheckTransportErrorIsNotPass(t *testing.T) {
	// A closed port: nothing is listening, so Inject fails at the transport
	// layer. That must surface as an error, never as a Pass grade.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	res, err := NewHEC("http://"+addr).Check(context.Background(), testCanary())
	if err == nil {
		t.Fatalf("unreachable endpoint must return an error, got grade %+v", res)
	}
	if res != (Result{}) {
		t.Fatalf("unreachable endpoint must return an ungraded zero Result, got %+v", res)
	}
}

func TestHECPurgeRequiresManualAction(t *testing.T) {
	h := NewHEC("http://127.0.0.1:8088")
	err := h.Purge(context.Background(), testCanary())
	if err == nil || !strings.Contains(err.Error(), "manual purge: search BRAVA-CHECK-") {
		t.Fatalf("HEC purge must demand manual action, got %v", err)
	}
}

func TestElasticVerifyFindsMarker(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/_search") {
			t.Errorf("verify must hit the ES search API, got %s", r.URL.Path)
		}
		io.WriteString(w, `{"hits":{"total":{"value":1}}}`)
	}))
	defer srv.Close()
	found, err := NewElastic(srv.URL).Verify(context.Background(), testCanary())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !found {
		t.Fatal("marker present in index must be found")
	}
}

func TestElasticPurgeDeletesByQuery(t *testing.T) {
	body := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "brava-research/_delete_by_query") {
			t.Errorf("purge must delete by query against brava-research, got %s", r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		body <- string(b)
		io.WriteString(w, `{"deleted":1}`)
	}))
	defer srv.Close()
	if err := NewElastic(srv.URL).Purge(context.Background(), testCanary()); err != nil {
		t.Fatalf("purge: %v", err)
	}
	if got := <-body; !strings.Contains(got, "BRAVA-CHECK-11111111-2222-3333-4444-555555555555") {
		t.Fatalf("delete query must match the marker, got %q", got)
	}
}

func TestElasticPurgeSurfacesShardFailures(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"deleted":0,"failures":[{"type":"es"}],"timed_out":false}`)
	}))
	defer srv.Close()
	err := NewElastic(srv.URL).Purge(context.Background(), testCanary())
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("shard failures must surface, got %v", err)
	}
}

func TestStatusString(t *testing.T) {
	for _, tc := range []struct {
		s    Status
		want string
	}{
		{Pass, "pass"}, {Warn, "warn"}, {Fail, "fail"},
	} {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("Status(%d).String() = %q, want %q", tc.s, got, tc.want)
		}
	}
}
