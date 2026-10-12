package ingest

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Brava-Security/ghost-telemetry-check/canary"
)

func TestSyslogUDPDeliversMarker(t *testing.T) {
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer pc.Close()
	done := make(chan string, 1)
	go func() { b := make([]byte, 2048); n, _ := pc.(*net.UDPConn).Read(b); done <- string(b[:n]) }()
	s := NewSyslogUDP(pc.LocalAddr().String())
	_ = s.Inject(context.Background(), testCanary())
	select {
	case got := <-done:
		if !strings.Contains(got, "BRAVA-CHECK-") {
			t.Fatalf("marker missing: %s", got)
		}
	case <-time.After(time.Second):
		t.Fatal("no datagram")
	}
}

func TestSyslogUDPFrameIsRFC5424(t *testing.T) {
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer pc.Close()
	done := make(chan string, 1)
	go func() { b := make([]byte, 2048); n, _ := pc.(*net.UDPConn).Read(b); done <- string(b[:n]) }()
	s := NewSyslogUDP(pc.LocalAddr().String())
	if err := s.Inject(context.Background(), testCanary()); err != nil {
		t.Fatalf("inject: %v", err)
	}
	got := <-done
	c := testCanary()
	// local0.info = facility 16, severity 6 => PRI 134
	if !strings.HasPrefix(got, "<134>1 ") {
		t.Fatalf("missing RFC5424 header: %s", got)
	}
	if !strings.Contains(got, "brava-res-11111111-2222-3333-4444-555555555555 brava-research - - "+c.Marker) {
		t.Fatalf("frame fields wrong: %s", got)
	}
}

func TestSyslogTCPDeliversFramedLine(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan string, 1)
	go func() {
		conn, _ := ln.Accept()
		defer conn.Close()
		line, _ := bufio.NewReader(conn).ReadString('\n')
		done <- line
	}()
	s := NewSyslogTCP(ln.Addr().String())
	if err := s.Inject(context.Background(), testCanary()); err != nil {
		t.Fatalf("inject: %v", err)
	}
	select {
	case got := <-done:
		if !strings.Contains(got, testCanary().Marker) || !strings.HasSuffix(got, "\n") {
			t.Fatalf("framed line wrong: %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("no connection")
	}
}

func TestSyslogTCPTransportError(t *testing.T) {
	s := NewSyslogTCP("127.0.0.1:1") // nothing listens
	if err := s.Inject(context.Background(), testCanary()); err == nil {
		t.Fatal("refused connection must be a transport error")
	}
}

func TestGELFDeliversMarker(t *testing.T) {
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer pc.Close()
	done := make(chan string, 1)
	go func() { b := make([]byte, 2048); n, _ := pc.(*net.UDPConn).Read(b); done <- string(b[:n]) }()
	s := NewGELF(pc.LocalAddr().String())
	if err := s.Inject(context.Background(), testCanary()); err != nil {
		t.Fatalf("inject: %v", err)
	}
	var g map[string]any
	if err := json.Unmarshal([]byte(<-done), &g); err != nil {
		t.Fatalf("not valid GELF JSON: %v", err)
	}
	if g["version"] != "1.1" {
		t.Fatalf("version: %v", g["version"])
	}
	if g["host"] != "brava-res-11111111-2222-3333-4444-555555555555" {
		t.Fatalf("host: %v", g["host"])
	}
	if g["level"] != float64(6) {
		t.Fatalf("level: %v", g["level"])
	}
	if !strings.Contains(g["short_message"].(string), testCanary().Marker) {
		t.Fatalf("short_message missing marker: %v", g["short_message"])
	}
	if g["_marker"] != testCanary().Marker {
		t.Fatalf("_marker: %v", g["_marker"])
	}
}

func TestSyslogVerifyPurgeUnsupported(t *testing.T) {
	for _, in := range []Ingestor{NewSyslogTCP("127.0.0.1:514"), NewSyslogUDP("127.0.0.1:514"), NewGELF("127.0.0.1:12201")} {
		if _, err := in.Verify(context.Background(), testCanary()); err == nil || !strings.Contains(err.Error(), "agent mode") {
			t.Fatalf("%s Verify must return agent-mode error, got %v", in.Name(), err)
		}
		if err := in.Purge(context.Background(), testCanary()); err == nil || !strings.Contains(err.Error(), "agent mode") {
			t.Fatalf("%s Purge must return agent-mode error, got %v", in.Name(), err)
		}
	}
}

func TestSyslogNames(t *testing.T) {
	if NewSyslogTCP("127.0.0.1:514").Name() != "syslog-tcp" {
		t.Fatal("bad name")
	}
	if NewSyslogUDP("127.0.0.1:514").Name() != "syslog-udp" {
		t.Fatal("bad name")
	}
	if NewGELF("127.0.0.1:12201").Name() != "gelf" {
		t.Fatal("bad name")
	}
}

func TestSyslogInjectHonorsContextDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := NewSyslogTCP("127.0.0.1:1").Inject(ctx, canary.FromUUID("x")); err == nil {
		t.Fatal("canceled context must abort inject")
	}
}
