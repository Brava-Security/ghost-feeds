package canary

import (
	"strings"
	"testing"
)

func TestNewBuildsBravaCheckMarker(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !strings.HasPrefix(c.Marker, "BRAVA-CHECK-") || c.UUID == "" {
		t.Fatalf("marker %q / uuid %q malformed", c.Marker, c.UUID)
	}
	if want := "BRAVA-CHECK-" + c.UUID; c.Marker != want {
		t.Fatalf("marker = %q, want %q", c.Marker, want)
	}
}
func TestNewIsUnique(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		c, err := New()
		if err != nil {
			t.Fatal(err)
		}
		if seen[c.UUID] {
			t.Fatalf("duplicate uuid %s", c.UUID)
		}
		seen[c.UUID] = true
	}
}

func TestFromUUIDIsDeterministic(t *testing.T) {
	c := FromUUID("abc")
	if c.UUID != "abc" || c.Marker != "BRAVA-CHECK-abc" {
		t.Fatalf("got %+v", c)
	}
}
