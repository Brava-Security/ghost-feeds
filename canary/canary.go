// Package canary defines the marker event used to test whether an ingestion
// endpoint accepts unauthenticated events. Customer-run checks use their own
// UUID namespace, distinct from campaign batches (BRAVA-RES-*).
package canary

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// Canary is a single semantically inert marker event: no auth-failure or
// login-like shapes that could match detection rules.
type Canary struct {
	UUID   string
	Marker string // "BRAVA-CHECK-<UUID>"
}

// New returns a canary with a fresh random UUID (RFC 4122 version 4).
func New() (Canary, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Canary{}, fmt.Errorf("canary: generating uuid: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // variant 10
	u := fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]), hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]), hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]))
	return FromUUID(u), nil
}

// FromUUID builds a canary from a known UUID.
func FromUUID(uuid string) Canary {
	return Canary{UUID: uuid, Marker: "BRAVA-CHECK-" + uuid}
}
