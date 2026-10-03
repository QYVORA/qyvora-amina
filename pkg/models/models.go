// Package models holds the shared, framework-independent data contracts for
// operational-security assessments: the assessment host, its users, software,
// provenance, findings, evidence, risk and results.
//
// The vocabulary here is OPSEC-specific rather than generic, because Amina's
// central question is not "is this host secure" but "what does this machine
// reveal about the operator who runs it". An observation that is perfectly
// benign in isolation — a hostname, a git email, an installed package source —
// becomes an exposure only when it is correlated with other identity signals,
// which is why Asset, IdentitySignal and their correlation are first-class
// models rather than free-text attributes.
package models

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// State distinguishes how the framework knows a value: directly observed,
// validated, inferred, unknown, or explicitly not seen.
type State string

const (
	StateObserved  State = "observed"
	StateValidated State = "validated"
	StateInferred  State = "inferred"
	StateUnknown   State = "unknown"
	StateNotSeen   State = "not_seen"
)

// NewID returns a random lowercase hex identifier with the given prefix, or a
// timestamp fallback if the CSPRNG is unavailable.
func NewID(prefix string) string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return prefix + "-" + time.Now().UTC().Format("20060102T150405.000")
	}
	return prefix + "-" + hex.EncodeToString(b[:])
}

// Now returns the current UTC instant, the standard timestamp for all
// framework records.
func Now() time.Time { return time.Now().UTC() }
