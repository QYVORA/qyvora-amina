package models

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// EvidenceKind classifies how evidence was obtained.
type EvidenceKind string

const (
	EvidenceAttribute     EvidenceKind = "attribute"
	EvidenceConfiguration EvidenceKind = "configuration"
	EvidenceObservation   EvidenceKind = "observation"
	EvidenceArtifact      EvidenceKind = "artifact"
	EvidenceFile          EvidenceKind = "file"
	EvidenceSignature     EvidenceKind = "signature"
	EvidenceHash          EvidenceKind = "hash"
)

// EvidenceKinds lists every evidence kind.
var EvidenceKinds = []EvidenceKind{
	EvidenceAttribute, EvidenceConfiguration, EvidenceObservation,
	EvidenceArtifact, EvidenceFile, EvidenceSignature, EvidenceHash,
}

// Redaction describes how a value was withheld before it reached a report.
//
// Amina's redaction is auditable on purpose. A finding that says "a secret was
// found" without saying whether the value was redacted, fingerprinted or
// merely not printed is indistinguishable from a finding that leaked it.
type Redaction string

const (
	RedactionNone        Redaction = "none"        // value was never secret-shaped
	RedactionFull        Redaction = "full"        // value withheld entirely
	RedactionPartial     Redaction = "partial"     // leading/trailing characters kept
	RedactionFingerprint Redaction = "fingerprint" // only a hash derivative survives
	RedactionCount       Redaction = "count"       // only an occurrence count survives
)

// RedactionDetail carries the audit fields of a redaction.
type RedactionDetail struct {
	Mode        Redaction `json:"mode"`
	Fingerprint string    `json:"fingerprint,omitempty"` // truncated, non-reversible
	Length      int       `json:"length,omitempty"`
	Reason      string    `json:"reason,omitempty"`
}

// Evidence is one verifiable observation backing a finding. It carries a
// content hash so reports can trace finding → evidence → source deterministically,
// and it never carries an unredacted secret: Data is populated only after
// Redaction has been applied.
type Evidence struct {
	ID          string          `json:"id"`
	Kind        EvidenceKind    `json:"kind"`
	Source      string          `json:"source"`              // collector, e.g. "platform:accounts"
	SourceID    string          `json:"source_id,omitempty"` // entity id the evidence describes
	Target      string          `json:"target,omitempty"`    // target identifier
	Location    string          `json:"location,omitempty"`  // file path, registry key, command
	Data        string          `json:"data,omitempty"`      // quoted value, redacted if secret
	Expected    string          `json:"expected,omitempty"`  // the property that should have held
	Redaction   RedactionDetail `json:"redaction"`
	Hash        string          `json:"hash"`
	State       State           `json:"state"`
	CollectedAt time.Time       `json:"collected_at,omitempty"`
	Timestamp   time.Time       `json:"timestamp"`
}

// HashContent returns the lowercase hex SHA-256 digest of s.
func HashContent(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
