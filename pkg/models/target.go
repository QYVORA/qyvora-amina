package models

import (
	"strings"
	"time"
)

// TargetType distinguishes the kind of assessment target.
type TargetType string

const (
	// TargetHost identifies the local machine Amina is running on. This is the
	// only live source type implemented, and it is read-only by construction.
	TargetHost TargetType = "host"
	// TargetSnapshot identifies an offline capture file produced by a previous
	// Amina run, so a report can be re-rendered without re-reading the host.
	TargetSnapshot TargetType = "snapshot"
	// TargetSimulation is the built-in deterministic simulation dataset.
	TargetSimulation TargetType = "simulation"
)

// TargetTypes lists every target type.
var TargetTypes = []TargetType{TargetHost, TargetSnapshot, TargetSimulation}

// ParseTargetType converts a case-insensitive type string, defaulting to the
// local host because that is the only target Amina can honestly assess.
func ParseTargetType(s string) TargetType {
	switch TargetType(strings.ToLower(strings.TrimSpace(s))) {
	case TargetHost, TargetSnapshot, TargetSimulation:
		return TargetType(strings.ToLower(strings.TrimSpace(s)))
	default:
		return TargetHost
	}
}

// Valid reports whether the target type is known.
func (t TargetType) Valid() bool {
	switch t {
	case TargetHost, TargetSnapshot, TargetSimulation:
		return true
	}
	return false
}

// IsLive reports whether the type reads the machine Amina runs on. Amina never
// scans a remote host, so "live" here means "this host", never "a network".
func (t TargetType) IsLive() bool { return t == TargetHost }

// Offline reports whether the target involves no host reads at all.
func (t TargetType) Offline() bool { return t == TargetSnapshot || t == TargetSimulation }

// Authorization records the explicit consent state of a target. Amina
// assesses the operator's own machine, so authorization is granted by default;
// the field exists so the gate is visible in the machine contract rather than
// implied, and so a future remote mode cannot silently reuse the local path.
type Authorization struct {
	Granted   bool      `json:"granted"`
	GrantedAt time.Time `json:"granted_at,omitempty"`
	Scope     string    `json:"scope,omitempty"`
	GrantedBy string    `json:"granted_by,omitempty"`
}

// Target is the object an assessment runs against.
type Target struct {
	ID        string        `json:"id"`
	Name      string        `json:"name,omitempty"`
	Type      TargetType    `json:"type"`
	Value     string        `json:"value"`
	Profile   string        `json:"profile,omitempty"`
	Platform  Platform      `json:"platform"`
	Auth      Authorization `json:"authorization"`
	CreatedAt time.Time     `json:"created_at"`
}

// Authorized reports whether the target passed the authorization gate.
func (t *Target) Authorized() bool { return t != nil && t.Auth.Granted }

// DisplayName returns a short human-readable label for the target.
func (t *Target) DisplayName() string {
	if t == nil {
		return "<nil>"
	}
	if t.Name != "" {
		return t.Name
	}
	if t.Value != "" {
		return t.Value
	}
	return "local host"
}

// TypedName renders the target with its type prefix, e.g. "host:workstation".
func (t *Target) TypedName() string {
	if t == nil {
		return "<nil>"
	}
	if t.Value == "" {
		return string(t.Type)
	}
	return string(t.Type) + ":" + t.Value
}

// Itoa is a dependency-free integer formatter used by report renderers and
// terminal tables.
func Itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	const digits = "0123456789"
	for v > 0 {
		i--
		buf[i] = digits[v%10]
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
