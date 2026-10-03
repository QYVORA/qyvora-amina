// Package evidence stores the verifiable observations collected during an
// assessment, optionally persisted to a JSON file for reproducibility.
//
// Evidence is write-once at the collector: the value stored here has already
// passed through redaction, so nothing downstream has to be trusted to hide a
// secret. That ordering is the whole point — a redaction pass at the render
// layer alone is one missed call site away from a leak.
package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// Store keeps evidence for one assessment run.
type Store struct {
	mu    sync.Mutex
	path  string
	items []models.Evidence
}

// New returns an empty evidence store. When path is non-empty the store is
// written there on Save (owner-only).
func New(path string) *Store { return &Store{path: path} }

// Add records a piece of evidence, filling in the derived identity and hash
// fields. Secret-shaped payloads are redacted here rather than at render time.
func (s *Store) Add(ev models.Evidence) {
	if ev.ID == "" {
		ev.ID = models.NewID("ev")
	}
	if ev.Hash == "" {
		ev.Hash = models.HashContent(ev.Data)
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = ev.CollectedAt
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = models.Now()
	}
	if models.LooksSecretValue(ev.Data) {
		ev.Data = "<redacted>"
		if ev.Redaction.Mode == models.RedactionNone {
			ev.Redaction.Mode = models.RedactionFull
		}
		if ev.Redaction.Reason == "" {
			ev.Redaction.Reason = "secret-shaped value redacted at collection"
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, ev)
}

// List returns all evidence in insertion order.
func (s *Store) List() []models.Evidence {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]models.Evidence, len(s.items))
	copy(out, s.items)
	return out
}

// Len returns the number of recorded evidence items.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// Save writes the store to its configured path (0600 in a 0700 directory).
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" {
		return nil
	}
	if dir := filepath.Dir(s.path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	data, err := json.MarshalIndent(s.items, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0o600)
}
