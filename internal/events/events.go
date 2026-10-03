// Package events implements the shared QYVORA JSONL event envelope. Every
// emitted line is one JSON object:
//
//	{"schema_version":"1.0","timestamp":"...","execution_id":"...",
//	 "framework":"amina","level":"info","event":"module.completed","data":{}}
//
// Consumers key on event names, never on terminal output.
package events

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/QYVORA/qyvora-amina/internal/version"
)

// SchemaVersion is the event schema version every event carries.
const SchemaVersion = "1.0"

// Ecosystem-wide verbs plus Amina's OPSEC-specific verbs, shaped
// "category.thing.state" so consumers can route on prefix.
const (
	AssessmentStarted   = "assessment.started"
	AssessmentCompleted = "assessment.completed"
	SimulationLoaded    = "simulation.loaded"
	HostDetected        = "host.detected"
	ModuleStarted       = "module.started"
	ModuleCompleted     = "module.completed"
	ModuleSkipped       = "module.skipped"
	ModuleFailed        = "module.failed"
	FindingDiscovered   = "finding.discovered"
	EvidenceCollected   = "evidence.collected"
	Warning             = "warning"
	Error               = "error"
	ReportGenerated     = "report.generated"
	CapabilityDegraded  = "capability.degraded"
	PrivilegeRequired   = "privilege.required"

	AssetDiscovered     = "asset.discovered"
	IdentityDiscovered  = "identity.discovered"
	AccountDiscovered   = "account.discovered"
	RemoteAccessChecked = "remote_access.checked"
	NetworkExamined     = "network.examined"
	SoftwareDiscovered  = "software.discovered"
	PackageSourceSeen   = "package_source.seen"
	BinaryAnalyzed      = "binary.analyzed"
	ProvenanceChecked   = "provenance.checked"
	SecretDetected      = "secret.detected"
	SecretRedacted      = "secret.redacted"
	ShellInspected      = "shell.inspected"
	EnvironmentScanned  = "environment.scanned"
	GitInspected        = "git.inspected"
	CloudInspected      = "cloud.inspected"
	ProcessEnumerated   = "process.enumerated"
	ServiceDiscovered   = "service.discovered"
	PersistenceFound    = "persistence.found"
	ToolingDiscovered   = "tooling.discovered"
	ArtifactFound       = "artifact.found"
	PostureChecked      = "posture.checked"
	ApplicationFound    = "application.found"
	IdentityCorrelated  = "identity.correlated"
	MetadataObserved    = "metadata.observed"
	RiskCalculated      = "risk.calculated"
)

// Verbs lists every event name Amina can emit, in documentation order. The
// capability document publishes this list so an orchestrator can validate an
// event stream against the framework that claims to have produced it.
var Verbs = []string{
	AssessmentStarted, AssessmentCompleted, SimulationLoaded, HostDetected,
	ModuleStarted, ModuleCompleted, ModuleSkipped, ModuleFailed,
	AssetDiscovered, FindingDiscovered, EvidenceCollected,
	CapabilityDegraded, PrivilegeRequired, Warning, Error, ReportGenerated,
	IdentityDiscovered, AccountDiscovered, RemoteAccessChecked, NetworkExamined,
	SoftwareDiscovered, PackageSourceSeen, BinaryAnalyzed, ProvenanceChecked,
	SecretDetected, SecretRedacted, ShellInspected, EnvironmentScanned,
	GitInspected, CloudInspected, ProcessEnumerated, ServiceDiscovered,
	PersistenceFound, ToolingDiscovered, ArtifactFound, PostureChecked,
	ApplicationFound, IdentityCorrelated, MetadataObserved, RiskCalculated,
}

// Level values for the envelope's level field.
const (
	LevelInfo    = "info"
	LevelWarning = "warning"
	LevelError   = "error"
)

// Event is the wire shape of one event line.
type Event struct {
	SchemaVersion string         `json:"schema_version"`
	Timestamp     time.Time      `json:"timestamp"`
	ExecutionID   string         `json:"execution_id"`
	Framework     string         `json:"framework"`
	Level         string         `json:"level"`
	Event         string         `json:"event"`
	Data          map[string]any `json:"data,omitempty"`
}

// Stream writes events as JSONL to w. It is safe for concurrent use.
type Stream struct {
	mu          sync.Mutex
	w           io.Writer
	executionID string
	count       int
}

// NewStream returns a stream bound to a freshly generated execution id.
func NewStream(w io.Writer) *Stream {
	return &Stream{w: w, executionID: newExecutionID()}
}

// ExecutionID returns the execution id bound to this stream.
func (s *Stream) ExecutionID() string {
	if s == nil {
		return ""
	}
	return s.executionID
}

// Count returns the number of events emitted by this stream.
func (s *Stream) Count() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

// Emit writes one event. Data may be nil.
func (s *Stream) Emit(level, name string, data map[string]any) {
	if s == nil || s.w == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count++
	ev := Event{
		SchemaVersion: SchemaVersion,
		Timestamp:     time.Now().UTC(),
		ExecutionID:   s.executionID,
		Framework:     version.Framework,
		Level:         level,
		Event:         name,
		Data:          data,
	}
	if err := json.NewEncoder(s.w).Encode(ev); err != nil {
		return
	}
}

// Info emits an informational event.
func (s *Stream) Info(name string, data map[string]any) { s.Emit(LevelInfo, name, data) }

// Warn emits a warning event.
func (s *Stream) Warn(name string, data map[string]any) { s.Emit(LevelWarning, name, data) }

// Fail emits an error event.
func (s *Stream) Fail(name string, data map[string]any) { s.Emit(LevelError, name, data) }

func newExecutionID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return version.Framework + "-" + time.Now().UTC().Format("20060102T150405.000000000")
	}
	return hex.EncodeToString(b[:])
}
