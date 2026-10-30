// Package events implements the shared QYVORA JSONL event envelope. Every
// emitted line is one JSON object:
//
//	{"schema_version":"1.0","timestamp":"...","execution_id":"...",
//	 "framework":"amina","level":"info","event":"module.completed","data":{}}
//
// Consumers key on event names, never on terminal output.
package events

import (
	"io"

	shared "github.com/QYVORA/qyvora-events"
)

// SchemaVersion is the event schema version every event carries.
const SchemaVersion = shared.SchemaVersion

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
	LevelInfo    = shared.LevelInfo
	LevelWarning = shared.LevelWarning
	LevelError   = shared.LevelError
)

type Event = shared.Event
type Stream = shared.Stream

// NewStream returns a stream bound to amina.
func NewStream(w io.Writer) *Stream { return shared.NewStream(w, "amina") }
