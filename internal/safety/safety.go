// Package safety implements the architectural safety model of amina.
//
// Every operation carries metadata describing its class, risk, authorization
// requirement, whether it changes state, and whether it is reversible.
//
// The model is deliberately blunt about what Amina cannot do:
//
//   - Nothing implemented changes state. There is no remediation path, no
//     cleanup path and no "fix" verb, and adding one would require a different
//     safety argument than this package can make.
//   - Nothing implemented reaches the network except the self-updater, which
//     contacts only the project's own release endpoint and verifies a checksum
//     before installing.
//   - Nothing implemented escalates privilege. Where elevation would help, the
//     capability reports requires_privilege and the run continues without it.
//   - Nothing implemented reads another machine. Amina assesses the operator's
//     own host; remote scanning belongs to a different framework.
//
// Secret material is fingerprinted inside the collector and never stored, so
// the redaction boundary is the collector rather than the renderer.
package safety

import "github.com/QYVORA/qyvora-amina/pkg/models"

// Class identifies a family of assessment operation.
type Class string

const (
	// ClassDiscovery enumerates local state without interpreting it.
	ClassDiscovery Class = "discovery"
	// ClassAnalysis interprets collected state and derives findings.
	ClassAnalysis Class = "analysis"
	// ClassReporting renders already-collected state into an artifact.
	ClassReporting Class = "reporting"
	// ClassNetwork is the only class that touches the network at all.
	ClassNetwork Class = "network"
)

// OperationMetadata describes one operation's safety contract.
type OperationMetadata struct {
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	Description  string           `json:"description"`
	Class        Class            `json:"class"`
	Risk         models.RiskLevel `json:"risk"`
	TargetType   string           `json:"target_type"`
	AuthRequired bool             `json:"authorization_required"`
	Confirm      bool             `json:"confirmation_required"`
	ChangesState bool             `json:"changes_state"`
	Reversible   bool             `json:"reversible"`
	ReadOnly     bool             `json:"read_only"`
}

// Known operations.
var (
	// OpEnumerate reads local host state. Read-only, local, no auth.
	OpEnumerate = OperationMetadata{
		ID: "amina.enumerate", Name: "local host enumeration",
		Description: "Read local identity, account, network, software, provenance, " +
			"filesystem, shell, developer, cloud, process, persistence, tooling, " +
			"artifact, posture and application state from this machine.",
		Class: ClassDiscovery, Risk: models.RiskS1, TargetType: "host",
		AuthRequired: false, Confirm: false, ChangesState: false,
		Reversible: true, ReadOnly: true,
	}
	// OpAssess runs the full pipeline: enumerate, correlate, score, report.
	OpAssess = OperationMetadata{
		ID: "amina.assess", Name: "operational security assessment",
		Description: "Run every assessment module, correlate identity signals, " +
			"score deterministic risk and produce findings with evidence.",
		Class: ClassAnalysis, Risk: models.RiskS2, TargetType: "host",
		AuthRequired: false, Confirm: false, ChangesState: false,
		Reversible: true, ReadOnly: true,
	}
	// OpReport re-renders stored findings without re-reading the host.
	OpReport = OperationMetadata{
		ID: "amina.report", Name: "assessment reporting",
		Description: "Render the latest assessment as terminal, JSON, YAML, " +
			"Markdown or HTML.",
		Class: ClassReporting, Risk: models.RiskS1, TargetType: "any",
		AuthRequired: false, Confirm: false, ChangesState: false,
		Reversible: true, ReadOnly: true,
	}
	// OpSelfUpdate is the only network operation. It replaces the running
	// binary, so it is the one operation that changes state — which is why it
	// is the one operation that requires confirmation.
	OpSelfUpdate = OperationMetadata{
		ID: "amina.self_update", Name: "self update",
		Description: "Download a published release artifact, verify its SHA-256 " +
			"against checksums.txt, and replace the running binary.",
		Class: ClassNetwork, Risk: models.RiskS3, TargetType: "self",
		AuthRequired: false, Confirm: true, ChangesState: true,
		Reversible: true, ReadOnly: false,
	}
)

// All returns every declared operation in documentation order.
func All() []OperationMetadata {
	return []OperationMetadata{OpEnumerate, OpAssess, OpReport, OpSelfUpdate}
}

// Implemented reports whether an operation actually exists in this build.
//
// Every declared operation is implemented; the predicate exists so the CLI can
// gate on the same registry the capability document publishes, rather than on a
// hand-maintained list that can drift.
func (op OperationMetadata) Implemented() bool {
	for _, known := range All() {
		if known.ID == op.ID {
			return true
		}
	}
	return false
}

// RequiresAuthorization reports whether an operation only runs on an
// authorized target. No Amina operation requires authorization, because Amina
// only ever reads the machine it is running on, which its operator already
// controls. The field is retained so the gate is visible in the machine
// contract and a future remote mode cannot reuse this path by accident.
func (op OperationMetadata) RequiresAuthorization() bool { return op.AuthRequired }

// IsReadOnly reports whether an operation leaves the host exactly as it found
// it. It is a method rather than a bare field read because the field and the
// derived answer are different questions: an operation can declare itself
// read-only and still change state, and the contradiction is a bug worth
// catching rather than a value worth propagating.
func (op OperationMetadata) IsReadOnly() bool { return op.ReadOnly && !op.ChangesState }
