package models

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Report is one assessment's complete result.
//
// It is a flat, self-describing document on purpose. A report is what leaves
// the machine — it is uploaded, attached to a ticket, compared between runs and
// archived — so it carries everything needed to understand and defend the
// findings without reference to the host it came from, including the version
// of the tool that produced it and the exact settings used.
type Report struct {
	// Schema identifies the report format, so a consumer can tell what it is
	// reading without guessing from the fields present.
	Schema string `json:"schema"`
	// ID is this run's identifier.
	ID string `json:"id"`
	// Framework and FrameworkVersion identify the producing tool.
	Framework        string `json:"framework"`
	FrameworkVersion string `json:"framework_version"`
	// GeneratedAt is when the report was produced.
	GeneratedAt time.Time `json:"generated_at"`
	// Target is the assessed host.
	Target Target `json:"target"`

	// Configuration records the settings the run used, so a report can be
	// reproduced or challenged.
	Configuration map[string]string `json:"configuration,omitempty"`
	// Depth is the scan depth, as a number and as a name.
	Depth     int    `json:"depth"`
	DepthName string `json:"depth_name"`
	// DurationMS is the wall-clock collection time.
	DurationMS int64 `json:"duration_ms"`

	// Host is the host identity summary, when the host module ran.
	Host *HostSummary `json:"host,omitempty"`
	// Findings are the normalised findings, ordered by risk then identity.
	Findings []Finding `json:"findings"`
	// Summary aggregates the findings.
	Summary Summary `json:"summary"`
	// Modules is the per-module status, which is how a reader tells "nothing
	// found" from "not looked at".
	Modules []ModuleStatus `json:"modules"`
	// Identities are the correlated operator identities.
	Identities []CorrelatedIdentity `json:"identities,omitempty"`
	// Secrets are the detected secrets, as fingerprints.
	Secrets []SecretRecord `json:"secrets,omitempty"`
	// Sources are the configured package sources.
	Sources []PackageSource `json:"package_sources,omitempty"`
	// Software is the installed-software inventory.
	Software []Software `json:"software,omitempty"`
	// Assets is the collected evidence inventory.
	Assets []Asset `json:"assets,omitempty"`
	// Skipped lists rules that did not run, with the reason.
	Skipped []Skipped `json:"skipped,omitempty"`
	// Limitations are the honest-degradation statements: what this run could
	// not see. A report without this section implies more than the tool knows.
	Limitations []string `json:"limitations,omitempty"`
	// Warnings are non-fatal problems encountered during the run.
	Warnings []string `json:"warnings,omitempty"`
	// Integrity is a checksum over the findings, so two reports can be
	// compared for equality without diffing every field.
	Integrity string `json:"integrity"`
	// Redaction states how secrets were handled in this report.
	Redaction RedactionPolicy `json:"redaction"`
}

// HostSummary is the compact host identity block.
type HostSummary struct {
	Hostname  string `json:"hostname,omitempty"`
	FQDN      string `json:"fqdn,omitempty"`
	Platform  string `json:"platform"`
	Kernel    string `json:"kernel,omitempty"`
	OS        string `json:"os,omitempty"`
	Arch      string `json:"arch,omitempty"`
	Uptime    string `json:"uptime,omitempty"`
	MachineID string `json:"machine_id,omitempty"`
	Virtual   bool   `json:"virtual,omitempty"`
	Container bool   `json:"container,omitempty"`
	Cloud     string `json:"cloud,omitempty"`
	LocalUser string `json:"local_user,omitempty"`
	Timezone  string `json:"timezone,omitempty"`
	Locale    string `json:"locale,omitempty"`
	Shell     string `json:"shell,omitempty"`
}

// Summary aggregates a report's findings.
type Summary struct {
	Total      int              `json:"total"`
	BySeverity map[Severity]int `json:"by_severity"`
	ByCategory map[Category]int `json:"by_category"`
	ByState    map[State]int    `json:"by_state"`
	// MaxRisk is the highest final risk score, 0 when there are no findings.
	MaxRisk int `json:"max_risk"`
	// MeanRisk is the mean of the final scores, rounded down.
	MeanRisk int `json:"mean_risk"`
	// RiskBand is the overall risk band implied by MaxRisk.
	RiskBand string `json:"risk_band"`
	// Correlated counts findings that identity correlation produced.
	Correlated int `json:"correlated"`
	// IdentityCount is the number of correlated operator identities.
	IdentityCount int `json:"identity_count"`
}

// Skipped records a rule or module that did not run and why.
type Skipped struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"` // rule | module
	Reason string `json:"reason"`
}

// RedactionPolicy states how secrets were treated in this report.
type RedactionPolicy struct {
	// Strategy names the policy, e.g. "fingerprint-only".
	Strategy string `json:"strategy"`
	// ValuesRetained must be false and is present so a reader can assert it
	// rather than infer it.
	ValuesRetained bool `json:"values_retained"`
	// Note explains it in words.
	Note string `json:"note,omitempty"`
}

// DefaultRedaction is the policy every Amina report carries.
func DefaultRedaction() RedactionPolicy {
	return RedactionPolicy{
		Strategy:       "fingerprint-only",
		ValuesRetained: false,
		Note: "No secret value is stored in this report. Each secret is recorded as a salted fingerprint, " +
			"its location and its length; the value itself is discarded by the collector that read it.",
	}
}

// ReportSchema is the schema identifier for the current report format.
const ReportSchema = "qyvora.amina.report/v1"

// ComputeIntegrity returns a checksum over the report's findings and summary.
//
// The integrity field makes two reports comparable with one comparison, and it
// is what a determinism test asserts on: two runs over the same input must
// produce the same value, and any change to any finding must change it.
//
// Two things are excluded deliberately, and both for the same reason — they
// identify this run rather than this assessment:
//
//   - The per-record random IDs, which differ between runs by construction.
//   - The report ID and the generation timestamp.
//
// The target identifier is excluded for a different reason: the same host
// assessed through two target names is the same assessment, and a checksum that
// changed on the naming would be misleading.
func (r *Report) ComputeIntegrity() string {
	h := sha256.New()
	write := func(s string) { h.Write([]byte(s)); h.Write([]byte{0}) }

	write(r.Schema)
	write(r.Framework)
	write(r.FrameworkVersion)
	write(r.DepthName)
	for _, f := range r.Findings {
		// The random per-record ID is deliberately excluded. Two runs of the
		// same assessment produce different IDs by construction, so hashing
		// them would make every comparison between runs differ and the checksum
		// would be useless for its only purpose. Fingerprint() below is the
		// stable identity of the finding: same rule, same objects, same
		// attributes.
		write(f.RuleID)
		write(f.ModuleID)
		write(f.Title)
		write(string(f.Severity))
		write(string(f.State))
		write(string(f.Exposure))
		write(string(f.Privilege))
		write(string(f.Sensitivity))
		write(string(f.Confidence))
		write(f.Fingerprint())
		write(strings.Join(f.Objects, "\x00"))
	}
	for _, s := range r.Secrets {
		write(s.Location)
		write(s.Fingerprint)
	}
	for _, id := range r.Identities {
		write(id.ID)
		write(id.Canonical)
	}
	for _, m := range r.Modules {
		write(m.ID)
		write(string(m.Status))
	}
	for _, l := range r.Limitations {
		write(l)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// RiskScore returns a finding's final risk score.
//
// The score is carried in Attributes as a formatted number because pkg/risk
// computes it and pkg/models cannot import pkg/risk without a cycle: the risk
// package's input type is built from these models. Reading it back here keeps
// the dependency in one direction and keeps the score's provenance visible in
// the report rather than in a field no JSON reader would think to check.
//
// A finding without a score is treated as zero rather than as an error, because
// a hand-constructed finding is legitimate input to a formatter and should not
// have to know the scoring contract to be printable.
func (f *Finding) RiskScore() int {
	if f.Attributes == nil {
		return 0
	}
	v, err := strconv.ParseFloat(f.Attributes["risk_score"], 64)
	if err != nil {
		return 0
	}
	return int(v)
}

// RiskBand returns the finding's risk band as the rules engine computed it.
func (f *Finding) RiskBand() string {
	if f.Attributes == nil {
		return ""
	}
	return f.Attributes["risk_band"]
}

// riskBandFor scores the band boundaries used for the summary.
//
// These are the same thresholds pkg/risk publishes. They are restated here
// rather than imported for the same reason RiskScore reads from Attributes: the
// dependency runs risk -> models, not the other way. The duplication is
// asserted against pkg/risk by TestRiskBandThresholdsMatchTheRiskPackage, so
// the two cannot drift apart silently.
var riskBandThresholds = []struct {
	Min  int
	Band string
}{
	{90, "critical"}, {75, "high"}, {55, "elevated"}, {35, "moderate"}, {15, "low"},
}

// RiskBandFor buckets a score, mirroring pkg/risk.BandFor.
func RiskBandFor(score int) string {
	if score < 0 {
		return "minimal"
	}
	for _, t := range riskBandThresholds {
		if score >= t.Min {
			return t.Band
		}
	}
	return "minimal"
}

// SortFindings orders findings the way a report presents them: highest risk
// first, then by module and rule so that two findings of equal risk do not
// swap places between runs.
//
// Determinism here is not cosmetic. A report whose order changes between runs
// produces a diff that is all noise, and a diff that is all noise is a diff
// nobody reads.
func SortFindings(in []Finding) {
	sort.SliceStable(in, func(i, j int) bool {
		a, b := in[i], in[j]
		if a.RiskScore() != b.RiskScore() {
			return a.RiskScore() > b.RiskScore()
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.ModuleID != b.ModuleID {
			return a.ModuleID < b.ModuleID
		}
		// The remaining comparisons are on content, never on the record ID. An
		// ID is random by construction, so using it as a tiebreak makes the
		// report order differ between two runs over identical data — which
		// turns every diff between two assessments into noise and defeats the
		// integrity stamp, since the digest is taken over an ordered list.
		if a.Title != b.Title {
			return a.Title < b.Title
		}
		if aj, bj := strings.Join(a.Objects, "\x00"), strings.Join(b.Objects, "\x00"); aj != bj {
			return aj < bj
		}
		return a.Fingerprint() < b.Fingerprint()
	})
}

// Summarize builds the summary block from a set of findings.
func Summarize(findings []Finding, identities []CorrelatedIdentity) Summary {
	s := Summary{
		BySeverity:    map[Severity]int{},
		ByCategory:    map[Category]int{},
		ByState:       map[State]int{},
		Total:         len(findings),
		IdentityCount: len(identities),
	}
	total, max := 0, 0
	for _, f := range findings {
		s.BySeverity[f.Severity]++
		s.ByCategory[f.Category]++
		s.ByState[f.State]++
		if f.Correlated {
			s.Correlated++
		}
		score := f.RiskScore()
		total += score
		if score > max {
			max = score
		}
	}
	if len(findings) > 0 {
		s.MeanRisk = total / len(findings)
	}
	s.MaxRisk = max
	s.RiskBand = RiskBandFor(max)
	return s
}

// NewReport starts a report with the fields that do not depend on collection.
func NewReport(target Target, depth int, depthName string) Report {
	return Report{
		Schema:        ReportSchema,
		Framework:     "amina",
		Target:        target,
		Depth:         depth,
		DepthName:     depthName,
		Redaction:     DefaultRedaction(),
		Configuration: map[string]string{},
		Summary:       Summary{BySeverity: map[Severity]int{}, ByCategory: map[Category]int{}, ByState: map[State]int{}},
	}
}

// Finalize sorts the report, builds its summary and stamps its integrity
// field. It must be the last step before writing, because anything added
// afterwards is outside the checksum.
func (r *Report) Finalize() {
	SortFindings(r.Findings)
	SortAssets(r.Assets)
	SortIdentitySignals(nil)
	sort.SliceStable(r.Modules, func(i, j int) bool { return r.Modules[i].ID < r.Modules[j].ID })
	sort.SliceStable(r.Secrets, func(i, j int) bool {
		if r.Secrets[i].Location != r.Secrets[j].Location {
			return r.Secrets[i].Location < r.Secrets[j].Location
		}
		return r.Secrets[i].Fingerprint < r.Secrets[j].Fingerprint
	})
	sort.SliceStable(r.Identities, func(i, j int) bool {
		if r.Identities[i].Strength != r.Identities[j].Strength {
			return r.Identities[i].Strength > r.Identities[j].Strength
		}
		return r.Identities[i].ID < r.Identities[j].ID
	})
	SortSoftware(r.Software)
	SortSources(r.Sources)
	r.Summary = Summarize(r.Findings, r.Identities)
	r.Integrity = r.ComputeIntegrity()
	// The ID is derived from the integrity stamp rather than drawn at random, so
	// that two assessments of the same host carry the same identifier. That is
	// what lets a reader diff reports, spot an unchanged host, and compare a
	// golden fixture against a live run: with random IDs nothing lines up.
	// The integrity digest deliberately excludes the ID, so deriving one from
	// the other cannot loop.
	if r.ID == "" {
		r.ID = "rep-" + strings.TrimPrefix(r.Integrity, "sha256:")[:24]
	}
}

func SortSoftware(in []Software) {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].Name != in[j].Name {
			return in[i].Name < in[j].Name
		}
		return in[i].Version < in[j].Version
	})
}

func SortSources(in []PackageSource) {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].Provider != in[j].Provider {
			return in[i].Provider < in[j].Provider
		}
		if in[i].URI != in[j].URI {
			return in[i].URI < in[j].URI
		}
		return in[i].ID < in[j].ID
	})
}

// Limitations extracts the honest-degradation statements from module statuses.
//
// These are the sentences that keep a report honest: a module that could not
// read what it needed says so here, so "no findings" is never read as "this
// host is clean" when the truth is "part of this host was not examined".
func Limitations(statuses []ModuleStatus) []string {
	var out []string
	for _, m := range statuses {
		switch m.Status {
		case ExposureSkipped:
			if m.Reason != "" {
				out = append(out, m.Name+": not assessed ("+m.Reason+")")
			} else {
				out = append(out, m.Name+": not assessed")
			}
		case ExposurePrivilege:
			out = append(out, m.Name+": requires privileges this run did not have")
		case ExposureDegraded, ExposurePartial:
			detail := m.Reason
			if len(m.Unavailable) > 0 {
				if detail != "" {
					detail += "; "
				}
				detail += "unavailable: " + strings.Join(m.Unavailable, ", ")
			}
			if detail == "" {
				detail = "some sources could not be read"
			}
			out = append(out, m.Name+": incomplete — "+detail)
		}
	}
	sort.Strings(out)
	return out
}
