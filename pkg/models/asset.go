package models

import (
	"sort"
	"strings"
	"time"
)

// AssetKind classifies what a collector observed. The kinds mirror the
// assessment domains, so a report can group by domain without re-deriving
// meaning from a finding title.
type AssetKind string

const (
	KindHostIdentity     AssetKind = "host_identity"
	KindAccount          AssetKind = "account"
	KindRemoteAccess     AssetKind = "remote_access"
	KindNetworkInterface AssetKind = "network_interface"
	KindListeningSocket  AssetKind = "listening_socket"
	KindRoute            AssetKind = "route"
	KindSoftware         AssetKind = "software"
	KindPackageSource    AssetKind = "package_source"
	KindProvenance       AssetKind = "provenance"
	KindFileExposure     AssetKind = "file_exposure"
	KindSecret           AssetKind = "secret"
	KindShellConfig      AssetKind = "shell_config"
	KindEnvironment      AssetKind = "environment"
	KindGitIdentity      AssetKind = "git_identity"
	KindCloudIdentity    AssetKind = "cloud_identity"
	KindProcess          AssetKind = "process"
	KindService          AssetKind = "service"
	KindPersistence      AssetKind = "persistence"
	KindTooling          AssetKind = "tooling"
	KindArtifact         AssetKind = "artifact"
	KindPosture          AssetKind = "posture"
	KindApplication      AssetKind = "application"
	KindIdentitySignal   AssetKind = "identity_signal"
)

// AssetKinds lists every asset kind in documentation order.
var AssetKinds = []AssetKind{
	KindHostIdentity, KindAccount, KindRemoteAccess, KindNetworkInterface,
	KindListeningSocket, KindRoute, KindSoftware, KindPackageSource,
	KindProvenance, KindFileExposure, KindSecret, KindShellConfig,
	KindEnvironment, KindGitIdentity, KindCloudIdentity, KindProcess,
	KindService, KindPersistence, KindTooling, KindArtifact, KindPosture,
	KindApplication, KindIdentitySignal,
}

// Asset is one observed thing. Attributes carry the kind-specific detail; the
// typed fields carry what the framework needs regardless of kind, so a generic
// report and the correlation engine can both read every asset.
type Asset struct {
	ID         string            `json:"id"`
	Kind       AssetKind         `json:"kind"`
	Domain     string            `json:"domain"`
	Name       string            `json:"name"`
	Path       string            `json:"path,omitempty"`
	Platform   Platform          `json:"platform"`
	Support    SupportLevel      `json:"support"`
	Source     string            `json:"source"`
	Exposure   ExposureScope     `json:"exposure,omitempty"`
	Privilege  Privilege         `json:"privilege,omitempty"`
	Tags       []string          `json:"tags,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Timestamp  time.Time         `json:"timestamp"`
}

// Set stores a named attribute. Setting the same key twice keeps the last
// value, which is what lets a collector layer refinement onto a shared record.
func (a *Asset) Set(key, value string) {
	if a.Attributes == nil {
		a.Attributes = map[string]string{}
	}
	a.Attributes[key] = value
}

// Attr returns a named attribute.
func (a *Asset) Attr(key string) string {
	if a == nil || a.Attributes == nil {
		return ""
	}
	return a.Attributes[key]
}

// Label returns the most useful human-readable identifier for the asset.
func (a *Asset) Label() string {
	switch {
	case a == nil:
		return "<nil>"
	case a.Path != "":
		return a.Path
	case a.Name != "":
		return a.Name
	default:
		return a.Domain
	}
}

// Account is a local or domain identity on the assessed host.
type Account struct {
	Name           string                `json:"name"`
	UID            string                `json:"uid,omitempty"`
	GID            string                `json:"gid,omitempty"`
	Groups         []string              `json:"groups,omitempty"`
	Shell          string                `json:"shell,omitempty"`
	Home           string                `json:"home,omitempty"`
	GECOS          string                `json:"gecos,omitempty"`
	Privileged     bool                  `json:"privileged"`
	Service        bool                  `json:"service"`
	Locked         bool                  `json:"locked"`
	NoLogin        bool                  `json:"no_login"`
	LastLogin      time.Time             `json:"last_login,omitempty"`
	Classification AccountClassification `json:"classification"`
	Reason         string                `json:"reason,omitempty"`
	AuthorizedKeys int                   `json:"authorized_keys,omitempty"`
	Source         string                `json:"source"`
}

// IdentitySignal is one operator-identity observation from any module. The
// correlation engine's entire input is a flat list of these, which is why a
// hostname observed by the network module and the same hostname observed by
// the shell module collapse into one correlated exposure.
type IdentitySignal struct {
	Type     string    `json:"type"`  // username, hostname, email, home, remote, org, account, key_comment
	Value    string    `json:"value"` // already redacted if secret-shaped
	Source   string    `json:"source"`
	Domain   string    `json:"domain"`
	Module   string    `json:"module_id"`
	Redacted bool      `json:"redacted,omitempty"`
	At       time.Time `json:"at"`
}

// CorrelatedIdentity is the output of correlation: several identity signals
// that resolve to one operator, reported as a single exposure rather than as
// independent warnings.
type CorrelatedIdentity struct {
	ID          string           `json:"id"`
	Canonical   string           `json:"canonical"`
	Strength    int              `json:"strength"` // 0..100
	SignalCount int              `json:"signal_count"`
	Signals     []IdentitySignal `json:"signals"`
	Sources     []string         `json:"sources"`
	Domains     []string         `json:"domains"`
	Summary     string           `json:"summary"`
}

// SecretRecord is a detected secret. It deliberately has no Value field: the
// collector computes the fingerprint and drops the value before the record is
// constructed, so a SecretRecord is incapable of leaking.
type SecretRecord struct {
	Type        SecretType `json:"type"`
	Location    string     `json:"location"`
	Line        int        `json:"line,omitempty"`
	Field       string     `json:"field,omitempty"`
	Fingerprint string     `json:"fingerprint"`
	Length      int        `json:"length"`
	Source      string     `json:"source"`
	Redaction   Redaction  `json:"redaction"`
}

// Software is an installed program, attributed to the package ecosystem that
// installed it (or explicitly unattributed).
type Software struct {
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	Arch      string `json:"arch,omitempty"`
	Provider  string `json:"provider"`
	Source    string `json:"source,omitempty"`
	Path      string `json:"path,omitempty"`
	SizeBytes int64  `json:"size_bytes,omitempty"`
	Installed bool   `json:"installed"`
	Origin    string `json:"origin"` // official | third_party | local | unknown | unavailable
}

// PackageSource is a configured repository or installation source.
type PackageSource struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Kind     string `json:"kind"`
	URI      string `json:"uri,omitempty"`
	Trust    string `json:"trust"` // official | third_party | unsigned | unknown
	Keys     int    `json:"keys"`
	Enabled  bool   `json:"enabled"`
	Note     string `json:"note,omitempty"`
}

// ProvenanceRecord is the conclusion about one executable file: where it came
// from and whether its integrity could be established.
type ProvenanceRecord struct {
	Path           string          `json:"path"`
	State          ProvenanceState `json:"state"`
	PackageOwner   string          `json:"package_owner,omitempty"`
	PackageVersion string          `json:"package_version,omitempty"`
	Publisher      string          `json:"publisher,omitempty"`
	Certificate    string          `json:"certificate,omitempty"`
	SHA256         string          `json:"sha256,omitempty"`
	SizeBytes      int64           `json:"size_bytes,omitempty"`
	Format         string          `json:"format,omitempty"`
	Machine        string          `json:"machine,omitempty"`
	Interpreter    string          `json:"interpreter,omitempty"`
	Modified       bool            `json:"modified,omitempty"`
	Source         string          `json:"source"`
	Note           string          `json:"note,omitempty"`
}

// ExposureLevel describes how a module executed on this host. It is the
// honest-degradation channel: a module that could not read what it needed says
// so here rather than reporting zero findings as though the host were clean.
type ExposureLevel string

const (
	ExposureComplete  ExposureLevel = "complete"
	ExposurePartial   ExposureLevel = "partial"
	ExposureDegraded  ExposureLevel = "degraded"
	ExposurePrivilege ExposureLevel = "requires_privilege"
	ExposureSkipped   ExposureLevel = "skipped"
)

// ModuleStatus is one module's result within a run.
type ModuleStatus struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Domain      string        `json:"domain"`
	Status      ExposureLevel `json:"status"`
	Assets      int           `json:"assets"`
	Findings    int           `json:"findings"`
	DurationMS  int64         `json:"duration_ms"`
	Reason      string        `json:"reason,omitempty"`
	Unavailable []string      `json:"unavailable,omitempty"` // capability IDs unavailable here
}

// SortAssets orders assets by kind then name, so any collection order produces
// byte-identical simulation output.
func SortAssets(in []Asset) {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].Kind != in[j].Kind {
			return in[i].Kind < in[j].Kind
		}
		if in[i].Name != in[j].Name {
			return in[i].Name < in[j].Name
		}
		return in[i].Path < in[j].Path
	})
}

// SortIdentitySignals orders signals by type, then value, so correlation is
// deterministic regardless of collection order.
func SortIdentitySignals(in []IdentitySignal) {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].Type != in[j].Type {
			return in[i].Type < in[j].Type
		}
		return in[i].Value < in[j].Value
	})
}

// Unique returns the distinct values of s in first-seen order. Package lists,
// listening sockets and tool inventories all use it so an asset is reported
// once no matter how many collectors saw it.
func Unique(s []string) []string {
	seen := make(map[string]bool, len(s))
	out := make([]string, 0, len(s))
	for _, v := range s {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// NormalizeToken lowercases and trims an identifier for comparison. Identity
// correlation depends on "amina" and "AMINA" being the same operator, but must
// not conflate "amina" with "amina-workstation".
func NormalizeToken(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}
