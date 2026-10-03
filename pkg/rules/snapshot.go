package rules

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-amina/internal/platform"
	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// Snapshot is everything the collectors observed, in one immutable value.
//
// It is a plain struct rather than an interface with twenty methods: rules read
// it directly, so every field a rule touches is visible in the type, and adding
// a collector is a matter of adding a field here rather than extending an
// interface every rule would then depend on.
//
// Every field may be empty. Empty means "not observed", and rules are required
// to distinguish that from "observed and empty" — a collector that could not
// read something leaves the slice empty and records a degraded support level,
// which is why the Capability levels below travel with the data.
type Snapshot struct {
	Target      models.Target
	Env         *platform.Env
	CollectedAt time.Time
	Depth       int

	Accounts   []models.Account
	Sockets    []platform.Socket
	Interfaces []platform.Interface
	Processes  []platform.Process
	Services   []platform.Service
	Packages   []platform.PackageQuery
	Software   []models.Software
	Sources    []models.PackageSource
	Provenance []models.ProvenanceRecord
	Secrets    []models.SecretRecord
	Identities []models.IdentitySignal
	Assets     []models.Asset
	Findings   []models.Finding
	Correlated []models.CorrelatedIdentity

	// ModuleStatus is how each collector reports what it managed to do.
	ModuleStatus []models.ModuleStatus

	// Remote is set when the snapshot describes a remote target rather than the
	// local host. Rules that reason about local-only state check it rather than
	// assuming local access, because a report about a remote box that silently
	// contains local-host observations is worse than no report.
	Remote bool
	// RemoteNote explains what a remote assessment could not observe.
	RemoteNote string
}

// Capability returns the support level recorded for a capability, or
// SupportNone when no module reported it.
func (s *Snapshot) Capability(cap string) models.SupportLevel {
	if s == nil {
		return models.SupportNone
	}
	for _, m := range s.ModuleStatus {
		if m.ID == cap {
			return exposureToSupport(m.Status)
		}
	}
	return models.SupportNone
}

func exposureToSupport(e models.ExposureLevel) models.SupportLevel {
	switch e {
	case models.ExposureComplete:
		return models.SupportFull
	case models.ExposurePartial, models.ExposureDegraded:
		return models.SupportPartial
	case models.ExposurePrivilege:
		return models.SupportPrivilege
	case models.ExposureSkipped:
		return models.SupportNone
	default:
		return models.SupportLimited
	}
}

// HasCapability reports whether a capability produced usable data. Rules gate
// on this rather than on slice length, because a capability that ran and found
// nothing is a different state from one that never ran.
func (s *Snapshot) HasCapability(cap string) bool { return s.Capability(cap).Works() }

// AccountByName returns an account by exact name.
func (s *Snapshot) AccountByName(name string) (models.Account, bool) {
	for _, a := range s.Accounts {
		if a.Name == name {
			return a, true
		}
	}
	return models.Account{}, false
}

// WorldBoundSockets returns the sockets bound to a wildcard address, which are
// the only ones reachable from beyond this host.
//
// This is the single most important filter in the network rules. Presenting a
// loopback listener as network exposure is the classic false positive of every
// port scanner, and it is the failure Amina's scope model exists to prevent.
func (s *Snapshot) WorldBoundSockets() []platform.Socket {
	var out []platform.Socket
	for _, sock := range s.Sockets {
		if sock.Scope == models.ScopeWildcard || sock.Scope == models.ScopePublic {
			out = append(out, sock)
		}
	}
	return out
}

// SortedSecrets orders secrets deterministically, most exposed first, so that
// two runs on an unchanged host produce an identical report.
func (s *Snapshot) SortedSecrets() []models.SecretRecord {
	out := make([]models.SecretRecord, len(s.Secrets))
	copy(out, s.Secrets)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Location != out[j].Location {
			return out[i].Location < out[j].Location
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}

// Builder incrementally assembles a Snapshot from collector results. Collectors
// cannot construct a Snapshot directly because each one only produces part of
// it, and letting each construct a whole one would mean twenty competing
// definitions of the same struct.
type Builder struct {
	snap Snapshot
	ctx  context.Context
}

// NewBuilder starts a snapshot for a target at a depth.
func NewBuilder(ctx context.Context, target models.Target, depth int) *Builder {
	return &Builder{
		ctx: ctx,
		snap: Snapshot{
			Target:      target,
			Depth:       depth,
			CollectedAt: time.Now().UTC(),
		},
	}
}

// WithEnv attaches the detected platform environment.
func (b *Builder) WithEnv(e *platform.Env) *Builder { b.snap.Env = e; return b }

// WithAccounts attaches collected accounts.
func (b *Builder) WithAccounts(a []models.Account) *Builder { b.snap.Accounts = a; return b }

// WithSockets attaches enumerated sockets.
func (b *Builder) WithSockets(s []platform.Socket) *Builder { b.snap.Sockets = s; return b }

// WithInterfaces attaches enumerated interfaces.
func (b *Builder) WithInterfaces(i []platform.Interface) *Builder {
	b.snap.Interfaces = i
	return b
}

// WithProcesses attaches the process table.
func (b *Builder) WithProcesses(p []platform.Process) *Builder {
	b.snap.Processes = p
	return b
}

// WithServices attaches managed services.
func (b *Builder) WithServices(s []platform.Service) *Builder { b.snap.Services = s; return b }

// WithPackages attaches the package inventory.
func (b *Builder) WithPackages(p []platform.PackageQuery) *Builder {
	b.snap.Packages = p
	return b
}

// WithSoftware attaches installed software records.
func (b *Builder) WithSoftware(s []models.Software) *Builder { b.snap.Software = s; return b }

// WithSources attaches configured package sources.
func (b *Builder) WithSources(s []models.PackageSource) *Builder {
	b.snap.Sources = s
	return b
}

// WithProvenance attaches provenance verdicts.
func (b *Builder) WithProvenance(p []models.ProvenanceRecord) *Builder {
	b.snap.Provenance = p
	return b
}

// WithSecrets attaches secret records.
func (b *Builder) WithSecrets(s []models.SecretRecord) *Builder {
	b.snap.Secrets = s
	return b
}

// WithIdentities attaches identity signals.
func (b *Builder) WithIdentities(s []models.IdentitySignal) *Builder {
	b.snap.Identities = s
	return b
}

// WithAssets attaches inventory assets.
func (b *Builder) WithAssets(a []models.Asset) *Builder { b.snap.Assets = a; return b }

// WithCorrelated attaches correlation results.
func (b *Builder) WithCorrelated(c []models.CorrelatedIdentity) *Builder {
	b.snap.Correlated = c
	return b
}

// WithModuleStatus attaches per-module outcome records.
func (b *Builder) WithModuleStatus(m []models.ModuleStatus) *Builder {
	b.snap.ModuleStatus = m
	return b
}

// WithRemote marks the snapshot as describing a remote target.
func (b *Builder) WithRemote(note string) *Builder {
	b.snap.Remote = true
	b.snap.RemoteNote = note
	return b
}

// WithFindings attaches findings already raised by collectors.
func (b *Builder) WithFindings(f []models.Finding) *Builder {
	b.snap.Findings = f
	return b
}

// At pins the collection timestamp, for reproducible simulation output.
func (b *Builder) At(t time.Time) *Builder { b.snap.CollectedAt = t.UTC(); return b }

// Build normalises ordering and returns the snapshot.
func (b *Builder) Build() Snapshot {
	s := b.snap
	models.SortAssets(s.Assets)
	models.SortIdentitySignals(s.Identities)
	platform.SortPackages(s.Packages)
	platform.SortServices(s.Services)
	if s.CollectedAt.IsZero() {
		s.CollectedAt = time.Now().UTC()
	}
	return s
}

// DefaultDepths names the three documented scan depths. Rules gate on these
// through MinimumDepth, so `--depth quick` can skip expensive sweeps without
// the report claiming they found nothing.
const (
	DepthQuick    = 1
	DepthStandard = 2
	DepthDeep     = 3
)

// DepthNames maps the numeric depth to its published name.
var DepthNames = map[int]string{
	DepthQuick:    "quick",
	DepthStandard: "standard",
	DepthDeep:     "deep",
}

// DepthName returns the published name for a depth, or "unknown".
func DepthName(d int) string {
	if n, ok := DepthNames[d]; ok {
		return n
	}
	return "unknown"
}

// ParseDepth converts a case-insensitive depth name to its number.
func ParseDepth(s string) (int, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "quick", "fast", "1":
		return DepthQuick, true
	case "standard", "default", "normal", "2":
		return DepthStandard, true
	case "deep", "full", "thorough", "3":
		return DepthDeep, true
	}
	return 0, false
}
