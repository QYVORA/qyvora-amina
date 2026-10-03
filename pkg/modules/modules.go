// Package modules holds the assessment module registry and the runner that
// executes it.
//
// A module is one assessment domain: the specification names twenty-two of
// them, and each answers a different question about the host. The registry
// exists so that a module is not merely a function but a declared, documented
// unit with a stable ID, a spec section, a platform applicability and an
// honest status.
//
// The registry is also the mechanism that prevents a fake module. Every entry
// either has a collector that works, or is reported as not implemented, and a
// test enforces that correspondence. The specification is explicit about this
// (PROMPT.md, "Do not create fake modules"), and it matters for a security tool
// in a way it does not for most software: a module that reports "clean" when it
// never looked is worse than a module that reports nothing.
package modules

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/QYVORA/qyvora-amina/internal/platform"
	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// Module is one assessment domain.
type Module struct {
	// ID is the stable machine identifier. It appears in findings, in
	// ModuleStatus, and in the JSONL stream, so it is part of the contract.
	ID string
	// Name is the human label.
	Name string
	// Category is the finding taxonomy this module reports under.
	Category models.Category
	// SpecSection is the PROMPT.md section that specifies this domain. It is
	// recorded so a reader can check the implementation against its source.
	SpecSection int
	// Purpose is one sentence on what the module decides.
	Purpose string
	// Platforms lists the platforms where the module can do real work. A module
	// absent from this list reports unsupported on the others rather than
	// returning an empty result that reads as a clean host.
	Platforms []models.Platform
	// MinimumDepth is the shallowest depth at which the module runs. A deep
	// scan that reads every configuration file belongs at DepthDeep, not at
	// DepthQuick, where the operator asked for a fast answer.
	MinimumDepth int
	// Collect performs the collection. A nil Collect means the module is
	// declared but not yet implemented, and the runner reports it as such.
	Collect Collector
}

// Supports reports whether the module can do real work on a platform.
func (m Module) Supports(p models.Platform) bool {
	for _, have := range m.Platforms {
		if have == p {
			return true
		}
	}
	return false
}

// Implemented reports whether the module has a working collector.
func (m Module) Implemented() bool { return m.Collect != nil }

// Input is everything a collector is allowed to see.
//
// A collector receives the environment and the requested depth and nothing
// else. It cannot see another module's results, which keeps modules independent
// and makes the set of modules an explicit composition rather than an
// accumulating global.
type Input struct {
	Ctx    context.Context
	Env    *platform.Env
	Target models.Target
	Depth  int
}

// Result is what a collector found. Every field is optional; a module fills in
// only what it actually observed.
type Result struct {
	Accounts   []models.Account
	Interfaces []platform.Interface
	Sockets    []platform.Socket
	Processes  []platform.Process
	Services   []platform.Service
	Packages   []platform.PackageQuery
	Software   []models.Software
	Sources    []models.PackageSource
	Provenance []models.ProvenanceRecord
	Secrets    []models.SecretRecord
	Identities []models.IdentitySignal
	Assets     []models.Asset

	// Degraded marks the module as having run but not fully. A collector that
	// could read two of three sources sets Degraded and names them in
	// Unavailable, so the report can distinguish "nothing found" from "not
	// everything was looked at".
	Degraded bool
	// Unavailable names the capabilities that were missing.
	Unavailable []string
	// Note explains the degradation in words, for the report.
	Note string
}

// Collector is one module's collection step.
//
// Collect must be read-only. It must not write to the host, must not make
// network connections, and must not retain anything it was given. It returns
// an error only for a genuine failure; a capability that is merely absent is
// reported through Result.Degraded and Result.Unavailable, not as an error.
type Collector interface {
	Collect(Input) (Result, error)
}

// CollectorFunc adapts a function to the Collector interface.
type CollectorFunc func(Input) (Result, error)

func (f CollectorFunc) Collect(in Input) (Result, error) { return f(in) }

var allPosix = []models.Platform{
	models.PlatformLinux, models.PlatformDarwin, models.PlatformTermux,
}
var allDesktop = []models.Platform{
	models.PlatformLinux, models.PlatformDarwin, models.PlatformWindows, models.PlatformTermux,
}

// registry is the ordered list of assessment domains, in the order the
// specification introduces them. Order matters: it is the order modules run in,
// the order they appear in the report, and the order a reader meets them.
var registry = []Module{
	{
		ID:           "host-identity",
		Name:         "Host Identity",
		Category:     models.CategoryMetadata,
		SpecSection:  8,
		Purpose:      "Decide whether the machine's own identity disclosures name its operator.",
		Platforms:    allDesktop,
		MinimumDepth: rulesQuick,
		Collect:      CollectorFunc(collectHostIdentity),
	},
	{
		ID:           "accounts",
		Name:         "User and Account Audit",
		Category:     models.CategoryAccount,
		SpecSection:  9,
		Purpose:      "Decide which local accounts exist, which can log in, and which are left enabled.",
		Platforms:    allDesktop,
		MinimumDepth: rulesQuick,
		Collect:      CollectorFunc(collectAccounts),
	},
	{
		ID:           "remote-access",
		Name:         "SSH and Remote Access",
		Category:     models.CategoryRemoteAccess,
		SpecSection:  10,
		Purpose:      "Decide how the host can be reached from elsewhere and how strongly it authenticates.",
		Platforms:    allDesktop,
		MinimumDepth: rulesQuick,
		Collect:      CollectorFunc(collectRemoteAccess),
	},
	{
		ID:           "network",
		Name:         "Network Exposure",
		Category:     models.CategoryNetwork,
		SpecSection:  11,
		Purpose:      "Decide which services are reachable from outside this host and from where.",
		Platforms:    allDesktop,
		MinimumDepth: rulesQuick,
		Collect:      CollectorFunc(collectNetwork),
	},
	{
		ID:           "software",
		Name:         "Software Inventory",
		Category:     models.CategorySoftware,
		SpecSection:  12,
		Purpose:      "Decide what is installed and which of it discloses the operator's work or tools.",
		Platforms:    allDesktop,
		MinimumDepth: rulesQuick,
		Collect:      CollectorFunc(collectSoftware),
	},
	{
		ID:           "provenance",
		Name:         "Software Provenance",
		Category:     models.CategoryProvenance,
		SpecSection:  13,
		Purpose:      "Decide whether installed software is attributable to a package source.",
		Platforms:    allDesktop,
		MinimumDepth: rulesStandard,
		Collect:      CollectorFunc(collectProvenance),
	},
	{
		ID:           "binary-integrity",
		Name:         "Binary Integrity",
		Category:     models.CategoryIntegrity,
		SpecSection:  14,
		Purpose:      "Decide whether executables are signed, owned by a package, or unexplained.",
		Platforms:    allDesktop,
		MinimumDepth: rulesDeep,
		Collect:      CollectorFunc(collectBinaryIntegrity),
	},
	{
		ID:           "package-sources",
		Name:         "Package Source Audit",
		Category:     models.CategoryProvenance,
		SpecSection:  15,
		Purpose:      "Decide which repositories the host installs software from and which are unofficial.",
		Platforms:    allDesktop,
		MinimumDepth: rulesStandard,
		Collect:      CollectorFunc(collectPackageSources),
	},
	{
		ID:           "filesystem-exposure",
		Name:         "Filesystem Exposure",
		Category:     models.CategoryFilesystem,
		SpecSection:  16,
		Purpose:      "Decide what the filesystem layout reveals about the host and its operator.",
		Platforms:    allDesktop,
		MinimumDepth: rulesStandard,
		Collect:      CollectorFunc(collectFilesystemExposure),
	},
	{
		ID:           "secret-material",
		Name:         "Secret Detection",
		Category:     models.CategorySecrets,
		SpecSection:  17,
		Purpose:      "Decide which credentials exist on disk, without ever recording their values.",
		Platforms:    allDesktop,
		MinimumDepth: rulesStandard,
		Collect:      CollectorFunc(collectSecretMaterial),
	},
	{
		ID:           "shell-terminal",
		Name:         "Shell and Terminal Exposure",
		Category:     models.CategoryShell,
		SpecSection:  18,
		Purpose:      "Decide what shell configuration and terminal history disclose.",
		Platforms:    allPosix,
		MinimumDepth: rulesStandard,
		Collect:      CollectorFunc(collectShellTerminal),
	},
	{
		ID:           "environment",
		Name:         "Environment Variables",
		Category:     models.CategoryExposure,
		SpecSection:  19,
		Purpose:      "Decide which environment variables disclose identity, tokens or infrastructure names.",
		Platforms:    allDesktop,
		MinimumDepth: rulesQuick,
		Collect:      CollectorFunc(collectEnvironment),
	},
	{
		ID:           "developer-identity",
		Name:         "Git and Developer Identity",
		Category:     models.CategoryGit,
		SpecSection:  20,
		Purpose:      "Decide what developer tooling records about who wrote the code.",
		Platforms:    allDesktop,
		MinimumDepth: rulesStandard,
		Collect:      CollectorFunc(collectDeveloperIdentity),
	},
	{
		ID:           "cloud-identity",
		Name:         "Cloud and Infrastructure Identity",
		Category:     models.CategoryCloud,
		SpecSection:  21,
		Purpose:      "Decide which cloud accounts, subscriptions and instance identities are configured.",
		Platforms:    allDesktop,
		MinimumDepth: rulesStandard,
		Collect:      CollectorFunc(collectCloudIdentity),
	},
	{
		ID:           "process-service",
		Name:         "Process and Service Audit",
		Category:     models.CategoryProcess,
		SpecSection:  22,
		Purpose:      "Decide what is running, under which identity, and listening for work.",
		Platforms:    allDesktop,
		MinimumDepth: rulesStandard,
		Collect:      CollectorFunc(collectProcessService),
	},
	{
		ID:           "persistence",
		Name:         "Persistence and Startup",
		Category:     models.CategoryPersistence,
		SpecSection:  23,
		Purpose:      "Decide what will run again after a reboot or login without anyone choosing it.",
		Platforms:    allDesktop,
		MinimumDepth: rulesDeep,
		Collect:      CollectorFunc(collectPersistence),
	},
	{
		ID:           "tooling",
		Name:         "Development and Security Tooling",
		Category:     models.CategoryTooling,
		SpecSection:  24,
		Purpose:      "Decide which security and development tools disclose their presence or their history.",
		Platforms:    allDesktop,
		MinimumDepth: rulesStandard,
		Collect:      CollectorFunc(collectTooling),
	},
	{
		ID:           "artifacts-logs",
		Name:         "Logging and Local Artifacts",
		Category:     models.CategoryLogging,
		SpecSection:  25,
		Purpose:      "Decide what local logs and artifacts accumulate and who can read them.",
		Platforms:    allDesktop,
		MinimumDepth: rulesStandard,
		Collect:      CollectorFunc(collectArtifacts),
	},
	{
		ID:           "browser-apps",
		Name:         "Browser and User Application Exposure",
		Category:     models.CategoryPrivacy,
		SpecSection:  26,
		Purpose:      "Decide what user application data directories disclose by existing at all.",
		Platforms:    allDesktop,
		MinimumDepth: rulesStandard,
		Collect:      CollectorFunc(collectBrowserApps),
	},
	{
		ID:           "os-posture",
		Name:         "OS Security Posture",
		Category:     models.CategoryConfiguration,
		SpecSection:  27,
		Purpose:      "Decide which host hardening settings would change the outcome of the other findings.",
		Platforms:    allDesktop,
		MinimumDepth: rulesStandard,
		Collect:      CollectorFunc(collectOSPosture),
	},
	{
		ID:           "file-permissions",
		Name:         "File Permissions",
		Category:     models.CategoryFilesystem,
		SpecSection:  28,
		Purpose:      "Decide which sensitive files are readable or writable by accounts that should not reach them.",
		Platforms:    allDesktop,
		MinimumDepth: rulesStandard,
		Collect:      CollectorFunc(collectFilePermissions),
	},
	{
		ID:           "temp-cache",
		Name:         "Temporary and Cache Data",
		Category:     models.CategoryPrivacy,
		SpecSection:  29,
		Purpose:      "Decide what survives in temporary directories that nobody intends to keep.",
		Platforms:    allDesktop,
		MinimumDepth: rulesStandard,
		Collect:      CollectorFunc(collectTempCache),
	},
	{
		ID:           "metadata",
		Name:         "Metadata Exposure",
		Category:     models.CategoryMetadata,
		SpecSection:  30,
		Purpose:      "Decide what file and document metadata carries that the filenames do not.",
		Platforms:    allDesktop,
		MinimumDepth: rulesDeep,
		Collect:      CollectorFunc(collectMetadata),
	},
}

// Depth constants, restated here so the registry does not import the rules
// package. The values are the framework's published depths.
const (
	rulesQuick    = 1
	rulesStandard = 2
	rulesDeep     = 3
)

// All returns every registered module in specification order.
func All() []Module {
	out := make([]Module, len(registry))
	copy(out, registry)
	return out
}

// ByID returns a module by its identifier.
func ByID(id string) (Module, bool) {
	for _, m := range registry {
		if m.ID == id {
			return m, true
		}
	}
	return Module{}, false
}

// IsKnown reports whether id names a registered module.
//
// The configuration package validates --include and --exclude against this
// without importing this package, so that a misspelled module name is reported
// as a usage error instead of quietly producing an empty assessment.
func IsKnown(id string) bool {
	_, ok := ByID(id)
	return ok
}

// IDs returns every module identifier in specification order.
func IDs() []string {
	out := make([]string, 0, len(registry))
	for _, m := range registry {
		out = append(out, m.ID)
	}
	return out
}

// platformSummary renders a module's platform list for the capability report.
func platformSummary(p []models.Platform) string {
	names := make([]string, 0, len(p))
	for _, x := range p {
		names = append(names, string(x))
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

var _ = fmt.Sprintf
var _ = platformSummary
