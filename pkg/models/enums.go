package models

import "strings"

// Severity describes the security or operational impact of a finding.
type Severity string

const (
	SeverityCritical      Severity = "critical"
	SeverityHigh          Severity = "high"
	SeverityMedium        Severity = "medium"
	SeverityLow           Severity = "low"
	SeverityInformational Severity = "informational"
)

// Severities lists every severity in descending order of impact.
var Severities = []Severity{
	SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInformational,
}

// ParseSeverity converts a case-insensitive string into a Severity, defaulting
// to informational for unknown values.
func ParseSeverity(s string) Severity {
	switch Severity(strings.ToLower(strings.TrimSpace(s))) {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow:
		return Severity(strings.ToLower(strings.TrimSpace(s)))
	default:
		return SeverityInformational
	}
}

// Weights maps a Severity to a 0..4 impact weight used by the risk engine.
func (s Severity) Weights() int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// Rank orders severities so a finding can escalate but never be downgraded by
// a weaker observation of the same issue.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInformational:
		return 1
	default:
		return 0
	}
}

// Confidence expresses how sure the framework is about a finding.
type Confidence string

const (
	ConfidenceConfirmed   Confidence = "confirmed"    // direct authoritative record or independent sources agree
	ConfidenceObserved    Confidence = "observed"     // seen in at least one primary source
	ConfidenceProbable    Confidence = "probable"     // strong but not direct evidence
	ConfidencePossible    Confidence = "possible"     // weak or single-source inference
	ConfidenceUnknown     Confidence = "unknown"      // insufficient information
	ConfidenceNotObserved Confidence = "not_observed" // explicit absence of observation
)

// Confidences lists every confidence level in descending order of certainty.
var Confidences = []Confidence{
	ConfidenceConfirmed, ConfidenceObserved, ConfidenceProbable,
	ConfidencePossible, ConfidenceUnknown, ConfidenceNotObserved,
}

// ParseConfidence converts a case-insensitive string into a Confidence.
func ParseConfidence(s string) Confidence {
	switch Confidence(strings.ToLower(strings.TrimSpace(s))) {
	case ConfidenceConfirmed, ConfidenceObserved, ConfidenceProbable,
		ConfidencePossible, ConfidenceUnknown, ConfidenceNotObserved:
		return Confidence(strings.ToLower(strings.TrimSpace(s)))
	default:
		return ConfidenceUnknown
	}
}

// Rank orders confidence values: confirmed > observed > probable > possible >
// unknown > not_observed. Zero means the value is invalid.
func (c Confidence) Rank() int {
	switch c {
	case ConfidenceConfirmed:
		return 6
	case ConfidenceObserved:
		return 5
	case ConfidenceProbable:
		return 4
	case ConfidencePossible:
		return 3
	case ConfidenceUnknown:
		return 2
	case ConfidenceNotObserved:
		return 1
	default:
		return 0
	}
}

// RiskLevel rates the operational risk of a collection or analysis step.
type RiskLevel string

const (
	RiskS1 RiskLevel = "S1" // read-only, reversible, low impact
	RiskS2 RiskLevel = "S2" // read-only, may read privileged local state
	RiskS3 RiskLevel = "S3" // state-changing but bounded and reversible
	RiskS4 RiskLevel = "S4" // destructive / irreversible
)

// NoiseLevel defines the OPSEC footprint of an operation
type NoiseLevel string

const (
	NoiseLevelPassive    NoiseLevel = "passive"    // No active probing, analysis only
	NoiseLevelLow        NoiseLevel = "low"        // Minimal interaction, basic enumeration
	NoiseLevelModerate   NoiseLevel = "moderate"   // Active testing, noticeable
	NoiseLevelAggressive NoiseLevel = "aggressive" // Exploitation attempts, highly visible
)

// Rank orders risk levels.
func (r RiskLevel) Rank() int {
	switch r {
	case RiskS1:
		return 1
	case RiskS2:
		return 2
	case RiskS3:
		return 3
	case RiskS4:
		return 4
	default:
		return 0
	}
}

// RequiresConfirmation reports whether an operation of this risk class demands
// explicit interactive confirmation before it may run.
//
// Amina declares every implemented operation read-only, so no S3/S4 operation
// exists and the predicate always returns false in practice. It is retained
// because the safety model is part of the published capability contract and
// downstream orchestrators switch on it.
func (r RiskLevel) RequiresConfirmation() bool { return r == RiskS3 || r == RiskS4 }

// Category is the finding taxonomy. Every rule declares exactly one category,
// and the risk engine derives exposure from it, so the taxonomy is part of the
// scoring contract rather than free-form labelling.
type Category string

const (
	CategoryIdentity       Category = "identity"
	CategoryAccount        Category = "account"
	CategoryAuthentication Category = "authentication"
	CategoryRemoteAccess   Category = "remote_access"
	CategoryNetwork        Category = "network"
	CategorySoftware       Category = "software"
	CategoryProvenance     Category = "provenance"
	CategoryIntegrity      Category = "integrity"
	CategoryFilesystem     Category = "filesystem"
	CategorySecrets        Category = "secrets"
	CategoryCredentials    Category = "credentials"
	CategoryShell          Category = "shell"
	CategoryGit            Category = "git"
	CategoryCloud          Category = "cloud"
	CategoryProcess        Category = "process"
	CategoryService        Category = "service"
	CategoryPersistence    Category = "persistence"
	CategoryLogging        Category = "logging"
	CategoryMetadata       Category = "metadata"
	CategoryPrivacy        Category = "privacy"
	CategoryConfiguration  Category = "configuration"
	CategoryTooling        Category = "tooling"
	CategoryExposure       Category = "exposure"
)

// Categories lists the complete finding taxonomy in documentation order.
var Categories = []Category{
	CategoryIdentity, CategoryAccount, CategoryAuthentication, CategoryRemoteAccess,
	CategoryNetwork, CategorySoftware, CategoryProvenance, CategoryIntegrity,
	CategoryFilesystem, CategorySecrets, CategoryCredentials, CategoryShell,
	CategoryGit, CategoryCloud, CategoryProcess, CategoryService,
	CategoryPersistence, CategoryLogging, CategoryMetadata, CategoryPrivacy,
	CategoryConfiguration, CategoryTooling, CategoryExposure,
}

// ParseCategory converts a case-insensitive string into a Category, returning
// false when the value is outside the taxonomy.
func ParseCategory(s string) (Category, bool) {
	want := Category(strings.ToLower(strings.TrimSpace(s)))
	for _, c := range Categories {
		if c == want {
			return c, true
		}
	}
	return Category(""), false
}

// Valid reports whether c is a member of the taxonomy.
func (c Category) Valid() bool {
	_, ok := ParseCategory(string(c))
	return ok
}

// Platform is a supported operating-system family. Termux is modelled
// separately from Linux because Android's userspace has no conventional
// account, service or boot model, and pretending otherwise is precisely the
// failure mode this framework exists to avoid.
type Platform string

const (
	PlatformLinux   Platform = "linux"
	PlatformWindows Platform = "windows"
	PlatformDarwin  Platform = "darwin"
	PlatformTermux  Platform = "termux"
)

// Platforms lists every platform this framework supports.
var Platforms = []Platform{PlatformLinux, PlatformWindows, PlatformDarwin, PlatformTermux}

// ParsePlatform converts a case-insensitive string into a Platform.
func ParsePlatform(s string) (Platform, bool) {
	want := Platform(strings.ToLower(strings.TrimSpace(s)))
	for _, p := range Platforms {
		if p == want {
			return p, true
		}
	}
	return Platform(""), false
}

// Label returns the human-readable platform name used in reports.
func (p Platform) Label() string {
	switch p {
	case PlatformLinux:
		return "Linux"
	case PlatformWindows:
		return "Windows"
	case PlatformDarwin:
		return "macOS"
	case PlatformTermux:
		return "Termux/Android"
	default:
		return string(p)
	}
}

// SupportLevel is a runtime-reported capability level. Amina deliberately
// reports what it can actually observe rather than a flat yes/no, because the
// same capability is full, partial, degraded or absent depending on privilege
// and platform, and a binary answer would be a lie in three of those cases.
type SupportLevel string

const (
	// SupportFull means the capability was exercised and returned complete data.
	SupportFull SupportLevel = "full"
	// SupportPartial means the capability returned data with documented gaps.
	SupportPartial SupportLevel = "partial"
	// SupportLimited means the capability ran but only in a reduced form.
	SupportLimited SupportLevel = "limited"
	// SupportPrivilege means the capability needs elevation this run did not have.
	SupportPrivilege SupportLevel = "requires_privilege"
	// SupportNone means the capability does not exist on this platform.
	SupportNone SupportLevel = "unavailable"
)

// SupportLevels lists every support level in decreasing capability order.
var SupportLevels = []SupportLevel{
	SupportFull, SupportPartial, SupportLimited, SupportPrivilege, SupportNone,
}

// Rank orders support levels so the weakest observed level wins when a
// capability is reported by several modules.
func (s SupportLevel) Rank() int {
	switch s {
	case SupportFull:
		return 5
	case SupportPartial:
		return 4
	case SupportLimited:
		return 3
	case SupportPrivilege:
		return 2
	case SupportNone:
		return 1
	default:
		return 0
	}
}

// Works reports whether the capability returned usable data.
func (s SupportLevel) Works() bool {
	return s == SupportFull || s == SupportPartial || s == SupportLimited
}

// ParseSupportLevel converts a case-insensitive string into a SupportLevel.
func ParseSupportLevel(s string) SupportLevel {
	switch SupportLevel(strings.ToLower(strings.TrimSpace(s))) {
	case SupportFull:
		return SupportFull
	case SupportPartial:
		return SupportPartial
	case SupportLimited:
		return SupportLimited
	case SupportPrivilege:
		return SupportPrivilege
	case SupportNone:
		return SupportNone
	default:
		return SupportNone
	}
}

// AccountClassification is the evidence-based label attached to an account.
// Amina never calls an account malicious for being unfamiliar: "unknown" means
// "no baseline exists to compare against", which is a statement about the
// framework's knowledge, not about the account.
type AccountClassification string

const (
	AccountUnknown       AccountClassification = "unknown"
	AccountUnexpected    AccountClassification = "unexpected"
	AccountUnusual       AccountClassification = "unusual"
	AccountPrivileged    AccountClassification = "privileged"
	AccountExposed       AccountClassification = "exposed"
	AccountMisconfigured AccountClassification = "misconfigured"
	AccountService       AccountClassification = "service"
	AccountDormant       AccountClassification = "dormant"
	AccountStandard      AccountClassification = "standard"
)

// AccountClassifications lists every account classification.
var AccountClassifications = []AccountClassification{
	AccountUnknown, AccountUnexpected, AccountUnusual, AccountPrivileged,
	AccountExposed, AccountMisconfigured, AccountService, AccountDormant,
	AccountStandard,
}

// ParseAccountClassification converts a case-insensitive string, falling back to
// AccountUnknown for values outside the vocabulary.
func ParseAccountClassification(s string) AccountClassification {
	want := AccountClassification(strings.ToLower(strings.TrimSpace(s)))
	for _, c := range AccountClassifications {
		if c == want {
			return c
		}
	}
	return AccountUnknown
}

// ProvenanceState is what can honestly be concluded about a piece of software.
// The vocabulary deliberately separates "signed", "verified" and "package-owned",
// which are frequently conflated: a signed binary from an unowned directory is
// still unattributable, and a package-owned binary is only "verified" if the
// package manager's own verification actually passed.
type ProvenanceState string

const (
	ProvVerified         ProvenanceState = "verified"
	ProvSigned           ProvenanceState = "signed"
	ProvSignatureInvalid ProvenanceState = "signature_invalid"
	ProvUnsigned         ProvenanceState = "unsigned"
	ProvHashMismatch     ProvenanceState = "hash_mismatch"
	ProvPackageOwned     ProvenanceState = "package_owned"
	ProvUnowned          ProvenanceState = "unowned"
	ProvUnknownOrigin    ProvenanceState = "unknown_origin"
	ProvLocallyModified  ProvenanceState = "locally_modified"
	ProvUnverifiable     ProvenanceState = "unverifiable"
)

// ProvenanceStates lists every provenance conclusion.
var ProvenanceStates = []ProvenanceState{
	ProvVerified, ProvSigned, ProvSignatureInvalid, ProvUnsigned,
	ProvHashMismatch, ProvPackageOwned, ProvUnowned, ProvUnknownOrigin,
	ProvLocallyModified, ProvUnverifiable,
}

// ParseProvenanceState converts a case-insensitive string, falling back to
// ProvUnknownOrigin.
func ParseProvenanceState(s string) ProvenanceState {
	want := ProvenanceState(strings.ToLower(strings.TrimSpace(s)))
	for _, p := range ProvenanceStates {
		if p == want {
			return p
		}
	}
	return ProvUnknownOrigin
}

// Trustworthy reports whether a provenance state is a positive attestation.
func (p ProvenanceState) Trustworthy() bool { return p == ProvVerified || p == ProvSigned }

// ExposureScope classifies how reachable an observed surface is. Distinguishing
// loopback from LAN from wildcard is the difference between an observation and
// a finding, and it is the single most important input to the risk score after
// severity.
type ExposureScope string

const (
	ScopeLoopback  ExposureScope = "loopback"
	ScopeLocal     ExposureScope = "local"
	ScopeContainer ExposureScope = "container"
	ScopeVirtual   ExposureScope = "virtual"
	ScopeVPN       ExposureScope = "vpn"
	ScopeLAN       ExposureScope = "lan"
	ScopeWildcard  ExposureScope = "wildcard"
	ScopePublic    ExposureScope = "public"
	ScopeUnknown   ExposureScope = "unknown"
)

// ExposureScopes lists every exposure scope in increasing reachability.
var ExposureScopes = []ExposureScope{
	ScopeLoopback, ScopeLocal, ScopeContainer, ScopeVirtual, ScopeVPN,
	ScopeLAN, ScopeWildcard, ScopePublic, ScopeUnknown,
}

// ParseExposureScope converts a case-insensitive string, falling back to
// ScopeUnknown.
func ParseExposureScope(s string) ExposureScope {
	want := ExposureScope(strings.ToLower(strings.TrimSpace(s)))
	for _, e := range ExposureScopes {
		if e == want {
			return e
		}
	}
	return ScopeUnknown
}

// Weight maps an exposure scope onto the 0..5 exposure component of the risk
// model. Loopback is 0: a service that is genuinely only reachable by its own
// host is not an exposure and must not be scored as one.
func (e ExposureScope) Weight() int {
	switch e {
	case ScopeLoopback:
		return 0
	case ScopeLocal:
		return 1
	case ScopeContainer, ScopeVirtual:
		return 2
	case ScopeVPN:
		return 3
	case ScopeLAN:
		return 4
	case ScopeWildcard:
		return 5
	case ScopePublic:
		return 5
	default:
		return 2
	}
}

// Privilege is the privilege level required to reach or use an observation.
type Privilege string

const (
	PrivNone     Privilege = "none"
	PrivUser     Privilege = "user"
	PrivElevated Privilege = "elevated"
	PrivSystem   Privilege = "system"
)

// Privileges lists every privilege level in increasing order.
var Privileges = []Privilege{PrivNone, PrivUser, PrivElevated, PrivSystem}

// ParsePrivilege converts a case-insensitive string, falling back to PrivNone.
func ParsePrivilege(s string) Privilege {
	want := Privilege(strings.ToLower(strings.TrimSpace(s)))
	for _, p := range Privileges {
		if p == want {
			return p
		}
	}
	return PrivNone
}

// Weight maps a privilege level onto the 0..1 privilege component of the risk
// model.
func (p Privilege) Weight() float64 {
	switch p {
	case PrivNone:
		return 0.0
	case PrivUser:
		return 0.34
	case PrivElevated:
		return 0.67
	case PrivSystem:
		return 1.0
	default:
		return 0.0
	}
}

// Sensitivity classifies how much a finding's subject is worth protecting.
type Sensitivity string

const (
	SensitivityPublic    Sensitivity = "public"
	SensitivityInternal  Sensitivity = "internal"
	SensitivitySensitive Sensitivity = "sensitive"
	SensitivitySecret    Sensitivity = "secret"
)

// Sensitivities lists every sensitivity class.
var Sensitivities = []Sensitivity{
	SensitivityPublic, SensitivityInternal, SensitivitySensitive, SensitivitySecret,
}

// ParseSensitivity converts a case-insensitive string, falling back to
// SensitivityInternal.
func ParseSensitivity(s string) Sensitivity {
	want := Sensitivity(strings.ToLower(strings.TrimSpace(s)))
	for _, v := range Sensitivities {
		if v == want {
			return v
		}
	}
	return SensitivityInternal
}

// Weight maps a sensitivity class onto the 0..1 sensitivity component of the
// risk model.
func (s Sensitivity) Weight() float64 {
	switch s {
	case SensitivityPublic:
		return 0.0
	case SensitivityInternal:
		return 0.4
	case SensitivitySensitive:
		return 0.75
	case SensitivitySecret:
		return 1.0
	default:
		return 0.4
	}
}

// SecretType classifies detected credential material. Only the type, location
// and a truncated fingerprint ever travel downstream; the value itself never
// leaves the collector.
type SecretType string

const (
	SecretAPIKey             SecretType = "api_key"
	SecretToken              SecretType = "token"
	SecretPrivateKey         SecretType = "private_key"
	SecretPassword           SecretType = "password"
	SecretCloudCredential    SecretType = "cloud_credential"
	SecretSSHKey             SecretType = "ssh_key"
	SecretDatabaseCredential SecretType = "database_credential"
	SecretJWT                SecretType = "jwt"
	SecretOAuthToken         SecretType = "oauth_token"
	SecretSessionToken       SecretType = "session_token"
	SecretEnvironment        SecretType = "environment_secret"
	SecretConfiguration      SecretType = "configuration_secret"
	SecretCICD               SecretType = "cicd_credential"
)

// SecretTypes lists every detected secret class.
var SecretTypes = []SecretType{
	SecretAPIKey, SecretToken, SecretPrivateKey, SecretPassword,
	SecretCloudCredential, SecretSSHKey, SecretDatabaseCredential, SecretJWT,
	SecretOAuthToken, SecretSessionToken, SecretEnvironment,
	SecretConfiguration, SecretCICD,
}

// ParseSecretType converts a case-insensitive string, falling back to
// SecretConfiguration.
func ParseSecretType(s string) SecretType {
	want := SecretType(strings.ToLower(strings.TrimSpace(s)))
	for _, t := range SecretTypes {
		if t == want {
			return t
		}
	}
	return SecretConfiguration
}
