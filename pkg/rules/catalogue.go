package rules

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// Builtin returns the catalogue shipped with Amina.
//
// Rule IDs are stable and namespaced by domain. They are part of the machine
// contract: a downstream system suppresses findings by rule ID, so a rule ID
// that changes between releases silently changes what that system suppresses.
// Renumbering is therefore a breaking change and is avoided.
func Builtin() []Rule {
	var out []Rule
	out = append(out, accountRules()...)
	out = append(out, networkRules()...)
	out = append(out, remoteAccessRules()...)
	out = append(out, identityRules()...)
	out = append(out, secretRules()...)
	out = append(out, provenanceRules()...)
	out = append(out, filesystemRules()...)
	out = append(out, shellRules()...)
	out = append(out, cloudRules()...)
	out = append(out, postureRules()...)
	out = append(out, artifactRules()...)
	out = append(out, softwareRules()...)
	out = append(out, processRules()...)
	out = append(out, persistenceRules()...)
	out = append(out, toolingRules()...)
	out = append(out, appRules()...)
	out = append(out, permissionRules()...)
	out = append(out, tempRules()...)
	out = append(out, metadataRules()...)
	return out
}

// worldBoundPanicPorts are ports whose presence on a wildcard bind is worth a
// finding regardless of what the process claims, because they are only ever
// exposed for administration, never as a general service.
var adminPorts = map[int]string{
	22:    "Secure Shell",
	23:    "Telnet",
	445:   "SMB",
	1433:  "Microsoft SQL Server",
	3306:  "MySQL",
	5432:  "PostgreSQL",
	5900:  "VNC",
	6379:  "Redis",
	9200:  "Elasticsearch",
	27017: "MongoDB",
	11211: "Memcached",
}

// sensitivePorts are ports that carry credentials in the clear or grant an
// interactive session, and are therefore findings when world-bound even though
// the service may be legitimate.
var sensitivePorts = map[int]string{
	21:   "FTP",
	23:   "Telnet",
	25:   "SMTP",
	110:  "POP3",
	143:  "IMAP",
	389:  "LDAP",
	2049: "NFS",
	548:  "AFP",
	3389: "RDP",
}

// accountRules covers the account domain.
func accountRules() []Rule {
	return []Rule{
		{
			ID:             "ACC-001",
			Title:          "Interactive login shell for a service account",
			Category:       models.CategoryAccount,
			ModuleID:       "accounts",
			Description:    "An account whose shell is an interactive shell can be logged into directly, which turns a service identity into a person.",
			Recommendation: "Set the shell to nologin or false so the account cannot be used for an interactive session.",
			Severity:       models.SeverityMedium,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceConfirmed,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, a := range s.Accounts {
					// An account already restricted to a non-login shell cannot
					// be logged into, which is the condition being reported.
					if a.NoLogin || a.Shell == "" {
						continue
					}
					base := filepath.Base(a.Shell)
					if !isInteractiveShell(base) {
						continue
					}
					// An ordinary user account having bash is the normal case,
					// not a finding. This rule is about machine identities that
					// a person could log in as.
					if !isServiceIdentity(a) {
						continue
					}
					out = append(out, Match{
						Objects: []string{a.Name},
						Attributes: map[string]string{
							"shell": a.Shell,
							"uid":   a.UID,
						},
						SeverityOverride: &SeverityOverride{Impact: "Shell " + a.Shell + " permits direct login as " + a.Name},
					})
				}
				return out
			},
		},
		{
			ID:             "ACC-002",
			Title:          "Privileged account with authorized SSH keys",
			Category:       models.CategoryAccount,
			ModuleID:       "accounts",
			Description:    "A privileged account holding SSH keys is reachable without a password, so the privilege boundary is only as strong as every key ever added to it.",
			Recommendation: "Move day-to-day work to an unprivileged account with sudo, and review which keys are actually still in use.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivElevated,
			Sensitivity:    models.SensitivitySensitive,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, a := range s.Accounts {
					if !a.Privileged || a.AuthorizedKeys == 0 {
						continue
					}
					out = append(out, Match{
						Objects: []string{a.Name},
						Attributes: map[string]string{
							"authorized_keys": fmt.Sprintf("%d", a.AuthorizedKeys),
							"uid":             a.UID,
						},
					})
				}
				return out
			},
		},
		{
			ID:             "ACC-003",
			Title:          "Account with no last-login record",
			Category:       models.CategoryAccount,
			ModuleID:       "accounts",
			Description:    "An interactive account with no observable last-login record may be dormant, which keeps an unnecessary authentication path alive.",
			Recommendation: "Confirm the account is still required; disable or remove it otherwise.",
			Severity:       models.SeverityLow,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivityInternal,
			// Possible rather than Observed: on a container, a host with rotated
			// logs, or a fresh install, an empty record means "no evidence",
			// not "never used".
			Confidence: models.ConfidencePossible,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, a := range s.Accounts {
					if a.Service || a.NoLogin {
						continue
					}
					// The condition is the *absence* of a login record, so the
					// guard is the opposite of the intuitive one: accounts with
					// a known last-login are not the finding.
					if !a.LastLogin.IsZero() {
						continue
					}
					if filepath.Base(a.Shell) == "bash" && a.UID == "0" {
						continue // the root account is used constantly via automation
					}
					out = append(out, Match{
						Objects: []string{a.Name},
						Attributes: map[string]string{
							"shell": a.Shell,
							"home":  a.Home,
						},
					})
				}
				return out
			},
		},
		{
			ID:             "ACC-004",
			Title:          "Account with a human name in the GECOS field",
			Category:       models.CategoryMetadata,
			ModuleID:       "accounts",
			Description:    "A real name in the comment field is readable by anyone who can read the account list, and it survives reinstalls that clear everything else.",
			Recommendation: "Replace the comment field with a role or team identifier.",
			Severity:       models.SeverityLow,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, a := range s.Accounts {
					if a.GECOS == "" || !containsSpace(a.GECOS) {
						continue
					}
					// A GECOS holding only a role is not a name leak.
					if looksLikeRole(a.GECOS) {
						continue
					}
					out = append(out, Match{
						Objects: []string{a.Name},
						Attributes: map[string]string{
							"gecos": a.GECOS,
						},
					})
				}
				return out
			},
		},
	}
}

// networkRules covers bind scope and listening services.
func networkRules() []Rule {
	return []Rule{
		{
			ID:             "NET-001",
			Title:          "Service listening on a wildcard address",
			Category:       models.CategoryNetwork,
			ModuleID:       "network",
			Description:    "A socket bound to a wildcard address accepts connections from every network the host is attached to, not only from this machine.",
			Recommendation: "Bind to a specific interface or to loopback unless remote reachability is intended.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeWildcard,
			Privilege:      models.PrivNone,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, sock := range s.WorldBoundSockets() {
					service := sock.Process
					if service == "" {
						service = "unknown"
					}
					out = append(out, Match{
						Title:   fmt.Sprintf("Service %s listening on all interfaces, port %d", service, sock.Port),
						Objects: []string{fmt.Sprintf("%s:%d", sock.Addr, sock.Port)},
						Attributes: map[string]string{
							"port":    fmt.Sprintf("%d", sock.Port),
							"process": service,
							"pid":     fmt.Sprintf("%d", sock.PID),
							"proto":   sock.Proto,
						},
						Evidence: []models.Evidence{{
							Kind:     models.EvidenceObservation,
							Source:   service,
							Location: fmt.Sprintf("%s:%d", sock.Addr, sock.Port),
						}},
					})
				}
				return out
			},
		},
		{
			ID:             "NET-002",
			Title:          "Administrative service exposed beyond this host",
			Category:       models.CategoryRemoteAccess,
			ModuleID:       "network",
			Description:    "A remote-administration port bound to a wildcard address is reachable from every network the host touches.",
			Recommendation: "Restrict the listener to loopback or a VPN interface, and require a jump host for administrative access.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeWildcard,
			Privilege:      models.PrivNone,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, sock := range s.WorldBoundSockets() {
					name, ok := adminPorts[sock.Port]
					if !ok {
						continue
					}
					service := sock.Process
					if service == "" {
						service = "unknown"
					}
					out = append(out, Match{
						Title:   fmt.Sprintf("%s exposed on port %d", name, sock.Port),
						Objects: []string{fmt.Sprintf("%s:%d", sock.Addr, sock.Port)},
						Attributes: map[string]string{
							"service": name,
							"port":    fmt.Sprintf("%d", sock.Port),
							"process": service,
						},
					})
				}
				return out
			},
		},
		{
			// NET-003 is the rule that exists because the alternative is the
			// single most common false positive in host assessment: reporting
			// loopback listeners as network exposure. A loopback bind is
			// information, not a finding.
			ID:             "NET-003",
			Title:          "Service reachable only from this host",
			Category:       models.CategoryExposure,
			ModuleID:       "network",
			Description:    "A loopback-bound service is reachable only by processes on this host, which is usually the intended configuration and is recorded here as context rather than as a defect.",
			Recommendation: "No action required unless the process itself is a concern.",
			Severity:       models.SeverityInformational,
			Exposure:       models.ScopeLoopback,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivityPublic,
			Confidence:     models.ConfidenceObserved,
			MinimumDepth:   DepthStandard,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, sock := range s.Sockets {
					if sock.Scope != models.ScopeLoopback {
						continue
					}
					service := sock.Process
					if service == "" {
						service = "unknown"
					}
					out = append(out, Match{
						Objects: []string{fmt.Sprintf("%s:%d", sock.Addr, sock.Port)},
						Attributes: map[string]string{
							"port":    fmt.Sprintf("%d", sock.Port),
							"process": service,
						},
					})
				}
				return out
			},
		},
		{
			ID:             "NET-004",
			Title:          "Service carrying credentials in the clear",
			Category:       models.CategoryAuthentication,
			ModuleID:       "network",
			Description:    "This protocol transmits authentication material unencrypted, and world-binding the listener extends that to every network the host reaches.",
			Recommendation: "Replace with an encrypted protocol, or terminate TLS in front of it on a trusted segment.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeWildcard,
			Privilege:      models.PrivNone,
			Sensitivity:    models.SensitivitySensitive,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, sock := range s.WorldBoundSockets() {
					name, ok := sensitivePorts[sock.Port]
					if !ok {
						continue
					}
					out = append(out, Match{
						Title:   fmt.Sprintf("%s exposed without transport encryption", name),
						Objects: []string{fmt.Sprintf("%s:%d", sock.Addr, sock.Port)},
						Attributes: map[string]string{
							"service": name,
							"port":    fmt.Sprintf("%d", sock.Port),
						},
					})
				}
				return out
			},
		},
		{
			ID:             "NET-005",
			Title:          "Listener on a VPN or virtual interface",
			Category:       models.CategoryNetwork,
			ModuleID:       "network",
			Description:    "A service bound to a tunnel interface is reachable by every peer on that tunnel, which is a wider audience than the local machine.",
			Recommendation: "Confirm every tunnel peer is trusted to reach this service.",
			Severity:       models.SeverityMedium,
			Exposure:       models.ScopeVPN,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				vpnNames := map[string]bool{}
				for _, i := range s.Interfaces {
					if i.Scope == string(models.ScopeVPN) || i.Kind == "vpn" {
						vpnNames[i.Name] = true
					}
				}
				if len(vpnNames) == 0 {
					return nil
				}
				var out []Match
				for _, sock := range s.Sockets {
					if sock.Scope != models.ScopeVPN {
						continue
					}
					out = append(out, Match{
						Objects: []string{fmt.Sprintf("%s:%d", sock.Addr, sock.Port)},
						Attributes: map[string]string{
							"port": fmt.Sprintf("%d", sock.Port),
						},
					})
				}
				return out
			},
		},
	}
}

// remoteAccessRules covers the configured remote-access surface.
func remoteAccessRules() []Rule {
	return []Rule{
		{
			ID:             "RMT-001",
			Title:          "Password authentication permitted for SSH",
			Category:       models.CategoryRemoteAccess,
			ModuleID:       "remote-access",
			Description:    "Permitting password authentication for remote logins means the strength of every account password on the host is the strength of the login.",
			Recommendation: "Set PasswordAuthentication no and use key-based authentication.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeLAN,
			Privilege:      models.PrivNone,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			Platforms:      []models.Platform{models.PlatformLinux, models.PlatformDarwin, models.PlatformTermux},
			Match: func(s *Snapshot) []Match {
				if s.Env == nil {
					return nil
				}
				path := s.Env.Paths.SSHDConfig
				if path == "" || !fileAt(path) {
					return nil
				}
				lines := readAt(path)
				enabled, sawDirective := false, false
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "#") {
						continue
					}
					f := strings.Fields(line)
					if len(f) < 2 || !strings.EqualFold(f[0], "PasswordAuthentication") {
						continue
					}
					sawDirective = true
					if strings.EqualFold(f[1], "yes") {
						enabled = true
					}
				}
				if enabled || !sawDirective && defaultPasswordAuth() {
					return []Match{{Objects: []string{path}}}
				}
				return nil
			},
		},
		{
			ID:             "RMT-002",
			Title:          "PermitRootLogin is not disabled",
			Category:       models.CategoryRemoteAccess,
			ModuleID:       "remote-access",
			Description:    "Permitting direct root login makes the highest-privilege account remotely reachable using only its password or its keys.",
			Recommendation: "Set PermitRootLogin no and escalate with sudo from an unprivileged account.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeLAN,
			Privilege:      models.PrivNone,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			Platforms:      []models.Platform{models.PlatformLinux, models.PlatformTermux},
			Match: func(s *Snapshot) []Match {
				if s.Env == nil || !fileAt(s.Env.Paths.SSHDConfig) {
					return nil
				}
				for _, line := range readAt(s.Env.Paths.SSHDConfig) {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "#") {
						continue
					}
					f := strings.Fields(line)
					if len(f) >= 2 && strings.EqualFold(f[0], "PermitRootLogin") &&
						!strings.EqualFold(f[1], "no") {
						return []Match{{
							Objects:    []string{s.Env.Paths.SSHDConfig},
							Attributes: map[string]string{"directive": strings.Join(f, " ")},
						}}
					}
				}
				return nil
			},
		},
	}
}

// identityRules covers what the host itself discloses about its operator.
func identityRules() []Rule {
	return []Rule{
		{
			ID:             "IDN-001",
			Title:          "Hostname discloses a name or identifier",
			Category:       models.CategoryIdentity,
			ModuleID:       "host-identity",
			Description:    "A hostname containing a personal name, an organisation or a machine role is published to every service this host contacts.",
			Recommendation: "Use a neutral hostname that identifies the function rather than the person.",
			Severity:       models.SeverityLow,
			Exposure:       models.ScopeLAN,
			Privilege:      models.PrivNone,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				if s.Env == nil || s.Env.Hostname == "" {
					return nil
				}
				h := s.Env.Hostname
				// The three generic forms are the overwhelming majority of
				// real hostnames and are not an exposure.
				l := strings.ToLower(h)
				if l == "localhost" || strings.HasPrefix(l, "desktop-") ||
					strings.HasPrefix(l, "laptop-") || strings.HasSuffix(l, "-pc") {
					return nil
				}
				if !identityShaped(h) {
					return nil
				}
				return []Match{{
					Objects:    []string{h},
					Attributes: map[string]string{"hostname": h},
				}}
			},
		},
		{
			ID:             "IDN-002",
			Title:          "Login name disclosed in the environment",
			Category:       models.CategoryMetadata,
			ModuleID:       "environment",
			Description:    "The login name travels with many ordinary operations and appears in logs, prompts and process listings.",
			Recommendation: "Use a generic service account name for anything that runs unattended.",
			Severity:       models.SeverityInformational,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				if s.Env == nil || s.Env.User == "" {
					return nil
				}
				if !identityShaped(s.Env.User) {
					return nil
				}
				return []Match{{
					Objects:    []string{s.Env.User},
					Attributes: map[string]string{"user": s.Env.User},
				}}
			},
		},
		{
			ID:             "IDN-003",
			Title:          "Git author identity configured",
			Category:       models.CategoryGit,
			ModuleID:       "developer-identity",
			Description:    "A configured git identity is written into every commit, travels with the repository when it is pushed, and is rarely revisited.",
			Recommendation: "Use a name and address that do not identify you personally unless that is intended.",
			Severity:       models.SeverityMedium,
			Exposure:       models.ScopePublic,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				if s.Env == nil {
					return nil
				}
				path := s.Env.Paths.GitConfig
				if path == "" || !fileAt(path) {
					return nil
				}
				var name, email string
				for _, line := range readAt(path) {
					trimmed := strings.TrimSpace(line)
					if k, v, ok := strings.Cut(trimmed, "="); ok {
						switch strings.ToLower(strings.TrimSpace(k)) {
						case "name":
							name = strings.TrimSpace(v)
						case "email":
							email = strings.TrimSpace(v)
						}
					}
				}
				if name == "" && email == "" {
					return nil
				}
				attrs := map[string]string{}
				if name != "" {
					attrs["git_name"] = name
				}
				if email != "" {
					attrs["git_email"] = email
				}
				return []Match{{Objects: []string{path}, Attributes: attrs}}
			},
		},
	}
}

// secretRules covers material that must never appear in a report or a repo.
func secretRules() []Rule {
	return []Rule{
		{
			ID:             "SEC-001",
			Title:          "Private key material present",
			Category:       models.CategorySecrets,
			ModuleID:       "secret-material",
			Description:    "Private key material on disk is a single-file compromise of every identity the key has ever been authorised for.",
			Recommendation: "Move keys to an agent or a hardware-backed store, and remove the private half from the filesystem.",
			Severity:       models.SeverityCritical,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivitySecret,
			Confidence:     models.ConfidenceConfirmed,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, sec := range s.Secrets {
					if sec.Type != models.SecretPrivateKey && sec.Type != models.SecretSSHKey {
						continue
					}
					out = append(out, Match{
						Objects: []string{sec.Location},
						Attributes: map[string]string{
							"fingerprint": sec.Fingerprint,
							"type":        string(sec.Type),
							"line":        fmt.Sprintf("%d", sec.Line),
						},
					})
				}
				return out
			},
		},
		{
			ID:             "SEC-002",
			Title:          "Credential material present",
			Category:       models.CategoryCredentials,
			ModuleID:       "secret-material",
			Description:    "A credential stored in a file is readable by every process running as that user and by anything that later obtains them.",
			Recommendation: "Move the credential to a secret store or an agent, and rotate the exposed value.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivitySecret,
			Confidence:     models.ConfidenceConfirmed,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, sec := range s.Secrets {
					switch sec.Type {
					case models.SecretPrivateKey, models.SecretSSHKey:
						continue // already raised by SEC-001 at critical
					case models.SecretPassword, models.SecretAPIKey, models.SecretToken,
						models.SecretCloudCredential, models.SecretDatabaseCredential,
						models.SecretJWT, models.SecretOAuthToken, models.SecretSessionToken:
					default:
						continue
					}
					out = append(out, Match{
						Objects: []string{sec.Location},
						Attributes: map[string]string{
							"fingerprint": sec.Fingerprint,
							"type":        string(sec.Type),
						},
					})
				}
				return out
			},
		},
		{
			ID:             "SEC-003",
			Title:          "Secret material readable by other local users",
			Category:       models.CategoryFilesystem,
			ModuleID:       "secret-material",
			Description:    "A credential file readable beyond its owner is readable by every local account, not only by the person who created it.",
			Recommendation: "Restrict the file to the owning account with mode 0600.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivitySecret,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				// SecretRecord deliberately carries no permission data: it is
				// the redacted record of what was found, and adding filesystem
				// metadata to it would blur the redaction boundary. Permissions
				// are joined in from the file-exposure assets by path.
				modes := assetModesByPath(s)
				var out []Match
				for _, sec := range s.SortedSecrets() {
					mode, known := modes[sec.Location]
					if !known || modeIsRestricted(mode) {
						continue
					}
					out = append(out, Match{
						Objects:    []string{sec.Location},
						Attributes: map[string]string{"mode": mode, "type": string(sec.Type)},
					})
				}
				return out
			},
		},
	}
}

// provenanceRules covers where executables came from.
func provenanceRules() []Rule {
	return []Rule{
		{
			ID:             "PRV-001",
			Title:          "Executable in a system path with no package owner",
			Category:       models.CategoryProvenance,
			ModuleID:       "provenance",
			Description:    "An executable in a system directory that no package manager claims was installed outside the normal distribution channel, which is also what an implant looks like.",
			Recommendation: "Establish where the file came from and remove it if that cannot be established.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, p := range s.Provenance {
					if p.State != models.ProvUnowned {
						continue
					}
					out = append(out, Match{
						Objects:    []string{p.Path},
						Attributes: map[string]string{"state": string(p.State), "source": p.Source},
					})
				}
				return out
			},
		},
		{
			ID:             "PRV-002",
			Title:          "System binary modified relative to its package",
			Category:       models.CategoryIntegrity,
			ModuleID:       "binary-integrity",
			Description:    "A file whose checksum no longer matches the one recorded by the package manager has been changed after installation.",
			Recommendation: "Reinstall the package from the distribution channel and investigate how the change was made.",
			Severity:       models.SeverityCritical,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivElevated,
			Sensitivity:    models.SensitivitySensitive,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, p := range s.Provenance {
					if p.State != models.ProvHashMismatch && !p.Modified {
						continue
					}
					override := &SeverityOverride{}
					out = append(out, Match{
						Objects:          []string{p.Path},
						Attributes:       map[string]string{"state": string(p.State), "owner": p.PackageOwner},
						SeverityOverride: override,
					})
				}
				return out
			},
		},
		{
			ID:             "PRV-003",
			Title:          "Third-party package source configured",
			Category:       models.CategorySoftware,
			ModuleID:       "package-sources",
			Description:    "A configured repository outside the distribution's own channels is an additional supply chain the distribution does not vouch for.",
			Recommendation: "Confirm each additional source is required and trustworthy, and remove the rest.",
			Severity:       models.SeverityMedium,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivElevated,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, src := range s.Sources {
					if src.Trust == "official" {
						continue
					}
					out = append(out, Match{
						Objects: []string{src.ID},
						Attributes: map[string]string{
							"uri":   src.URI,
							"trust": src.Trust,
							"keys":  fmt.Sprintf("%d", src.Keys),
						},
					})
				}
				return out
			},
		},
		{
			ID:             "PRV-004",
			Title:          "Package source configured without a signing key",
			Category:       models.CategoryProvenance,
			ModuleID:       "package-sources",
			Description:    "A repository configured without a signing key can be populated by anyone who can reach the mirror.",
			Recommendation: "Configure a signing key, or remove the source.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeLAN,
			Privilege:      models.PrivElevated,
			Sensitivity:    models.SensitivitySensitive,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, src := range s.Sources {
					if !src.Enabled || src.Keys != 0 || src.Trust != "unknown" {
						continue
					}
					out = append(out, Match{
						Objects:    []string{src.ID},
						Attributes: map[string]string{"uri": src.URI},
					})
				}
				return out
			},
		},
	}
}

// filesystemRules covers world-writable and stale artifacts.
func filesystemRules() []Rule {
	return []Rule{
		{
			ID:             "FS-001",
			Title:          "World-writable file in a sensitive directory",
			Category:       models.CategoryFilesystem,
			ModuleID:       "filesystem-exposure",
			Description:    "A world-writable file in a directory the system trusts is writable by every local account, including one that should not be able to modify the host's behaviour.",
			Recommendation: "Restrict the file to the owning account and review what else writes to the directory.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivitySensitive,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, a := range s.Assets {
					if !isFileAsset(a) || a.Attributes["world_writable"] != "true" {
						continue
					}
					if !sensitivePath(a.Path) {
						continue
					}
					out = append(out, Match{
						Objects:    []string{a.Path},
						Attributes: map[string]string{"mode": a.Attributes["mode"]},
					})
				}
				return out
			},
		},
		{
			ID:             "FS-002",
			Title:          "Secret-material directory readable by other accounts",
			Category:       models.CategoryFilesystem,
			ModuleID:       "filesystem-exposure",
			Description:    "The SSH or cloud credential directory is readable beyond its owner, which exposes every key inside it to other local accounts.",
			Recommendation: "Restrict the directory to mode 0700.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivitySecret,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				if s.Env == nil {
					return nil
				}
				var out []Match
				for _, a := range s.Assets {
					if !isDirAsset(a) || a.Attributes["group_readable"] != "true" &&
						a.Attributes["world_readable"] != "true" {
						continue
					}
					if !isCredentialDir(a.Path) {
						continue
					}
					out = append(out, Match{
						Objects:    []string{a.Path},
						Attributes: map[string]string{"mode": a.Attributes["mode"]},
					})
				}
				return out
			},
		},
	}
}

// shellRules covers shell configuration and history.
func shellRules() []Rule {
	return []Rule{
		{
			ID:             "SHL-001",
			Title:          "Shell history readable beyond its owner",
			Category:       models.CategoryShell,
			ModuleID:       "shell-terminal",
			Description:    "Command history records what was typed, including arguments that turn out to be credentials after the fact.",
			Recommendation: "Restrict history files to the owning account and review them for credentials already pasted.",
			Severity:       models.SeverityMedium,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivitySensitive,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				if s.Env == nil {
					return nil
				}
				var out []Match
				for _, f := range s.Env.Paths.HistoryFiles {
					for _, a := range s.Assets {
						if a.Path != f || !isFileAsset(a) {
							continue
						}
						if a.Attributes["world_readable"] != "true" &&
							a.Attributes["group_readable"] != "true" {
							continue
						}
						out = append(out, Match{
							Objects:    []string{f},
							Attributes: map[string]string{"mode": a.Attributes["mode"]},
						})
					}
				}
				return out
			},
		},
		{
			ID:             "SHL-002",
			Title:          "Credential-shaped content in shell history",
			Category:       models.CategoryShell,
			ModuleID:       "shell-terminal",
			Description:    "A command line that matches a credential pattern was typed into the shell, and remains in the history file indefinitely.",
			Recommendation: "Remove the entry from history and rotate the credential.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivitySecret,
			Confidence:     models.ConfidencePossible,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, sec := range s.SortedSecrets() {
					if !isHistoryPath(sec.Location) {
						continue
					}
					out = append(out, Match{
						Objects:    []string{fmt.Sprintf("%s:%d", sec.Location, sec.Line)},
						Attributes: map[string]string{"type": string(sec.Type)},
					})
				}
				return out
			},
		},
	}
}

// cloudRules covers cloud provider identity material.
func cloudRules() []Rule {
	return []Rule{
		{
			ID:             "CLD-001",
			Title:          "Cloud provider configuration present",
			Category:       models.CategoryCloud,
			ModuleID:       "cloud-identity",
			Description:    "Cloud provider configuration identifies the operator's organisation and account on every machine they use.",
			Recommendation: "Use per-machine profiles with only the permissions that machine needs.",
			Severity:       models.SeverityLow,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				if s.Env == nil || s.Env.Cloud == "" {
					return nil
				}
				return []Match{{
					Objects:    []string{s.Env.Cloud},
					Attributes: map[string]string{"provider": s.Env.Cloud},
				}}
			},
		},
		{
			ID:             "CLD-002",
			Title:          "Cloud credential file present",
			Category:       models.CategoryCredentials,
			ModuleID:       "cloud-identity",
			Description:    "A stored cloud credential grants whatever the associated identity can do, from any process running as this user.",
			Recommendation: "Replace static credentials with short-lived tokens, and rotate what has already been stored.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivitySecret,
			Confidence:     models.ConfidenceConfirmed,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, sec := range s.Secrets {
					if sec.Type != models.SecretCloudCredential {
						continue
					}
					out = append(out, Match{
						Objects:    []string{sec.Location},
						Attributes: map[string]string{"fingerprint": sec.Fingerprint},
					})
				}
				return out
			},
		},
	}
}

// postureRules covers host security state.
func postureRules() []Rule {
	return []Rule{
		{
			ID:             "PST-001",
			Title:          "Mandatory access control not enforcing",
			Category:       models.CategoryConfiguration,
			ModuleID:       "os-posture",
			Description:    "With MAC disabled, a process running as this user can read most files on the host regardless of their permissions.",
			Recommendation: "Enable the mandatory access control the distribution ships with.",
			Severity:       models.SeverityMedium,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			Platforms:      []models.Platform{models.PlatformLinux},
			Match: func(s *Snapshot) []Match {
				for _, a := range s.Assets {
					if a.Kind == models.KindPosture && a.Name == "selinux" &&
						a.Attributes["enforcing"] == "false" {
						return []Match{{
							Objects:    []string{a.Name},
							Attributes: map[string]string{"state": a.Attributes["state"]},
						}}
					}
				}
				return nil
			},
		},
		{
			ID:             "PST-002",
			Title:          "Full disk encryption not confirmed",
			Category:       models.CategoryExposure,
			ModuleID:       "os-posture",
			Description:    "Without full disk encryption, the host's contents are recoverable from the physical device without any credential.",
			Recommendation: "Enable full disk encryption if the device can be lost or stolen.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivSystem,
			Sensitivity:    models.SensitivitySensitive,
			// Possible rather than Observed: this run may simply lack the
			// privilege to read the encryption state, which is not evidence
			// that encryption is off.
			Confidence: models.ConfidencePossible,
			Match: func(s *Snapshot) []Match {
				for _, a := range s.Assets {
					if a.Kind != models.KindPosture {
						continue
					}
					switch a.Name {
					case "bitlocker", "luks", "disk_encryption", "filevault":
						if a.Attributes["encrypted"] == "true" {
							return nil
						}
						return []Match{{Objects: []string{a.Name}}}
					}
				}
				return nil
			},
		},
	}
}

// artifactRules covers logs and build artifacts.
func artifactRules() []Rule {
	return []Rule{
		{
			ID:             "ART-001",
			Title:          "Log or artifact directory readable beyond its owner",
			Category:       models.CategoryLogging,
			ModuleID:       "artifacts-logs",
			Description:    "Build logs, crash dumps and diagnostic archives frequently contain paths, hostnames and occasionally credentials, and are often left world-readable.",
			Recommendation: "Restrict the directory and sweep existing archives for credentials before sharing them.",
			Severity:       models.SeverityMedium,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivitySensitive,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, a := range s.Assets {
					if !isDirAsset(a) || !isArtifactDir(a.Path) {
						continue
					}
					if a.Attributes["world_readable"] != "true" &&
						a.Attributes["group_readable"] != "true" {
						continue
					}
					out = append(out, Match{
						Objects:    []string{a.Path},
						Attributes: map[string]string{"mode": a.Attributes["mode"]},
					})
				}
				return out
			},
		},
		{
			ID:             "ART-002",
			Title:          "Container environment exposes the host's identity",
			Category:       models.CategoryExposure,
			ModuleID:       "os-posture",
			Description:    "A container inherits the host's name, identity files and, in some configurations, its network reachability.",
			Recommendation: "Run untrusted workloads with an isolated hostname and a restricted bind set.",
			Severity:       models.SeverityLow,
			Exposure:       models.ScopeContainer,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				if s.Env == nil || !s.Env.Container {
					return nil
				}
				return []Match{{
					Objects:    []string{s.Env.ContainerKind},
					Attributes: map[string]string{"kind": s.Env.ContainerKind},
				}}
			},
		},
	}
}
