package rules

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// Rules for the eight modules whose collectors arrived after the first
// catalogue pass.
//
// These follow the same discipline as the rest of the catalogue: each rule
// fires on evidence a collector actually observed, and where a naive version of
// the check would be noisy, the rule says so and narrows instead. The software,
// process and tooling rules in particular are where "report everything
// installed" would be worthless, so each one names a specific disclosure.

// softwareRules covers the installed-software inventory.
func softwareRules() []Rule {
	return []Rule{
		{
			ID:             "SW-001",
			Title:          "Installed package records a generic or absent origin",
			Category:       models.CategorySoftware,
			ModuleID:       "software",
			Description:    "A package whose origin is unknown cannot be attributed to a repository, which means it also cannot be updated, patched or rolled back through one.",
			Recommendation: "Identify the repository that provides the package, or remove it in favour of a packaged equivalent.",
			Severity:       models.SeverityLow,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				// A package manager that cannot report a package's origin —
				// dpkg is the common case — would otherwise make this fire once
				// per installed package, which on a real host is thousands of
				// identical findings. The condition worth reporting is about the
				// host's configuration, not about each package, so it is counted
				// and reported once.
				byProvider := map[string]int{}
				for _, p := range s.Software {
					if p.Origin != "" && p.Origin != "unknown" && p.Origin != "local" {
						continue
					}
					byProvider[p.Provider]++
				}
				providers := make([]string, 0, len(byProvider))
				for prov := range byProvider {
					providers = append(providers, prov)
				}
				sort.Strings(providers)

				var out []Match
				for _, prov := range providers {
					// When the host has configured repositories for this
					// provider, packages installed through it are attributable by
					// construction and nothing is actually unattributed.
					if hasConfiguredSource(s.Sources, prov) {
						continue
					}
					out = append(out, Match{
						Objects: []string{prov},
						Attributes: map[string]string{
							"provider": prov,
							"count":    fmt.Sprintf("%d", byProvider[prov]),
						},
					})
				}
				return out
			},
		},
		{
			ID:             "SW-002",
			Title:          "Installed software is associated with a development project or employer",
			Category:       models.CategorySoftware,
			ModuleID:       "software",
			Description:    "Package names, versions and origins routinely disclose the projects, employers and internal toolchains a workstation is used for, and travel with it on every backup and image.",
			Recommendation: "Separate the workstation's work profile from its personal profile, and prune packages belonging to a project you no longer work on.",
			Severity:       models.SeverityLow,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				// Grouped by namespace. A workstation with a few hundred
				// internal-looking package names should produce a handful of
				// findings about those namespaces, not one per package: the
				// reader's question is "which projects is this machine
				// associated with", and the answer is the group.
				groups := map[string][]string{}
				for _, p := range s.Software {
					ns := internalNamespace(p.Name)
					if ns == "" {
						continue
					}
					groups[ns] = append(groups[ns], p.Name)
				}
				namespaces := make([]string, 0, len(groups))
				for ns := range groups {
					namespaces = append(namespaces, ns)
				}
				sort.Strings(namespaces)

				var out []Match
				for _, ns := range namespaces {
					members := groups[ns]
					sort.Strings(members)
					out = append(out, Match{
						Objects: append([]string{ns}, sampleNames(members, 10)...),
						Attributes: map[string]string{
							"namespace": ns,
							"count":     fmt.Sprintf("%d", len(members)),
						},
					})
				}
				return out
			},
		},
		{
			ID:             "SW-003",
			Title:          "Software installed outside the system package manager",
			Category:       models.CategorySoftware,
			ModuleID:       "software",
			Description:    "Manually installed binaries and vendor installers are not covered by the distribution's update mechanism, so a known-good version can stay on disk indefinitely.",
			Recommendation: "Track manually installed software and remove it when it is no longer needed.",
			Severity:       models.SeverityLow,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceProbable,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, a := range s.Assets {
					if a.Domain != "software" {
						continue
					}
					if a.Attributes["package_owned"] != "false" {
						continue
					}
					out = append(out, Match{
						Objects:    []string{a.Path},
						Attributes: map[string]string{"mode": a.Attributes["mode"], "owner": a.Attributes["owner"]},
					})
				}
				return out
			},
		},
	}
}

// internalNamespace returns the internal-looking identifier a package name
// carries, or "" when it carries none.
//
// The test is deliberately much narrower than "looks unusual". An earlier
// version treated any name containing a dot as internal, which matched every
// Debian package carrying a version suffix — libcbc3.1, aspnetcore-runtime-6.0 —
// and turned a workstation's package list into hundreds of identical findings.
// Version suffixes are common in public packages; mixed-case segments and
// embedded domains are not.
func internalNamespace(name string) string {
	if name == "" {
		return ""
	}
	// An upper-case segment is not used by public distributions and is standard
	// for internal builds: myorg-MyService.
	for _, part := range strings.FieldsFunc(name, func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	}) {
		if part != "" && part[0] >= 'A' && part[0] <= 'Z' {
			return part
		}
	}
	// A domain-shaped token. The name must actually carry a dot: splitting a
	// dotless name on "." yields the name itself, so without the length check
	// every purely alphabetic package in the distribution looks like a domain.
	// A numeric final segment is a version rather than a suffix, which is the
	// single most common shape in a public package name.
	if parts := strings.Split(name, "."); len(parts) >= 2 {
		suffix := parts[len(parts)-1]
		if len(suffix) >= 2 && len(suffix) <= 24 && isAlpha(suffix) && parts[0] != "" {
			return parts[0]
		}
	}
	// An underscore is legal but vanishingly rare in a public package name.
	if i := strings.IndexByte(name, '_'); i > 0 {
		return name[:i]
	}
	return ""
}

// isAlpha reports whether s is entirely ASCII letters.
func isAlpha(s string) bool {
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}

// sampleNames returns at most n names, for listing inside a finding without
// turning the finding into a package listing.
func sampleNames(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

// sourceEcosystems maps a package provider to the ecosystems whose configured
// repositories make its packages attributable.
//
// The two vocabularies are deliberately different: an installed package records
// the tool that installed it (dpkg, rpm) while a configured source records the
// ecosystem it belongs to (apt, dnf). Comparing them directly would find no
// source for any package on a Debian-family host and report every installed
// package as unattributable.
func sourceEcosystems(pkgProvider string) []string {
	switch pkgProvider {
	case "dpkg":
		return []string{"apt"}
	case "rpm":
		return []string{"dnf", "yum"}
	case "brew", "brew-cask":
		return []string{"brew"}
	case "termux-pkg":
		return []string{"termux"}
	case "pkgutil", "port":
		return nil // no repository configuration to read; nothing to compare
	default:
		return []string{pkgProvider}
	}
}

// hasConfiguredSource reports whether an enabled repository is configured for
// the ecosystem a package provider belongs to.
func hasConfiguredSource(sources []models.PackageSource, pkgProvider string) bool {
	ecosystems := sourceEcosystems(pkgProvider)
	if len(ecosystems) == 0 {
		return true // nothing to check against, so no unattributable claim
	}
	for _, s := range sources {
		if !s.Enabled {
			continue
		}
		for _, eco := range ecosystems {
			if s.Provider == eco {
				return true
			}
		}
	}
	return false
}

// processRules covers running processes and registered services.
func processRules() []Rule {
	return []Rule{
		{
			ID:             "PRC-001",
			Title:          "Process command line exposes credentials or tokens",
			Category:       models.CategoryProcess,
			ModuleID:       "process-service",
			Description:    "A process launched with a token or password on its command line publishes it to every local account, since the process table is world-readable on most systems.",
			Recommendation: "Pass credentials through the environment or a file with restrictive permissions rather than on the command line.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivitySecret,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, p := range s.Processes {
					if !argsHoldCredential(p.Args) {
						continue
					}
					out = append(out, Match{
						Objects: []string{p.Name},
						Attributes: map[string]string{
							"pid": strconv.Itoa(p.PID), "user": p.User, "executable": p.Exe,
						},
					})
				}
				return out
			},
		},
		{
			ID:             "PRC-002",
			Title:          "Process running with an unexpected working directory",
			Category:       models.CategoryProcess,
			ModuleID:       "process-service",
			Description:    "A long-running process whose working directory is a temporary or world-writable location is either badly written or has been started from a location another account can write to.",
			Recommendation: "Start the process from a directory only its own account can write to.",
			Severity:       models.SeverityMedium,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, p := range s.Processes {
					if p.Cwd == "" {
						continue
					}
					if !isTemporaryPath(p.Cwd) {
						continue
					}
					out = append(out, Match{
						Objects: []string{p.Name},
						Attributes: map[string]string{
							"pid": strconv.Itoa(p.PID), "user": p.User, "cwd": p.Cwd,
						},
					})
				}
				return out
			},
		},
		{
			ID:             "PRC-003",
			Title:          "Enabled service runs as an interactive-capable account",
			Category:       models.CategoryProcess,
			ModuleID:       "process-service",
			Description:    "A service that starts at boot and runs under an account which can also open a login session gives an attacker who reaches that service a shell, not just the service's own privileges.",
			Recommendation: "Give the service a dedicated non-interactive account.",
			Severity:       models.SeverityMedium,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivitySensitive,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, svc := range s.Services {
					if !strings.EqualFold(svc.State, "running") && svc.Enabled != "enabled" {
						continue
					}
					if svc.User == "" || !isInteractiveShell(filepath.Base(svc.User)) {
						continue
					}
					// A service running as a real person's account is the
					// expected shape on a workstation and suspicious on a
					// server; both are reported, the exposure carries the
					// difference.
					out = append(out, Match{
						Objects:    []string{svc.Name},
						Attributes: map[string]string{"user": svc.User, "kind": svc.Kind, "exec_start": svc.ExecStart},
					})
				}
				return out
			},
		},
		{
			ID:             "PRC-004",
			Title:          "Service definition references a path outside the standard locations",
			Category:       models.CategoryProcess,
			ModuleID:       "process-service",
			Description:    "A unit or launch definition that points at a binary in a temporary or home directory is running with elevated privileges from a location that is writable without them.",
			Recommendation: "Install the executable under the service manager's own directory and remove the permissive path.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivSystem,
			Sensitivity:    models.SensitivitySensitive,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, svc := range s.Services {
					exe := svc.ExecStart
					if exe == "" {
						continue
					}
					if !isWritableByUserPath(exe) {
						continue
					}
					out = append(out, Match{
						Objects:    []string{svc.Name},
						Attributes: map[string]string{"exec_start": exe, "user": svc.User, "kind": svc.Kind},
					})
				}
				return out
			},
		},
	}
}

// argsHoldCredential reports whether a command line contains a credential-shaped
// argument.
//
// The check is on the shape of the argument after an assignment flag, not on the
// whole string, so that a program path containing the word "password" is not
// reported and a genuinely embedded token is.
func argsHoldCredential(args string) bool {
	if args == "" {
		return false
	}
	lower := strings.ToLower(args)
	for _, flag := range []string{
		"--password", "-p", "--pass", "--token", "--secret", "--api-key",
		"--apikey", "--access-key", "--auth-token", "--client-secret",
	} {
		for _, sep := range []string{"=", " "} {
			idx := strings.Index(lower, flag+sep)
			if idx < 0 {
				continue
			}
			value := args[idx+len(flag)+len(sep):]
			if i := strings.IndexAny(value, " \t"); i >= 0 {
				value = value[:i]
			}
			if len(value) >= 8 && !isPlaceholderToken(value) {
				return true
			}
		}
	}
	// A URI with inline credentials, in any argument.
	if strings.Contains(args, "://") {
		if at := strings.Index(args, "@"); at > 0 {
			cred := args[:at]
			if colon := strings.LastIndex(cred, ":"); colon > 0 && len(cred[colon+1:]) >= 6 {
				return true
			}
		}
	}
	return false
}

func isPlaceholderToken(v string) bool {
	l := strings.ToLower(v)
	switch l {
	case "true", "false", "none", "null", "prompt", "ask", "-", "--", "0", "1":
		return true
	}
	return strings.Contains(l, "changeme") || strings.Contains(l, "example") ||
		strings.Contains(l, "redacted") || strings.Contains(l, "your")
}

func isTemporaryPath(path string) bool {
	l := strings.ToLower(path)
	for _, prefix := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/private/var/folders/"} {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	if strings.HasPrefix(l, "c:\\windows\\temp") || strings.Contains(l, "\\temp\\") {
		return true
	}
	return false
}

func isWritableByUserPath(path string) bool {
	l := strings.ToLower(path)
	if isTemporaryPath(l) {
		return true
	}
	for _, prefix := range []string{"/home/", "/users/", "/export/home/", "/var/folders/"} {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	if strings.Contains(l, "appdata\\") || strings.Contains(l, "appdata/") {
		return true
	}
	// Windows per-user installs.
	if strings.HasPrefix(l, `c:\users\`) {
		return true
	}
	return false
}

// persistenceRules covers what runs again without anyone choosing it.
func persistenceRules() []Rule {
	return []Rule{
		{
			ID:             "PER-001",
			Title:          "Startup entry runs a command from a user-writable location",
			Category:       models.CategoryPersistence,
			ModuleID:       "persistence",
			Description:    "A shell profile, launch agent or scheduled task that executes something from a temporary or home directory gives any process running as the user a way to run code with that user's privileges at every login.",
			Recommendation: "Move the target into a directory only an administrator can write to.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivitySensitive,
			Confidence:     models.ConfidenceObserved,
			MinimumDepth:   DepthDeep,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, a := range s.Assets {
					if a.Domain != "persistence" {
						continue
					}
					target := a.Attributes["exec_start"]
					if target == "" {
						target = a.Attributes["command"]
					}
					if target == "" || !isWritableByUserPath(target) {
						continue
					}
					out = append(out, Match{
						Objects:    []string{a.Path},
						Attributes: map[string]string{"mechanism": a.Attributes["mechanism"], "target": target},
					})
				}
				return out
			},
		},
		{
			ID:             "PER-002",
			Title:          "Shell profile sources an external or generated file",
			Category:       models.CategoryPersistence,
			ModuleID:       "persistence",
			Description:    "A profile that sources a file it generates, or one outside the home directory, makes the contents of that file part of every future session; the file's own permissions then decide who controls the session.",
			Recommendation: "Source only files the owning account alone can write to.",
			Severity:       models.SeverityMedium,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivitySensitive,
			Confidence:     models.ConfidenceProbable,
			MinimumDepth:   DepthDeep,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, a := range s.Assets {
					if a.Domain != "persistence" {
						continue
					}
					cmd := a.Attributes["command"]
					if cmd == "" || !strings.HasPrefix(cmd, ".") && !strings.HasPrefix(cmd, "source") {
						continue
					}
					target := strings.Fields(cmd)
					if len(target) == 0 {
						continue
					}
					last := target[len(target)-1]
					if strings.HasPrefix(last, "/") && isWritableByUserPath(last) {
						out = append(out, Match{
							Objects:    []string{a.Path},
							Attributes: map[string]string{"command": cmd, "mechanism": a.Attributes["mechanism"]},
						})
					}
				}
				return out
			},
		},
		{
			ID:             "PER-003",
			Title:          "Startup entry runs a hidden or obfuscated command",
			Category:       models.CategoryPersistence,
			ModuleID:       "persistence",
			Description:    "A startup entry using base64 decoding, an eval, or a piped download executes code the operator cannot read from the configuration file, which is how a persistence mechanism avoids being noticed.",
			Recommendation: "Rewrite the entry as a readable command, or remove it if its purpose is unknown.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivitySensitive,
			Confidence:     models.ConfidenceObserved,
			MinimumDepth:   DepthDeep,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, a := range s.Assets {
					if a.Domain != "persistence" {
						continue
					}
					cmd := a.Attributes["command"] + " " + a.Attributes["exec_start"]
					lower := strings.ToLower(cmd)
					obfuscated := false
					for _, token := range []string{"base64 -d", "base64 --decode", "| sh", "| bash", "eval ", "exec ", "curl ", "wget ", "base64 -D"} {
						if strings.Contains(lower, token) {
							obfuscated = true
							break
						}
					}
					if !obfuscated {
						continue
					}
					out = append(out, Match{
						Objects:    []string{a.Path},
						Attributes: map[string]string{"mechanism": a.Attributes["mechanism"], "command": strings.TrimSpace(cmd)},
					})
				}
				return out
			},
		},
	}
}

// toolingRules covers installed development and security tooling.
func toolingRules() []Rule {
	return []Rule{
		{
			ID:             "TOOL-001",
			Title:          "Offensive security tooling is installed on this host",
			Category:       models.CategoryTooling,
			ModuleID:       "tooling",
			Description:    "Credential crackers, exploitation frameworks and scanners are present. On an operator's workstation this is frequently legitimate, and it is also exactly the toolset an attacker installs after gaining access, so it is reported with the tool named rather than as a category.",
			Recommendation: "Confirm the tooling is expected for this host's role, and remove what is not. On a shared or general-purpose host, keep offensive tooling on a dedicated analysis machine.",
			Severity:       models.SeverityMedium,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, a := range s.Assets {
					if a.Domain != "tooling" || a.Attributes["category"] != "offensive" {
						continue
					}
					out = append(out, Match{
						Objects:    []string{a.Name},
						Attributes: map[string]string{"kind": a.Attributes["disclosure"]},
					})
				}
				return out
			},
		},
		{
			ID:             "TOOL-002",
			Title:          "Packet capture or intrusion detection tooling can observe all traffic",
			Category:       models.CategoryTooling,
			ModuleID:       "tooling",
			Description:    "A traffic capture tool on a workstation sees everything crossing the machine, including traffic to services the operator does not own.",
			Recommendation: "Capture only on hosts and interfaces where it is needed, and prefer a dedicated sensor.",
			Severity:       models.SeverityLow,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivSystem,
			Sensitivity:    models.SensitivitySensitive,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, a := range s.Assets {
					if a.Domain != "tooling" || a.Attributes["category"] != "defensive" {
						continue
					}
					switch a.Name {
					case "wireshark", "tshark", "tcpdump", "suricata", "snort", "falco", "osquery":
					default:
						continue
					}
					out = append(out, Match{
						Objects:    []string{a.Name},
						Attributes: map[string]string{"kind": a.Attributes["disclosure"]},
					})
				}
				return out
			},
		},
	}
}

// appRules covers user application data directories.
func appRules() []Rule {
	return []Rule{
		{
			ID:             "APP-001",
			Title:          "Browser profile data is present on this host",
			Category:       models.CategoryPrivacy,
			ModuleID:       "browser-apps",
			Description:    "A browser profile directory holds history, cookies, saved credentials and autofill data. Its existence discloses the applications in use and its volume indicates how much history they hold. Nothing inside it is read.",
			Recommendation: "Review what each browser stores locally, and use a dedicated or hardened browser profile for work that carries organisational data.",
			Severity:       models.SeverityLow,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, a := range s.Assets {
					if a.Domain != "browser-apps" {
						continue
					}
					out = append(out, Match{
						Objects:    []string{a.Name},
						Attributes: map[string]string{"path": a.Path, "bytes": a.Attributes["bytes"]},
					})
				}
				return out
			},
		},
		{
			ID:             "APP-002",
			Title:          "Messenger or mail client data is present on this host",
			Category:       models.CategoryPrivacy,
			ModuleID:       "browser-apps",
			Description:    "Local mail and messenger stores hold message history, contact lists and often cached attachments, and they are usually retained long after the conversations matter.",
			Recommendation: "Apply the same retention policy to local mail and chat stores that applies to the server, and encrypt them at rest.",
			Severity:       models.SeverityLow,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, a := range s.Assets {
					if a.Domain != "browser-apps" {
						continue
					}
					switch a.Attributes["category"] {
					case "mail", "messenger":
					default:
						continue
					}
					out = append(out, Match{
						Objects:    []string{a.Name},
						Attributes: map[string]string{"path": a.Path, "bytes": a.Attributes["bytes"]},
					})
				}
				return out
			},
		},
	}
}

// permissionRules covers sensitive files readable by accounts that should not
// reach them.
func permissionRules() []Rule {
	return []Rule{
		{
			ID:             "PERM-001",
			Title:          "Private key file is readable by another account",
			Category:       models.CategoryFilesystem,
			ModuleID:       "file-permissions",
			Description:    "An SSH or cloud private key that other local accounts can read is a key that those accounts can use to authenticate as this user.",
			Recommendation: "Set the file mode to 0600 and its directory to 0700.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivitySecret,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, a := range s.Assets {
					if a.Domain != "file-permissions" || !isPrivateKeyFile(a.Path) {
						continue
					}
					if a.Attributes["world_readable"] != "true" && a.Attributes["group_readable"] != "true" {
						continue
					}
					out = append(out, Match{
						Objects:    []string{a.Path},
						Attributes: map[string]string{"mode": a.Attributes["mode"], "owner": a.Attributes["owner"]},
					})
				}
				return out
			},
		},
		{
			ID:             "PERM-002",
			Title:          "Credential or secret file is readable by another account",
			Category:       models.CategoryFilesystem,
			ModuleID:       "file-permissions",
			Description:    "A file that holds a credential in cleartext and is readable by other local accounts discloses that credential to every one of them.",
			Recommendation: "Restrict the file to mode 0600, or move the credential into a secret store.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivitySecret,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, a := range s.Assets {
					if a.Domain != "file-permissions" || isPrivateKeyFile(a.Path) {
						continue
					}
					if !isCredentialFileName(a.Path) {
						continue
					}
					if a.Attributes["world_readable"] != "true" && a.Attributes["group_readable"] != "true" {
						continue
					}
					out = append(out, Match{
						Objects:    []string{a.Path},
						Attributes: map[string]string{"mode": a.Attributes["mode"], "owner": a.Attributes["owner"]},
					})
				}
				return out
			},
		},
		{
			ID:             "PERM-003",
			Title:          "Sensitive file is world-writable",
			Category:       models.CategoryFilesystem,
			ModuleID:       "file-permissions",
			Description:    "A sensitive file that every account can write is a file whose contents the next process to read them does not control.",
			Recommendation: "Remove world-write permission and confirm which account needs write access.",
			Severity:       models.SeverityHigh,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivitySensitive,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, a := range s.Assets {
					if a.Domain != "file-permissions" || a.Attributes["world_writable"] != "true" {
						continue
					}
					if !sensitivePath(a.Path) {
						continue
					}
					out = append(out, Match{
						Objects:    []string{a.Path},
						Attributes: map[string]string{"mode": a.Attributes["mode"], "owner": a.Attributes["owner"]},
					})
				}
				return out
			},
		},
	}
}

func isPrivateKeyFile(path string) bool {
	l := strings.ToLower(filepath.Base(path))
	if strings.Contains(l, "id_rsa") || strings.Contains(l, "id_ed25519") ||
		strings.Contains(l, "id_ecdsa") || strings.Contains(l, "id_dsa") {
		return true
	}
	if strings.HasPrefix(l, "ssh_host_") {
		return true
	}
	if strings.Contains(path, "/.ssh/") && !strings.Contains(l, ".pub") {
		return strings.Contains(l, "_key") || !strings.Contains(l, "config")
	}
	return false
}

func isCredentialFileName(path string) bool {
	l := strings.ToLower(filepath.Base(path))
	if strings.Contains(l, "credentials") || strings.Contains(l, "secrets") ||
		strings.Contains(l, ".netrc") || strings.Contains(l, ".pgpass") ||
		strings.Contains(l, ".git-credentials") || l == ".npmrc" || l == ".pypirc" ||
		strings.Contains(l, "access_tokens") || l == ".env" ||
		strings.HasPrefix(l, ".env.") {
		return true
	}
	return false
}

// tempRules covers what survives in temporary and cache directories.
func tempRules() []Rule {
	return []Rule{
		{
			ID:             "TMP-001",
			Title:          "Temporary directory holds a large volume of unreviewed data",
			Category:       models.CategoryPrivacy,
			ModuleID:       "temp-cache",
			Description:    "Temporary directories accumulate working copies, exports and cached documents that nobody intends to keep and nobody has reviewed. Their lifetime is unbounded and their permissions are usually inherited from a shared directory.",
			Recommendation: "Clear temporary directories on a schedule, and exclude them from backups and from image capture.",
			Severity:       models.SeverityLow,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, a := range s.Assets {
					if a.Domain != "temp-cache" {
						continue
					}
					size := a.Attributes["bytes"]
					if size == "" || parseBytes(size) < tempNoiseFloor {
						continue
					}
					out = append(out, Match{
						Objects:    []string{a.Path},
						Attributes: map[string]string{"bytes": size, "files": a.Attributes["files"]},
					})
				}
				return out
			},
		},
		{
			ID:             "TMP-002",
			Title:          "Temporary directory is readable by other accounts",
			Category:       models.CategoryPrivacy,
			ModuleID:       "temp-cache",
			Description:    "A per-user temporary directory other accounts can list is a directory they can also read, and it is where applications write files while working on them.",
			Recommendation: "Give each user their own temporary directory with mode 0700.",
			Severity:       models.SeverityMedium,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivitySensitive,
			Confidence:     models.ConfidenceObserved,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, a := range s.Assets {
					if a.Domain != "temp-cache" {
						continue
					}
					if a.Attributes["world_readable"] != "true" && a.Attributes["group_readable"] != "true" {
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

// tempNoiseFloor is the volume above which a temporary directory is worth a
// finding. Below this it is a cache, which is the directory's purpose.
const tempNoiseFloor = 50 << 20

func parseBytes(s string) int64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	var mult int64 = 1
	switch {
	case strings.HasSuffix(s, "KiB"):
		mult, s = 1<<10, strings.TrimSuffix(s, "KiB")
	case strings.HasSuffix(s, "MiB"):
		mult, s = 1<<20, strings.TrimSuffix(s, "MiB")
	case strings.HasSuffix(s, "GiB"):
		mult, s = 1<<30, strings.TrimSuffix(s, "GiB")
	}
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0
	}
	return n * mult
}

// metadataRules covers embedded document metadata.
func metadataRules() []Rule {
	return []Rule{
		{
			ID:             "META-001",
			Title:          "Document embeds author or organisation metadata",
			Category:       models.CategoryPrivacy,
			ModuleID:       "metadata",
			Description:    "The document records who created or last edited it, or the organisation it was produced for. That travels with every copy and is usually left in place when the content is scrubbed.",
			Recommendation: "Strip document metadata before sharing externally, and use a template that does not embed a personal identity.",
			Severity:       models.SeverityMedium,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			MinimumDepth:   DepthDeep,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, a := range s.Assets {
					if a.Domain != "metadata" || a.Attributes["identity_metadata"] != "true" {
						continue
					}
					out = append(out, Match{
						Objects: []string{a.Path},
						Attributes: map[string]string{
							"keys":             a.Attributes["metadata_keys"],
							"author":           a.Attributes["meta_author"],
							"last_modified_by": a.Attributes["meta_last_modified_by"],
							"company":          a.Attributes["meta_company"],
						},
					})
				}
				return out
			},
		},
		{
			ID:             "META-002",
			Title:          "Document with embedded identity metadata is readable by other accounts",
			Category:       models.CategoryPrivacy,
			ModuleID:       "metadata",
			Description:    "A document carrying its author's identity is readable by other local accounts, so the identity is disclosed to them as well as to whoever the document is later shared with.",
			Recommendation: "Restrict the containing directory to the owning account.",
			Severity:       models.SeverityMedium,
			Exposure:       models.ScopeLocal,
			Privilege:      models.PrivUser,
			Sensitivity:    models.SensitivityInternal,
			Confidence:     models.ConfidenceObserved,
			MinimumDepth:   DepthDeep,
			Match: func(s *Snapshot) []Match {
				var out []Match
				for _, a := range s.Assets {
					if a.Domain != "metadata" || a.Attributes["identity_metadata"] != "true" {
						continue
					}
					if !worldReadableMode(a.Attributes["mode"]) && !groupReadableMode(a.Attributes["mode"]) {
						continue
					}
					out = append(out, Match{
						Objects:    []string{a.Path},
						Attributes: map[string]string{"mode": a.Attributes["mode"], "author": a.Attributes["meta_author"]},
					})
				}
				return out
			},
		},
	}
}

func worldReadableMode(mode string) bool {
	if len(mode) != 9 {
		return false
	}
	return mode[6] != '-'
}

func groupReadableMode(mode string) bool {
	if len(mode) != 9 {
		return false
	}
	return mode[3] != '-'
}
