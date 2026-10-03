package modules

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/QYVORA/qyvora-amina/internal/platform"
	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// This file holds the collectors that read what the operator left behind: shell
// configuration, environment variables, developer identity, cloud credentials,
// installed tooling, user application data and host hardening.

// collectShellTerminal reads shell configuration and history presence.
//
// Configuration is parsed for its own contents because a history file is
// reported by existence, size and readability only. Its content is the most
// sensitive thing on a workstation and nothing in the report requires reading
// it; the finding is "there is a history here and other accounts can read it".
func collectShellTerminal(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapShell}}, nil
	}
	support := e.SupportLevel(platform.CapShell)

	var assets []models.Asset
	var secrets []models.SecretRecord
	var signals []models.IdentitySignal

	// Shell configuration: parsed for the settings that matter and for the
	// identity disclosures it contains.
	for _, rc := range e.Paths.ShellRC {
		if !platform.Readable(rc) {
			continue
		}
		lines, err := platform.ReadLines(rc, 2000)
		if err != nil {
			continue
		}
		a := models.Asset{
			Kind: models.KindShellConfig, Domain: "shell-terminal",
			Name: filepath.Base(rc), Path: rc, Platform: e.Platform,
			Support: support, Source: "platform:shell-config",
		}
		a.Set("mode", platform.ModeString(rc))
		a.Set("owner", ownerOf(rc))
		a.Set("lines", itoa(len(lines)))

		// PS1 is the prompt. A prompt carrying the username, the host or the
		// working directory publishes all three in every screenshot ever taken.
		for n, line := range lines {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "PS1=") && !strings.HasPrefix(trimmed, "PROMPT=") {
				continue
			}
			a.Set("prompt_line", itoa(n+1))
			a.Set("prompt", promptDisclosures(trimmed))
			break
		}
		// HISTFILE / HISTCONTROL / HISTSIZE tell the reader what will be kept.
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			for _, key := range []string{"HISTFILE", "HISTCONTROL", "HISTSIZE", "HISTFILESIZE", "HISTTIMEFORMAT"} {
				if strings.HasPrefix(trimmed, key) {
					a.Set(strings.ToLower(key), strings.TrimSpace(strings.TrimPrefix(trimmed, key)))
				}
			}
		}
		assets = append(assets, a)

		// A credential pasted into a shell rc file is a real and common leak.
		det := newSecretDetector(e)
		for n, line := range lines {
			typ, field, value, ok := det.match(line)
			if !ok {
				continue
			}
			rec := secretRecord(typ, rc, n+1, field, e, "credential in shell configuration")
			rec.Length = len(value)
			secrets = append(secrets, rec)
			sa := secretAsset(rc, string(typ), field, e, support)
			sa.Set("line", itoa(n+1))
			assets = append(assets, sa)
		}
	}

	// History files: presence, size and who can read them.
	for _, hf := range e.Paths.HistoryFiles {
		if !platform.Exists(hf) {
			continue
		}
		a := models.Asset{
			Kind: models.KindShellConfig, Domain: "shell-terminal",
			Name: filepath.Base(hf), Path: hf, Platform: e.Platform,
			Support: support, Source: "platform:shell-history",
		}
		a.Set("mode", platform.ModeString(hf))
		a.Set("owner", ownerOf(hf))
		a.Set("bytes", itoa64(fileSize(hf)))
		a.Set("readable_by_others", boolString(groupReadable(platform.ModeString(hf)) || worldReadable(platform.ModeString(hf))))
		assets = append(assets, a)
	}

	// TERM and the terminal program are identity signals, and they are among
	// the most commonly leaked in shared screen recordings.
	if e.Terminal != "" {
		signals = append(signals, models.IdentitySignal{
			Type: "device", Value: e.Terminal, Source: "environment", Domain: "shell-terminal",
		})
	}
	if e.TermProgram != "" {
		signals = append(signals, models.IdentitySignal{
			Type: "device", Value: e.TermProgram, Source: "environment", Domain: "shell-terminal",
		})
	}

	res := Result{Assets: assets, Secrets: secrets, Identities: signals}
	if support == models.SupportNone {
		res.Degraded = true
		res.Note = "shell configuration could not be read on this host"
		res.Unavailable = []string{platform.CapShell}
	}
	return res, nil
}

func worldReadable(mode string) bool {
	return len(mode) >= 9 && mode[6] != '-'
}

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// promptDisclosures reports which identity components a prompt string will show.
func promptDisclosures(prompt string) string {
	var found []string
	// The escapes are the shell prompt expansions. Each one is something a
	// screenshot of the terminal will contain.
	for escape, name := range map[string]string{
		"\\u": "username", "\\h": "hostname", "\\H": "fqdn",
		"\\w": "working_directory", "\\W": "working_directory_basename",
		"\\n": "username", "\\d": "date", "\\T": "time",
		"\\s": "shell", "\\v": "shell_version", "\\@": "time",
		"\\[`": "command_output",
	} {
		if strings.Contains(prompt, escape) {
			found = append(found, name)
		}
	}
	sort.Strings(found)
	return strings.Join(found, ",")
}

// collectEnvironment reads the process environment for identity and token
// disclosures.
//
// Only variables whose *names* indicate a credential or an identity are
// recorded, and a secret-shaped value is reduced to a fingerprint. A general
// environment dump is not produced: it would copy the parent process's
// environment into a report file, which is a worse version of the problem this
// tool exists to report.
func collectEnvironment(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapEnvironment}}, nil
	}
	support := e.SupportLevel(platform.CapEnvironment)

	env := environMap()
	if len(env) == 0 {
		return Result{Degraded: true, Note: "the process environment could not be read on this host",
			Unavailable: []string{platform.CapEnvironment}}, nil
	}

	names := make([]string, 0, len(env))
	for k := range env {
		names = append(names, k)
	}
	sort.Strings(names)

	var assets []models.Asset
	var secrets []models.SecretRecord
	var signals []models.IdentitySignal

	for _, name := range names {
		value := env[name]
		upper := strings.ToUpper(name)

		// Environment variables whose value is credential-shaped are recorded as
		// a fingerprint and nothing else.
		if typ, ok := credentialVariable(upper); ok && len(value) >= 8 && !isPlaceholder(value) {
			fp := platform.Fingerprint(e.MachineID+":"+name+":"+value, 12)
			secrets = append(secrets, models.SecretRecord{
				Type:        typ,
				Location:    "environment:" + name,
				Field:       name,
				Fingerprint: fp,
				Length:      len(value),
				Source:      "platform:environment",
				Redaction:   models.RedactionFingerprint,
			})
			a := models.Asset{
				Kind: models.KindEnvironment, Domain: "environment",
				Name: name, Platform: e.Platform, Support: support,
				Source: "platform:environment",
			}
			a.Set("secret_type", string(typ))
			a.Set("fingerprint", fp)
			a.Set("length", itoa(len(value)))
			assets = append(assets, a)
			continue
		}

		// Identity-bearing variables are recorded in full: they are not secret,
		// they are the disclosure being reported.
		if identityVariable(upper) && value != "" {
			a := models.Asset{
				Kind: models.KindEnvironment, Domain: "environment",
				Name: name, Platform: e.Platform, Support: support,
				Source: "platform:environment",
			}
			a.Set("value", value)
			assets = append(assets, a)
			signals = append(signals, models.IdentitySignal{
				Type: "username", Value: value, Source: "environment:" + name, Domain: "environment",
			})
		}
	}

	res := Result{Assets: assets, Secrets: secrets, Identities: signals}
	if support == models.SupportNone {
		res.Degraded = true
		res.Note = "environment inspection was not possible on this host"
		res.Unavailable = []string{platform.CapEnvironment}
	}
	return res, nil
}

// credentialVariables are the environment variable names that hold credentials.
// The match is on the name alone, so an unknown provider's token is still
// classified correctly.
var credentialVariables = map[string]models.SecretType{
	"AWS_SECRET_ACCESS_KEY":          models.SecretCloudCredential,
	"AWS_ACCESS_KEY_ID":              models.SecretCloudCredential,
	"AWS_SESSION_TOKEN":              models.SecretCloudCredential,
	"AZURE_CLIENT_SECRET":            models.SecretCloudCredential,
	"GOOGLE_APPLICATION_CREDENTIALS": models.SecretCloudCredential,
	"GITHUB_TOKEN":                   models.SecretToken,
	"GH_TOKEN":                       models.SecretToken,
	"GL_TOKEN":                       models.SecretToken,
	"NPM_TOKEN":                      models.SecretToken,
	"DOCKER_PASSWORD":                models.SecretPassword,
	"OPENAI_API_KEY":                 models.SecretAPIKey,
	"ANTHROPIC_API_KEY":              models.SecretAPIKey,
	"SLACK_TOKEN":                    models.SecretToken,
	"DATABASE_URL":                   models.SecretDatabaseCredential,
	"DB_PASSWORD":                    models.SecretPassword,
	"SSH_AUTH_SOCK":                  models.SecretConfiguration,
}

func credentialVariable(upper string) (models.SecretType, bool) {
	if t, ok := credentialVariables[upper]; ok {
		return t, true
	}
	// A suffix match catches provider-specific names the table does not list,
	// such as ACME_API_TOKEN.
	for _, suffix := range []string{"_TOKEN", "_PASSWORD", "_PASSWD", "_SECRET", "_API_KEY", "_SECRET_KEY", "_ACCESS_KEY", "_JWT"} {
		if strings.HasSuffix(upper, suffix) && len(upper) > len(suffix) {
			switch {
			case strings.Contains(upper, "AWS") || strings.Contains(upper, "AZURE") || strings.Contains(upper, "GCP") || strings.Contains(upper, "GOOGLE"):
				return models.SecretCloudCredential, true
			case strings.Contains(upper, "DB") || strings.Contains(upper, "DATABASE") || strings.Contains(upper, "POSTGRES") || strings.Contains(upper, "MYSQL") || strings.Contains(upper, "MONGO"):
				return models.SecretDatabaseCredential, true
			case strings.Contains(upper, "JWT"):
				return models.SecretJWT, true
			default:
				return models.SecretToken, true
			}
		}
	}
	return "", false
}

// identityVariables are the environment variable names that disclose who or
// where the operator is.
var identityVariables = map[string]string{
	"USER": "username", "USERNAME": "username", "LOGNAME": "username",
	"HOSTNAME": "hostname", "COMPUTERNAME": "hostname", "HOME": "home",
	"HOMEPATH": "home", "USERPROFILE": "home", "PWD": "working_directory",
	"OLDPWD": "working_directory", "SHELL": "shell", "TERM": "device",
	"TERM_PROGRAM": "device", "GIT_AUTHOR_EMAIL": "email",
	"GIT_COMMITTER_EMAIL": "email", "EMAIL": "email",
	"KUBECONFIG": "path", "AWS_PROFILE": "account",
	"CONTAINER": "environment", "KUBERNETES_SERVICE_HOST": "environment",
	"AWS_REGION": "infrastructure", "AWS_DEFAULT_REGION": "infrastructure",
	"GOOGLE_CLOUD_PROJECT": "infrastructure", "GIT_WORK_TREE": "project",
	"SSH_CONNECTION": "network", "SSH_CLIENT": "network", "SSH_TTY": "device",
	"DISPLAY": "device", "LANG": "locale", "EDITOR": "tooling",
}

func identityVariable(upper string) bool {
	_, ok := identityVariables[upper]
	return ok
}

// collectDeveloperIdentity reads git configuration, which records a name and an
// email address on every host a developer commits from.
func collectDeveloperIdentity(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapGit}}, nil
	}
	support := e.SupportLevel(platform.CapGit)

	var assets []models.Asset
	var signals []models.IdentitySignal

	seen := map[string]bool{}
	for _, cfg := range gitConfigFiles(e) {
		if seen[cfg] || !platform.Readable(cfg) {
			continue
		}
		seen[cfg] = true
		lines, err := platform.ReadLines(cfg, 1000)
		if err != nil {
			continue
		}
		// Only the identity and remote sections are read. Repository-specific
		// settings are not this module's concern and may contain credentials
		// in URLs.
		inScope := false
		for n, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "[") {
				section := strings.ToLower(strings.Trim(trimmed, "[]"))
				inScope = strings.HasPrefix(section, "user") || strings.HasPrefix(section, "remote")
				continue
			}
			if !inScope {
				continue
			}
			key, value, ok := strings.Cut(trimmed, "=")
			if !ok {
				continue
			}
			key = strings.ToLower(strings.TrimSpace(key))
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			switch key {
			case "user.name":
				assets = append(assets, gitAsset(e, cfg, n+1, "user.name", value, support))
				signals = append(signals, models.IdentitySignal{
					Type: "username", Value: value, Source: cfg, Domain: "developer-identity",
				})
			case "user.email":
				assets = append(assets, gitAsset(e, cfg, n+1, "user.email", value, support))
				signals = append(signals, models.IdentitySignal{
					Type: "email", Value: value, Source: cfg, Domain: "developer-identity",
				})
			}
			if strings.HasPrefix(key, "remote.") && strings.HasSuffix(key, ".url") {
				// A remote URL can embed a token. Only the host and path are
				// recorded, and only after the userinfo is stripped.
				clean := stripURLCredentials(value)
				assets = append(assets, gitAsset(e, cfg, n+1, "remote.url", clean, support))
				if host, path, ok := splitRemoteURL(clean); ok {
					signals = append(signals, models.IdentitySignal{
						Type: "remote", Value: host + "/" + path, Source: cfg, Domain: "developer-identity",
					})
				}
			}
		}
	}

	// Remotes of the repository in the working directory, when there is one.
	if wd, err := os.Getwd(); err == nil {
		if out, err := platform.Run(in.Ctx, "git", "-C", wd, "remote", "-v"); err == nil {
			for _, line := range strings.Split(out, "\n") {
				clean := stripURLCredentials(strings.TrimSpace(line))
				if clean == "" {
					continue
				}
				assets = append(assets, gitAsset(e, filepath.Join(wd, ".git", "config"), 0, "remote", clean, support))
				if host, path, ok := splitRemoteURL(clean); ok {
					signals = append(signals, models.IdentitySignal{
						Type: "remote", Value: host + "/" + path, Source: "git remote", Domain: "developer-identity",
					})
				}
			}
		}
	}

	res := Result{Assets: assets, Identities: signals}
	if len(assets) == 0 {
		res.Degraded = true
		res.Note = "no git identity configuration was found on this host"
		res.Unavailable = []string{platform.CapGit}
	}
	return res, nil
}

func gitConfigFiles(e *platform.Env) []string {
	var out []string
	if e.Paths.GitConfig != "" {
		out = append(out, e.Paths.GitConfig)
	}
	if e.Paths.GitConfigGlobal != "" {
		out = append(out, e.Paths.GitConfigGlobal)
	}
	if e.Home != "" {
		out = append(out, filepath.Join(e.Home, ".gitconfig"))
	}
	if e.Paths.ConfigHome != "" {
		out = append(out, filepath.Join(e.Paths.ConfigHome, "git", "config"))
	}
	return out
}

func gitAsset(e *platform.Env, path string, line int, key, value string, support models.SupportLevel) models.Asset {
	a := models.Asset{
		Kind: models.KindGitIdentity, Domain: "developer-identity",
		Name: key, Path: path, Platform: e.Platform, Support: support,
		Source: "platform:git-config",
	}
	a.Set("value", value)
	a.Set("setting", key)
	if line > 0 {
		a.Set("line", itoa(line))
	}
	a.Set("mode", platform.ModeString(path))
	return a
}

// stripURLCredentials removes any userinfo from a URL, including a token
// embedded in it. A git remote is the classic place a personal access token
// ends up written to disk in plain text.
//
// Two forms are handled and one deliberately is not:
//
//   - "https://token@host/path" and "user:pass@host/path" lose the userinfo.
//   - "git@host:path" is an scp-style remote, where the part before the @ is
//     the SSH user, not a secret. Rewriting it would produce a URL that no
//     longer works, so it is returned unchanged.
func stripURLCredentials(url string) string {
	scheme := ""
	rest := url
	if i := strings.Index(url, "://"); i >= 0 {
		scheme = url[:i+3]
		rest = url[i+3:]
	} else {
		// A scheme-less "user:pass@host/path" still carries a credential, but
		// only if something precedes the @ that looks like a password. Without
		// a colon it is an scp remote.
		at := strings.Index(rest, "@")
		colon := strings.Index(rest, ":")
		slash := strings.Index(rest, "/")
		if at < 0 || colon < 0 || colon > at || (slash >= 0 && colon > slash) {
			return url
		}
		return rest[at+1:]
	}

	// The authority ends at the first slash after the scheme.
	authority, tail := rest, ""
	if end := strings.Index(rest, "/"); end >= 0 {
		authority, tail = rest[:end], rest[end:]
	}
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		authority = authority[at+1:]
	}
	return scheme + authority + tail
}

// splitRemoteURL breaks a remote into the host and the repository path, which
// are the two parts that identify where code comes from.
func splitRemoteURL(url string) (host, path string, ok bool) {
	rest := url
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	// Drop any userinfo.
	if end := strings.Index(rest, "/"); end >= 0 {
		if at := strings.LastIndex(rest[:end], "@"); at >= 0 {
			rest = rest[at+1:]
		}
	} else if at := strings.Index(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	// An scp-style remote separates host and path with a colon.
	if !strings.Contains(url, "://") {
		if colon := strings.Index(rest, ":"); colon >= 0 && !strings.Contains(rest, "//") {
			host = rest[:colon]
			path = rest[colon+1:]
			path = strings.TrimPrefix(path, "/")
			if host != "" && path != "" {
				return host, path, true
			}
			return "", "", false
		}
	}
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// collectCloudIdentity records which cloud accounts and instances are
// configured, without authenticating to anything.
func collectCloudIdentity(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapCloud}}, nil
	}
	support := e.SupportLevel(platform.CapCloud)

	var assets []models.Asset
	var signals []models.IdentitySignal
	var secrets []models.SecretRecord
	det := newSecretDetector(e)

	rel := []string{
		".aws/credentials", ".aws/config",
		".config/gcloud/application_default_credentials.json",
		".config/gcloud/configurations/config_default",
		".azure/accessTokens.json", ".azure/azureProfile.json",
		".azure/settings", ".kube/config",
		".docker/config.json",
		".config/doctl/config.yaml",
		".terraform.d/credentials.tfrc.json",
	}
	for _, home := range userHomes(e) {
		for _, r := range rel {
			p := filepath.Join(home, filepath.FromSlash(r))
			if !platform.Exists(p) {
				continue
			}
			a := models.Asset{
				Kind: models.KindCloudIdentity, Domain: "cloud-identity",
				Name: filepath.Base(p), Path: p, Platform: e.Platform,
				Support: support, Source: "platform:cloud-config",
			}
			a.Set("mode", platform.ModeString(p))
			a.Set("owner", ownerOf(p))
			a.Set("readable_by_others", boolString(groupReadable(platform.ModeString(p)) || worldReadable(platform.ModeString(p))))

			lines, err := platform.ReadLines(p, 1000)
			if err == nil {
				for n, line := range lines {
					if typ, field, value, ok := det.match(line); ok {
						rec := secretRecord(typ, p, n+1, field, e, "credential in cloud configuration")
						rec.Length = len(value)
						secrets = append(secrets, rec)
					}
					// A profile or account name is an identity disclosure.
					for _, key := range []string{"aws_access_key_id", "aws_profile", "account", "project", "subscription", "tenant", "client_id"} {
						if kv, v, ok := strings.Cut(line, "="); ok && strings.EqualFold(strings.TrimSpace(kv), key) {
							v = strings.Trim(strings.TrimSpace(v), `"',`)
							if v != "" {
								signals = append(signals, models.IdentitySignal{
									Type: "account", Value: v, Source: p, Domain: "cloud-identity",
								})
							}
						}
					}
				}
			}
			assets = append(assets, a)
		}
	}

	// The instance's own metadata identity is a cloud disclosure even when no
	// credential file exists.
	if e.Cloud != "" {
		a := models.Asset{
			Kind: models.KindCloudIdentity, Domain: "cloud-identity",
			Name: "cloud_environment", Platform: e.Platform, Support: support,
			Source: "platform:host-identity",
		}
		a.Set("value", e.Cloud)
		assets = append(assets, a)
	}
	if e.Container {
		a := models.Asset{
			Kind: models.KindCloudIdentity, Domain: "cloud-identity",
			Name: "container_runtime", Platform: e.Platform, Support: support,
			Source: "platform:host-identity",
		}
		a.Set("value", e.ContainerKind)
		assets = append(assets, a)
	}

	res := Result{Assets: assets, Identities: signals, Secrets: secrets}
	if len(assets) == 0 {
		res.Degraded = true
		res.Note = "no cloud identity configuration was found on this host"
		res.Unavailable = []string{platform.CapCloud}
	}
	return res, nil
}

// collectTooling records which development and security tools are installed.
//
// Installed tooling is reported because a tool's presence is itself a
// disclosure: an offensive security toolchain on a workstation says something
// about the operator that no single configuration file would.
func collectTooling(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapTooling}}, nil
	}
	support := e.SupportLevel(platform.CapTooling)

	var assets []models.Asset
	installed := 0
	for _, t := range knownTools {
		if !platform.HasCommand(t.name) {
			continue
		}
		installed++
		a := models.Asset{
			Kind: models.KindTooling, Domain: "tooling",
			Name: t.name, Platform: e.Platform, Support: support,
			Source: "platform:tooling",
		}
		a.Set("category", t.category)
		a.Set("disclosure", t.disclosure)
		assets = append(assets, a)
	}

	res := Result{Assets: assets}
	if installed == 0 {
		res.Note = "no recognised development or security tooling was found on the PATH"
	} else if support == models.SupportNone {
		res.Degraded = true
		res.Note = "the PATH could not be enumerated, so tool presence is unknown"
		res.Unavailable = []string{platform.CapTooling}
	}
	return res, nil
}

type toolSpec struct {
	name       string
	category   string
	disclosure string
}

// knownTools is the set of tools whose presence is worth reporting. It is a
// list of names rather than a pattern match, because a report that says "an
// offensive tool is installed" is only credible if it names the tool.
var knownTools = []toolSpec{
	// Offensive and red-team tooling.
	{"nmap", "offensive", "network scanner"},
	{"masscan", "offensive", "network scanner"},
	{"metasploit", "offensive", "exploitation framework"},
	{"msfconsole", "offensive", "exploitation framework"},
	{"hydra", "offensive", "credential brute-forcer"},
	{"john", "offensive", "password cracker"},
	{"hashcat", "offensive", "password cracker"},
	{"sqlmap", "offensive", "injection tool"},
	{"nikto", "offensive", "web vulnerability scanner"},
	{"gobuster", "offensive", "content discovery"},
	{"ffuf", "offensive", "web fuzzer"},
	{"aircrack-ng", "offensive", "wireless auditing"},
	{"burpsuite", "offensive", "web proxy"},
	{"bettercap", "offensive", "network attack tool"},
	{"responder", "offensive", "network poisoning tool"},
	{"mimikatz", "offensive", "credential extraction"},
	{"impacket", "offensive", "network protocol toolkit"},
	{"cobaltstrike", "offensive", "command and control"},

	// Security and network defence.
	{"wireshark", "defensive", "packet analyser"},
	{"tshark", "defensive", "packet analyser"},
	{"tcpdump", "defensive", "packet capture"},
	{"suricata", "defensive", "intrusion detection"},
	{"snort", "defensive", "intrusion detection"},
	{"falco", "defensive", "runtime security"},
	{"osquery", "defensive", "host query tool"},
	{"lynis", "defensive", "security auditing"},
	{"chkrootkit", "defensive", "rootkit detection"},
	{"rkhunter", "defensive", "rootkit detection"},

	// Developer tooling, which is nearly always present and only occasionally
	// interesting. Included because a leaked path can disclose a company or a
	// project.
	{"git", "development", "version control"},
	{"docker", "development", "container runtime"},
	{"kubectl", "development", "kubernetes client"},
	{"terraform", "development", "infrastructure as code"},
	{"ansible", "development", "configuration management"},
	{"aws", "cloud", "aws command line"},
	{"gcloud", "cloud", "google cloud cli"},
	{"az", "cloud", "azure cli"},
	{"gh", "cloud", "github cli"},
}

// collectBrowserApps records the existence of user application data
// directories.
//
// Only existence, size and permission. The contents of a browser profile are
// the user's browsing history, which is not this tool's subject and which no
// finding in this catalogue requires.
func collectBrowserApps(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapApplications}}, nil
	}
	support := e.SupportLevel(platform.CapApplications)

	var assets []models.Asset
	for _, spec := range appDataLocations(e) {
		if !platform.Exists(spec.path) {
			continue
		}
		a := models.Asset{
			Kind: models.KindApplication, Domain: "browser-apps",
			Name: spec.app, Path: spec.path, Platform: e.Platform,
			Support: support, Source: "platform:application-data",
		}
		a.Set("application", spec.app)
		a.Set("category", spec.category)
		n, bytes := countTree(spec.path, 2)
		a.Set("files", itoa(n))
		a.Set("bytes", itoa64(bytes))
		a.Set("mode", platform.ModeString(spec.path))
		assets = append(assets, a)
	}

	res := Result{Assets: assets}
	if len(assets) == 0 {
		res.Note = "no recognised user application data directories were found"
	} else if support == models.SupportNone {
		res.Degraded = true
		res.Note = "user application directories could not be read on this host"
		res.Unavailable = []string{platform.CapApplications}
	}
	return res, nil
}

// appSpec is a user application data directory. It carries its own shape
// because the browser module reports the application, not a file to read.
type appSpec struct {
	app      string
	path     string
	category string
}

func appDataLocations(e *platform.Env) []appSpec {
	home := e.Home
	if home == "" {
		return nil
	}
	var rel []appSpec
	switch e.Platform {
	case models.PlatformWindows:
		appdata := platform.JoinPath(home, "AppData", "Roaming")
		rel = []appSpec{
			{filepath.Join(appdata, "Mozilla", "Firefox", "Profiles"), "firefox", "browser"},
			{filepath.Join(appdata, "Google", "Chrome", "User Data"), "chrome", "browser"},
			{filepath.Join(appdata, "Microsoft", "Edge", "User Data"), "edge", "browser"},
			{filepath.Join(appdata, "Mozilla", "Thunderbird"), "thunderbird", "mail"},
			{filepath.Join(appdata, "Signal"), "signal", "messenger"},
			{filepath.Join(appdata, "discord"), "discord", "messenger"},
		}
	default:
		cfg := filepath.Join(home, ".config")
		rel = []appSpec{
			{filepath.Join(home, ".mozilla", "firefox"), "firefox", "browser"},
			{filepath.Join(cfg, "google-chrome"), "chrome", "browser"},
			{filepath.Join(cfg, "chromium"), "chromium", "browser"},
			{filepath.Join(cfg, "BraveSoftware"), "brave", "browser"},
			{filepath.Join(home, ".thunderbird"), "thunderbird", "mail"},
			{filepath.Join(cfg, "Signal"), "signal", "messenger"},
			{filepath.Join(cfg, "discord"), "discord", "messenger"},
			{filepath.Join(cfg, "Slack"), "slack", "messenger"},
		}
	}
	out := rel[:0]
	for _, s := range rel {
		if platform.Exists(s.path) {
			out = append(out, s)
		}
	}
	return out
}

// collectOSPosture reads the host hardening settings that change the outcome of
// the other modules' findings.
func collectOSPosture(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapPosture}}, nil
	}
	support := e.SupportLevel(platform.CapPosture)

	var assets []models.Asset
	var missing []string

	posture := func(name, value, expectation string) {
		if value == "" {
			return
		}
		a := models.Asset{
			Kind: models.KindPosture, Domain: "os-posture",
			Name: name, Platform: e.Platform, Support: support,
			Source: "platform:posture",
		}
		a.Set("value", value)
		a.Set("expected", expectation)
		a.Set("setting", name)
		assets = append(assets, a)
	}

	switch e.Platform {
	case models.PlatformLinux, models.PlatformTermux:
		if out, err := platform.Run(in.Ctx, "sysctl", "-n", "kernel.randomize_va_space"); err == nil {
			posture("kernel.randomize_va_space", strings.TrimSpace(out), "2")
		} else {
			missing = append(missing, platform.CapPosture)
		}
		for _, f := range []struct{ path, name, expect string }{
			{"/proc/sys/kernel/yama/ptrace_scope", "kernel.yama.ptrace_scope", "1 or higher"},
			{"/proc/sys/net/ipv4/conf/all/accept_redirects", "net.ipv4.conf.all.accept_redirects", "0"},
			{"/proc/sys/net/ipv4/tcp_syncookies", "net.ipv4.tcp_syncookies", "1"},
		} {
			if lines, err := platform.ReadLines(f.path, 2); err == nil && len(lines) > 0 {
				posture(f.name, strings.TrimSpace(lines[0]), f.expect)
			} else {
				missing = append(missing, platform.CapPosture)
			}
		}
		if platform.Exists("/proc/sys/kernel/randomize_va_space") {
			assets = append(assets, procAsset(e, support, "/proc/sys/kernel/randomize_va_space", "kernel.randomize_va_space", "2"))
		}
		if platform.HasCommand("aa-status") {
			if _, err := platform.Run(in.Ctx, "aa-status", "--json"); err == nil {
				posture("apparmor", "loaded", "enforcing")
			} else {
				missing = append(missing, platform.CapAppArmor)
			}
		}
		if platform.HasCommand("getenforce") {
			if out, err := platform.Run(in.Ctx, "getenforce"); err == nil {
				posture("selinux", strings.TrimSpace(out), "Enforcing")
			} else {
				missing = append(missing, platform.CapSELinux)
			}
		}

	case models.PlatformDarwin:
		if out, err := platform.Run(in.Ctx, "csrutil", "status"); err == nil {
			posture("sip", strings.TrimSpace(out), "enabled")
		} else {
			missing = append(missing, platform.CapGatekeeper)
		}
		if out, err := platform.Run(in.Ctx, "spctl", "--status"); err == nil {
			posture("gatekeeper", strings.TrimSpace(out), "assessments enabled")
		} else {
			missing = append(missing, platform.CapGatekeeper)
		}
		if out, err := platform.Run(in.Ctx, "fdesetup", "status"); err == nil {
			posture("filvault", strings.TrimSpace(out), "On")
		} else {
			missing = append(missing, platform.CapBitLocker)
		}

	case models.PlatformWindows:
		// These need elevation, which the gate has already checked for. If the
		// module is running at all here, the queries are expected to work.
		for _, q := range []struct {
			cmd    string
			args   []string
			name   string
			expect string
		}{
			{"powershell", []string{"-NoProfile", "-Command", "(Get-MpComputerStatus).RealTimeProtectionEnabled"}, "defender.realtime", "True"},
			{"powershell", []string{"-NoProfile", "-Command", "$b=Get-BitLockerVolume -MountPoint C:; $b.ProtectionStatus"}, "bitlocker", "On"},
			{"powershell", []string{"-NoProfile", "-Command", "Confirm-SecureBootUEFI"}, "secureboot", "True"},
		} {
			if out, err := platform.Run(in.Ctx, q.cmd, q.args...); err == nil {
				posture(q.name, strings.TrimSpace(out), q.expect)
			} else {
				missing = append(missing, platform.CapPosture)
			}
		}
	}

	res := Result{Assets: assets}
	if len(missing) > 0 {
		res.Degraded = true
		res.Note = "some hardening settings could not be read on this host"
		res.Unavailable = mergeUnique(nil, missing)
	}
	return res, nil
}

func procAsset(e *platform.Env, support models.SupportLevel, path, name, expect string) models.Asset {
	a := models.Asset{
		Kind: models.KindPosture, Domain: "os-posture",
		Name: name, Path: path, Platform: e.Platform, Support: support,
		Source: "platform:posture",
	}
	a.Set("expected", expect)
	a.Set("setting", name)
	if lines, err := platform.ReadLines(path, 2); err == nil && len(lines) > 0 {
		a.Set("value", strings.TrimSpace(lines[0]))
	}
	return a
}
