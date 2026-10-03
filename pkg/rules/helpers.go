package rules

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/QYVORA/qyvora-amina/internal/platform"
	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// Helpers used by the rule catalogue.
//
// Each one exists because the naive version produces a finding that is either
// noise or a miss, and in both directions that error matters: a ruleset that
// cries wolf gets disabled, and one that is too permissive provides no
// assurance.

// fileAt reports whether a path exists and is a regular file.
func fileAt(path string) bool { return platform.Readable(path) }

// readAt returns a file's lines, bounded so a pathological config file cannot
// stall a scan.
func readAt(path string) []string {
	lines, err := platform.ReadLines(path, 2000)
	if err != nil {
		return nil
	}
	return lines
}

// isInteractiveShell reports whether a shell allows an interactive session.
func isInteractiveShell(base string) bool {
	switch base {
	case "bash", "sh", "zsh", "ksh", "ksh93", "csh", "tcsh", "fish", "dash",
		"ash", "busybox", "powershell", "pwsh", "cmd":
		return true
	}
	return false
}

// isServiceIdentity reports whether an account exists to run a program rather
// than for a person to log in as.
//
// This is the discriminator that keeps "service account with an interactive
// shell" from firing on every ordinary user. Almost every real account has an
// interactive shell, so a rule that matches on the shell alone reports the same
// finding on every human account on the host and is quickly ignored. The test
// is whether the account is a machine identity: the collector marked it as one,
// its name is a known daemon name, or it lives in the system UID range.
func isServiceIdentity(a models.Account) bool {
	if a.Service {
		return true
	}
	switch a.Classification {
	case models.AccountService, models.AccountDormant, models.AccountUnexpected:
		return true
	}
	if isDaemonName(a.Name) {
		return true
	}
	return uidInSystemRange(a.UID)
}

// uidInSystemRange reports whether a UID is below the first ordinary user UID.
//
// The threshold is 1000 on Linux. macOS and BSD allocate ordinary users from
// 500, so a single threshold would mislabel every macOS account as a system
// account — which would silently disable this rule on precisely the platform
// where service accounts are most often left with a shell.
func uidInSystemRange(uid string) bool {
	n, err := strconv.Atoi(uid)
	if err != nil || n <= 0 {
		return false
	}
	return n < 500
}

// isDaemonName recognises the account names distributions use for their own
// daemons. These accounts often carry an interactive shell by packaging
// convention and are not therefore an exposure.
//
// The list covers the service accounts of the major distributions. It is
// deliberately a list of known daemon names rather than a pattern, because the
// patterns that would catch the rest — "contains the name of a server" — also
// match every human account whose name happens to be a common word. A ruleset
// that flags "web" because it ships a web server trains its reader to ignore it.
func isDaemonName(name string) bool {
	l := strings.ToLower(name)
	switch l {
	case "nobody", "daemon", "bin", "sys", "sync", "games", "man", "lp",
		"mysql", "redis", "nginx", "apache", "postgres", "postgresql", "mongodb",
		"rabbitmq", "elasticsearch", "tomcat", "jenkins", "git", "svn",
		"www-data", "sshd", "nogroup", "tcpdump", "audit", "nfsnobody",
		"docker", "lxd", "systemd-network", "avahi", "cups", "mail", "news",
		"uucp", "proxy", "list", "irc", "gnats", "backup", "operator":
		return true
	}
	for _, suffix := range []string{
		"nologin", "_svc", "-svc", "svc", "_service", "-service", "service",
		"dovecot", "sshd", "messagebus", "systemd-", "_user", "-user",
	} {
		if strings.HasSuffix(l, suffix) {
			return true
		}
	}
	// Names ending in a digit are overwhelmingly service accounts in Debian
	// and its derivatives (redis, mysql and postgres all follow this).
	if last := l[len(l)-1]; last >= '0' && last <= '9' {
		return true
	}
	return false
}

// containsSpace reports whether a string holds whitespace, which is the cheapest
// test for a human name in a single-word comment field.
func containsSpace(s string) bool { return strings.ContainsAny(s, " \t") }

// looksLikeRole filters out GECOS fields that hold a role rather than a person.
// Every distribution ships a handful of these and flagging them would add
// permanent noise that trains the reader to ignore this rule.
// roleWords is the vocabulary of a GECOS field that describes a job rather than
// a person: "System Administrator", "Web Server", "Unprivileged Account".
var roleWords = map[string]bool{
	"admin": true, "administrator": true, "system": true, "sys": true,
	"sysadmin": true, "root": true, "user": true, "users": true,
	"account": true, "accounts": true, "unprivileged": true, "privileged": true,
	"service": true, "daemon": true, "nobody": true, "operator": true,
	"support": true, "build": true, "builder": true, "ci": true, "cd": true,
	"deploy": true, "deployment": true, "devops": true, "bot": true,
	"server": true, "web": true, "www": true, "www-data": true, "mail": true,
	"ftp": true, "dns": true, "dhcp": true, "database": true, "postgres": true,
	"postgresql": true, "mysql": true, "redis": true, "elasticsearch": true,
	"shell": true, "session": true, "login": true, "default": true,
	"guest": true, "test": true, "info": true, "network": true, "security": true,
	"audit": true, "log": true, "logs": true, "video": true, "audio": true,
	"games": true, "proxy": true, "list": true, "irc": true, "gnats": true,
	"backup": true, "sync": true, "man": true, "lp": true,
	"public": true, "private": true, "shared": true, "local": true,
}

// looksLikeRole reports whether a GECOS field describes a job rather than a
// person. Every word must be role vocabulary: a field that mixes a role with
// something else ("Amina Administrator") still names a person, and the
// distinction is the whole point of the check.
func looksLikeRole(s string) bool {
	words := strings.Fields(strings.ToLower(strings.TrimSpace(s)))
	if len(words) == 0 {
		return false
	}
	for _, w := range words {
		if !roleWords[strings.Trim(w, ",;()[]")] {
			return false
		}
	}
	return true
}

// identityShaped reports whether a token looks like it names a person or an
// organisation rather than a machine role.
//
// This is inherently heuristic, which is why every rule that uses it scores at
// reduced confidence: the honest position is that Amina cannot reliably tell
// "amina-laptop" (a person's name) from "build-07" (a role), and saying so
// beats guessing.
func identityShaped(token string) bool {
	t := strings.ToLower(strings.TrimSpace(token))
	if t == "" {
		return false
	}
	parts := splitNonAlnum(t)
	if len(parts) == 0 {
		return false
	}
	// A token that is entirely numeric is a device identifier, not a name.
	if isAllDigits(t) {
		return false
	}
	// Reject only when *every* part is a generic role word. Rejecting on any
	// one role word would miss the case that matters most: a hostname like
	// "amina-laptop" is named after a person precisely because one part is not
	// a role word.
	var distinctive []string
	for _, p := range parts {
		if !isKnownRoleWord(p) {
			distinctive = append(distinctive, p)
		}
	}
	if len(distinctive) == 0 {
		return false
	}
	// Personal-name-shaped: no digits, and either several parts or a single
	// part that reads as a given name.
	if strings.ContainsAny(t, "0123456789") {
		return false
	}
	return len(parts) >= 2 || looksLikeGivenName(distinctive[0])
}

// isKnownRoleWord filters the generic tokens that appear in almost every
// hostname and would otherwise trip this rule on nearly every host.
func isKnownRoleWord(w string) bool {
	switch w {
	case "pc", "laptop", "desktop", "workstation", "server", "srv", "host",
		"node", "vm", "vbox", "kvm", "ec2", "gcp", "azure", "aws", "local",
		"build", "dev", "prod", "test", "staging", "ci", "runner", "cijob",
		"ubuntu", "debian", "kali", "fedora", "mac", "win", "apple", "windows",
		"linux", "android", "termux", "docker", "k8s", "kube", "minikube",
		"raspberrypi", "pi", "wsl", "vagrant", "qemu", "vmware", "oracle",
		"user", "admin", "root", "tmp", "temp", "sys", "system":
		return true
	}
	return false
}

// looksLikeGivenName is deliberately small. Amina's rule is not to carry a list
// of names — that would both be wrong for most of the world and encode exactly
// the kind of cultural assumption this framework is meant to avoid — but to
// recognise the most common English-language given names, which are enough to
// catch a hostname built from one.
func looksLikeGivenName(w string) bool {
	switch w {
	case "amina", "amir", "ali", "anna", "ben", "sara", "sarah", "mary",
		"john", "james", "peter", "david", "michael", "yusuf", "fatima",
		"zainab", "khadija", "maryam", "ibrahim", "hassan", "hussain",
		"umar", "usman", "aisha", "layla", "omar", "karim", "noor":
		return true
	}
	return false
}

func splitNonAlnum(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		lower := r >= 'a' && r <= 'z'
		digit := r >= '0' && r <= '9'
		return !lower && !digit
	})
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// modeIsRestricted reports whether a mode string denies group and world access.
// It is the inverse of the permission checks in the platform package, written
// here so the rules package does not reach into platform internals for a
// predicate this small.
func modeIsRestricted(mode string) bool {
	if mode == "" {
		return false
	}
	m := strings.TrimPrefix(strings.TrimSpace(mode), "0")
	v, err := parseOctal(m)
	if err != nil {
		// An unparseable mode is not assumed to be restricted.
		return false
	}
	return v&0o077 == 0
}

func parseOctal(s string) (uint64, error) {
	var v uint64
	for _, r := range s {
		if r < '0' || r > '7' {
			return 0, errBadOctal
		}
		v = v*8 + uint64(r-'0')
	}
	return v, nil
}

type octalError struct{}

func (octalError) Error() string { return "not an octal mode" }

var errBadOctal = octalError{}

// sensitivePath reports whether a path sits in a location the system trusts to
// control behaviour at boot or for all users.
func sensitivePath(path string) bool {
	// filepath.ToSlash only rewrites the separator of the host OS, so a Windows
	// path seen from a Linux ruleset still arrives with backslashes in it. Rules
	// are evaluated against snapshots that may have been captured on another
	// platform, so both separators are normalised by hand.
	l := strings.ToLower(strings.ReplaceAll(filepath.ToSlash(path), `\`, "/"))
	prefixes := []string{
		"/etc/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/bin/", "/sbin/",
		"/lib/", "/boot/", "/opt/", "/usr/local/bin/", "/usr/local/sbin/",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	// Windows equivalents. A drive path normalises to "c:/...", so it is
	// compared both with and without the leading separator: collectors may
	// report either form depending on the tool that produced the path.
	winPrefixes := []string{
		"c:/windows/", "c:/program files/", "c:/programdata/", "c:/users/",
	}
	for _, p := range winPrefixes {
		if strings.HasPrefix(l, p) || strings.HasPrefix(l, "/"+p) {
			return true
		}
	}
	return false
}

// isCredentialDir reports whether a directory conventionally holds secrets.
func isCredentialDir(path string) bool {
	l := strings.ToLower(filepath.ToSlash(path))
	suffixes := []string{
		"/.ssh", "/.aws", "/.azure", "/.gnupg", "/.kube", "/.docker",
		"/.config/gcloud", "/.termux", "/.password-store",
	}
	for _, s := range suffixes {
		if strings.HasSuffix(l, s) {
			return true
		}
	}
	return strings.HasSuffix(l, "/credentials") || strings.HasSuffix(l, "/.netrc")
}

// isHistoryPath reports whether a path is a shell or REPL history file.
func isHistoryPath(path string) bool {
	l := strings.ToLower(filepath.Base(path))
	for _, suffix := range []string{
		"_history", "history", "hist", "_psql_history", "_mysql_history",
	} {
		if l == suffix || strings.HasSuffix(l, suffix) {
			return true
		}
	}
	return strings.HasSuffix(l, "_history") || strings.HasSuffix(l, "history.txt")
}

// isArtifactDir reports whether a directory holds build or diagnostic output.
func isArtifactDir(path string) bool {
	l := strings.ToLower(filepath.ToSlash(path))
	base := filepath.Base(strings.TrimSuffix(l, "/"))
	switch base {
	case "logs", "log", "target", "build", "dist", "out", "output", "reports",
		"coverage", "tmp", "cache", ".next", "node_modules", "vendor":
		return true
	}
	return strings.HasSuffix(l, "/logs") || strings.HasSuffix(l, "/.logs")
}

// defaultPasswordAuth reports the OpenSSH default when the directive is absent.
// The answer changed across OpenSSH releases and Amina does not guess from a
// version string; this returns the modern default, which is the conservative
// assumption in the sense that it does not manufacture a finding on a host that
// has explicitly not configured the directive.
func defaultPasswordAuth() bool { return false }

// isFileAsset reports whether an asset describes a regular file. Asset kinds
// describe a *domain*, so a file and a directory in the filesystem domain
// share a kind and are distinguished by the entry_type attribute the collector
// sets.
func isFileAsset(a models.Asset) bool {
	return a.Kind == models.KindFileExposure && a.Attributes["entry_type"] == "file"
}

func isDirAsset(a models.Asset) bool {
	return a.Kind == models.KindFileExposure && a.Attributes["entry_type"] == "directory"
}

// assetModesByPath indexes the observed file modes so rules can join permission
// evidence to findings by path without the collectors having to duplicate it
// onto every record.
func assetModesByPath(s *Snapshot) map[string]string {
	out := make(map[string]string, len(s.Assets))
	for _, a := range s.Assets {
		if a.Path == "" || a.Attributes["mode"] == "" {
			continue
		}
		out[a.Path] = a.Attributes["mode"]
	}
	return out
}

// identityShapedCases documents the boundary of the hostname heuristic. The
// false negatives are deliberate and are listed because a reader who finds one
// should understand it was chosen rather than overlooked.
var identityShapedCases = []struct {
	token string
	want  bool
	why   string
}{
	{"localhost", false, "the default name, not an identity"},
	{"ubuntu-laptop", false, "every part is a generic role word"},
	{"build-07", false, "digits indicate a build number, not a name"},
	{"ip-10-0-0-5", false, "digits indicate an address"},
	{"web-01", false, "digits indicate an index"},
	{"amina-laptop", true, "a given name joined to a role is still a name leak"},
	{"DESKTOP-A1B2C3", false, "the Windows default pattern carries no identity"},
	{"a", false, "a single character is not a name"},
	{"", false, "empty input is not an identity"},
}
