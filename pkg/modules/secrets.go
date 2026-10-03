package modules

import (
	"regexp"
	"strings"

	"github.com/QYVORA/qyvora-amina/internal/platform"
	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// secretDetector decides which files to read and which lines contain
// credentials.
//
// Two properties matter more than detection coverage, and both are structural
// rather than a matter of tuning:
//
//   - A candidate line is tested against patterns that establish the *shape* of
//     a credential. The pattern must not itself capture the secret, so the
//     engine cannot be coaxed into recording one.
//   - The value is used to measure length and to build a salted fingerprint,
//     then dropped. No field of SecretRecord can hold a credential, so a bug
//     elsewhere in the framework cannot leak one.
type secretDetector struct {
	env *platform.Env
	// salt keeps a fingerprint from being a precomputed lookup table entry for
	// a well-known value.
	salt string
}

// secretPattern matches a configuration line whose key names a credential.
type secretPattern struct {
	typ models.SecretType
	re  *regexp.Regexp
	// capture names the submatch holding the value, or 0 for the whole match.
	capture int
	// field names the configuration key, reported so the finding says which
	// setting holds the credential.
	field string
}

// patterns is deliberately conservative. A line that merely mentions the word
// "token" is not a finding; a line that assigns a long opaque string to a
// credential-shaped key is. The cost of a false positive here is an operator
// chasing a non-issue, and the cost of a false negative is a credential left on
// disk, so the threshold sits towards the former only where the shape is
// unambiguous.
var patterns = []secretPattern{
	{
		typ:     models.SecretPrivateKey,
		re:      regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
		field:   "private_key",
		capture: 0,
	},
	{
		typ:     models.SecretCloudCredential,
		re:      regexp.MustCompile(`(?i)\baws_secret_access_key\b\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})`),
		field:   "aws_secret_access_key",
		capture: 1,
	},
	{
		typ:     models.SecretCloudCredential,
		re:      regexp.MustCompile(`(?i)\baws_access_key_id\b\s*[:=]\s*["']?([A-Z0-9]{16,})`),
		field:   "aws_access_key_id",
		capture: 1,
	},
	{
		typ:     models.SecretCICD,
		re:      regexp.MustCompile(`(?i)\b(github_pat|glpat|ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}`),
		field:   "forge_token",
		capture: 0,
	},
	{
		typ:     models.SecretCICD,
		re:      regexp.MustCompile(`(?i)\b(DEPLOY_KEY|SECRET_KEY|CI_JOB_TOKEN|REGISTRY_PASSWORD)\s*[:=]`),
		field:   "cicd_credential",
		capture: 0,
	},
	{
		typ:     models.SecretToken,
		re:      regexp.MustCompile(`(?i)\b(api[_-]?key|apikey|access[_-]?token|auth[_-]?token|bearer[_-]?token|personal[_-]?access[_-]?token|pat)\b\s*[:=]\s*["']?([A-Za-z0-9_\-./+=]{16,})`),
		field:   "api_credential",
		capture: 2,
	},
	{
		typ:     models.SecretPassword,
		re:      regexp.MustCompile(`(?i)\b(password|passwd|pwd)\b\s*[:=]\s*["']?([^\s"'#]{8,})`),
		field:   "password",
		capture: 2,
	},
	{
		typ:     models.SecretJWT,
		re:      regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b`),
		field:   "jwt",
		capture: 0,
	},
	{
		typ:     models.SecretOAuthToken,
		re:      regexp.MustCompile(`(?i)\b(xox[baprs]-[A-Za-z0-9-]{10,}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,})\b`),
		field:   "oauth_token",
		capture: 0,
	},
	{
		typ:     models.SecretDatabaseCredential,
		re:      regexp.MustCompile(`(?i)\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)://[^\s:/@]+:([^\s@]{6,})@`),
		field:   "database_url",
		capture: 1,
	},
	{
		typ:     models.SecretSessionToken,
		re:      regexp.MustCompile(`(?i)\b(session[_-]?id|cookie|set[_-]?cookie)\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})`),
		field:   "session_token",
		capture: 2,
	},
}

func newSecretDetector(e *platform.Env) *secretDetector {
	// The salt is the machine ID, so a fingerprint means nothing on another
	// host and cannot be matched against a list of known credentials.
	salt := e.MachineID
	if salt == "" {
		salt = e.Hostname
	}
	if salt == "" {
		salt = "amina"
	}
	return &secretDetector{env: e, salt: salt}
}

// match tests one line and returns the classified secret.
//
// The returned value is for measurement only. Callers must not store it.
func (d *secretDetector) match(line string) (typ models.SecretType, field, value string, ok bool) {
	if len(line) > 4096 {
		return "", "", "", false
	}
	for _, p := range patterns {
		m := p.re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		idx := p.capture
		if idx >= len(m) {
			idx = 0
		}
		v := m[idx]
		// A pattern that matched a placeholder is not a finding. This is the
		// single most effective false-positive filter: documentation and example
		// files are full of credential-shaped values that are not credentials.
		if isPlaceholder(v) {
			continue
		}
		return p.typ, p.field, v, true
	}
	return "", "", "", false
}

// placeholders are the literal values that appear in documentation, templates
// and tests. They are not secrets and reporting them buries the real findings.
var placeholders = []string{
	"changeme", "change_me", "password", "passwd", "secret", "token",
	"your_password", "yourpassword", "your_token", "yourtoken", "your_key",
	"yourkey", "your_api_key", "xxx", "xxxx", "todo", "none", "null", "example",
	"placeholder", "redacted", "hidden", "unset", "empty", "dummy", "test",
	"sample", "abc123", "123456", "qwerty", "admin", "root", "default",
	"insert", "replace", "here", "value", "string", "abcdef", "12345678",
	"notasecret", "notreal", "example.com", "foo", "bar", "baz", "key",
	"api_key_here", "token_here", "secret_here", "password_here", "s3cr3t",
	"hunter2", "correcthorsebatterystaple", "akiaexample",
}

// templateShape matches the shapes a placeholder is written in. It is
// deliberately structural rather than lexical: it looks for the markers that
// only appear in documentation.
var templateShape = regexp.MustCompile(
	`(?i)^(your|my|the|insert|replace|example|placeholder|changeme|change[_-]?me|todo|some|any|sample|dummy|fake|test[_-]?only|do[_-]?not|not[_-]?a|no[_-]?value|redacted|hidden|unset|blank|empty|none|null|nil|undefined|false|true)[\s_\-.<>]*` +
		`|\{+|\}+|\$\{|\$\(|<[a-z_ ]+>|x{4,}|\*{4,}|\.{3,}`)

func isPlaceholder(v string) bool {
	l := strings.ToLower(strings.Trim(strings.TrimSpace(v), `"'`))
	if len(l) == 0 {
		return true
	}
	// A value that is entirely one repeated character is a template.
	if len(l) > 2 {
		first := l[0]
		uniform := true
		for i := 1; i < len(l); i++ {
			if l[i] != first {
				uniform = false
				break
			}
		}
		if uniform {
			return true
		}
	}
	for _, p := range placeholders {
		if l == p {
			return true
		}
	}
	// A decorated placeholder is a template, and a template says so with its
	// own shape: a leading "your"/"insert" word, an interpolation marker, or a
	// run of filler characters. Matching on "contains a common word and a
	// dash" instead would reject every credential containing one, which is most
	// of them.
	if templateShape.MatchString(l) {
		return true
	}
	// Environment interpolation is a reference, not a value.
	if strings.HasPrefix(l, "${") || strings.HasPrefix(l, "$(") || strings.HasPrefix(l, "%") {
		return true
	}
	return false
}

// keyFiles lists the private key files that exist on this host.
func (d *secretDetector) keyFiles() []string {
	var candidates []string
	if d.env.Platform == models.PlatformWindows {
		if d.env.Paths.ProgramData != "" {
			candidates = append(candidates,
				platform.JoinPath(d.env.Paths.ProgramData, "ssh"),
				platform.JoinPath(d.env.Paths.ProgramData, "Amazon", "EC2", "instance_identity_key"),
			)
		}
		if d.env.Paths.SystemRoot != "" {
			candidates = append(candidates, platform.JoinPath(d.env.Paths.SystemRoot, "System32", "config", "ssh"))
		}
	} else {
		candidates = append(candidates,
			"/etc/ssh/ssh_host_rsa_key", "/etc/ssh/ssh_host_ecdsa_key",
			"/etc/ssh/ssh_host_ed25519_key", "/etc/ssh/ssh_host_dsa_key",
		)
	}
	if d.env.Paths.SSHDir != "" {
		candidates = append(candidates, platform.JoinPath(d.env.Paths.SSHDir, "ssh_host_ed25519_key"))
	}
	// Per-user keys, found by name rather than by scanning: the file is private
	// by definition, so the name is the discovery mechanism.
	for _, home := range userHomes(d.env) {
		sshDir := platform.JoinPath(home, ".ssh")
		if !platform.DirExists(sshDir) {
			continue
		}
		names, err := readDirNames(sshDir, 100)
		if err != nil {
			continue
		}
		for _, n := range names {
			if strings.HasSuffix(n, "_key") || strings.HasSuffix(n, "_rsa") ||
				strings.HasSuffix(n, "_ed25519") || strings.HasSuffix(n, "_ecdsa") ||
				strings.HasSuffix(n, "_dsa") {
				candidates = append(candidates, platform.JoinPath(sshDir, n))
			}
		}
	}

	seen := map[string]bool{}
	var out []string
	for _, p := range candidates {
		if p == "" || seen[p] || !platform.Exists(p) {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// userHomes lists the home directories to search for per-user credentials.
func userHomes(e *platform.Env) []string {
	seen := map[string]bool{}
	var out []string
	add := func(h string) {
		if h == "" || seen[h] || !platform.DirExists(h) {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	add(e.Home)
	if !runtimeIsWindows() {
		out = append(out, allHomeDirectories()...)
	}
	return out
}

// configFiles lists the files whose contents are searched for credentials.
//
// The list is built from known credential-bearing locations rather than by
// scanning for the word "key", because a content search across a home directory
// reads files whose names already say what they are.
func (d *secretDetector) configFiles() []string {
	rel := []string{
		".netrc", "_netrc", ".npmrc", ".pypirc", ".dockercfg",
		".git-credentials", ".gitconfig",
		".aws/credentials", ".aws/config",
		".azure/accessTokens.json", ".azure/azureProfile.json",
		".kube/config", ".docker/config.json",
		".config/gcloud/application_default_credentials.json",
		".config/gh/hosts.yml",
		".s3cfg", ".boto",
		".pgpass", ".my.cnf",
		".gem/credentials", ".cargo/credentials.toml",
		".config/gh/cli.yml",
	}
	if d.env.Platform == models.PlatformWindows {
		rel = append(rel,
			".git-credentials", ".netrc", ".npmrc",
			"AppData/Roaming/Amazon/AWS/credentials",
		)
	}

	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" || seen[p] || !platform.Exists(p) {
			return
		}
		seen[p] = true
		out = append(out, p)
	}

	for _, home := range userHomes(d.env) {
		for _, r := range rel {
			add(platform.JoinPath(home, r))
		}
	}
	// Project-local credential files in the operator's own directories. A .env
	// in a project directory is one of the most common places a real credential
	// sits, and it is never in a home-directory config path.
	for _, home := range userHomes(d.env) {
		names, err := readDirNames(home, 300)
		if err != nil {
			continue
		}
		for _, n := range names {
			if strings.HasPrefix(n, ".") {
				continue
			}
			dir := platform.JoinPath(home, n)
			if !platform.DirExists(dir) {
				continue
			}
			inner, err := readDirNames(dir, 200)
			if err != nil {
				continue
			}
			for _, f := range inner {
				switch f {
				case ".env", ".env.local", ".env.production", "credentials",
					"credentials.json", "secrets.yml", "secrets.yaml", ".secrets":
					add(platform.JoinPath(dir, f))
				}
			}
		}
	}
	if !runtimeIsWindows() {
		add("/etc/environment")
		add("/etc/default/locale")
	}
	return out
}
