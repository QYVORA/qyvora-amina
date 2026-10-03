package modules

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/QYVORA/qyvora-amina/internal/platform"
	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// collectFilesystemExposure records the shape of the filesystem where the shape
// itself discloses something: home directory names, project directories,
// per-user data directories and mounts.
func collectFilesystemExposure(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapFilesystem}}, nil
	}
	support := e.SupportLevel(platform.CapFilesystem)

	var assets []models.Asset
	var signals []models.IdentitySignal

	record := func(path string, mode os.FileMode) {
		if path == "" {
			return
		}
		a := models.Asset{
			Kind: models.KindFileExposure, Domain: "filesystem-exposure",
			Name: filepath.Base(path), Path: path, Platform: e.Platform,
			Support: support, Source: "platform:filesystem",
		}
		a.Set("entry_type", "directory")
		a.Set("mode", modeString(mode))
		assets = append(assets, a)
	}

	// The home directory names its owner. That is the single most common
	// identity disclosure on a POSIX host and it is collected here so the
	// correlation engine can join it with the account and hostname signals.
	if e.Home != "" {
		if fi, err := os.Stat(e.Home); err == nil {
			record(e.Home, fi.Mode())
		}
	}

	// Per-user home directories expose every other account on the host.
	for _, home := range allHomeDirectories() {
		if home == e.Home {
			continue
		}
		if fi, err := os.Stat(home); err == nil {
			record(home, fi.Mode())
		}
		leaf := filepath.Base(home)
		signals = append(signals, models.IdentitySignal{
			Type: "username", Value: leaf, Source: "/etc/passwd", Domain: "filesystem-exposure",
		})
	}

	// Project directories under the home directory name what the operator is
	// working on, which is often more identifying than their username.
	if e.Home != "" && platform.DirExists(e.Home) {
		if names, err := readDirNames(e.Home, 500); err == nil {
			for _, n := range names {
				p := filepath.Join(e.Home, n)
				fi, err := os.Stat(p)
				if err != nil || !fi.IsDir() {
					continue
				}
				// Only the directories a developer would recognise as work;
				// .config and .cache are covered by their own modules.
				if strings.HasPrefix(n, ".") {
					continue
				}
				record(p, fi.Mode())
				signals = append(signals, models.IdentitySignal{
					Type: "project", Value: n, Source: "home directory", Domain: "filesystem-exposure",
				})
			}
		}
	}

	res := Result{Assets: assets, Identities: signals}
	if support == models.SupportNone {
		res.Degraded = true
		res.Note = "filesystem layout could not be read on this host"
		res.Unavailable = []string{platform.CapFilesystem}
	}
	return res, nil
}

// collectFilePermissions checks the permissions on files whose mode is itself a
// finding: world-writable configuration, and credentials that other accounts
// can read.
func collectFilePermissions(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapFilesystem}}, nil
	}
	support := e.SupportLevel(platform.CapFilesystem)

	targets := sensitiveFiles(e)
	if len(targets) == 0 {
		return Result{Degraded: true, Note: "no permission-sensitive files were found to check",
			Unavailable: []string{platform.CapFilesystem}}, nil
	}

	assets := make([]models.Asset, 0, len(targets))
	for _, p := range targets {
		mode := platform.ModeString(p)
		if mode == "" {
			continue
		}
		a := models.Asset{
			Kind: models.KindFileExposure, Domain: "file-permissions",
			Name: filepath.Base(p), Path: p, Platform: e.Platform,
			Support: support, Source: "platform:permissions",
		}
		a.Set("entry_type", "file")
		a.Set("mode", mode)
		a.Set("world_writable", boolString(worldWritable(mode)))
		a.Set("group_readable", boolString(groupReadable(mode)))
		owner, group := platform.OwnerGroup(p)
		a.Set("owner", owner)
		a.Set("group", group)
		assets = append(assets, a)
	}

	res := Result{Assets: assets}
	if runtimeIsWindows() {
		// POSIX mode bits do not exist on NTFS. Reading them as octal would
		// produce plausible-looking nonsense, so the module says what it could
		// not do instead.
		res.Degraded = true
		res.Note = "POSIX permission bits do not apply on this filesystem; Windows ACLs are not yet read"
		res.Unavailable = []string{platform.CapFilesystem}
	}
	return res, nil
}

// sensitiveFiles lists the files whose permissions are worth a finding.
func sensitiveFiles(e *platform.Env) []string {
	var candidates []string
	if e.Platform == models.PlatformWindows {
		if e.Paths.Etc != "" {
			candidates = append(candidates, platform.JoinPath(e.Paths.Etc, "hosts"))
		}
	} else {
		candidates = append(candidates,
			"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers",
			"/etc/ssh/sshd_config", "/etc/crontab", "/etc/hosts", "/etc/resolv.conf",
		)
	}
	if e.Paths.SSHDConfig != "" {
		candidates = append(candidates, e.Paths.SSHDConfig)
	}
	if e.Paths.AuthorizedKeys != "" {
		candidates = append(candidates, e.Paths.AuthorizedKeys)
	}
	if e.Home != "" {
		candidates = append(candidates,
			platform.JoinPath(e.Home, ".ssh", "authorized_keys"),
			platform.JoinPath(e.Home, ".ssh", "config"),
			platform.JoinPath(e.Home, ".gitconfig"),
			platform.JoinPath(e.Home, ".bashrc"),
			platform.JoinPath(e.Home, ".zshrc"),
			platform.JoinPath(e.Home, ".netrc"),
			platform.JoinPath(e.Home, ".aws", "credentials"),
			platform.JoinPath(e.Home, ".docker", "config.json"),
			platform.JoinPath(e.Home, ".kube", "config"),
			platform.JoinPath(e.Home, ".npmrc"),
		)
	}
	if e.Paths.GitConfig != "" {
		candidates = append(candidates, e.Paths.GitConfig)
	}
	if e.Paths.GitConfigGlobal != "" {
		candidates = append(candidates, e.Paths.GitConfigGlobal)
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

func allHomeDirectories() []string {
	if runtimeIsWindows() || !platform.Readable("/etc/passwd") {
		return nil
	}
	lines, err := platform.ReadLines("/etc/passwd", 5000)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range lines {
		if strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 6 {
			continue
		}
		if h := strings.TrimSpace(f[5]); strings.HasPrefix(h, "/") && len(h) > 1 {
			out = append(out, h)
		}
	}
	sort.Strings(out)
	return out
}

func modeString(m os.FileMode) string {
	perm := m.Perm()
	s := []byte("---------")
	// The nine characters are emitted in the order stat(2) reports them:
	// user, group, other, each as read, write, execute.
	const rwx = "rwxrwxrwx"
	for i, bit := range []os.FileMode{0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001} {
		if perm&bit != 0 {
			s[i] = rwx[i]
		}
	}
	return string(s)
}

func worldWritable(mode string) bool {
	return len(mode) >= 9 && mode[8] != '-'
}

func groupReadable(mode string) bool {
	return len(mode) >= 6 && mode[5] != '-'
}

// collectSecretMaterial detects credentials on disk.
//
// The detection never retains a matched value. Each hit is reduced to a
// truncated, salted fingerprint at the point of detection, and the plaintext
// goes out of scope immediately. A collector that returned the secret it found
// would make every downstream component responsible for not leaking it, and
// every one of them would eventually get it wrong.
func collectSecretMaterial(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapSecrets}}, nil
	}
	support := e.SupportLevel(platform.CapSecrets)

	detector := newSecretDetector(e)
	var secrets []models.SecretRecord
	var assets []models.Asset

	// Private key files are unambiguous: the file's own structure says it is a
	// key, so there is nothing to guess.
	for _, p := range detector.keyFiles() {
		secrets = append(secrets, secretRecord(models.SecretPrivateKey, p, 0, "", e, "private key file"))
		assets = append(assets, secretAsset(p, string(models.SecretPrivateKey), "private key file", e, support))
	}

	// Credential-bearing configuration files are matched by content, with a
	// bounded read so that a large log cannot exhaust memory.
	for _, p := range detector.configFiles() {
		lines, err := platform.ReadLines(p, 500)
		if err != nil {
			continue
		}
		for n, line := range lines {
			if len(line) > 4096 {
				continue
			}
			typ, field, value, ok := detector.match(line)
			if !ok {
				continue
			}
			rec := secretRecord(typ, p, n+1, field, e, "credential in configuration")
			rec.Length = len(value)
			secrets = append(secrets, rec)
			a := secretAsset(p, string(typ), field, e, support)
			a.Set("line", itoa(n+1))
			assets = append(assets, a)
		}
	}

	res := Result{Secrets: secrets, Assets: assets}
	if len(detector.configFiles()) == 0 && len(detector.keyFiles()) == 0 {
		res.Degraded = true
		res.Note = "no credential-bearing files were located to scan"
		res.Unavailable = []string{platform.CapSecrets}
	}
	return res, nil
}

// secretRecord builds a redacted record. The value never reaches this function:
// the caller passes the location so the fingerprint is derived from the file's
// identity, and the secret's length is set separately.
func secretRecord(typ models.SecretType, path string, line int, field string, e *platform.Env, why string) models.SecretRecord {
	// The fingerprint is derived from the file identity rather than the secret
	// itself. That is enough to tell two occurrences apart across a report while
	// being useless to anyone trying to recover the credential.
	fp := platform.Fingerprint(path+":"+itoa(line)+":"+string(typ), 12)
	return models.SecretRecord{
		Type:        typ,
		Location:    path,
		Line:        line,
		Field:       field,
		Fingerprint: fp,
		Source:      "platform:secret-scan",
		Redaction:   models.RedactionFingerprint,
	}
}

func secretAsset(path, typ, field string, e *platform.Env, support models.SupportLevel) models.Asset {
	a := models.Asset{
		Kind: models.KindSecret, Domain: "secret-material",
		Name: filepath.Base(path), Path: path, Platform: e.Platform,
		Support: support, Source: "platform:secret-scan",
	}
	a.Set("secret_type", typ)
	a.Set("field", field)
	// The mode belongs here rather than on the record: it is what makes
	// SEC-003 (readable by other users) decidable, and it is not part of the
	// redaction boundary.
	a.Set("mode", platform.ModeString(path))
	a.Set("owner", ownerOf(path))
	return a
}

func ownerOf(path string) string {
	owner, _ := platform.OwnerGroup(path)
	return owner
}

// collectTempCache inventories what is left in temporary directories.
//
// Counts and sizes only: a temporary file's *content* is not this tool's
// business, and reading it would create the exposure it is meant to report.
func collectTempCache(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapFilesystem}}, nil
	}
	support := e.SupportLevel(platform.CapFilesystem)

	roots := tempRoots(e)
	if len(roots) == 0 {
		return Result{Degraded: true, Note: "no temporary directory could be located",
			Unavailable: []string{platform.CapFilesystem}}, nil
	}

	var assets []models.Asset
	var total int64
	var files int
	for _, root := range roots {
		n, bytes := countTree(root, 3)
		files += n
		total += bytes
		a := models.Asset{
			Kind: models.KindFileExposure, Domain: "temp-cache",
			Name: filepath.Base(root), Path: root, Platform: e.Platform,
			Support: support, Source: "platform:filesystem",
		}
		a.Set("entry_type", "directory")
		a.Set("files", itoa(n))
		a.Set("bytes", itoa64(bytes))
		assets = append(assets, a)
	}

	res := Result{Assets: assets}
	if support == models.SupportNone {
		res.Degraded = true
		res.Note = "temporary directories could not be read on this host"
		res.Unavailable = []string{platform.CapFilesystem}
	}
	return res, nil
}

func tempRoots(e *platform.Env) []string {
	var candidates []string
	if e.Paths.Temp != "" {
		candidates = append(candidates, e.Paths.Temp)
	}
	if !runtimeIsWindows() {
		candidates = append(candidates, "/tmp", "/var/tmp")
	}
	if e.Home != "" {
		candidates = append(candidates, filepath.Join(e.Home, ".cache"))
	}

	seen := map[string]bool{}
	var out []string
	for _, p := range candidates {
		if p == "" || seen[p] || !platform.DirExists(p) {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// countTree counts files and bytes under a directory to a bounded depth.
func countTree(root string, maxDepth int) (files int, bytes int64) {
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > maxDepth {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			if e.IsDir() {
				walk(p, depth+1)
				continue
			}
			files++
			if fi, err := e.Info(); err == nil {
				bytes += fi.Size()
			}
		}
	}
	walk(root, 0)
	return files, bytes
}

// collectArtifacts inventories logs and local artifacts, reporting existence,
// ownership and size rather than content.
func collectArtifacts(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapArtifacts}}, nil
	}
	support := e.SupportLevel(platform.CapArtifacts)

	var assets []models.Asset
	for _, spec := range artifactLocations(e) {
		fi, err := os.Stat(spec.path)
		if err != nil {
			continue
		}
		a := models.Asset{
			Kind: models.KindArtifact, Domain: "artifacts-logs",
			Name: spec.label, Path: spec.path, Platform: e.Platform,
			Support: support, Source: "platform:filesystem",
		}
		a.Set("entry_type", "directory")
		if fi.IsDir() {
			n, bytes := countTree(spec.path, 2)
			a.Set("files", itoa(n))
			a.Set("bytes", itoa64(bytes))
		} else {
			a.Set("bytes", itoa64(fi.Size()))
			a.Set("mode", modeString(fi.Mode()))
		}
		a.Set("owner", ownerOf(spec.path))
		assets = append(assets, a)
	}

	res := Result{Assets: assets}
	if len(assets) == 0 {
		res.Degraded = true
		res.Note = "no local log or artifact locations were found on this host"
		res.Unavailable = []string{platform.CapArtifacts}
	}
	return res, nil
}

func artifactLocations(e *platform.Env) []fileSpec {
	var specs []fileSpec
	if runtimeIsWindows() {
		if e.Paths.SystemRoot != "" {
			specs = append(specs,
				fileSpec{platform.JoinPath(e.Paths.SystemRoot, "System32", "winevt", "Logs"), "windows.eventlog", platform.CapArtifacts},
				fileSpec{platform.JoinPath(e.Paths.SystemRoot, "Temp"), "windows.temp", platform.CapArtifacts},
			)
		}
	} else {
		specs = append(specs,
			fileSpec{"/var/log", "system.log", platform.CapArtifacts},
			fileSpec{"/var/log/auth.log", "auth.log", platform.CapArtifacts},
			fileSpec{"/var/log/secure", "secure.log", platform.CapArtifacts},
			fileSpec{"/var/log/wtmp", "wtmp", platform.CapArtifacts},
			fileSpec{"/var/log/btmp", "btmp", platform.CapArtifacts},
			fileSpec{"/var/log/wtmp", "wtmp.mac", platform.CapArtifacts},
		)
	}
	if e.Home != "" {
		specs = append(specs,
			fileSpec{filepath.Join(e.Home, ".bash_history"), "shell.history", platform.CapArtifacts},
			fileSpec{filepath.Join(e.Home, ".zsh_history"), "shell.history.zsh", platform.CapArtifacts},
			fileSpec{filepath.Join(e.Home, ".python_history"), "python.history", platform.CapArtifacts},
			fileSpec{filepath.Join(e.Home, ".node_repl_history"), "node.history", platform.CapArtifacts},
		)
	}
	return specs
}

// collectMetadata checks documents and files for embedded metadata that their
// names do not disclose.
func collectMetadata(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapFilesystem}}, nil
	}
	support := e.SupportLevel(platform.CapFilesystem)

	var assets []models.Asset
	// Files with extensions that routinely embed author and organisation
	// metadata. The list is by extension rather than by content because reading
	// a document to see whether it has metadata is itself the expensive part.
	metadataExtensions := map[string]bool{
		".docx": true, ".doc": true, ".xlsx": true, ".xls": true,
		".pptx": true, ".ppt": true, ".pdf": true, ".odt": true,
		".ods": true, ".jpg": true, ".jpeg": true, ".png": true,
		".tiff": true, ".heic": true,
	}
	limit := 200
	if in.Depth >= 3 {
		limit = 2000
	}

	scanned, examined := 0, 0
	for _, root := range metadataRoots(e) {
		for _, p := range walkFiles(root, limit-scanned, 3) {
			if !metadataExtensions[strings.ToLower(filepath.Ext(p))] {
				continue
			}
			scanned++
			if scanned > limit {
				break
			}
			a := models.Asset{
				Kind: models.KindArtifact, Domain: "metadata",
				Name: filepath.Base(p), Path: p, Platform: e.Platform,
				Support: support, Source: "platform:filesystem",
			}
			a.Set("entry_type", "file")
			a.Set("kind", "embedded-metadata")
			a.Set("extension", strings.ToLower(filepath.Ext(p)))
			a.Set("owner", ownerOf(p))
			a.Set("mode", platform.ModeString(p))

			// The metadata itself is read, not inferred from the extension.
			// A document with no embedded identity is a different result from
			// one that could not be parsed, and only the first is clean.
			fields := documentMetadata(p)
			examined++
			if len(fields) == 0 {
				a.Set("metadata_state", "none-found")
				a.Set("metadata_keys", "")
			} else {
				a.Set("metadata_state", "present")
				keys := make([]string, 0, len(fields))
				for _, f := range fields {
					if f.Value == "" {
						continue
					}
					keys = append(keys, f.Key)
					a.Set("meta_"+f.Key, f.Value)
				}
				sort.Strings(keys)
				a.Set("metadata_keys", strings.Join(keys, ","))
				a.Set("identity_metadata", boolString(hasIdentityField(fields)))
			}
			assets = append(assets, a)
		}
	}

	res := Result{Assets: assets}
	if in.Depth < 3 && scanned >= limit {
		res.Degraded = true
		res.Note = "metadata scanning covered the first " + itoa(limit) + " files; run at deep depth for a full pass"
		res.Unavailable = []string{platform.CapFilesystem}
	}
	return res, nil
}

// hasIdentityField reports whether any extracted field names a person or an
// organisation. A document whose only metadata is a software name has not
// disclosed who produced it, and reporting it as metadata exposure would be the
// same noise that gets a ruleset switched off.
func hasIdentityField(fields []metaField) bool {
	for _, f := range fields {
		switch f.Key {
		case "author", "last_modified_by", "company", "manager":
			return true
		}
	}
	return false
}

func metadataRoots(e *platform.Env) []string {
	var out []string
	if e.Home != "" {
		out = append(out, e.Home, filepath.Join(e.Home, "Documents"), filepath.Join(e.Home, "Desktop"))
	}
	if e.Paths.ConfigHome != "" {
		out = append(out, e.Paths.ConfigHome)
	}
	var seen = map[string]bool{}
	var roots []string
	for _, p := range out {
		if p != "" && !seen[p] && platform.DirExists(p) {
			seen[p] = true
			roots = append(roots, p)
		}
	}
	return roots
}

func walkFiles(root string, limit int, maxDepth int) []string {
	if limit <= 0 {
		return nil
	}
	var out []string
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > maxDepth || len(out) >= limit {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			if e.IsDir() {
				// Hidden directories hold the same documents as visible ones
				// and are where downloads land, so they are not skipped.
				walk(p, depth+1)
				continue
			}
			out = append(out, p)
			if len(out) >= limit {
				return
			}
		}
	}
	walk(root, 0)
	return out
}

func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [24]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
