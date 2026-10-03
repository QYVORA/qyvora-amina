package modules

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/QYVORA/qyvora-amina/internal/platform"
	"github.com/QYVORA/qyvora-amina/pkg/models"
)

func itoa(n int) string { return strconv.Itoa(n) }

// environMap returns the current process environment as a name/value map.
//
// os.Environ is tried first because it is portable. On Linux the /proc file is
// preferred instead, for one reason: os.Environ reflects the environment this
// process was started with, while /proc/self/environ is the kernel's copy and
// therefore includes variables a parent process changed after exec.
func environMap() map[string]string {
	out := map[string]string{}
	raw, err := os.ReadFile("/proc/self/environ")
	if err == nil && len(raw) > 0 {
		for _, entry := range bytes.Split(raw, []byte{0}) {
			name, value, ok := bytes.Cut(entry, []byte{'='})
			if !ok || len(name) == 0 {
				continue
			}
			out[string(name)] = string(value)
		}
		if len(out) > 0 {
			return out
		}
	}
	for _, entry := range os.Environ() {
		if name, value, ok := strings.Cut(entry, "="); ok {
			out[name] = value
		}
	}
	return out
}

// levelFrom derives a capability level from a result and the sources that were
// unavailable.
//
// Results and sources are both needed: an empty result with no unavailable
// source means the host genuinely has nothing to report, while an empty result
// with an unavailable source means the check did not run.
func levelFrom(count int, unavailableSources []string) models.SupportLevel {
	switch {
	case len(unavailableSources) > 0 && count > 0:
		return models.SupportPartial
	case len(unavailableSources) > 0:
		return models.SupportNone
	case count > 0:
		return models.SupportFull
	default:
		// Nothing found and nothing missing: a host with no processes is not a
		// real answer, but neither is it a failure, so it is reported as
		// limited rather than as a clean bill of health.
		return models.SupportLimited
	}
}

// runtimeIsWindows reports whether this build targets Windows. File-name
// heuristics differ between the two families, and a collector that guessed
// wrong would classify every executable correctly on neither.
func runtimeIsWindows() bool { return runtime.GOOS == "windows" }

// readDirNames lists the entries of a directory, sorted.
//
// os.ReadDir already sorts, but the sort is re-applied explicitly because the
// whole framework depends on collection order never reaching the report: a
// dependency changing its ReadDir contract should not change Amina's output.
func readDirNames(dir string, limit int) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if limit > 0 && len(names) > limit {
		names = names[:limit]
	}
	return names, nil
}

// isExecutableFile reports whether a path is a regular file with any execute bit
// set, or a Windows executable by extension.
func isExecutableFile(path string) bool {
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return false
	}
	if runtimeIsWindows() {
		switch strings.ToLower(filepath.Ext(path)) {
		case ".exe", ".dll", ".sys", ".msi", ".bat", ".cmd", ".ps1":
			return true
		}
		return false
	}
	return fi.Mode().Perm()&0o111 != 0
}

// officialHosts are the distribution package hosts. A source on one of these is
// classified official; anything else is a third-party source, which is a finding
// only in combination with the provenance rules rather than on its own.
var officialHosts = map[string]bool{
	"archive.ubuntu.com": true, "security.ubuntu.com": true,
	"ports.ubuntu.com": true, "deb.debian.org": true, "security.debian.org": true,
	"deb.debian.org.": true, "ftp.debian.org": true, "snapshot.debian.org": true,
	"dl.fedoraproject.org": true, "mirror.fedoraproject.org": true,
	"download.fedoraproject.org": true, "mirror.centos.org": true,
	"repo.almalinux.org": true, "vault.centos.org": true,
	"mirror.rockylinux.org": true, "dl.rockylinux.org": true,
	"mirror.archlinux.org": true, "archlinux.org": true,
	"dl-cdn.alpinelinux.org": true, "security.alpinelinux.org": true,
	"pkg.freebsd.org": true, "packages.debian.org": true,
	"developer.download.windowsupdate.com": true, "packages.microsoft.com": true,
}

// packageSourcesFor reads the configured repositories for this platform.
func packageSourcesFor(e *platform.Env) ([]models.PackageSource, models.SupportLevel) {
	switch e.Platform {
	case models.PlatformLinux, models.PlatformTermux:
		return posixPackageSources(e)
	case models.PlatformDarwin:
		// Homebrew records its taps in the installation itself, not in a
		// declarative file, so there is nothing to audit. Reporting "complete"
		// would be claiming a check that did not happen.
		return nil, models.SupportLimited
	case models.PlatformWindows:
		// Sources live in the registry; the platform layer has no reader for
		// them yet. SupportNone makes the gap visible instead of implying that
		// no third-party source is configured.
		return nil, models.SupportNone
	}
	return nil, models.SupportNone
}

func posixPackageSources(e *platform.Env) ([]models.PackageSource, models.SupportLevel) {
	var out []models.PackageSource
	seen := map[string]bool{}
	found := false

	read := func(path, provider, kind string) {
		if path == "" || seen[path] || !platform.Readable(path) {
			return
		}
		seen[path] = true
		found = true
		lines, err := platform.ReadLines(path, 2000)
		if err != nil {
			return
		}
		for n, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			uri, extra := parseSourceLine(trimmed)
			if uri == "" {
				continue
			}
			s := models.PackageSource{
				ID:       filepath.Base(path) + "#" + strconv.Itoa(n+1),
				Provider: provider,
				Kind:     kind,
				URI:      uri,
				Trust:    classifySource(uri),
				Keys:     extra,
				Enabled:  true,
			}
			if s.Trust == "unsigned" {
				s.Note = "source is not served over TLS"
			}
			out = append(out, s)
		}
	}

	// apt, the most common Debian-family layout.
	read("/etc/apt/sources.list", "apt", "deb")
	if platform.DirExists("/etc/apt/sources.list.d") {
		if names, err := readDirNames("/etc/apt/sources.list.d", 200); err == nil {
			for _, n := range names {
				read(filepath.Join("/etc/apt/sources.list.d", n), "apt", "deb")
			}
		}
	}
	// dnf and yum.
	if platform.DirExists("/etc/yum.repos.d") {
		if names, err := readDirNames("/etc/yum.repos.d", 200); err == nil {
			for _, n := range names {
				readRepoFile(filepath.Join("/etc/yum.repos.d", n), "dnf", &out)
			}
		}
	}
	// pacman.
	readPacmanConf(&out, &found)
	// apk.
	read("/etc/apk/repositories", "apk", "repository")

	if !found {
		return nil, models.SupportNone
	}
	return out, models.SupportFull
}

// readRepoFile parses a yum/dnf .repo file, which is INI rather than one URI per
// line.
func readRepoFile(path, provider string, out *[]models.PackageSource) {
	if !platform.Readable(path) {
		return
	}
	lines, err := platform.ReadLines(path, 2000)
	if err != nil {
		return
	}
	section := ""
	for n, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section = strings.Trim(trimmed, "[]")
			continue
		}
		key, val, ok := strings.Cut(trimmed, "=")
		if !ok || strings.ToLower(strings.TrimSpace(key)) != "baseurl" {
			continue
		}
		uri := strings.TrimSpace(val)
		s := models.PackageSource{
			ID:       filepath.Base(path) + "#" + strconv.Itoa(n+1),
			Provider: provider,
			Kind:     section,
			URI:      uri,
			Trust:    classifySource(uri),
			Enabled:  true,
		}
		if gpgcheck, present := repoGPGCheck(lines, section); present {
			s.Keys = 1
			if !gpgcheck {
				s.Trust = "unsigned"
				s.Note = "gpgcheck is disabled for this repository"
			}
		}
		*out = append(*out, s)
	}
}

// repoGPGCheck finds the gpgcheck setting for one section of a .repo file.
func repoGPGCheck(lines []string, section string) (bool, bool) {
	in := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			in = strings.Trim(trimmed, "[]") == section
			continue
		}
		if !in {
			continue
		}
		key, val, ok := strings.Cut(trimmed, "=")
		if ok && strings.ToLower(strings.TrimSpace(key)) == "gpgcheck" {
			v := strings.TrimSpace(val)
			return v == "1" || strings.EqualFold(v, "true"), true
		}
	}
	return false, false
}

func readPacmanConf(out *[]models.PackageSource, found *bool) {
	lines, err := platform.ReadLines("/etc/pacman.conf", 1000)
	if err != nil {
		return
	}
	*found = true
	for n, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || !strings.HasPrefix(trimmed, "Server") {
			continue
		}
		uri := strings.TrimSpace(strings.TrimPrefix(trimmed, "Server"))
		if uri == "" {
			continue
		}
		*out = append(*out, models.PackageSource{
			ID:       "pacman.conf#" + strconv.Itoa(n+1),
			Provider: "pacman",
			Kind:     "repository",
			URI:      uri,
			Trust:    classifySource(uri),
			Keys:     1, // SigLevel is a pacman default, not a per-repo key count
			Enabled:  true,
		})
	}
}

// parseSourceLine extracts a URI from one line of a source list, returning the
// URI and the number of signing keys declared on that line.
func parseSourceLine(line string) (string, int) {
	fields := strings.Fields(line)
	// A .sources file (deb822) is a stanza, not a one-line entry; only the
	// single-line form is parsed here, and unsupported forms are left out
	// rather than half-interpreted.
	if len(fields) == 0 {
		return "", 0
	}
	keys := 0
	for _, f := range fields {
		if strings.HasPrefix(f, "[") && strings.HasSuffix(f, "]") && len(f) > 2 {
			keys++
		}
	}
	for _, f := range fields {
		if strings.HasPrefix(f, "http://") || strings.HasPrefix(f, "https://") ||
			strings.HasPrefix(f, "ftp://") || strings.HasPrefix(f, "rsync://") ||
			strings.HasPrefix(f, "file://") {
			return f, keys
		}
	}
	return "", 0
}

// classifySource decides how much a repository can be trusted.
func classifySource(uri string) string {
	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "ftp://") {
		return "unsigned"
	}
	host := uri
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.IndexAny(host, "/:"); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(host)
	if officialHosts[host] {
		return "official"
	}
	if strings.HasSuffix(host, ".edu") || strings.HasSuffix(host, ".gov") ||
		strings.HasSuffix(host, ".ac.uk") {
		return "official"
	}
	return "third_party"
}
