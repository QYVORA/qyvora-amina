package platform

import (
	"context"
	"sort"
	"strings"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// PackageQuery describes one installed package, whatever ecosystem it came
// from. One shape for dpkg, rpm, pacman, brew, pkgutil and the Windows
// uninstall registry keeps the software-inventory module free of per-ecosystem
// branches.
type PackageQuery struct {
	// Name and Version identify the package within its ecosystem.
	Name    string
	Version string
	Arch    string
	// Provider names the ecosystem: dpkg, rpm, pacman, apk, brew, pkgutil,
	// termux-pkg, windows-uninstall.
	Provider string
	// Origin is the classification the provenance rules act on.
	Origin string
}

// InstalledSoftware enumerates installed packages across every ecosystem present
// on this host, which is what "software inventory" has to mean on a machine
// where several of them coexist.
//
// Coverage is judged against the host's *primary* package manager, not against
// every binary that happens to be installed. Kali ships rpm alongside dpkg, and
// a stock Debian box often has a stray rpm from an rpm2cpio dependency; those
// tools return nothing because they do not manage this host, and letting them
// downgrade the capability would make a 5000-package inventory report itself as
// barely covered.
func InstalledSoftware(ctx context.Context, e *Env) ([]PackageQuery, models.SupportLevel) {
	type source struct {
		name     string
		present  bool
		primary  bool
		query    func(context.Context) []PackageQuery
		fallback models.SupportLevel
	}

	primary := primaryPackageManager(e)
	dpkgPrimary := primary == "dpkg"
	rpmPrimary := primary == "rpm"

	sources := []source{
		{"dpkg", HasCommand("dpkg-query"), dpkgPrimary, dpkgPackages, models.SupportPrivilege},
		{"rpm", HasCommand("rpm"), rpmPrimary, rpmPackages, models.SupportPrivilege},
		{"pacman", HasCommand("pacman"), primary == "pacman", pacmanPackages, models.SupportPrivilege},
		{"apk", HasCommand("apk"), primary == "apk", apkPackages, models.SupportPrivilege},
		{"brew", HasCommand("brew"), primary == "brew", brewPackages, models.SupportPartial},
		{"pkgutil", HasCommand("pkgutil"), primary == "pkgutil", pkgutilPackages, models.SupportPartial},
		{"termux-pkg", HasCommand("pkg"), primary == "termux-pkg", termuxPackages, models.SupportPartial},
	}

	var out []PackageQuery
	level := models.SupportFull
	sawPrimary := false

	for _, s := range sources {
		if !s.present {
			continue
		}
		pkgs := s.query(ctx)
		out = append(out, pkgs...)
		if s.primary {
			// The host's own package database is the one that decides whether
			// the inventory is complete. Empty here means unreadable, not empty.
			sawPrimary = true
			if len(pkgs) == 0 && level.Rank() > s.fallback.Rank() {
				level = s.fallback
			}
		}
		if len(pkgs) == 0 && !s.primary && level.Rank() > models.SupportPartial.Rank() {
			// A secondary manager is installed but did not answer. It is noted
			// by leaving coverage slightly reduced rather than silently ignored.
			level = models.SupportPartial
		}
	}

	if e.Platform == models.PlatformWindows {
		if progs, lv := windowsUninstallPrograms(ctx); len(progs) > 0 {
			out = append(out, progs...)
			if lv.Rank() < level.Rank() {
				level = lv
			}
		}
	}

	if primary == "" && !sawPrimary {
		// No package manager could be identified at all. That is a real answer
		// about this host, not a failure of Amina, but it is not a full
		// inventory of installed software either.
		level = models.SupportLimited
	}
	SortPackages(out)
	return out, level
}

// primaryPackageManager identifies the package database that actually governs
// this host, by looking for the database file each ecosystem maintains rather
// than by trusting which binaries are on PATH.
func primaryPackageManager(e *Env) string {
	switch e.Platform {
	case models.PlatformTermux:
		return "termux-pkg"
	case models.PlatformDarwin:
		return "brew"
	case models.PlatformWindows:
		return "windows-uninstall"
	default:
		switch {
		case dirExists("/var/lib/dpkg"):
			return "dpkg"
		case dirExists("/var/lib/rpm") || dirExists("/usr/lib/sysimage/rpm"):
			return "rpm"
		case dirExists("/var/lib/pacman"):
			return "pacman"
		case dirExists("/etc/apk") || fileExists("/etc/apk/repositories"):
			return "apk"
		}
		return ""
	}
}

// SortPackages orders packages by provider then name then version, so that two
// runs over the same host produce byte-identical output.
func SortPackages(in []PackageQuery) {
	sort.SliceStable(in, func(i, j int) bool {
		if in[i].Provider != in[j].Provider {
			return in[i].Provider < in[j].Provider
		}
		if in[i].Name != in[j].Name {
			return in[i].Name < in[j].Name
		}
		return in[i].Version < in[j].Version
	})
}

// dpkgPackages parses `dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n'`.
//
// The origin field from dpkg is deliberately not used as an authority: a
// third-party repository that was once added and later removed leaves origin
// "now" or "unknown" on already-installed packages, so Amina's provenance
// module reads the configured sources separately rather than trusting a field
// that describes when a package was installed, not where it came from.
func dpkgPackages(ctx context.Context) []PackageQuery {
	out, err := Run(ctx, "dpkg-query", "-W",
		"-f=${Package}\t${Version}\t${Architecture}\n")
	if err != nil {
		return nil
	}
	var pkgs []PackageQuery
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(line), "\t")
		if len(f) < 2 || f[0] == "" {
			continue
		}
		pkgs = append(pkgs, PackageQuery{
			Name:     f[0],
			Version:  strings.TrimSpace(f[1]),
			Arch:     trimSpaceField(f, 2),
			Provider: "dpkg",
			Origin:   "unknown",
		})
	}
	return pkgs
}

func rpmPackages(ctx context.Context) []PackageQuery {
	out, err := Run(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{VENDOR}\n")
	if err != nil {
		return nil
	}
	var pkgs []PackageQuery
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(line), "\t")
		if len(f) < 2 || f[0] == "" {
			continue
		}
		pkgs = append(pkgs, PackageQuery{
			Name:     f[0],
			Version:  strings.TrimSpace(f[1]),
			Arch:     trimSpaceField(f, 2),
			Provider: "rpm",
			Origin:   classifyVendor(trimSpaceField(f, 3)),
		})
	}
	return pkgs
}

// classifyVendor maps an rpm vendor string onto an origin. An empty or unknown
// vendor stays unknown: rpm's VENDOR is frequently unset for locally built
// packages, and calling those official would understate the exposure.
func classifyVendor(vendor string) string {
	switch v := strings.ToLower(strings.TrimSpace(vendor)); v {
	case "fedora", "red hat", "centos", "redhat", "suse", "suse linux",
		"debian", "ubuntu", "canonical", "alpine", "arch linux", "almalinux",
		"rocky linux", "amazon", "photon", "opensuse":
		return "official"
	case "":
		return "unknown"
	default:
		return "third_party"
	}
}

func pacmanPackages(ctx context.Context) []PackageQuery {
	out, err := Run(ctx, "pacman", "-Q")
	if err != nil {
		return nil
	}
	var pkgs []PackageQuery
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		pkgs = append(pkgs, PackageQuery{
			Name:     f[0],
			Version:  f[1],
			Provider: "pacman",
			Origin:   "official",
		})
	}
	return pkgs
}

func apkPackages(ctx context.Context) []PackageQuery {
	out, err := Run(ctx, "apk", "info", "-v")
	if err != nil {
		return nil
	}
	var pkgs []PackageQuery
	for _, line := range strings.Split(out, "\n") {
		// Format is name-version-r{N}-description...
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "WARNING") {
			continue
		}
		name, version, arch := splitAPKLine(line)
		if name == "" {
			continue
		}
		pkgs = append(pkgs, PackageQuery{
			Name: name, Version: version, Arch: arch,
			Provider: "apk", Origin: "official",
		})
	}
	return pkgs
}

// splitAPKLine separates the package name from its version in apk's compact
// format, splitting on the last hyphen before the release tag so that hyphens
// inside the package name are preserved.
func splitAPKLine(line string) (name, version, arch string) {
	i := strings.Index(line, "-r")
	if i < 0 {
		return line, "", ""
	}
	name = line[:i]
	rest := line[i+1:]
	j := strings.Index(rest, "-")
	if j < 0 {
		return name, rest, ""
	}
	return name, rest[:j], rest[j+1:]
}

func brewPackages(ctx context.Context) []PackageQuery {
	// `brew list --versions` covers formulae; casks are separate and are also
	// installed software a user would expect to see inventoried.
	out, err := Run(ctx, "brew", "list", "--versions", "--formula")
	if err != nil {
		return nil
	}
	var pkgs []PackageQuery
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) == 0 {
			continue
		}
		pkgs = append(pkgs, PackageQuery{
			Name:     f[0],
			Version:  strings.Join(f[1:], " "),
			Provider: "brew",
			Origin:   classifyBrewTap(f[0]),
		})
	}
	if casks, err := Run(ctx, "brew", "list", "--cask"); err == nil {
		for _, line := range strings.Split(casks, "\n") {
			if name := strings.TrimSpace(line); name != "" {
				pkgs = append(pkgs, PackageQuery{
					Name: name, Provider: "brew-cask", Origin: "third_party",
				})
			}
		}
	}
	return pkgs
}

func classifyBrewTap(name string) string {
	if name == "" {
		return "unknown"
	}
	return "official"
}

func pkgutilPackages(ctx context.Context) []PackageQuery {
	out, err := Run(ctx, "pkgutil", "--pkgs")
	if err != nil {
		return nil
	}
	var pkgs []PackageQuery
	for _, line := range strings.Split(out, "\n") {
		id := strings.TrimSpace(line)
		if id == "" {
			continue
		}
		pkgs = append(pkgs, PackageQuery{
			Name:     id,
			Version:  macOSReceiptVersion(id, ctx),
			Provider: "pkgutil",
			Origin:   "unknown",
		})
	}
	return pkgs
}

func macOSReceiptVersion(id string, ctx context.Context) string {
	out, err := Run(ctx, "pkgutil", "--pkg-info", id)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok &&
			strings.TrimSpace(k) == "version" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func termuxPackages(ctx context.Context) []PackageQuery {
	out, err := Run(ctx, "pkg", "list-installed")
	if err != nil {
		return nil
	}
	var pkgs []PackageQuery
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		// pkg list-installed prints name/version and nothing else, so the
		// architecture is genuinely unknown rather than guessed.
		pkgs = append(pkgs, PackageQuery{
			Name: f[0], Version: f[1], Provider: "termux-pkg", Origin: "official",
		})
	}
	return pkgs
}

func trimSpaceField(f []string, i int) string {
	if i < len(f) {
		return strings.TrimSpace(f[i])
	}
	return ""
}
