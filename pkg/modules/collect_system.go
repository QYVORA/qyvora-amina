package modules

import (
	"strings"

	"github.com/QYVORA/qyvora-amina/internal/platform"
	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// This file holds the collectors that answer "what is installed, where did it
// come from, and what is running". They share a shape: ask the platform layer
// for a typed inventory, convert each record into an asset, and report the
// capability level honestly.

// collectRemoteAccess reads the SSH daemon configuration and the authorized
// keys that grant entry.
//
// The configuration is parsed rather than grepped. A rule that asks "is
// PermitRootLogin yes" has to know that an included file also sets it, because
// sshd's own precedence rules are what make the effective value hard to see.
func collectRemoteAccess(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapRemoteAccess}}, nil
	}
	paths := e.Paths

	var res Result
	var assets []models.Asset
	support := e.SupportLevel(platform.CapRemoteAccess)

	// Effective sshd directives, after following Include.
	if config, files, ok := effectiveSSHDConfig(in, paths.SSHDConfig); ok {
		for _, key := range []string{
			"PermitRootLogin", "PasswordAuthentication", "PubkeyAuthentication",
			"PermitEmptyPasswords", "X11Forwarding", "AllowTcpForwarding",
			"Protocol", "Port", "Banner", "MaxAuthTries",
		} {
			val, present := config[key]
			if !present {
				continue
			}
			a := models.Asset{
				Kind: models.KindRemoteAccess, Domain: "remote-access",
				Name: "sshd." + key, Path: paths.SSHDConfig, Platform: e.Platform, Support: support,
				Source: "platform:sshd-config",
			}
			a.Set("value", val)
			a.Set("setting", key)
			// An effective value can come from a file several layers deep in the
			// Include chain, and the report has to be able to show where.
			a.Set("config_files", strings.Join(files, ","))
			assets = append(assets, a)
		}
		if len(assets) == 0 {
			res.Degraded = true
			res.Note = "sshd configuration was read but no recognised directives were found"
			res.Unavailable = []string{platform.CapRemoteAccess}
		}
	} else if platform.Exists(paths.SSHDConfig) {
		a := models.Asset{
			Kind: models.KindRemoteAccess, Domain: "remote-access",
			Name: "sshd.config", Path: paths.SSHDConfig, Platform: e.Platform,
			Support: support, Source: "platform:sshd-config",
		}
		a.Set("value", "present")
		a.Set("parsed", "false")
		assets = append(assets, a)
		res.Degraded = true
		res.Note = "sshd configuration exists but its directives could not be parsed"
		res.Unavailable = []string{platform.CapRemoteAccess}
	} else {
		// No sshd configuration at all is itself an observation: either sshd is
		// not installed, or it is running with built-in defaults. The report must
		// be able to distinguish that from "we did not look".
		res.Degraded = true
		res.Note = "no sshd configuration found on this host"
		res.Unavailable = []string{platform.CapRemoteAccess}
	}

	// Authorized keys are the actual grant of access, and each one's comment is
	// an identity disclosure.
	for _, ak := range authorizedKeyFiles(in, paths) {
		a := models.Asset{
			Kind: models.KindRemoteAccess, Domain: "remote-access",
			Name: "authorized_keys", Path: ak, Platform: e.Platform, Support: support,
			Source: "platform:authorized-keys",
		}
		a.Set("value", "present")
		assets = append(assets, a)
	}

	res.Assets = assets
	return res, nil
}

// effectiveSSHDConfig reads an sshd_config and follows Include directives so the
// values returned are the ones sshd itself would use.
func effectiveSSHDConfig(in Input, path string) (map[string]string, []string, bool) {
	if path == "" || !platform.Readable(path) {
		return nil, nil, false
	}
	lines, err := platform.ReadLines(path, 4000)
	if err != nil {
		return nil, nil, false
	}

	settings := map[string]string{}
	var read []string
	read = append(read, path)

	// sshd applies the *first* occurrence of a keyword, so a value must not be
	// overwritten by a later one. Getting this backwards inverts the meaning of
	// every file that sets a default and then overrides it.
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			continue
		}
		key := strings.ToLower(fields[0])
		if key == "include" && len(fields) > 1 {
			for _, glob := range fields[1:] {
				// globs are not expanded: sshd expands them itself, and a Go
				// filepath.Glob would silently miss the patterns sshd honours.
				sub, subRead, ok := effectiveSSHDConfig(in, strings.Trim(glob, `"`))
				if !ok {
					continue
				}
				read = append(read, subRead...)
				for k, v := range sub {
					if _, seen := settings[k]; !seen {
						settings[k] = v
					}
				}
			}
			continue
		}
		if _, seen := settings[key]; seen {
			continue
		}
		settings[key] = strings.Join(fields[1:], " ")
	}
	return settings, read, len(settings) > 0
}

// authorizedKeyFiles lists the authorized_keys files that actually exist.
func authorizedKeyFiles(in Input, paths platform.PathSet) []string {
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" || seen[p] || !platform.Exists(p) {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	add(paths.AuthorizedKeys)
	if paths.SSHDir != "" && platform.DirExists(paths.SSHDir) {
		for _, p := range homeDirsFromSSHDir(paths.SSHDir) {
			add(platform.JoinPath(p, ".ssh", "authorized_keys"))
		}
	}
	return out
}

// homeDirsFromSSHDir reads the home directory of every account out of
// /etc/passwd. Authorized keys live in user home directories, so enumerating
// them requires knowing where the home directories are.
func homeDirsFromSSHDir(_ string) []string {
	if !platform.Readable("/etc/passwd") {
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
		fields := strings.Split(line, ":")
		if len(fields) < 6 {
			continue
		}
		if home := strings.TrimSpace(fields[5]); strings.HasPrefix(home, "/") && len(home) > 1 {
			out = append(out, home)
		}
	}
	return out
}

// collectSoftware inventories installed packages and classifies each by origin.
func collectSoftware(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapSoftwareInventory}}, nil
	}

	packages, support := platform.InstalledSoftware(in.Ctx, e)
	software := make([]models.Software, 0, len(packages))
	assets := make([]models.Asset, 0, len(packages))

	for _, p := range packages {
		sw := models.Software{
			Name: p.Name, Version: p.Version, Arch: p.Arch,
			Provider: p.Provider, Origin: p.Origin, Installed: true,
		}
		software = append(software, sw)

		a := models.Asset{
			Kind: models.KindSoftware, Domain: "software",
			Name: p.Name, Platform: e.Platform, Support: support,
			Source: "platform:" + p.Provider,
		}
		a.Set("version", p.Version)
		a.Set("arch", p.Arch)
		a.Set("provider", p.Provider)
		a.Set("origin", p.Origin)
		assets = append(assets, a)
	}

	res := Result{Software: software, Assets: assets}
	if support == models.SupportNone {
		res.Degraded = true
		res.Note = "no supported package manager was available to inventory software"
		res.Unavailable = []string{platform.CapSoftwareInventory}
	}
	return res, nil
}

// collectProvenance decides, for each executable in a system path, whether it
// is attributable to a package.
//
// The question is answered from both directions: which executables exist, and
// which of them does the package database claim. A file the database does not
// claim is only a finding if it is somewhere that matters, which is why the
// path set is restricted rather than scanning the whole filesystem.
func collectProvenance(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapProvenance}}, nil
	}

	paths := systemExecutables(e)
	if len(paths) == 0 {
		res := Result{Degraded: true, Note: "no system executable directories could be read",
			Unavailable: []string{platform.CapProvenance}}
		return res, nil
	}

	owners, ownerSupport := platform.PackageOwners(in.Ctx, e, paths)
	// One inventory call gives every file its version, instead of a subprocess
	// per executable.
	versions := installedVersions(in, e)
	assets := make([]models.Asset, 0, len(paths))
	records := make([]models.ProvenanceRecord, 0, len(paths))

	for _, p := range paths {
		owner := owners[p]
		state := models.ProvUnowned
		switch {
		case owner != "":
			state = models.ProvPackageOwned
		case ownerSupport == models.SupportNone:
			// The package database was not consulted successfully. "No owner"
			// here means "we could not ask", not "nothing owns this file", and
			// reporting it as unowned would manufacture a critical finding on
			// every executable.
			state = models.ProvUnverifiable
		}

		rec := models.ProvenanceRecord{Path: p, State: state, PackageOwner: owner}
		if owner != "" {
			rec.PackageVersion = versions[owner]
		}
		records = append(records, rec)

		a := models.Asset{
			Kind: models.KindProvenance, Domain: "provenance",
			Name: p, Path: p, Platform: e.Platform, Support: ownerSupport,
			Source: "platform:package-owners",
		}
		a.Set("state", string(state))
		a.Set("package_owner", owner)
		a.Set("package_version", rec.PackageVersion)
		assets = append(assets, a)
	}

	res := Result{Provenance: records, Assets: assets}
	if ownerSupport == models.SupportNone {
		res.Degraded = true
		res.Note = "the package database could not be queried, so ownership is unverified for every file"
		res.Unavailable = []string{platform.CapProvenance}
	}
	return res, nil
}

// systemExecutables lists the executables in the directories where an
// unexplained binary actually matters.
func systemExecutables(e *platform.Env) []string {
	var dirs []string
	if e.Platform == models.PlatformWindows {
		if e.Paths.SystemRoot != "" {
			dirs = append(dirs, platform.JoinPath(e.Paths.SystemRoot, "System32"))
		}
		if e.Paths.ProgramData != "" {
			dirs = append(dirs, e.Paths.ProgramData)
		}
	} else {
		dirs = []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/opt"}
	}

	seen := map[string]bool{}
	var out []string
	for _, d := range dirs {
		if d == "" || seen[d] || !platform.DirExists(d) {
			continue
		}
		seen[d] = true
		entries, err := readDirNames(d, 4000)
		if err != nil {
			continue
		}
		for _, name := range entries {
			p := platform.JoinPath(d, name)
			if isExecutableFile(p) {
				out = append(out, p)
			}
		}
	}
	return out
}

// installedVersions maps package name to version from the platform inventory.
func installedVersions(in Input, e *platform.Env) map[string]string {
	out := map[string]string{}
	pkgs, support := platform.InstalledSoftware(in.Ctx, e)
	if support == models.SupportNone {
		return out
	}
	for _, p := range pkgs {
		// dpkg reports "name:amd64" and rpm "name.arch"; strip the architecture
		// so the key matches what PackageOwners returns.
		name := p.Name
		if i := strings.LastIndex(name, ":"); i > 0 {
			name = name[:i]
		}
		if i := strings.LastIndex(name, "."); i > 0 {
			name = name[:i]
		}
		if name != "" {
			out[name] = p.Version
		}
	}
	return out
}

// collectBinaryIntegrity checks signatures and package verification.
func collectBinaryIntegrity(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapBinaryIntegrity}}, nil
	}

	paths := systemExecutables(e)
	if len(paths) == 0 {
		return Result{Degraded: true, Note: "no system executables to check",
			Unavailable: []string{platform.CapBinaryIntegrity}}, nil
	}
	// A signature check is a subprocess per file. At deep depth the full set is
	// checked; otherwise a bounded prefix is, and the bound is stated rather
	// than passed off as complete coverage.
	checked := paths
	truncated := false
	if in.Depth < 3 && len(paths) > 200 {
		checked = paths[:200]
		truncated = true
	}

	assets := make([]models.Asset, 0, len(checked))
	for _, p := range checked {
		sig := platform.VerifySignature(in.Ctx, e, p)
		a := models.Asset{
			Kind: models.KindArtifact, Domain: "binary-integrity",
			Name: p, Path: p, Platform: e.Platform,
			Support: e.SupportLevel(platform.CapBinaryIntegrity),
			Source:  "platform:signature",
		}
		a.Set("signed", boolString(sig.Signed))
		a.Set("verified", boolString(sig.Verified))
		a.Set("publisher", sig.Publisher)
		a.Set("method", sig.Method)
		assets = append(assets, a)
	}

	var problems []string
	problems, verifySupport := platform.VerifyPackageIntegrity(in.Ctx, e)

	assets = append(assets, packageVerificationAssets(e, problems)...)

	res := Result{Assets: assets}
	switch {
	case verifySupport == models.SupportNone:
		res.Degraded = true
		res.Note = "no package verification mechanism was available on this host"
		res.Unavailable = []string{platform.CapPackageVerify}
	case truncated:
		res.Degraded = true
		res.Note = "signature checking covered the first 200 system executables; run at deep depth for the rest"
	case len(problems) > 0:
		res.Note = "package verification reported problems; see the individual assets"
	}
	return res, nil
}

func packageVerificationAssets(e *platform.Env, problems []string) []models.Asset {
	out := make([]models.Asset, 0, len(problems))
	for _, pr := range problems {
		a := models.Asset{
			Kind: models.KindProvenance, Domain: "binary-integrity",
			Name: pr, Platform: e.Platform, Support: e.SupportLevel(platform.CapPackageVerify),
			Source: "platform:package-verify",
		}
		a.Set("state", string(models.ProvHashMismatch))
		a.Set("detail", pr)
		out = append(out, a)
	}
	return out
}

// collectPackageSources inventories the configured repositories and classifies
// each as official, third-party or unsigned.
func collectPackageSources(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapPackageSources}}, nil
	}

	sources, support := packageSourcesFor(e)
	assets := make([]models.Asset, 0, len(sources))
	for _, s := range sources {
		a := models.Asset{
			Kind: models.KindPackageSource, Domain: "package-sources",
			Name: s.ID, Platform: e.Platform, Support: support,
			Source: "platform:package-sources",
		}
		a.Set("provider", s.Provider)
		a.Set("uri", s.URI)
		a.Set("trust", s.Trust)
		a.Set("enabled", boolString(s.Enabled))
		a.Set("keys", itoa(s.Keys))
		assets = append(assets, a)
	}

	res := Result{Sources: sources, Assets: assets}
	if support == models.SupportNone {
		res.Degraded = true
		res.Note = "no supported package source configuration was found on this host"
		res.Unavailable = []string{platform.CapPackageSources}
	}
	return res, nil
}

// collectProcessService records running processes and managed services.
func collectProcessService(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapProcesses}}, nil
	}

	procs, procSources := platform.Processes(in.Ctx, e)
	procSupport := levelFrom(len(procs), procSources)
	services, svcSupport := platform.Services(in.Ctx, e)

	assets := make([]models.Asset, 0, len(procs)+len(services))
	for _, p := range procs {
		a := models.Asset{
			Kind: models.KindProcess, Domain: "process-service",
			Name: p.Name, Platform: e.Platform, Support: procSupport,
			Source: "platform:processes",
		}
		a.Set("pid", itoa(p.PID))
		a.Set("ppid", itoa(p.PPID))
		a.Set("user", p.User)
		a.Set("exe", p.Exe)
		a.Set("cwd", p.Cwd)
		// The argument string is where a token passed on a command line shows
		// up. The value is recorded; redaction is the secret module's job, and
		// that module sees this as an asset attribute.
		a.Set("args", p.Args)
		assets = append(assets, a)
	}
	for _, s := range services {
		a := models.Asset{
			Kind: models.KindService, Domain: "process-service",
			Name: s.Name, Path: s.UnitFile, Platform: e.Platform, Support: svcSupport,
			Source: "platform:services",
		}
		a.Set("state", s.State)
		a.Set("enabled", s.Enabled)
		a.Set("kind", s.Kind)
		a.Set("user", s.User)
		a.Set("exec_start", s.ExecStart)
		assets = append(assets, a)
	}

	res := Result{Processes: procs, Services: services, Assets: assets}
	var missing []string
	missing = append(missing, procSources...)
	if svcSupport == models.SupportNone {
		missing = append(missing, platform.CapServices)
	}
	if len(missing) > 0 {
		res.Degraded = true
		res.Note = "process or service enumeration was incomplete: " + strings.Join(missing, ", ")
		res.Unavailable = missing
	}
	return res, nil
}

// collectPersistence reads the startup mechanisms that survive a reboot.
func collectPersistence(in Input) (Result, error) {
	e := in.Env
	if e == nil {
		return Result{Degraded: true, Note: ReasonUnavailable, Unavailable: []string{platform.CapPersistence}}, nil
	}

	var assets []models.Asset
	var missing []string

	// Services are the primary persistence mechanism, so the service inventory
	// is the persistence inventory on every platform that has one.
	services, svcSupport := platform.Services(in.Ctx, e)
	if svcSupport == models.SupportNone {
		missing = append(missing, platform.CapServices)
	}
	for _, s := range services {
		if s.Enabled != "enabled" {
			continue
		}
		a := models.Asset{
			Kind: models.KindPersistence, Domain: "persistence",
			Name: s.Name, Path: s.UnitFile, Platform: e.Platform, Support: svcSupport,
			Source: "platform:services",
		}
		a.Set("mechanism", s.Kind)
		a.Set("exec_start", s.ExecStart)
		a.Set("user", s.User)
		assets = append(assets, a)
	}

	// User-level startup files are the ones nobody reviews, because they are not
	// in the service list.
	for _, spec := range startupFiles(e) {
		lines, err := platform.ReadLines(spec.path, 500)
		if err != nil {
			continue
		}
		for n, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			a := models.Asset{
				Kind: models.KindPersistence, Domain: "persistence",
				Name: spec.label, Path: spec.path, Platform: e.Platform,
				Support: e.SupportLevel(spec.capability), Source: "platform:startup-files",
			}
			a.Set("mechanism", spec.label)
			a.Set("line", itoa(n+1))
			a.Set("command", trimmed)
			assets = append(assets, a)
		}
	}

	res := Result{Assets: assets}
	if len(missing) > 0 {
		res.Degraded = true
		res.Note = "some startup mechanisms could not be read on this host"
		res.Unavailable = missing
	}
	return res, nil
}

type fileSpec struct {
	path       string
	label      string
	capability string
}

// startupFiles returns the per-user startup files that exist on this platform.
func startupFiles(e *platform.Env) []fileSpec {
	home := e.Home
	if home == "" {
		return nil
	}
	var specs []fileSpec

	switch e.Platform {
	case models.PlatformLinux:
		specs = append(specs,
			fileSpec{platform.JoinPath(home, ".config", "autostart"), "autostart", platform.CapStartupFolders},
			fileSpec{"/etc/rc.local", "rc.local", platform.CapCron},
		)
	case models.PlatformDarwin:
		specs = append(specs,
			fileSpec{platform.JoinPath(home, "Library", "LaunchAgents"), "launchd.user", platform.CapLaunchAgents},
			fileSpec{"/Library/LaunchAgents", "launchd.system", platform.CapLaunchAgents},
			fileSpec{"/Library/LaunchDaemons", "launchd.daemon", platform.CapLaunchAgents},
		)
	case models.PlatformWindows:
		appdata := e.Paths.ProgramData
		specs = append(specs,
			fileSpec{platform.JoinPath(home, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
				"startup.folder", platform.CapStartupFolders},
			fileSpec{platform.JoinPath(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
				"startup.folder.allusers", platform.CapStartupFolders},
		)
	}

	var out []fileSpec
	for _, s := range specs {
		if platform.Exists(s.path) {
			out = append(out, s)
		}
	}
	return out
}
