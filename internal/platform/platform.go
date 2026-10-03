// Package platform is Amina's cross-platform abstraction.
//
// The design rule is that capability is a runtime property, not a compile-time
// one. A single Amina binary cross-compiles to Linux, Windows, macOS and
// android, and every collector asks the platform what it can actually observe
// *here* rather than being excluded by a build tag. That buys two things a
// build-tag architecture cannot:
//
//   - An honest report. "systemd units: not applicable on Windows" is a
//     statement the framework can make truthfully. A collector that simply
//     does not exist in the Windows binary cannot say anything at all, and a
//     report that silently omits a domain reads exactly like a clean host.
//   - A truthful capability matrix. `amina platforms -o json` can report the
//     real state of the running machine instead of a table hard-coded at
//     release time, which drifts the moment a collector is added.
//
// Build tags are still used where they earn their keep: for parsing that
// genuinely cannot compile elsewhere (Windows `net user` output, macOS `dscl`
// output, Linux /proc and /etc/passwd formats) and for reading files only one
// platform has. Those are marked with explicit `//go:build` constraints and a
// comment saying why.
package platform

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// Names of the capabilities the matrix is keyed by. Using constants rather
// than bare strings means a typo in a collector shows up as a compile error
// instead of a capability that silently never appears in a report.
const (
	CapHostIdentity      = "host_identity"
	CapAccounts          = "accounts"
	CapRemoteAccess      = "remote_access"
	CapNetwork           = "network"
	CapSoftwareInventory = "software_inventory"
	CapPackageSources    = "package_sources"
	CapProvenance        = "provenance"
	CapBinaryIntegrity   = "binary_integrity"
	CapFilesystem        = "filesystem_exposure"
	CapSecrets           = "secret_detection"
	CapShell             = "shell_exposure"
	CapEnvironment       = "environment_exposure"
	CapGit               = "git_identity"
	CapCloud             = "cloud_identity"
	CapProcesses         = "processes"
	CapServices          = "services"
	CapPersistence       = "persistence"
	CapTooling           = "tooling"
	CapArtifacts         = "artifacts"
	CapPosture           = "os_posture"
	CapApplications      = "applications"
	CapCorrelation       = "identity_correlation"
	CapFirewall          = "firewall_state"
	CapSELinux           = "selinux"
	CapAppArmor          = "apparmor"
	CapDefender          = "windows_defender"
	CapBitLocker         = "bitlocker"
	CapSecureBoot        = "secure_boot"
	CapGatekeeper        = "gatekeeper"
	CapSystemd           = "systemd"
	CapRegistry          = "windows_registry"
	CapLaunchAgents      = "macos_launch_agents"
	CapCron              = "cron"
	CapWindowsServices   = "windows_services"
	CapScheduledTasks    = "windows_scheduled_tasks"
	CapStartupFolders    = "windows_startup_folders"
	CapAuthenticode      = "authenticode"
	CapCodesign          = "codesign"
	CapPackageVerify     = "package_verify"
	CapKernelModules     = "kernel_modules"
	CapTermuxPkg         = "termux_packages"
	CapDomainJoin        = "domain_join"
)

// Capabilities lists every capability Amina knows how to report on.
var Capabilities = []string{
	CapHostIdentity, CapAccounts, CapRemoteAccess, CapNetwork,
	CapSoftwareInventory, CapPackageSources, CapProvenance, CapBinaryIntegrity,
	CapFilesystem, CapSecrets, CapShell, CapEnvironment, CapGit, CapCloud,
	CapProcesses, CapServices, CapPersistence, CapTooling, CapArtifacts,
	CapPosture, CapApplications, CapCorrelation,
	CapFirewall, CapSELinux, CapAppArmor, CapDefender, CapBitLocker,
	CapSecureBoot, CapGatekeeper, CapSystemd, CapRegistry, CapLaunchAgents,
	CapCron, CapWindowsServices, CapScheduledTasks, CapStartupFolders,
	CapAuthenticode, CapCodesign, CapPackageVerify, CapKernelModules,
	CapTermuxPkg, CapDomainJoin,
}

// PathSet holds the well-known locations Amina reads, resolved once per run.
// Every path is probed rather than assumed: on Windows there is no /etc, and a
// hard-coded Unix path set would produce a wall of false "unavailable" results
// that hides the Windows-specific locations that do exist.
type PathSet struct {
	Etc             string
	Passwd          string
	Shadow          string
	Group           string
	Sudoers         string
	SSHConfig       string
	SSHDConfig      string
	SSHDir          string
	AuthorizedKeys  string
	Home            string
	ShellRC         []string
	HistoryFiles    []string
	GitConfig       string
	GitConfigGlobal string
	Temp            string
	ConfigHome      string
	ProgramData     string
	SystemRoot      string
	EtcHosts        string
	Resolver        string
}

// Env is the assessed host's platform description. It is the single value
// every collector receives in place of directly touching the OS, so a collector
// cannot accidentally depend on Linux, root, or a Unix filesystem.
type Env struct {
	Platform     models.Platform `json:"platform"`
	GOOS         string          `json:"goos"`
	GOARCH       string          `json:"goarch"`
	Kernel       string          `json:"kernel,omitempty"`
	Distro       string          `json:"distro,omitempty"`
	Hostname     string          `json:"hostname,omitempty"`
	MachineID    string          `json:"machine_id,omitempty"`
	ComputerName string          `json:"computer_name,omitempty"`
	Domain       string          `json:"domain,omitempty"`

	User        string `json:"user,omitempty"`
	UID         string `json:"uid,omitempty"`
	GID         string `json:"gid,omitempty"`
	Home        string `json:"home,omitempty"`
	Shell       string `json:"shell,omitempty"`
	Terminal    string `json:"terminal,omitempty"`
	TermProgram string `json:"term_program,omitempty"`
	UserDomain  string `json:"user_domain,omitempty"`

	Virtual       bool   `json:"virtual"`
	VirtualKind   string `json:"virtual_kind,omitempty"`
	Container     bool   `json:"container"`
	ContainerKind string `json:"container_kind,omitempty"`
	Cloud         string `json:"cloud,omitempty"`

	Privileged bool   `json:"privileged"`
	Locale     string `json:"locale,omitempty"`
	Timezone   string `json:"timezone,omitempty"`
	Language   string `json:"language,omitempty"`

	Paths   PathSet                        `json:"paths"`
	Support map[string]models.SupportLevel `json:"support"`
	Notes   []string                       `json:"notes,omitempty"`
}

// SupportLevel returns the recorded capability level, defaulting to
// SupportNone for a capability this build never attempted.
func (e *Env) SupportLevel(cap string) models.SupportLevel {
	if e == nil || e.Support == nil {
		return models.SupportNone
	}
	if lv, ok := e.Support[cap]; ok {
		return lv
	}
	return models.SupportNone
}

// SetSupport records a capability level, keeping the weakest level seen. A
// collector reporting partial coverage must not upgrade a capability another
// collector already reported as degraded, or the matrix starts overstating
// what the run actually observed.
func (e *Env) SetSupport(cap string, lv models.SupportLevel) {
	if e.Support == nil {
		e.Support = map[string]models.SupportLevel{}
	}
	if cur, ok := e.Support[cap]; ok && cur.Rank() < lv.Rank() {
		return
	}
	e.Support[cap] = lv
}

// Note records a human-readable observation about the host itself, such as a
// detection heuristic that fired. Notes are the audit trail behind the
// virtualised/container flags; a boolean with no explanation is not evidence.
func (e *Env) Note(format string, args ...any) {
	e.Notes = append(e.Notes, sprintf(format, args...))
}

// Detect builds the platform description for the machine Amina is running on.
//
// Detection never fails: an unreadable field becomes an empty value plus a
// note, because a partial environment description is still useful and a hard
// error would make the whole tool unusable on a locked-down host — which is
// exactly the host most worth assessing.
func Detect(ctx context.Context) *Env {
	e := &Env{
		GOOS:    runtime.GOOS,
		GOARCH:  runtime.GOARCH,
		Support: map[string]models.SupportLevel{},
	}
	e.Platform = resolvePlatform(ctx)
	e.Hostname = hostname(ctx)
	e.User = currentUser()
	e.Home = homeDir()
	e.Shell = shellName()
	e.Terminal = os.Getenv("TERM")
	e.TermProgram = firstNonEmpty(os.Getenv("TERM_PROGRAM"), os.Getenv("TERMINAL_EMULATOR"))
	e.Locale = firstNonEmpty(os.Getenv("LC_ALL"), os.Getenv("LC_MESSAGES"), os.Getenv("LANG"))
	e.Language = strings.SplitN(e.Locale, ".", 2)[0]
	e.Timezone = timezone()
	e.Paths = resolvePaths(e)
	e.Distro, e.Kernel = distroAndKernel(ctx, e)
	e.UID, e.GID = currentIDs()
	e.Privileged = isPrivileged(e)
	detectVirtualization(e)
	detectContainer(ctx, e)
	detectCloud(ctx, e)
	detectDomain(ctx, e)
	detectMachineID(ctx, e)
	primeCapabilities(ctx, e)
	return e
}

// Label returns the human-readable platform name.
func (e *Env) Label() string {
	if e == nil {
		return "unknown"
	}
	return e.Platform.Label()
}

// Summary renders a one-line host description for report headers.
func (e *Env) Summary() string {
	if e == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(e.Label())
	if e.Distro != "" {
		b.WriteString(" " + e.Distro)
	}
	if e.Hostname != "" {
		b.WriteString(" / " + e.Hostname)
	}
	if e.User != "" {
		b.WriteString(" / " + e.User)
	}
	return b.String()
}

// resolvePlatform maps runtime.GOOS onto Amina's platform vocabulary.
//
// android is its own platform rather than a flavour of Linux: bionic, the
// absence of a conventional passwd database, the absence of systemd and a
// Termux-specific package manager are not degree-of-linux details, they
// change which collectors work at all.
func resolvePlatform(ctx context.Context) models.Platform {
	switch runtime.GOOS {
	case "windows":
		return models.PlatformWindows
	case "darwin":
		return models.PlatformDarwin
	case "android":
		return models.PlatformTermux
	case "linux":
		if isTermux(ctx) {
			return models.PlatformTermux
		}
		return models.PlatformLinux
	default:
		return models.PlatformLinux
	}
}

// isTermux reports whether this Linux userspace is really Termux.
func isTermux(ctx context.Context) bool {
	if os.Getenv("TERMUX_VERSION") != "" {
		return true
	}
	if runtime.GOOS == "android" {
		return true
	}
	home := homeDir()
	if home == "" {
		return false
	}
	// Termux's $PREFIX is /data/data/com.termux/files/usr and it always has a
	// pkg binary. Checking the prefix alone is the cheapest reliable signal.
	if strings.Contains(home, "com.termux") {
		return true
	}
	if _, err := os.Stat(filepath.Join(home, "..", "bin", "pkg")); err == nil {
		return true
	}
	_, _ = ctx, home
	return false
}

// resolvePaths builds the path set for this platform. It is the one place that
// knows a Unix filesystem is not a Windows filesystem.
func resolvePaths(e *Env) PathSet {
	home := e.Home
	p := PathSet{Home: home}
	switch e.Platform {
	case models.PlatformWindows:
		p.SystemRoot = firstNonEmpty(os.Getenv("SystemRoot"), `C:\Windows`)
		p.ProgramData = firstNonEmpty(os.Getenv("ProgramData"), `C:\ProgramData`)
		p.Etc = filepath.Join(p.SystemRoot, "System32", "config")
		p.EtcHosts = filepath.Join(p.SystemRoot, "System32", "drivers", "etc", "hosts")
		p.Resolver = p.EtcHosts
		p.SSHDir = filepath.Join(home, ".ssh")
		p.SSHConfig = filepath.Join(p.SSHDir, "config")
		p.AuthorizedKeys = filepath.Join(p.SSHDir, "authorized_keys")
		p.Temp = firstNonEmpty(os.Getenv("TEMP"), os.Getenv("TMP"))
		p.ConfigHome = firstNonEmpty(os.Getenv("APPDATA"), filepath.Join(home, "AppData", "Roaming"))
		p.GitConfigGlobal = filepath.Join(p.ConfigHome, ".gitconfig")
		p.GitConfig = p.GitConfigGlobal
		p.HistoryFiles = windowsHistoryFiles(p.ConfigHome)
	case models.PlatformDarwin:
		p.Etc = "/etc"
		p.Passwd = "/etc/passwd"
		p.Group = "/etc/group"
		p.Sudoers = "/etc/sudoers"
		p.SSHDConfig = "/etc/ssh/sshd_config"
		p.SSHDir = filepath.Join(home, ".ssh")
		p.SSHConfig = filepath.Join(p.SSHDir, "config")
		p.AuthorizedKeys = filepath.Join(p.SSHDir, "authorized_keys")
		p.Temp = "/var/folders"
		p.ConfigHome = filepath.Join(home, ".config")
		p.EtcHosts = "/etc/hosts"
		p.Resolver = "/etc/resolv.conf"
		p.ShellRC = darwinShellRC(home)
		p.HistoryFiles = darwinHistoryFiles(home)
		p.GitConfigGlobal = filepath.Join(home, ".gitconfig")
		p.GitConfig = p.GitConfigGlobal
	default:
		// linux and termux share a filesystem layout; the differences are in
		// which services and package managers exist, not in where files live.
		p.Etc = "/etc"
		p.Passwd = "/etc/passwd"
		p.Shadow = "/etc/shadow"
		p.Group = "/etc/group"
		p.Sudoers = "/etc/sudoers"
		p.SSHDConfig = "/etc/ssh/sshd_config"
		p.SSHDir = filepath.Join(home, ".ssh")
		p.SSHConfig = filepath.Join(p.SSHDir, "config")
		p.AuthorizedKeys = filepath.Join(p.SSHDir, "authorized_keys")
		p.Temp = "/tmp"
		p.ConfigHome = firstNonEmpty(os.Getenv("XDG_CONFIG_HOME"), filepath.Join(home, ".config"))
		p.EtcHosts = "/etc/hosts"
		p.Resolver = "/etc/resolv.conf"
		p.ShellRC = unixShellRC(home)
		p.HistoryFiles = unixHistoryFiles(home)
		p.GitConfigGlobal = firstNonEmpty(os.Getenv("GIT_CONFIG_GLOBAL"), filepath.Join(home, ".gitconfig"))
		p.GitConfig = p.GitConfigGlobal
	}
	return p
}

// unixShellRC lists the startup files a POSIX shell reads, in read order.
// Existing files only — a collector that reports the existence of
// .bash_profile on a host that has never used one manufactures an exposure
// out of nothing.
func unixShellRC(home string) []string {
	candidates := []string{
		filepath.Join(home, ".profile"),
		filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".zprofile"),
		filepath.Join(home, ".bash_login"),
		"/etc/profile",
		"/etc/bash.bashrc",
		"/etc/zsh/zshrc",
		"/etc/environment",
	}
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if fileExists(c) {
			out = append(out, c)
		}
	}
	return out
}

func unixHistoryFiles(home string) []string {
	candidates := []string{
		filepath.Join(home, ".bash_history"),
		filepath.Join(home, ".zsh_history"),
		filepath.Join(home, ".sh_history"),
		filepath.Join(home, ".local", "share", "fish", "fish_history"),
		filepath.Join(home, ".python_history"),
		filepath.Join(home, ".node_repl_history"),
		filepath.Join(home, ".psql_history"),
		filepath.Join(home, ".mysql_history"),
	}
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if fileExists(c) {
			out = append(out, c)
		}
	}
	return out
}

// darwinShellRC lists zsh startup files. macOS ships zsh as the login shell
// and has done for long enough that bash is a minority case worth covering,
// but it is covered by name rather than by assuming a Unix layout.
func darwinShellRC(home string) []string {
	candidates := []string{
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".zprofile"),
		filepath.Join(home, ".zshenv"),
		filepath.Join(home, ".zlogin"),
		filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".bashrc"),
		"/etc/zshrc",
		"/etc/zprofile",
		"/etc/paths.d",
	}
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if fileExists(c) {
			out = append(out, c)
		}
	}
	return out
}

func darwinHistoryFiles(home string) []string {
	return unixHistoryFiles(home)
}

// windowsHistoryFiles lists the PowerShell and cmd history locations. These
// carry command history exactly as a Unix history file does, so omitting them
// would mean an assessment that silently ignores half of Windows.
func windowsHistoryFiles(appdata string) []string {
	if appdata == "" {
		return nil
	}
	candidates := []string{
		filepath.Join(appdata, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"),
		filepath.Join(appdata, "Microsoft", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"),
	}
	out := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if fileExists(c) {
			out = append(out, c)
		}
	}
	return out
}

// isPrivileged reports whether the process can read privileged local state.
// The check is capability-based rather than uid-based, because a Termux shell
// can hold capabilities, and because uid 0 inside a user namespace is not
// root on the host.
func isPrivileged(e *Env) bool {
	switch e.Platform {
	case models.PlatformWindows:
		return os.Getenv("USERDOMAIN") != "" && !strings.EqualFold(os.Getenv("USERDOMAIN"), "nt authority")
	default:
		return e.UID == "0" || e.GID == "0"
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// HostSummary projects the environment onto the report's host summary.
//
// The projection lives here rather than in the report package because the
// report package cannot import this one, and every renderer needs the same view.
// A summary is a value, not a pointer, so the caller decides whether the report
// carries one.
func HostSummary(e *Env) models.HostSummary {
	if e == nil {
		return models.HostSummary{}
	}
	return models.HostSummary{
		Hostname:  e.Hostname,
		Platform:  string(e.Platform),
		Kernel:    e.Kernel,
		OS:        e.Distro,
		Arch:      e.GOARCH,
		MachineID: e.MachineID,
		Virtual:   e.Virtual,
		Container: e.Container,
		Cloud:     e.Cloud,
		LocalUser: e.User,
		Timezone:  e.Timezone,
		Locale:    e.Locale,
		Shell:     e.Shell,
	}
}
