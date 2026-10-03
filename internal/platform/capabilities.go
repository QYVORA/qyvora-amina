package platform

import (
	"context"
	"strings"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// primeCapabilities records, before any collector runs, whether each capability
// exists on this platform at all.
//
// This is what makes `amina platforms` and the platform matrix trustworthy.
// A capability that is structurally absent on Windows is marked unavailable
// immediately, so a report can say "selinux: not applicable on this platform"
// rather than leaving the field empty for a reader to interpret. A capability
// that *is* available is marked limited — deliberately not SupportFull, because
// "the feature exists here" and "this run observed it completely" are different
// claims, and only a collector that has actually run can make the second one.
func primeCapabilities(ctx context.Context, e *Env) {
	// Implemented in portable Go over files and processes this process can see,
	// so these are offered on every platform.
	portable := []string{
		CapHostIdentity, CapAccounts, CapNetwork, CapSoftwareInventory,
		CapProvenance, CapBinaryIntegrity, CapFilesystem, CapSecrets,
		CapShell, CapEnvironment, CapGit, CapCloud, CapProcesses,
		CapArtifacts, CapApplications, CapCorrelation,
	}

	var absent []string
	switch e.Platform {
	case models.PlatformWindows:
		absent = []string{
			CapSystemd, CapCron, CapSELinux, CapAppArmor, CapCodesign,
			CapPackageVerify, CapKernelModules, CapLaunchAgents, CapTermuxPkg,
		}
	case models.PlatformDarwin:
		absent = []string{
			CapSystemd, CapCron, CapSELinux, CapAppArmor, CapDefender,
			CapBitLocker, CapSecureBoot, CapRegistry, CapWindowsServices,
			CapScheduledTasks, CapStartupFolders, CapAuthenticode, CapTermuxPkg,
		}
	case models.PlatformTermux:
		absent = []string{
			CapSystemd, CapCron, CapSELinux, CapAppArmor, CapDefender,
			CapBitLocker, CapSecureBoot, CapGatekeeper, CapRegistry,
			CapWindowsServices, CapScheduledTasks, CapStartupFolders,
			CapAuthenticode, CapCodesign, CapPackageVerify, CapPackageSources,
		}
	default:
		absent = []string{
			CapDefender, CapBitLocker, CapSecureBoot, CapGatekeeper,
			CapRegistry, CapWindowsServices, CapScheduledTasks,
			CapStartupFolders, CapAuthenticode, CapCodesign, CapLaunchAgents,
			CapTermuxPkg,
		}
	}

	for _, c := range portable {
		e.SetSupport(c, models.SupportLimited)
	}
	for _, c := range absent {
		e.SetSupport(c, models.SupportNone)
	}

	// Capabilities that depend on a helper being installed rather than on the
	// platform itself. A missing command means unavailable, not "found nothing".
	switch e.Platform {
	case models.PlatformLinux:
		if !HasCommand("dpkg-query") && !HasCommand("rpm") && !HasCommand("pacman") &&
			!HasCommand("apk") && !HasCommand("zypper") {
			e.SetSupport(CapPackageSources, models.SupportPrivilege)
			e.SetSupport(CapPackageVerify, models.SupportPrivilege)
		}
	case models.PlatformTermux:
		if !HasCommand("pkg") {
			e.SetSupport(CapTermuxPkg, models.SupportPrivilege)
		}
	case models.PlatformDarwin:
		if !HasCommand("pkgutil") {
			e.SetSupport(CapPackageVerify, models.SupportLimited)
		}
	case models.PlatformWindows:
		if !HasCommand("powershell") {
			// Without PowerShell the registry and scheduled-task collectors can
			// only reach what reg.exe and schtasks.exe expose, which is partial.
			e.SetSupport(CapRegistry, models.SupportLimited)
			e.SetSupport(CapScheduledTasks, models.SupportLimited)
		}
	}

	if !HasCommand("systemctl") {
		e.SetSupport(CapSystemd, models.SupportNone)
		// Services are still observable through SysV init scripts and the
		// process table, just not through the init system.
		e.SetSupport(CapServices, models.SupportLimited)
	}
	if !HasCommand("crontab") && !dirExists("/etc/cron.d") {
		e.SetSupport(CapCron, models.SupportNone)
	}

	// Security-state modules read kernel, service-manager and registry state.
	// Elevation is what makes most of that readable, so without it the honest
	// level is "requires privilege" rather than a guessed coverage.
	securityState := []string{
		CapFirewall, CapSELinux, CapAppArmor, CapDefender,
		CapBitLocker, CapSecureBoot, CapGatekeeper, CapPersistence,
	}
	for _, c := range securityState {
		if e.SupportLevel(c) == models.SupportNone {
			continue
		}
		if e.Privileged {
			e.SetSupport(c, models.SupportLimited)
		} else {
			e.SetSupport(c, models.SupportPrivilege)
		}
	}

	if e.Container {
		e.Note("containerised userspace: host-level state such as systemd units, boot security and disk encryption is not observable from inside")
	}
	if e.Platform == models.PlatformWindows && strings.TrimSpace(e.UserDomain) != "" {
		e.SetSupport(CapDomainJoin, models.SupportLimited)
	}
}

// PlatformSupport describes what a platform can do without running on it. It
// backs `amina platforms`, which must be answerable on any host — including one
// that is not the platform being described.
func PlatformSupport(p models.Platform) map[string]models.SupportLevel {
	out := map[string]models.SupportLevel{}
	for _, c := range Capabilities {
		switch {
		case windowsOnly(c):
			out[c] = supportOn(p, models.PlatformWindows)
		case linuxOnly(c):
			out[c] = supportOn(p, models.PlatformLinux, models.PlatformTermux)
		case darwinOnly(c):
			out[c] = supportOn(p, models.PlatformDarwin)
		default:
			out[c] = supportOn(p, models.PlatformLinux, models.PlatformWindows,
				models.PlatformDarwin, models.PlatformTermux)
		}
	}
	return out
}

func supportOn(p models.Platform, pl ...models.Platform) models.SupportLevel {
	for _, x := range pl {
		if p == x {
			return models.SupportLimited
		}
	}
	return models.SupportNone
}

func windowsOnly(c string) bool {
	switch c {
	case CapRegistry, CapDefender, CapBitLocker, CapAuthenticode, CapWindowsServices,
		CapScheduledTasks, CapStartupFolders, CapDomainJoin:
		return true
	}
	return false
}

func linuxOnly(c string) bool {
	switch c {
	case CapSystemd, CapSELinux, CapAppArmor, CapKernelModules, CapCron:
		return true
	}
	return false
}

func darwinOnly(c string) bool {
	switch c {
	case CapGatekeeper, CapCodesign, CapLaunchAgents:
		return true
	}
	return false
}
