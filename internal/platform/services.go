package platform

import (
	"context"
	"sort"
	"strings"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// Service is a managed unit: systemd, launchd, SysV, or a Windows service.
type Service struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	State       string `json:"state"`
	Enabled     string `json:"enabled"` // enabled | disabled | static | masked | unknown
	Kind        string `json:"kind"`    // systemd | launchd | sysv | windows
	UnitFile    string `json:"unit_file,omitempty"`
	User        string `json:"user,omitempty"`
	ExecStart   string `json:"exec_start,omitempty"`
	Source      string `json:"source"`
}

// Services enumerates managed services.
//
// Which mechanism answers is reported per service, because "no services" and
// "no service manager" are entirely different findings. A host with sysv-init
// scripts but no systemd is a host with legacy persistence, which is itself
// worth a module noticing.
func Services(ctx context.Context, e *Env) ([]Service, models.SupportLevel) {
	var out []Service
	level := models.SupportFull

	switch e.Platform {
	case models.PlatformWindows:
		return windowsServices(ctx, e)
	case models.PlatformDarwin:
		out = launchdServices(ctx)
		return out, pickLevel(level, len(out) > 0)
	default:
		if HasCommand("systemctl") {
			out = systemdServices(ctx)
			return out, pickLevel(level, len(out) > 0)
		}
		// No systemd: fall back to SysV so the host is not reported as bare.
		out = append(out, sysvServices()...)
		level = models.SupportLimited
		if len(out) == 0 {
			level = models.SupportPartial
		}
		return out, level
	}
}

func pickLevel(level models.SupportLevel, gotAny bool) models.SupportLevel {
	if !gotAny && level == models.SupportFull {
		// The manager exists but returned nothing, which usually means the
		// query failed rather than that the host has no services.
		return models.SupportPartial
	}
	return level
}

func systemdServices(ctx context.Context) []Service {
	// unit-files lists units even when the manager is not running, which
	// matters on an offline host: a disabled-enough unit still shows up as
	// persistence intent.
	outText, err := Run(ctx, "systemctl", "list-unit-files", "--type=service",
		"--no-legend", "--no-pager", "--no-legend")
	if err != nil {
		return nil
	}
	var units []Service
	byName := map[string]*Service{}
	for _, line := range strings.Split(outText, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		name := strings.TrimSuffix(f[0], ".service")
		svc := Service{
			Name:     name,
			Enabled:  systemdEnabledState(f[1]),
			Kind:     "systemd",
			UnitFile: f[0],
			Source:   "systemctl list-unit-files",
		}
		units = append(units, svc)
	}
	if len(units) > 0 {
		byName[units[0].Name] = &units[0]
	}

	// Run states come from a second query because list-unit-files does not
	// include them. A unit that exists but cannot be started is still a
	// persistence mechanism worth reporting.
	if outText, err := Run(ctx, "systemctl", "list-units", "--type=service",
		"--all", "--no-legend", "--no-pager"); err == nil {
		for _, line := range strings.Split(outText, "\n") {
			f := strings.Fields(line)
			if len(f) < 4 {
				continue
			}
			name := strings.TrimSuffix(f[0], ".service")
			for i := range units {
				if units[i].Name == name {
					units[i].State = f[2]
				}
			}
		}
	}
	return units
}

func systemdEnabledState(v string) string {
	switch v {
	case "enabled", "enabled-runtime", "static", "indirect", "disabled",
		"masked", "masked-runtime", "generated", "transient", "bad":
		return v
	default:
		return "unknown"
	}
}

func launchdServices(ctx context.Context) []Service {
	out, err := Run(ctx, "launchctl", "list")
	if err != nil {
		return nil
	}
	var svcs []Service
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		svcs = append(svcs, Service{
			Name:    f[2],
			State:   pidOrDash(f[0]),
			Kind:    "launchd",
			Enabled: "unknown",
			Source:  "launchctl list",
		})
	}
	// LaunchAgents and LaunchDaemons are the persistence surface, so they are
	// enumerated explicitly even though launchctl only lists loaded jobs.
	for _, dir := range []string{
		"/Library/LaunchAgents", "/Library/LaunchDaemons",
		"/System/Library/LaunchAgents", "/System/Library/LaunchDaemons",
	} {
		for _, plist := range globNames(dir, "*.plist") {
			base := strings.TrimSuffix(trimBase(plist), ".plist")
			svcs = append(svcs, Service{
				Name:     base,
				State:    "not-loaded",
				Kind:     "launchd",
				Enabled:  "on-disk",
				UnitFile: plist,
				Source:   dir,
			})
		}
	}
	return svcs
}

func pidOrDash(v string) string {
	if v == "-" {
		return "not-running"
	}
	return "running"
}

func sysvServices() []Service {
	var out []Service
	for _, dir := range []string{"/etc/init.d", "/etc/rc.d"} {
		for _, f := range globNames(dir, "*") {
			out = append(out, Service{
				Name:     trimBase(f),
				State:    "installed",
				Kind:     "sysv",
				Enabled:  "unknown",
				UnitFile: f,
				Source:   dir,
			})
		}
	}
	return out
}

// SortServices orders services by name so simulation output is stable.
func SortServices(in []Service) {
	sort.SliceStable(in, func(i, j int) bool { return in[i].Name < in[j].Name })
}
