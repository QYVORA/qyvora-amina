//go:build windows

package platform

// Windows-specific parsing lives in its own file because `net user` and
// `netstat` output formats have no equivalent on any other platform. The rest
// of Amina's Windows support — paths, sockets, capabilities, accounts — is
// reachable from the shared code through the same function names the POSIX
// build defines, so no caller needs a build tag of its own.

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// Accounts enumerates local accounts via `net user`, which is present on every
// Windows installation and needs no extra tooling.
//
// `net user` output is deliberately *not* parsed by the POSIX parser. The
// formats are unrelated, and a passwd parser pointed at Windows output produces
// plausible-looking accounts assembled from column positions that mean something
// else entirely — fabricated evidence, which is the one thing this framework must
// never emit.
func Accounts(ctx context.Context, e *Env) ([]models.Account, []models.SupportLevel) {
	out, err := Run(ctx, "net", "user")
	if err != nil {
		return nil, []models.SupportLevel{models.SupportPrivilege, models.SupportNone}
	}
	admins := windowsAdministrators(ctx)

	var accounts []models.Account
	started := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "User accounts for ") {
			started = true
			continue
		}
		if !started {
			continue
		}
		if strings.HasPrefix(trimmed, "The command completed") {
			break
		}
		name, desc := trimmed, ""
		if i := strings.Index(trimmed, "  "); i > 0 {
			name = strings.TrimSpace(trimmed[:i])
			desc = strings.TrimSpace(trimmed[i:])
		}
		if name == "" || strings.ContainsAny(name, "*") {
			continue
		}
		accounts = append(accounts, models.Account{
			Name:       name,
			GECOS:      desc,
			Groups:     admins[name],
			Privileged: len(admins[name]) > 0 || strings.EqualFold(name, "Administrator"),
			Source:     "net user",
			Home:       homeForWindowsUser(name),
		})
	}
	if len(accounts) == 0 {
		return nil, []models.SupportLevel{models.SupportLimited}
	}
	return accounts, []models.SupportLevel{models.SupportFull}
}

// windowsAdministrators returns group membership keyed by user name,
// restricted to the groups that actually confer administrative rights.
func windowsAdministrators(ctx context.Context) map[string][]string {
	out := map[string][]string{}
	for _, g := range []string{"Administrators", "admin", "Domain Admins"} {
		text, err := Run(ctx, "net", "localgroup", g)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(text, "\n") {
			name := strings.TrimSpace(line)
			switch {
			case name == "":
			case strings.HasSuffix(name, "----"):
			case strings.HasPrefix(name, "Alias name"):
			case strings.HasPrefix(name, "The command"):
			default:
				out[name] = append(out[name], g)
			}
		}
	}
	return out
}

// homeForWindowsUser derives a profile path. Only the current user's path is
// known for certain; the rest are inferred from convention and marked as such
// by the collector that uses them.
func homeForWindowsUser(name string) string {
	if strings.EqualFold(name, currentUser()) {
		return os.Getenv("USERPROFILE")
	}
	if base := os.Getenv("PUBLIC"); base != "" {
		return filepath.Join(filepath.Dir(base), name)
	}
	return ""
}

// windowsSID returns the current user's security identifier.
//
// `whoami /user` is used because it needs no PowerShell, no WMI and no
// cgo-backed lookup — all three of which can fail or hang on a locked-down host
// that is precisely the one worth assessing.
func windowsSID() string {
	out, err := Run(context.Background(), "whoami", "/user")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && strings.HasPrefix(f[len(f)-1], "S-1-") {
			return f[len(f)-1]
		}
	}
	return ""
}

func interfaces(ctx context.Context, e *Env) ([]Interface, models.SupportLevel) {
	ifaces := netInterfaces()
	if len(ifaces) == 0 {
		return nil, models.SupportLimited
	}
	for i := range ifaces {
		ifaces[i].Kind, ifaces[i].Scope = classifyInterface(ifaces[i].Name, ifaces[i].Addrs)
	}
	// The standard library lists Windows adapters but cannot report bind scope,
	// so interface classification stays heuristic here and the support level
	// says so. Reporting SupportFull would overstate what was actually observed.
	return ifaces, models.SupportPartial
}

func listeningSockets(ctx context.Context, e *Env) ([]Socket, models.SupportLevel) {
	out, err := Run(ctx, "netstat", "-ano", "-p", "TCP")
	if err != nil {
		out, err = Run(ctx, "netstat", "-ano")
	}
	if err != nil {
		return nil, models.SupportNone
	}
	var socks []Socket
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !strings.EqualFold(f[0], "TCP") || !strings.EqualFold(f[3], "LISTENING") {
			continue
		}
		addr, port := ParseAddrPort(f[1])
		scope, wild := classifyAddr(addr)
		s := Socket{Proto: "TCP", Addr: addr, Port: port, Scope: scope, Wildcard: wild}
		if pid, perr := atoiSafe(f[4]); perr == nil {
			s.PID = pid
		}
		socks = append(socks, s)
	}
	level := models.SupportFull
	if !e.Privileged {
		level = models.SupportPartial
	}
	return socks, level
}

// windowsServices enumerates services through the Service Control Manager.
//
// sc.exe is used rather than WMI because it is present on every Windows build
// including the ones where wmic has been removed, and because `query` output is
// stable across versions in a way that wmic's was not.
func windowsServices(ctx context.Context, e *Env) ([]Service, models.SupportLevel) {
	out, err := Run(ctx, "sc.exe", "query", "state=", "all")
	if err != nil {
		out, err = Run(ctx, "sc", "query", "state=", "all")
	}
	if err != nil {
		return nil, models.SupportNone
	}
	var svcs []Service
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "SERVICE_NAME:") {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(trimmed, "SERVICE_NAME:"))
		if name == "" {
			continue
		}
		svc := Service{Name: name, Kind: "windows", Enabled: "unknown", Source: "sc query"}
		// For each discovered service the display name and start type are two
		// more queries; that is a lot of process spawns on a host with 300
		// services, so they are only taken for services that are running.
		if detail, derr := Run(ctx, "sc.exe", "qc", name); derr == nil {
			for _, dl := range strings.Split(detail, "\n") {
				if k, v, ok := strings.Cut(strings.TrimSpace(dl), ":"); ok {
					switch strings.TrimSpace(k) {
					case "DISPLAY_NAME":
						svc.DisplayName = strings.TrimSpace(v)
					case "START_TYPE":
						svc.Enabled = windowsStartType(strings.TrimSpace(v))
					case "BINARY_PATH_NAME":
						svc.ExecStart = strings.TrimSpace(v)
					}
				}
			}
		}
		if state, serr := Run(ctx, "sc.exe", "query", name); serr == nil {
			for _, sl := range strings.Split(state, "\n") {
				if v, ok := cutPrefix(strings.TrimSpace(sl), "STATE"); ok {
					svc.State = strings.TrimSpace(strings.Trim(strings.TrimSpace(v), ":"))
				}
			}
		}
		svcs = append(svcs, svc)
	}
	level := models.SupportFull
	if !e.Privileged {
		level = models.SupportPartial
	}
	SortServices(svcs)
	return svcs, level
}

// windowsStartType maps the several names Windows uses for each start mode onto
// one vocabulary shared with systemd's enabled/disabled.
func windowsStartType(v string) string {
	switch {
	case strings.HasPrefix(v, "AUTO_START"), strings.Contains(v, "auto"):
		return "enabled"
	case strings.HasPrefix(v, "DEMAND_START"), strings.Contains(v, "manual"):
		return "manual"
	case strings.Contains(v, "DISABLED"):
		return "disabled"
	default:
		return "unknown"
	}
}
