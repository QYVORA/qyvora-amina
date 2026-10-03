package platform

import (
	"context"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// commandTimeout bounds every external command Amina runs. A collector that
// blocks on a wedged helper is worse than a collector that reports nothing,
// and on a machine that is already suspected of compromise the wedged helper
// may be the symptom being looked for.
const commandTimeout = 8 * time.Second

// Run executes a command and returns its combined stdout, stderr and whether it
// exited zero.
//
// It deliberately combines the streams: Amina's collectors parse tool output,
// not terminal transcripts, and splitting them would mean modelling which
// stream each of a dozen platform tools happens to use.
func Run(ctx context.Context, name string, args ...string) (string, error) {
	if _, err := exec.LookPath(name); err != nil {
		return "", err
	}
	cctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, name, args...).CombinedOutput()
	return string(out), err
}

// RunFirst executes the first available command from a candidate list and
// returns its output together with the name that ran. Most platform questions
// have more than one tool that can answer them — `ss` or `netstat` or `lsof`
// for listening sockets — and hard-coding one produces an empty result on
// hosts that ship another.
func RunFirst(ctx context.Context, candidates [][]string) (string, string, error) {
	var lastErr error
	for _, c := range candidates {
		if len(c) == 0 {
			continue
		}
		out, err := Run(ctx, c[0], c[1:]...)
		if err == nil {
			return out, c[0], nil
		}
		lastErr = err
	}
	return "", "", lastErr
}

// HasCommand reports whether a helper binary is on PATH. It is how a collector
// distinguishes "the tool is not installed" from "the tool is installed and
// told us there was nothing", which are very different evidence.
func HasCommand(name string) bool {
	if name == "" {
		return false
	}
	_, err := exec.LookPath(name)
	return err == nil
}

// Commands returns the subset of names present on PATH.
func Commands(names ...string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if HasCommand(n) {
			out = append(out, n)
		}
	}
	return out
}

func homeDir() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	return os.Getenv("HOME")
}

func shellName() string {
	s := os.Getenv("SHELL")
	if s != "" {
		return filepath.Base(s)
	}
	// Windows has no SHELL; the COMSPEC variable is the closest equivalent.
	if cs := os.Getenv("COMSPEC"); cs != "" {
		return filepath.Base(cs)
	}
	if os.Getenv("PSModulePath") != "" {
		return "powershell"
	}
	return ""
}

// currentUser returns the login name, preferring the environment because
// os/user.Current() performs a cgo-backed lookup that can fail or, worse,
// succeed slowly on a host with an unresponsive directory service.
func currentUser() string {
	for _, k := range []string{"USER", "USERNAME", "LOGNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return ""
}

// timezone reads the local timezone name. An empty result is normal in a
// minimal container and is recorded as "unavailable" rather than "UTC".
func timezone() string {
	if tz := os.Getenv("TZ"); tz != "" {
		return tz
	}
	if data, err := os.ReadFile("/etc/timezone"); err == nil {
		return strings.TrimSpace(string(data))
	}
	if link, err := os.Readlink("/etc/localtime"); err == nil {
		if i := strings.LastIndex(link, "zoneinfo/"); i >= 0 {
			return link[i+len("zoneinfo/"):]
		}
	}
	return ""
}

// hostname returns the machine name across platforms.
func hostname(ctx context.Context) string {
	if h, err := os.Hostname(); err == nil && h != "" {
		return h
	}
	out, _ := Run(ctx, "hostname")
	return strings.TrimSpace(out)
}

// detectMachineID reads the platform's stable machine identifier.
//
// A machine ID is one of the highest-value identity signals on a host and also
// one of the most identifying: it survives reinstallation on some platforms.
// Amina reports it as a fingerprint and never as a raw identifier, because the
// operator who reads the report should not be handed a fresh correlation key.
func detectMachineID(ctx context.Context, e *Env) {
	var raw string
	switch e.Platform {
	case models.PlatformLinux, models.PlatformTermux:
		if data, err := os.ReadFile("/etc/machine-id"); err == nil {
			raw = strings.TrimSpace(string(data))
		} else if data, err := os.ReadFile("/var/lib/dbus/machine-id"); err == nil {
			raw = strings.TrimSpace(string(data))
		}
	case models.PlatformDarwin:
		out, _ := Run(ctx, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, "IOPlatformUUID") {
				if i := strings.Index(line, `"`); i >= 0 {
					rest := line[i+1:]
					if j := strings.Index(rest, `"`); j > 0 {
						raw = rest[:j]
					}
				}
			}
		}
	case models.PlatformWindows:
		out, _ := Run(ctx, "reg", "query", `HKLM\SOFTWARE\Microsoft\Cryptography`,
			"/v", "MachineGuid")
		for _, line := range strings.Split(out, "\n") {
			if i := strings.Index(line, "REG_SZ"); i >= 0 {
				fields := strings.Fields(line[i+7:])
				if len(fields) > 0 {
					raw = fields[0]
				}
			}
		}
	}
	if raw == "" {
		return
	}
	e.MachineID = fingerprint(raw, 16)
	if raw != e.MachineID {
		e.Note("machine id present, reported as a %d-character fingerprint only", len(e.MachineID))
	}
}

// detectDomain reports Windows domain or workgroup membership. A joined
// machine publishes its domain to every service it contacts, which is a
// metadata exposure in its own right.
func detectDomain(ctx context.Context, e *Env) {
	switch e.Platform {
	case models.PlatformWindows:
		out, _ := Run(ctx, "wmic", "computersystem", "get", "domain")
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.EqualFold(line, "domain") {
				e.Domain = line
			}
		}
		if e.Domain == "" {
			if v := os.Getenv("USERDOMAIN"); v != "" && !strings.EqualFold(v, "nt authority") {
				e.Domain = v
			}
		}
	case models.PlatformDarwin:
		out, _ := Run(ctx, "dsconfiggroup", "-read", "/", "ComputerRecord", "NetworkAdminID")
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "NetworkAdminID:") {
				e.Domain = strings.TrimSpace(strings.TrimPrefix(line, "NetworkAdminID:"))
			}
		}
	}
}

// detectCloud probes the local cloud metadata services.
//
// Amina never issues a metadata *request* that a remote party could observe as
// a probe; it only reads what a cached environment variable or a link-local
// address's mere presence reveals. Publishing the account ID would be an
// exposure, not an assessment.
func detectCloud(ctx context.Context, e *Env) {
	if v := firstNonEmpty(os.Getenv("AWS_REGION"), os.Getenv("AWS_DEFAULT_REGION")); v != "" {
		e.Cloud = "aws"
		return
	}
	if v := firstNonEmpty(os.Getenv("KUBERNETES_SERVICE_HOST")); v != "" {
		e.Cloud = "kubernetes"
		return
	}
	if fileExists(filepath.Join(homeDir(), ".config", "gcloud", "configurations", "config_default")) {
		e.Cloud = "gcp"
		return
	}
	if fileExists(filepath.Join(homeDir(), ".azure")) {
		e.Cloud = "azure"
		return
	}
	if dirExists(filepath.Join(homeDir(), ".aws")) {
		e.Cloud = "aws"
		return
	}
	if e.Container {
		e.Note("cloud provider not identified from local configuration")
	}
}

// distroAndKernel resolves the OS and kernel identity in one place.
func distroAndKernel(ctx context.Context, e *Env) (string, string) {
	switch e.Platform {
	case models.PlatformWindows:
		e.Kernel = windowsVersion(ctx)
		return "Windows " + e.Kernel, e.Kernel
	case models.PlatformDarwin:
		out, _ := Run(ctx, "sw_vers")
		var name, version string
		for _, line := range strings.Split(out, "\n") {
			f := strings.SplitN(line, ":", 2)
			if len(f) != 2 {
				continue
			}
			switch strings.TrimSpace(f[0]) {
			case "ProductName":
				name = strings.TrimSpace(f[1])
			case "ProductVersion":
				version = strings.TrimSpace(f[1])
			}
		}
		k, _ := Run(ctx, "uname", "-r")
		return strings.TrimSpace(name + " " + version), strings.TrimSpace(k)
	default:
		return linuxDistro(ctx), linuxKernel(ctx)
	}
}

func linuxKernel(ctx context.Context) string {
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		return strings.TrimSpace(string(b))
	}
	out, _ := Run(ctx, "uname", "-r")
	return strings.TrimSpace(out)
}

func linuxDistro(ctx context.Context) string {
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		name, version := "", ""
		for _, line := range strings.Split(string(data), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok {
				continue
			}
			v = strings.Trim(v, `"`)
			switch k {
			case "PRETTY_NAME":
				name = v
			case "VERSION_ID":
				version = v
			}
		}
		if name != "" {
			if version != "" && !strings.Contains(name, version) {
				return name + " " + version
			}
			return name
		}
	}
	return ""
}

func windowsVersion(ctx context.Context) string {
	out, _ := Run(ctx, "cmd", "/c", "ver")
	fields := strings.Fields(out)
	if len(fields) >= 2 {
		return fields[len(fields)-1]
	}
	return strings.TrimSpace(out)
}
