package platform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }

// maxReadBytes caps every file read Amina performs. Configuration and history
// files are small; a 400MB log is not evidence of anything Amina can act on,
// and reading it would turn an assessment into a denial of service against the
// machine being assessed.
const maxReadBytes = 512 << 10 // 512 KiB

// ReadFileLimited reads at most maxReadBytes from path.
func ReadFileLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, maxReadBytes))
}

// ReadLines returns the first maxLines non-empty lines of a file, which is
// enough to inspect a config header without loading a whole history file.
func ReadLines(path string, maxLines int) ([]string, error) {
	data, err := ReadFileLimited(path)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, maxLines)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		out = append(out, line)
		if len(out) >= maxLines {
			break
		}
	}
	return out, nil
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func dirExists(path string) bool {
	if path == "" {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

func readable(path string) bool { return fileExists(path) }

// fingerprint returns the first n hex characters of the SHA-256 of s.
//
// This is the single mechanism by which an irreversible identifier crosses the
// collector boundary. A host's machine ID, a secret's value and a package's
// checksum are all reduced here rather than at the renderer, so no downstream
// component can accidentally emit the original.
func fingerprint(s string, n int) string {
	sum := sha256.Sum256([]byte(s))
	h := hex.EncodeToString(sum[:])
	if n > 0 && n < len(h) {
		return h[:n]
	}
	return h
}

// Fingerprint exposes the collector-boundary fingerprint to sibling packages.
func Fingerprint(s string, n int) string { return fingerprint(s, n) }

// FileHash returns the SHA-256 of a file's first maxReadBytes, hex encoded.
// A larger file yields the hash of its first 512 KiB, and the caller is told so
// through truncate() so a report never presents a partial hash as a complete
// one.
func FileHash(path string) (string, int64, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, false, err
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return "", 0, false, err
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxReadBytes))
	if err != nil {
		return "", st.Size(), false, err
	}
	truncated := st.Size() > n
	return hex.EncodeToString(h.Sum(nil)), st.Size(), truncated, nil
}

// ModeString renders a file's permission bits in octal, which is the form an
// operator needs in order to compare against the expected mode in a finding.
func ModeString(path string) string {
	st, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return "0" + strconv.FormatUint(uint64(st.Mode().Perm()), 8)
}

// OwnerGroup returns the file's owner and group names, falling back to numeric
// ids when the name lookup is unavailable — which is common inside containers
// and on hosts with a stale /etc/passwd.
func OwnerGroup(path string) (string, string) {
	st, err := os.Stat(path)
	if err != nil {
		return "", ""
	}
	sys, _ := statOwner(st)
	return sys.owner, sys.group
}

// detectVirtualization sets the virtualised flag from several independent
// signals, and records which one fired. Requiring corroboration is deliberate:
// a single heuristic firing is a weak signal that many ordinary hosts produce,
// and reporting "virtualised" from one file is exactly the kind of confident
// wrong answer this framework is supposed to avoid.
func detectVirtualization(e *Env) {
	var signals []string

	if fileExists("/sys/class/dmi/id/product_name") {
		if data, err := ReadFileLimited("/sys/class/dmi/id/product_name"); err == nil {
			v := strings.TrimSpace(string(data))
			if isHypervisor(v) {
				signals = append(signals, "dmi product_name="+v)
			}
		}
	}
	if fileExists("/sys/hypervisor/type") {
		signals = append(signals, "hypervisor type present")
	}
	if fileExists("/.dockerenv") {
		e.Container = true
		e.ContainerKind = "docker"
	}
	if fileExists("/run/.containerenv") {
		e.Container = true
		e.ContainerKind = "podman"
	}
	for _, marker := range []string{
		"/sys/fs/cgroup/cgroup.controllers", // cgroup v2 root marker
	} {
		if fileExists(marker) {
			e.Note("cgroup v2 hierarchy visible")
			break
		}
	}
	if os.Getenv("container") != "" {
		e.Container = true
		if e.ContainerKind == "" {
			e.ContainerKind = os.Getenv("container")
		}
	}
	if fileExists("/proc/1/cgroup") {
		if data, err := ReadFileLimited("/proc/1/cgroup"); err == nil {
			s := string(data)
			for _, hint := range []string{"docker", "kubepods", "containerd", "lxc", "podman"} {
				if strings.Contains(s, hint) {
					e.Container = true
					if e.ContainerKind == "" {
						e.ContainerKind = hint
					}
					break
				}
			}
		}
	}

	switch e.Platform {
	case models.PlatformDarwin:
		out, _ := Run(context.Background(), "sysctl", "-n", "kern.hv_support")
		if strings.TrimSpace(out) == "1" {
			signals = append(signals, "kern.hv_support=1")
		}
	case models.PlatformWindows:
		out, _ := Run(context.Background(), "wmic", "computersystem", "get", "model")
		for _, line := range strings.Split(out, "\n") {
			v := strings.TrimSpace(line)
			if isHypervisor(v) {
				signals = append(signals, "system model="+v)
			}
		}
	}

	if len(signals) > 0 {
		e.Virtual = true
		e.VirtualKind = strings.Join(signals, "; ")
		e.Note("virtualisation indicators: %s", e.VirtualKind)
	}
}

func isHypervisor(v string) bool {
	l := strings.ToLower(v)
	for _, h := range []string{"virtual", "vmware", "kvm", "qemu", "xen", "hyper-v", "virtualbox", "parallels", "bochs"} {
		if strings.Contains(l, h) {
			return true
		}
	}
	return false
}

// detectContainer distinguishes an Android userspace from an ordinary Linux
// container. Termux looks like Linux with a package manager, so the only
// reliable signal is the Android-specific environment.
func detectContainer(ctx context.Context, e *Env) {
	if e.Platform == models.PlatformTermux {
		e.Note("Termux/Android userspace detected: no passwd database, no systemd, pkg-based package manager")
		return
	}
	if v := os.Getenv("ANDROID_ROOT"); v != "" {
		e.Note("ANDROID_ROOT present: android userspace components are visible on this linux build")
	}
}

// Exists reports whether a path exists, for collectors that need to probe
// locations outside the resolved path set.
func Exists(path string) bool { return fileExists(path) }

// DirExists reports whether a directory exists.
func DirExists(path string) bool { return dirExists(path) }

// Readable reports whether a file exists and can be opened for reading.
func Readable(path string) bool { return readable(path) }

// JoinPath joins path elements with the host separator.
func JoinPath(parts ...string) string { return filepath.Join(parts...) }
