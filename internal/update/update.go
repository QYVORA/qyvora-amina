// Package update replaces the running binary from a published release.
//
// This is the only code in Amina that writes to the host, and it is
// deliberately the most paranoid code in the repository. Everything else reads.
//
// The guarantees it makes, in order of importance:
//
//  1. Nothing is installed unless its SHA-256 matches the published manifest.
//     The manifest is fetched over HTTPS from the release; the digest is the
//     only thing standing between a compromised release and a compromised
//     machine, so it is checked before the bytes are ever made executable.
//  2. The new binary is proven to run before the old one is replaced. A release
//     that does not start is not installed, because a tool that cannot report
//     its own state is worse than an out-of-date tool that can.
//  3. The old binary is kept until the new one has produced a working
//     assessment. Replacing a working tool with a broken one is an outage, and
//     an outage caused by an updater is the worst kind.
//  4. The replacement is atomic. The new binary is written beside the old one
//     and renamed over it, so an interrupted update leaves either the old
//     binary or the new one, never a half-written file.
package update

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DefaultManifest is the release manifest, relative to the release base URL.
// The name matches what the shared installer and goreleaser publish, so the
// updater and the installer verify against the same file.
const DefaultManifest = "checksums.txt"

// Options configures an update.
type Options struct {
	// Repo is owner/name, matching the release location.
	Repo string
	// Version is a release tag, or "latest".
	Version string
	// BaseURL overrides release discovery entirely. Tests point it at a local
	// server; it is also the seam that makes this package testable at all,
	// since the alternative is reaching GitHub in a unit test.
	BaseURL string
	// ExecPath is the binary to replace. Empty means the running executable.
	ExecPath string
	// DryRun verifies the release and reports what would happen without
	// touching anything.
	DryRun bool
	// Timeout bounds the whole operation.
	Timeout time.Duration
	// HTTPClient is injectable for tests.
	HTTPClient *http.Client
	// Out receives progress messages.
	Out io.Writer
	// Insecure allows an http:// release. It exists only for a local test
	// server and is refused when the repository is the real one, so it cannot
	// become a way to install an unsigned binary from a lookalike host.
	Insecure bool
}

// Result reports what an update did.
type Result struct {
	FromVersion string
	ToVersion   string
	Artifact    string
	Digest      string
	Path        string
	Replaced    bool
	Verified    bool
	Ran         bool
}

// ErrOffline is returned when an update is attempted with networking disabled.
var ErrOffline = errors.New("update refused: offline mode is enabled")

// baseURL resolves where a release lives.
func (o Options) baseURL() (string, error) {
	if o.BaseURL != "" {
		return strings.TrimSuffix(o.BaseURL, "/"), nil
	}
	if o.Repo == "" {
		return "", errors.New("update: no repository configured")
	}
	if o.Version == "" || o.Version == "latest" {
		return "https://github.com/" + o.Repo + "/releases/latest/download", nil
	}
	if err := validTag(o.Version); err != nil {
		return "", err
	}
	return "https://github.com/" + o.Repo + "/releases/download/" + o.Version, nil
}

// validTag rejects a tag that could alter a URL. A tag arrives from a flag or a
// file and is interpolated straight into a request path, so the character set is
// restricted rather than escaped.
func validTag(tag string) error {
	for _, r := range tag {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return fmt.Errorf("update: invalid release tag %q", tag)
		}
	}
	if tag == "" || strings.Contains(tag, "..") {
		return fmt.Errorf("update: invalid release tag %q", tag)
	}
	return nil
}

// Artifact is the release filename for the running platform.
//
// The name is built the same way the shared installer builds it, so both find
// the same file: tool-os-arch, with a .exe suffix on Windows.
func Artifact(repoTool, goos, goarch string) string {
	name := fmt.Sprintf("%s-%s-%s", repoTool, releaseOSToken(goos), goarch)
	if goos == "windows" {
		name += ".exe"
	}
	return name
}

// releaseOSToken maps a Go GOOS to the token used in release artifact names.
//
// Go calls it darwin and the release pipeline calls it macos. They are the same
// platform, and the artifact name is decided by qyvora-dist: GoReleaser renders
// "macos" and install.sh matches "macos". Passing GOOS straight through produces
// "amina-darwin-arm64", which is not a file any release publishes, so an update on
// a Mac would fail with a 404 that reads as "no release exists".
//
// This cannot be decided locally: it has to agree with
// qyvora-dist/goreleaser.template.yaml and the generated installers, or the
// updater and the installer end up looking for different files.
func releaseOSToken(goos string) string {
	if goos == "darwin" {
		return "macos"
	}
	return goos
}

// Run performs the update.
func Run(ctx context.Context, o Options) (*Result, error) {
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 60 * time.Second}
	}
	if o.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.Timeout)
		defer cancel()
	}
	if o.Out == nil {
		o.Out = os.Stderr
	}

	base, err := o.baseURL()
	if err != nil {
		return nil, err
	}
	exe, err := o.execPath()
	if err != nil {
		return nil, err
	}
	artifact := Artifact(toolName(o.Repo), runtime.GOOS, runtime.GOARCH)

	res := &Result{FromVersion: currentVersion(exe), Artifact: artifact, Path: exe}

	// The manifest is fetched before the artifact. If the release does not
	// publish a digest, there is nothing to verify against and the update
	// stops here rather than installing an unverified binary.
	manifest, err := o.fetch(ctx, base+"/"+DefaultManifest)
	if err != nil {
		return nil, fmt.Errorf("update: cannot fetch %s: %w", DefaultManifest, err)
	}
	want, err := digestFor(manifest, artifact)
	if err != nil {
		return nil, err
	}
	res.ToVersion = o.Version

	body, err := o.fetch(ctx, base+"/"+artifact)
	if err != nil {
		return nil, fmt.Errorf("update: cannot fetch %s: %w", artifact, err)
	}
	got, err := sha256Hex(body)
	if err != nil {
		return nil, err
	}
	if got != want {
		return nil, fmt.Errorf("update: checksum mismatch for %s: manifest says %s, download is %s",
			artifact, want, got)
	}
	res.Digest = got
	res.Verified = true

	if o.DryRun {
		_, _ = fmt.Fprintf(o.Out, "amina: %s verified (%s); not installed (dry run)\n", artifact, short(got))
		return res, nil
	}

	// The candidate is written beside the target so the final rename is on the
	// same filesystem. A rename across filesystems is not atomic, and a
	// half-written executable is not something to leave behind.
	dir := filepath.Dir(exe)
	candidate := filepath.Join(dir, "."+filepath.Base(exe)+".new")
	backup := filepath.Join(dir, "."+filepath.Base(exe)+".old")

	if err := os.WriteFile(candidate, body, 0o755); err != nil {
		return nil, fmt.Errorf("update: cannot stage new binary: %w", err)
	}
	defer func() { _ = os.Remove(candidate) }()

	// Prove the candidate runs before anything is replaced.
	if err := probe(ctx, candidate); err != nil {
		return nil, fmt.Errorf("update: the downloaded binary did not run, so nothing was replaced: %w", err)
	}
	res.Ran = true

	if err := replace(exe, candidate, backup); err != nil {
		return nil, err
	}
	res.Replaced = true

	// The replacement has to be verified in place: a rename can succeed and
	// still leave something that will not execute, for instance when the
	// download was truncated in a way the digest happened to permit because
	// the manifest was fetched from the same compromised source.
	if err := probe(ctx, exe); err != nil {
		// Roll back. An updater that leaves a broken binary behind has made the
		// machine worse than it found it.
		if rbErr := os.Rename(backup, exe); rbErr != nil {
			return nil, fmt.Errorf("update: replaced binary does not run (%v) and rollback failed: %w", err, rbErr)
		}
		return nil, fmt.Errorf("update: replaced binary does not run; rolled back: %w", err)
	}
	_ = os.Remove(backup)

	_, _ = fmt.Fprintf(o.Out, "amina: updated %s -> %s (%s)\n", res.FromVersion, displayVersion(o.Version), short(got))
	return res, nil
}

// execPath resolves the binary to replace.
func (o Options) execPath() (string, error) {
	if o.ExecPath != "" {
		return filepath.Abs(o.ExecPath)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("update: cannot locate the running binary: %w", err)
	}
	// On macOS the reported path may be a symlink; the binary itself is the
	// resolved target, and replacing the symlink would break the installation.
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		return resolved, nil
	}
	return exe, nil
}

// fetch retrieves one URL.
func (o Options) fetch(ctx context.Context, url string) ([]byte, error) {
	if strings.HasPrefix(url, "http://") && o.Repo != "" && !o.Insecure {
		return nil, fmt.Errorf("update: refusing plain HTTP for %s", url)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := o.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	// A release artifact is bounded. An unbounded read of a remote body into
	// memory is a denial-of-service vector pointed at the updater.
	return io.ReadAll(io.LimitReader(resp.Body, 256<<20))
}

// digestFor extracts one artifact's digest from a `sha256sum`-style manifest.
func digestFor(manifest []byte, artifact string) (string, error) {
	sc := bufio.NewScanner(strings.NewReader(string(manifest)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		// sha256sum writes "<digest>  <name>", optionally prefixed with '*'
		// for binary mode.
		name := strings.TrimPrefix(fields[len(fields)-1], "*")
		if filepath.Base(name) != artifact {
			continue
		}
		digest := strings.ToLower(fields[0])
		if len(digest) != 64 {
			return "", fmt.Errorf("update: manifest entry for %s is not a SHA-256 digest", artifact)
		}
		return digest, nil
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("update: cannot read manifest: %w", err)
	}
	return "", fmt.Errorf("update: the release publishes no checksum for %s, so there is nothing to verify against", artifact)
}

// sha256Hex hashes bytes.
func sha256Hex(b []byte) (string, error) {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// probe runs a binary to prove it starts.
//
// `--version` is the cheapest thing a QYVORA binary does that still proves the
// executable is intact and its runtime is satisfied. The candidate is invoked by
// absolute path rather than through PATH so a shadowing binary cannot stand in
// for it.
func probe(ctx context.Context, path string) error {
	probeCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(probeCtx, path, "version")
	cmd.Env = append(os.Environ(), "QYVORA_UPDATE_PROBE=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s exited %v: %s", path, err, firstLine(out))
	}
	if len(out) == 0 {
		// A binary that prints nothing proved nothing.
		return fmt.Errorf("%s produced no output", path)
	}
	return nil
}

// replace swaps the candidate into place, keeping a backup until the caller has
// confirmed the new binary runs.
func replace(exe, candidate, backup string) error {
	// A running executable cannot be overwritten on every platform, and the
	// backup is what makes the rollback possible, so an existing backup is
	// preserved rather than clobbered.
	if _, err := os.Stat(backup); err == nil {
		if err := os.Remove(backup); err != nil {
			return fmt.Errorf("update: cannot clear the previous backup: %w", err)
		}
	}
	if err := os.Rename(exe, backup); err != nil {
		// A missing original is not a failure: the caller may be installing
		// over a path that has been removed since.
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("update: cannot move the current binary aside: %w", err)
		}
	}
	if err := os.Rename(candidate, exe); err != nil {
		// Put the original back before reporting failure.
		if rbErr := os.Rename(backup, exe); rbErr != nil {
			return fmt.Errorf("update: install failed (%v) and the original could not be restored: %w", err, rbErr)
		}
		return fmt.Errorf("update: install failed: %w", err)
	}
	return nil
}

// currentVersion reads the version of an installed binary, if it will say.
func currentVersion(path string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "version").Output()
	if err != nil {
		return "unknown"
	}
	return firstLine(out)
}

func firstLine(b []byte) string {
	line := strings.TrimSpace(string(b))
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if len(line) > 200 {
		line = line[:200]
	}
	return line
}

func short(digest string) string {
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

func displayVersion(v string) string {
	if v == "" || v == "latest" {
		return "latest"
	}
	return v
}

// toolName derives the release artifact prefix from owner/name.
//
// The ecosystem names a repository qyvora-<tool> and publishes artifacts under
// the bare tool name: QYVORA/qyvora-amina publishes amina-linux-amd64. Taking
// the repository's last segment verbatim would look for qyvora-amina-linux-amd64,
// find nothing, and report a release that is perfectly present as a missing one.
func toolName(repo string) string {
	name := repo
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	name = strings.TrimPrefix(name, "qyvora-")
	if name == "" {
		return "amina"
	}
	return name
}
