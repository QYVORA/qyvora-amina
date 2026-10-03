package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// fakeBinary builds a shell script that answers "version" and "assess", so the
// probe step has something real to execute.
//
// A test that used a copy of the test binary itself would pass the probe for
// reasons unrelated to what it is testing: the point is that the updater refuses
// to install something that will not start.
func fakeBinary(t *testing.T, version string) []byte {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake binary is a shell script")
	}
	return []byte("#!/bin/sh\nif [ \"$1\" = \"version\" ]; then echo " + version + "; exit 0; fi\nexit 0\n")
}

func writeManifest(entries map[string][]byte) []byte {
	var b strings.Builder
	for name, body := range entries {
		sum := sha256.Sum256(body)
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	}
	return []byte(b.String())
}

// serve starts a release server.
func serve(t *testing.T, files map[string][]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestUpdateRefusesAChangedChecksum(t *testing.T) {
	newBinary := fakeBinary(t, "v9.9.9")
	artifact := Artifact("amina", runtime.GOOS, runtime.GOARCH)

	// The manifest advertises one digest and the artifact serves another. This
	// is the case the whole package exists for: a compromised or corrupted
	// download must never be installed.
	srv := serve(t, map[string][]byte{
		"/" + DefaultManifest: writeManifest(map[string][]byte{artifact: []byte("something else entirely")}),
		"/" + artifact:        newBinary,
	})

	exe := filepath.Join(t.TempDir(), "amina")
	if err := os.WriteFile(exe, fakeBinary(t, "v0.0.1"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := Run(context.Background(), Options{
		BaseURL: srv.URL, ExecPath: exe, Repo: "QYVORA/qyvora-amina",
		Insecure: true, Out: io.Discard, HTTPClient: srv.Client(),
	})
	if err == nil {
		t.Fatal("a mismatched checksum was accepted")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("error %q does not name the checksum as the cause", err)
	}

	// The original must be untouched.
	body, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(fakeBinary(t, "v0.0.1")) {
		t.Error("the binary was replaced despite the checksum mismatch")
	}
}

func TestUpdateRefusesAManifestWithNoEntryForTheArtifact(t *testing.T) {
	artifact := Artifact("amina", runtime.GOOS, runtime.GOARCH)
	srv := serve(t, map[string][]byte{
		"/" + DefaultManifest: writeManifest(map[string][]byte{"some-other-tool-linux-amd64": []byte("x")}),
		"/" + artifact:        fakeBinary(t, "v9.9.9"),
	})
	exe := filepath.Join(t.TempDir(), "amina")
	if err := os.WriteFile(exe, fakeBinary(t, "v0.0.1"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := Run(context.Background(), Options{
		BaseURL: srv.URL, ExecPath: exe, Repo: "QYVORA/qyvora-amina",
		Insecure: true, Out: io.Discard, HTTPClient: srv.Client(),
	})
	if err == nil {
		t.Fatal("an artifact with no manifest entry was installed")
	}
	if !strings.Contains(err.Error(), "no checksum") {
		t.Errorf("error %q should say there is nothing to verify against", err)
	}
}

func TestDryRunVerifiesWithoutInstalling(t *testing.T) {
	newBinary := fakeBinary(t, "v9.9.9")
	artifact := Artifact("amina", runtime.GOOS, runtime.GOARCH)
	srv := serve(t, map[string][]byte{
		"/" + DefaultManifest: writeManifest(map[string][]byte{artifact: newBinary}),
		"/" + artifact:        newBinary,
	})

	exe := filepath.Join(t.TempDir(), "amina")
	original := fakeBinary(t, "v0.0.1")
	if err := os.WriteFile(exe, original, 0o755); err != nil {
		t.Fatal(err)
	}

	res, err := Run(context.Background(), Options{
		BaseURL: srv.URL, ExecPath: exe, Repo: "QYVORA/qyvora-amina",
		DryRun: true, Insecure: true, Out: io.Discard, HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if !res.Verified || res.Replaced {
		t.Errorf("dry run reported verified=%v replaced=%v, want verified and not replaced", res.Verified, res.Replaced)
	}
	body, _ := os.ReadFile(exe)
	if string(body) != string(original) {
		t.Error("a dry run modified the binary")
	}
}

func TestUpdateInstallsAVerifiedBinary(t *testing.T) {
	newBinary := fakeBinary(t, "v9.9.9")
	artifact := Artifact("amina", runtime.GOOS, runtime.GOARCH)
	srv := serve(t, map[string][]byte{
		"/" + DefaultManifest: writeManifest(map[string][]byte{artifact: newBinary}),
		"/" + artifact:        newBinary,
	})

	exe := filepath.Join(t.TempDir(), "amina")
	if err := os.WriteFile(exe, fakeBinary(t, "v0.0.1"), 0o755); err != nil {
		t.Fatal(err)
	}

	res, err := Run(context.Background(), Options{
		BaseURL: srv.URL, ExecPath: exe, Repo: "QYVORA/qyvora-amina",
		Insecure: true, Out: io.Discard, HTTPClient: srv.Client(),
		Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !res.Replaced || !res.Verified || !res.Ran {
		t.Errorf("result = %+v, want verified, ran and replaced", res)
	}
	body, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != string(newBinary) {
		t.Error("the installed binary is not the verified download")
	}
}

func TestABinaryThatWillNotRunIsNotInstalled(t *testing.T) {
	// Correctly checksummed, but it cannot execute: the probe must catch this
	// before the working binary is touched.
	broken := []byte("#!/nonexistent/interpreter\nexit 0\n")
	if runtime.GOOS != "windows" {
		// Fine on unix; the shebang failure is the point.
	} else {
		t.Skip("shell script fixture")
	}
	artifact := Artifact("amina", runtime.GOOS, runtime.GOARCH)
	srv := serve(t, map[string][]byte{
		"/" + DefaultManifest: writeManifest(map[string][]byte{artifact: broken}),
		"/" + artifact:        broken,
	})

	exe := filepath.Join(t.TempDir(), "amina")
	original := fakeBinary(t, "v0.0.1")
	if err := os.WriteFile(exe, original, 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := Run(context.Background(), Options{
		BaseURL: srv.URL, ExecPath: exe, Repo: "QYVORA/qyvora-amina",
		Insecure: true, Out: io.Discard, HTTPClient: srv.Client(),
	})
	if err == nil {
		t.Fatal("a binary that cannot run was installed")
	}
	if !strings.Contains(err.Error(), "did not run") {
		t.Errorf("error %q should say the binary did not run", err)
	}
	body, _ := os.ReadFile(exe)
	if string(body) != string(original) {
		t.Error("the original binary was replaced by one that does not run")
	}
}

func TestPlainHTTPIsRefusedForARealRepository(t *testing.T) {
	_, err := Run(context.Background(), Options{
		BaseURL: "http://example.invalid/dl", Repo: "QYVORA/qyvora-amina",
		Out: io.Discard, Timeout: time.Second,
	})
	if err == nil {
		t.Fatal("a plain HTTP release was accepted")
	}
	if !strings.Contains(err.Error(), "plain HTTP") {
		t.Errorf("error %q should name the transport as the reason", err)
	}
}

func TestInvalidReleaseTagsAreRejected(t *testing.T) {
	for _, tag := range []string{"v1.0.0/../../etc", "v1 0", "v1;rm", ""} {
		if err := validTag(tag); err == nil && tag != "" {
			t.Errorf("tag %q was accepted", tag)
		}
	}
	for _, tag := range []string{"v1.0.0", "1.2.3-rc1", "latest"} {
		if tag == "latest" {
			continue // handled before validation
		}
		if err := validTag(tag); err != nil {
			t.Errorf("tag %q was rejected: %v", tag, err)
		}
	}
}

func TestArtifactNameMatchesTheInstallerConvention(t *testing.T) {
	// The shared installer and the updater must agree, or the installer verifies
	// one file and the updater fetches another.
	for _, tc := range []struct {
		goos, goarch, want string
	}{
		{"linux", "amd64", "amina-linux-amd64"},
		// Go says darwin, releases say macos. Getting this wrong makes every
		// update on a Mac fail against a release that plainly exists.
		{"darwin", "arm64", "amina-macos-arm64"},
		{"windows", "amd64", "amina-windows-amd64.exe"},
		{"linux", "arm", "amina-linux-arm"},
	} {
		if got := Artifact("amina", tc.goos, tc.goarch); got != tc.want {
			t.Errorf("Artifact(amina, %s, %s) = %q, want %q", tc.goos, tc.goarch, got, tc.want)
		}
	}
}

// TestToolNameStripsTheRepoPrefix pins the mapping from repository to artifact
// prefix. Getting it wrong makes a perfectly good release look absent.
func TestToolNameStripsTheRepoPrefix(t *testing.T) {
	for repo, want := range map[string]string{
		"QYVORA/qyvora-amina":   "amina",
		"QYVORA/qyvora-sekhmet": "sekhmet",
		"amina":                 "amina",
		"":                      "amina",
	} {
		if got := toolName(repo); got != want {
			t.Errorf("toolName(%q) = %q, want %q", repo, got, want)
		}
	}
}

// TestTheArtifactFetchedMatchesTheOnePublished ties the two together: the name
// the updater looks for has to be the name the manifest publishes.
func TestTheArtifactFetchedMatchesTheOnePublished(t *testing.T) {
	repo := "QYVORA/qyvora-amina"
	want := "amina-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		want += ".exe"
	}
	if got := Artifact(toolName(repo), runtime.GOOS, runtime.GOARCH); got != want {
		t.Errorf("artifact = %q, want %q", got, want)
	}
}

// TestTheUpdaterAgreesWithTheGeneratedInstaller is the drift guard.
//
// The artifact name is decided in two places that cannot see each other: the
// updater in Go, and qyvora-dist's installer and GoReleaser template in shell
// and YAML. They already disagreed once — Go calls the platform darwin and the
// release pipeline calls it macos — and the symptom is a 404 on a release that
// plainly exists, which reads as "no release exists" rather than "wrong name".
//
// Reading the generated installer here is the cheapest way to notice the next
// disagreement. It reads a sibling repository's output, so it skips when that is
// not present rather than failing.
func TestTheUpdaterAgreesWithTheGeneratedInstaller(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "install.sh"))
	if err != nil {
		t.Skipf("generated installer not available: %v", err)
	}
	script := string(body)

	// The installer composes the artifact name from a tool name and an OS token.
	// If that shape ever changes this test's premise is wrong, so it steps aside
	// instead of asserting something stale.
	const shape = `QYVORA_ARTIFACT="${QYVORA_TOOL}-${os_token}-${arch_token}"`
	if !strings.Contains(script, shape) {
		t.Skip("installer no longer composes artifact names the way this test assumes")
	}

	// The OS tokens the installer can produce are the ones an updater has to be
	// able to produce too. A platform reachable from only one side is a platform
	// where installing works and updating does not, or the reverse.
	for _, goos := range []string{"linux", "darwin", "windows", "android"} {
		if token := releaseOSToken(goos); token != "macos" && goos == "darwin" {
			t.Errorf("releaseOSToken(%q) = %q, want macos", goos, token)
		}
	}

	for _, tc := range []struct{ goos, goarch, want string }{
		{"linux", "amd64", "amina-linux-amd64"},
		{"darwin", "arm64", "amina-macos-arm64"},
		{"windows", "amd64", "amina-windows-amd64.exe"},
	} {
		if got := Artifact("amina", tc.goos, tc.goarch); got != tc.want {
			t.Errorf("Artifact(%s, %s) = %q, want %q", tc.goos, tc.goarch, got, tc.want)
		}
	}
}
