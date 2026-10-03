package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The CLI is the contract every other tool integrates against, so the things
// below are tested rather than assumed. Each of them is a behaviour a caller
// depends on and cannot see in the source: an exit code, or where bytes ended up.

func TestVersionExitsZero(t *testing.T) {
	if got := ExecuteArgs(t.Context(), []string{"version"}); got != 0 {
		t.Errorf("amina version exit = %d, want 0", got)
	}
}

func TestUnknownCommandIsAUsageError(t *testing.T) {
	if got := ExecuteArgs(t.Context(), []string{"nonsense"}); got != 2 {
		t.Errorf("unknown command exit = %d, want 2", got)
	}
}

func TestRemoteIsUnsupportedNotAUsageError(t *testing.T) {
	// The command line was valid; the platform cannot do this. That is exit 3,
	// and conflating it with exit 2 sends CI the wrong signal.
	got := ExecuteArgs(t.Context(), []string{"--remote", "--format", "json"})
	if got != 3 {
		t.Errorf("--remote exit = %d, want 3 (unsupported)", got)
	}
}

func TestSimulateNeedsNoFixture(t *testing.T) {
	// This is the documented one-word invocation. It used to be rejected because
	// configuration demanded --fixture, so the flag's own help text was false.
	if got := ExecuteArgs(t.Context(), []string{"--simulate", "--format", "json"}); got != 0 {
		t.Errorf("--simulate without --fixture exit = %d, want 0", got)
	}
}

func TestSimulateIsDeterministic(t *testing.T) {
	// The same fixture must produce the same report twice: a report whose
	// identifiers change on every run cannot be diffed, cached or signed.
	//
	// Duration is excluded, and that exclusion is the point rather than a
	// convenience. Two runs of the same fixture genuinely take different amounts
	// of wall-clock time, so comparing raw bytes made this test fail or pass
	// according to how loaded the machine happened to be. Zeroing the one field
	// that measures the machine instead of the data turns a coin flip into the
	// guarantee it was meant to state.
	first := withoutDuration(t, captureReport(t))
	second := withoutDuration(t, captureReport(t))
	if first != second {
		t.Error("two --simulate runs produced different reports")
	}
}

// withoutDuration canonicalises a report with its duration zeroed.
//
// The bytes are re-marshalled from parsed JSON rather than patched as text so
// that key order cannot make two identical reports look different.
func withoutDuration(t *testing.T, report string) string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal([]byte(report), &doc); err != nil {
		t.Fatalf("report is not JSON: %v", err)
	}
	doc["duration_ms"] = 0
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	return string(out)
}

// TestReportFileIgnoresEventRouting pins the bug where --events stdout pushed the
// report onto stderr and quietly overrode -o.
func TestReportFileIgnoresEventRouting(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "report.json")
	events := filepath.Join(dir, "events.jsonl")

	got := ExecuteArgs(t.Context(), []string{
		"--simulate", "--format", "json", "-o", report, "--events=" + events,
	})
	if got != 0 {
		t.Fatalf("exit = %d, want 0", got)
	}
	if _, err := os.Stat(report); err != nil {
		t.Errorf("report file was not written: %v", err)
	}
	body, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(body)), "{") {
		t.Errorf("report file does not contain a JSON report: %.60q", body)
	}
}

// TestEventsStreamIsNotMixedIntoTheReport is the other half of the routing
// contract: with events on stdout, stdout must be JSONL and nothing else.
func TestEventsStreamIsNotMixedIntoTheReport(t *testing.T) {
	dir := t.TempDir()
	events := filepath.Join(dir, "events.jsonl")

	if got := ExecuteArgs(t.Context(), []string{"--simulate", "--format", "json", "--events", events}); got != 0 {
		t.Fatalf("exit = %d, want 0", got)
	}
	body, err := os.ReadFile(events)
	if err != nil {
		t.Fatalf("event stream was not written: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("event stream is empty")
	}
	for i, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if !strings.HasPrefix(line, "{") {
			t.Errorf("event line %d is not JSON: %.60q", i+1, line)
		}
	}
}

func TestTerminalFormatToAFileIsRefused(t *testing.T) {
	got := ExecuteArgs(t.Context(), []string{"--simulate", "-o", filepath.Join(t.TempDir(), "r.txt")})
	if got != 2 {
		t.Errorf("terminal report to a file exit = %d, want 2", got)
	}
}

func TestFailOnGatesTheExitCode(t *testing.T) {
	// The built-in dataset contains high-severity findings, so a high threshold
	// must fail the run. The default must not, or every pipeline goes red.
	if got := ExecuteArgs(t.Context(), []string{"--simulate", "--format", "json", "--fail-on", "high"}); got == 0 {
		t.Error("--fail-on high did not fail a run that contains high findings")
	}
	if got := ExecuteArgs(t.Context(), []string{"--simulate", "--format", "json"}); got != 0 {
		t.Errorf("default run exit = %d, want 0: findings alone must not fail a run", got)
	}
}

func TestMinSeveritySuppressesLowerFindings(t *testing.T) {
	all := severityCounts(t, "")
	critical := severityCounts(t, "critical")

	for sev, n := range critical {
		if n > all[sev] {
			t.Errorf("--min-severity critical increased %s findings: %d -> %d", sev, all[sev], n)
		}
	}
	if critical["low"] != 0 || critical["medium"] != 0 {
		t.Errorf("--min-severity critical still reported low/medium: %v", critical)
	}
}

func TestUnknownFlagIsAUsageError(t *testing.T) {
	if got := ExecuteArgs(t.Context(), []string{"--no-such-flag"}); got != 2 {
		t.Errorf("unknown flag exit = %d, want 2", got)
	}
}

func TestUpdateRefusesWhenOffline(t *testing.T) {
	if got := ExecuteArgs(t.Context(), []string{"update", "--offline"}); got != 3 {
		t.Errorf("--offline update exit = %d, want 3 (unsupported)", got)
	}
}

func TestUpdateUnknownFlagIsAUsageError(t *testing.T) {
	if got := ExecuteArgs(t.Context(), []string{"update", "--no-such-flag"}); got != 2 {
		t.Errorf("update with an unknown flag exit = %d, want 2", got)
	}
}

func TestConfirmUpdateTreatsSilenceAsNo(t *testing.T) {
	var out strings.Builder
	for _, in := range []string{"", "\n", "n\n", "no\n", "maybe\n", "\x00\n"} {
		ok, err := confirmUpdate("", strings.NewReader(in), &out)
		if err != nil {
			t.Errorf("confirmUpdate(%q): %v", in, err)
		}
		if ok {
			t.Errorf("confirmUpdate(%q) said yes; a tool that rewrites its own binary must not", in)
		}
	}
}

func TestConfirmUpdateAcceptsExplicitConsent(t *testing.T) {
	for _, in := range []string{"y\n", "Y\n", "yes\n", "YES\n", "  y  \n"} {
		var out strings.Builder
		ok, err := confirmUpdate("", strings.NewReader(in), &out)
		if err != nil {
			t.Errorf("confirmUpdate(%q): %v", in, err)
		}
		if !ok {
			t.Errorf("confirmUpdate(%q) said no; explicit consent must be honoured", in)
		}
	}
}

// captureReport runs a simulated JSON assessment and returns the report bytes.
func captureReport(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.json")
	if got := ExecuteArgs(t.Context(), []string{"--simulate", "--format", "json", "-o", path}); got != 0 {
		t.Fatalf("--simulate exit = %d, want 0", got)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

// severityCounts counts findings per severity in a simulated run.
func severityCounts(t *testing.T, minSeverity string) map[string]int {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.json")
	args := []string{"--simulate", "--format", "json", "-o", path}
	if minSeverity != "" {
		args = append(args, "--min-severity", minSeverity)
	}
	if got := ExecuteArgs(t.Context(), args); got != 0 {
		t.Fatalf("exit = %d, want 0", got)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		Findings []struct {
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(body, &rep); err != nil {
		t.Fatalf("report is not JSON: %v", err)
	}
	counts := map[string]int{}
	for _, f := range rep.Findings {
		counts[f.Severity]++
	}
	return counts
}

// TestVersionAnswersTheSharedContract pins `version -o json`, which is how every
// orchestrator in the ecosystem asks a binary what it is. Answering it wrongly
// is what makes a tool unusable from automation, so it is a contract and not a
// convenience.
func TestVersionAnswersTheSharedContract(t *testing.T) {
	var code int
	out := captureStdout(t, func() { code = ExecuteArgs(t.Context(), []string{"version", "-o", "json"}) })
	if code != 0 {
		t.Fatalf("version -o json exit = %d, want 0", code)
	}

	var info struct {
		Framework string `json:"framework"`
		Version   string `json:"version"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		t.Fatalf("version -o json is not JSON: %v: %.80q", err, out)
	}
	if info.Framework != "amina" {
		t.Errorf("framework = %q, want %q", info.Framework, "amina")
	}
	if !strings.HasPrefix(info.Version, "v") {
		t.Errorf("version = %q, want a semver tag", info.Version)
	}
}

func TestVersionRejectsAnUnknownFormat(t *testing.T) {
	if got := ExecuteArgs(t.Context(), []string{"version", "-o", "yaml"}); got != 2 {
		t.Errorf("version -o yaml exit = %d, want 2", got)
	}
}

// captureStdout runs fn with os.Stdout redirected to a temporary file and returns
// what was written.
//
// A file rather than a pipe: a pipe needs a reader draining it concurrently, and
// a report is larger than the 64 KiB a pipe buffer holds, so the writer would
// block part-way through and the test would hang instead of failing.
func captureStdout(t *testing.T, fn func()) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdout")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = saved }()

	fn()

	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// TestUnknownModuleIsAUsageError is the end-to-end version of the module-name
// check: the seam is only worth having if the real binary installs it.
func TestUnknownModuleIsAUsageError(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"misspelled include", []string{"assess", "--include", "host-idenity", "--simulate"}},
		{"misspelled exclude", []string{"assess", "--exclude", "host-idenity", "--simulate"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code := ExecuteArgs(t.Context(), tc.args); code != 2 {
				t.Errorf("exit = %d, want 2 (a misspelled module is a usage error)", code)
			}
		})
	}
}

// TestKnownModulesAreAccepted guards the other direction: validation must not
// reject a real module name.
func TestKnownModulesAreAccepted(t *testing.T) {
	code := ExecuteArgs(t.Context(), []string{"assess", "--include", "host-identity", "--simulate", "--format", "json", "-o", os.DevNull})
	if code != 0 {
		t.Errorf("exit = %d, want 0 for a valid --include", code)
	}
}
