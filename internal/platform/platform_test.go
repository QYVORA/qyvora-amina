package platform

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// These tests run against the machine executing them rather than against
// fixtures. Amina's contract is that every capability reports its real
// behaviour on whatever host it lands on, so a fixture would test the fixture.
// What is asserted is the contract, not the host's contents.

func TestDetectProducesSelfConsistentEnv(t *testing.T) {
	e := Detect(ctxBackground())

	if e == nil {
		t.Fatal("Detect returned nil")
	}
	if e.Platform == "" {
		t.Error("platform was not resolved")
	}
	if e.GOOS == "" || e.GOARCH == "" {
		t.Errorf("runtime identity missing: GOOS=%q GOARCH=%q", e.GOOS, e.GOARCH)
	}
	if len(e.Support) == 0 {
		t.Fatal("no capabilities were primed")
	}
	if e.SupportLevel(CapCorrelation) == models.SupportNone {
		t.Error("identity correlation is portable and must never be unavailable")
	}
}

func TestMachineIDIsFingerprintedNotRaw(t *testing.T) {
	e := Detect(ctxBackground())
	if e.MachineID == "" {
		t.Skip("host exposes no machine identifier")
	}
	if len(e.MachineID) != 16 {
		t.Errorf("machine id should be a 16-character fingerprint, got %d characters: %q",
			len(e.MachineID), e.MachineID)
	}
	for _, r := range e.MachineID {
		if !strings.ContainsRune("0123456789abcdef", r) {
			t.Fatalf("fingerprint contains a non-hex character %q", r)
		}
	}
}

// TestMachineIDIsNotAnyKnownRawID is the test that would catch a regression
// where a collector starts emitting the machine ID verbatim.
func TestFingerprintDoesNotEchoItsInput(t *testing.T) {
	const secret = "d4e5f6091ee40266a6bdf9bd10f26f80"
	got := fingerprint(secret, 16)
	if got == secret {
		t.Fatal("fingerprint returned its input unchanged")
	}
	if !strings.Contains(fingerprint(secret, 64), got) {
		t.Error("short fingerprint should be a prefix of the full fingerprint")
	}
	if fingerprint(secret, 0) != fingerprint(secret, 64) {
		t.Error("a zero length should request the full fingerprint, not an empty one")
	}
}

func TestSetSupportKeepsWeakestObservation(t *testing.T) {
	e := &Env{Support: map[string]models.SupportLevel{}}

	e.SetSupport("cap", models.SupportFull)
	if got := e.SupportLevel("cap"); got != models.SupportFull {
		t.Fatalf("expected full, got %s", got)
	}

	// A second, weaker observation must not be able to upgrade the record.
	e.SetSupport("cap", models.SupportPrivilege)
	if got := e.SupportLevel("cap"); got != models.SupportPrivilege {
		t.Fatalf("expected the weaker level to win, got %s", got)
	}

	// And a stronger observation still cannot overwrite it.
	e.SetSupport("cap", models.SupportFull)
	if got := e.SupportLevel("cap"); got != models.SupportPrivilege {
		t.Fatalf("expected the weakest level to persist, got %s", got)
	}
}

func TestSupportLevelUnknownIsNone(t *testing.T) {
	e := &Env{Support: map[string]models.SupportLevel{}}
	if got := e.SupportLevel("never_recorded"); got != models.SupportNone {
		t.Errorf("an unrecorded capability should be unavailable, got %s", got)
	}
	var nilEnv *Env
	if got := nilEnv.SupportLevel("x"); got != models.SupportNone {
		t.Errorf("nil env must not panic and should report unavailable, got %s", got)
	}
	if nilEnv.Label() != "unknown" {
		t.Errorf("nil env label should be unknown, got %q", nilEnv.Label())
	}
	if nilEnv.Summary() != "" {
		t.Errorf("nil env summary should be empty, got %q", nilEnv.Summary())
	}
}

func TestClassifyAddrDistinguishesScopes(t *testing.T) {
	cases := []struct {
		addr     string
		want     models.ExposureScope
		wildcard bool
	}{
		{"0.0.0.0", models.ScopeWildcard, true},
		{"::", models.ScopeWildcard, true},
		{"127.0.0.1", models.ScopeLoopback, false},
		{"127.1.2.3", models.ScopeLoopback, false},
		{"::1", models.ScopeLoopback, false},
		{"10.0.0.5", models.ScopeLAN, false},
		{"172.16.4.4", models.ScopeLAN, false},
		{"172.32.4.4", models.ScopeLAN, false}, // outside the private range
		{"192.168.1.9", models.ScopeLAN, false},
		{"100.64.0.1", models.ScopeLAN, false},   // CGNAT
		{"169.254.10.1", models.ScopeLAN, false}, // link-local
	}
	for _, tc := range cases {
		got, wild := classifyAddr(tc.addr)
		if got != tc.want || wild != tc.wildcard {
			t.Errorf("classifyAddr(%q) = (%s, %v), want (%s, %v)",
				tc.addr, got, wild, tc.want, tc.wildcard)
		}
	}
}

// TestClassifyAddrNeverReportsLoopbackAsWildcard guards the single most
// consequential distinction in the network module: a loopback-bound service is
// not network-exposed.
func TestParseAddrPortHandlesBothIPFamilies(t *testing.T) {
	cases := []struct {
		in, host string
		port     int
	}{
		{"127.0.0.1:8080", "127.0.0.1", 8080},
		{"0.0.0.0:22", "0.0.0.0", 22},
		{"[::1]:443", "::1", 443},
		{"[fe80::1%eth0]:9090", "fe80::1", 9090},
		{"example.invalid", "example.invalid", 0},
	}
	for _, tc := range cases {
		host, port := ParseAddrPort(tc.in)
		if host != tc.host || port != tc.port {
			t.Errorf("ParseAddrPort(%q) = (%q, %d), want (%q, %d)",
				tc.in, host, port, tc.host, tc.port)
		}
	}
}

func TestParseRegQueryWalksKeyValuePairs(t *testing.T) {
	sample := `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip

    DisplayName    REG_SZ    7-Zip 23.01 (x64)
    DisplayVersion    REG_SZ    23.01
    Publisher    REG_SZ    Igor Pavlov

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Other

    DisplayName    REG_SZ    Other Tool`
	entries := parseRegQuery(sample)
	if len(entries) != 2 {
		t.Fatalf("expected two subkey entries, got %d: %#v", len(entries), entries)
	}
	if entries[0]["DisplayName"] != "7-Zip 23.01 (x64)" {
		t.Errorf("DisplayName parsed as %q", entries[0]["DisplayName"])
	}
	if entries[0]["Publisher"] != "Igor Pavlov" {
		t.Errorf("Publisher parsed as %q", entries[0]["Publisher"])
	}
	if entries[1]["DisplayName"] != "Other Tool" {
		t.Errorf("second entry parsed as %q", entries[1]["DisplayName"])
	}
}

func TestParseCSVLineHonoursQuotedCommas(t *testing.T) {
	got := parseCSVLine(`"\Task\One, daily",Manual,Ready`)
	if len(got) != 3 {
		t.Fatalf("expected 3 fields, got %d: %#v", len(got), got)
	}
	if got[0] != `\Task\One, daily` {
		t.Errorf("quoted comma mangled: %q", got[0])
	}
	if got[2] != "Ready" {
		t.Errorf("trailing field parsed as %q", got[2])
	}
}

func TestParseCSVLineHandlesEscapedQuotes(t *testing.T) {
	got := parseCSVLine(`"a ""quoted"" name",b`)
	if len(got) != 2 || got[0] != `a "quoted" name` {
		t.Errorf("escaped quotes not unescaped: %#v", got)
	}
}

func TestPlatformSupportIsConsistentAcrossPlatforms(t *testing.T) {
	for _, p := range models.Platforms {
		byCap := PlatformSupport(p)
		if len(byCap) != len(Capabilities) {
			t.Errorf("%s: matrix covers %d capabilities, expected %d",
				p, len(byCap), len(Capabilities))
		}
		// Every platform must offer the portable domains; a matrix that reports
		// a core domain as unavailable is worse than no matrix.
		for _, c := range []string{CapHostIdentity, CapNetwork, CapFilesystem, CapSecrets, CapCorrelation} {
			if byCap[c] == models.SupportNone {
				t.Errorf("%s: portable capability %q reported unavailable", p, c)
			}
		}
	}
	if PlatformSupport(models.PlatformWindows)[CapSELinux] != models.SupportNone {
		t.Error("SELinux should be unavailable on Windows")
	}
	if PlatformSupport(models.PlatformLinux)[CapRegistry] != models.SupportNone {
		t.Error("the Windows registry should be unavailable on Linux")
	}
	if PlatformSupport(models.PlatformLinux)[CapSELinux] == models.SupportNone {
		t.Error("SELinux should be available on Linux")
	}
}

func TestCapabilitiesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Capabilities {
		if seen[c] {
			t.Errorf("duplicate capability id %q", c)
		}
		seen[c] = true
	}
}

func TestFileHashFlagsTruncation(t *testing.T) {
	// A short file must hash completely and report no truncation.
	path := writeTempFile(t, "small", []byte("amina"))
	sum, size, truncated, err := FileHash(path)
	if err != nil {
		t.Fatalf("FileHash: %v", err)
	}
	if truncated {
		t.Error("a small file should not be reported as truncated")
	}
	if size != 5 {
		t.Errorf("size = %d, want 5", size)
	}
	if len(sum) != 64 {
		t.Errorf("sha256 hex length = %d, want 64", len(sum))
	}

	// A file larger than the read cap must say so rather than presenting a
	// partial hash as a complete one.
	big := make([]byte, maxReadBytes+1024)
	path = writeTempFile(t, "big", big)
	_, size, truncated, err = FileHash(path)
	if err != nil {
		t.Fatalf("FileHash(big): %v", err)
	}
	if !truncated {
		t.Error("a file past the read cap must be reported as truncated")
	}
	if size != int64(len(big)) {
		t.Errorf("size = %d, want %d", size, len(big))
	}
}

func TestReadFileLimitedCapsReads(t *testing.T) {
	path := writeTempFile(t, "huge", make([]byte, maxReadBytes*2))
	data, err := ReadFileLimited(path)
	if err != nil {
		t.Fatalf("ReadFileLimited: %v", err)
	}
	if len(data) != maxReadBytes {
		t.Errorf("read %d bytes, want the cap of %d", len(data), maxReadBytes)
	}
}

func TestAccountsArePopulatedOnThisHost(t *testing.T) {
	e := Detect(ctxBackground())
	accts, levels := Accounts(ctxBackground(), e)
	if len(levels) == 0 {
		t.Fatal("Accounts returned no support level")
	}
	if len(accts) == 0 {
		// A host with no readable account database is unusual but not invalid;
		// the level is what must tell the truth about it.
		if levels[0].Works() {
			t.Error("no accounts found but the capability claims to have worked")
		}
		return
	}
	var privileged int
	for _, a := range accts {
		if a.Name == "" {
			t.Error("account with an empty name")
		}
		if a.Source == "" {
			t.Error("account without a source is not evidence")
		}
		if a.Privileged {
			privileged++
		}
	}
	if privileged == 0 {
		t.Log("no privileged accounts visible; this run is almost certainly unprivileged")
	}
}

func TestProcessesResolveUserNames(t *testing.T) {
	procs, _ := Processes(ctxBackground(), Detect(ctxBackground()))
	if len(procs) == 0 {
		t.Skip("no processes visible to this run")
	}
	var numeric int
	for _, p := range procs {
		if p.Name == "" {
			continue
		}
		if isAllDigits(p.User) {
			numeric++
		}
	}
	// Some uids legitimately have no passwd entry, but the table should resolve
	// the overwhelming majority.
	if numeric > 0 && numeric == len(procs) {
		t.Error("no process user was resolved to a name; the uid table is not being applied")
	}
}

func TestServicesDoNotClaimEmptyWhenQueryFails(t *testing.T) {
	svcs, level := Services(ctxBackground(), Detect(ctxBackground()))
	if len(svcs) == 0 && level == models.SupportFull {
		t.Error("an empty service list must not be reported as full coverage")
	}
	for _, s := range svcs {
		if s.Name == "" || s.Source == "" {
			t.Errorf("service without identity or provenance: %+v", s)
		}
	}
}

func TestInstalledSoftwareIsSortedAndAttributed(t *testing.T) {
	pkgs, level := InstalledSoftware(ctxBackground(), Detect(ctxBackground()))
	if len(pkgs) == 0 && level == models.SupportFull {
		t.Error("an empty inventory must not claim full coverage")
	}
	for i := 1; i < len(pkgs); i++ {
		a, b := pkgs[i-1], pkgs[i]
		if a.Provider > b.Provider {
			t.Fatalf("inventory is not sorted: %q before %q", a.Provider, b.Provider)
		}
		if a.Provider == b.Provider && a.Name > b.Name {
			t.Fatalf("inventory is not sorted within %q: %q before %q", a.Provider, a.Name, b.Name)
		}
	}
	for _, p := range pkgs {
		if p.Provider == "" {
			t.Errorf("package %q has no ecosystem attribution", p.Name)
		}
		if p.Origin == "" {
			t.Errorf("package %q has an empty origin; it should be explicit or unknown", p.Name)
		}
	}
}

func TestProcStartTimeSurvivesSpacesInCommandName(t *testing.T) {
	// A process whose comm contains a space and parentheses is the case that
	// breaks naive /proc/<pid>/stat splitting.
	line := "1234 (my prog (x)) S 1 1234 1234 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 3 " +
		"0 98765 4242 918 18446744073709551615 1 1 0 0 0 0 0 0 0 17 2 0 0 0 0 0"
	if got := procStartTimeFrom(line); got != "98765" {
		t.Errorf("start time parsed as %q, want %q", got, "98765")
	}
}

func TestTrimUnitNormalizesSizes(t *testing.T) {
	cases := map[string]float64{
		"512": 512, "1K": 1024, "1KB": 1000, "2 MiB": 2 * 1024 * 1024,
		"3GB": 3e9, "1024B": 1024,
	}
	for in, want := range cases {
		got, err := trimUnit(in)
		if err != nil {
			t.Errorf("trimUnit(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("trimUnit(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := trimUnit("not-a-size"); err == nil {
		t.Error("expected an error for non-numeric input")
	}
}

func TestMatchPatternCoversPersistenceCases(t *testing.T) {
	cases := []struct {
		name, pattern string
		want          bool
	}{
		{"anything", "*", true},
		{"com.example.plist", "*.plist", true},
		{"com.example.txt", "*.plist", false},
		{"crontab", "cron*", true},
		{"exact", "exact", true},
		{"other", "exact", false},
	}
	for _, tc := range cases {
		if got := matchPattern(tc.name, tc.pattern); got != tc.want {
			t.Errorf("matchPattern(%q, %q) = %v, want %v",
				tc.name, tc.pattern, got, tc.want)
		}
	}
}

func TestFileIsExecutableUsesMagicBytesNotExtension(t *testing.T) {
	// An ELF binary named .txt is still an executable and must be treated as
	// one; an attacker controls the extension and not the header.
	elf := []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0}
	if !fileIsExecutable(writeTempFile(t, "disguised.txt", elf)) {
		t.Error("ELF content with a .txt name was not recognised as executable")
	}
	if fileIsExecutable(writeTempFile(t, "notes.md", []byte("just prose"))) {
		t.Error("a prose file was reported as executable")
	}
}

func writeTempFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

func ctxBackground() context.Context { return context.Background() }
