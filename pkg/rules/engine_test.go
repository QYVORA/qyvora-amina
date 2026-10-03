package rules

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-amina/internal/platform"
	"github.com/QYVORA/qyvora-amina/pkg/models"
)

func testTarget() models.Target {
	return models.Target{
		ID:       "target-test",
		Type:     models.TargetHost,
		Value:    "local",
		Platform: models.PlatformLinux,
		Auth:     models.Authorization{Granted: true},
	}
}

func testSnapshot(t *testing.T) *Snapshot {
	t.Helper()
	return &Snapshot{
		Target:      testTarget(),
		Env:         &platform.Env{Platform: models.PlatformLinux, GOOS: "linux"},
		CollectedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Depth:       DepthStandard,
	}
}

func TestBuiltinCatalogueIsWellFormed(t *testing.T) {
	cat := Builtin()
	if len(cat) == 0 {
		t.Fatal("the built-in catalogue is empty")
	}

	seen := map[string]Rule{}
	moduleIDs := map[string]bool{}
	for _, r := range cat {
		if r.ID == "" || r.Title == "" || r.Description == "" {
			t.Errorf("rule %q is missing required metadata: %+v", r.ID, r)
			continue
		}
		if dup, ok := seen[r.ID]; ok {
			t.Errorf("duplicate rule id %q (%q and %q)", r.ID, dup.Title, r.Title)
		}
		seen[r.ID] = r

		// Rule IDs are part of the machine contract, so the domain prefix is
		// part of it too.
		if !strings.Contains(r.ID, "-") {
			t.Errorf("rule id %q carries no domain prefix", r.ID)
		}
		if r.ModuleID == "" {
			t.Errorf("rule %q names no module", r.ID)
		}
		moduleIDs[r.ModuleID] = true
		if r.Match == nil {
			t.Errorf("rule %q has no matcher", r.ID)
		}
		if r.Severity == "" {
			t.Errorf("rule %q has no severity", r.ID)
		}
		if r.Confidence == "" {
			t.Errorf("rule %q has no confidence", r.ID)
		}
		if r.Exposure == "" {
			t.Errorf("rule %q has no exposure", r.ID)
		}
		if r.Privilege == "" {
			t.Errorf("rule %q has no privilege", r.ID)
		}
		// Anything an operator would be expected to act on must say what to do.
		if r.Severity != models.SeverityInformational && r.Recommendation == "" {
			t.Errorf("rule %q (%s) has no recommendation", r.ID, r.Severity)
		}
		// Zero means "no gate": the rule runs at every depth. Anything else
		// must name one of the three published depths.
		if r.MinimumDepth != 0 && (r.MinimumDepth < DepthQuick || r.MinimumDepth > DepthDeep) {
			t.Errorf("rule %q has an out-of-range depth gate %d", r.ID, r.MinimumDepth)
		}
	}
	if len(moduleIDs) < 10 {
		t.Errorf("catalogue covers only %d modules; the framework claims twenty domains", len(moduleIDs))
	}
}

func TestEngineBuildsDoesNotPanicOnDuplicateIDs(t *testing.T) {
	// NewEngine panics on a duplicate rule id rather than silently dropping one,
	// because a shadowed rule means a suppressed finding nobody can explain.
	defer func() {
		if recover() == nil {
			t.Error("expected a panic on duplicate rule ids")
		}
	}()
	NewEngine([]Rule{
		{ID: "X-001", Title: "a"},
		{ID: "X-001", Title: "b"},
	}, testTarget())
}

func TestSkippedRulesAlwaysCarryAReason(t *testing.T) {
	e := NewEngine(Builtin(), testTarget())
	snap := testSnapshot(t)
	res := e.Evaluate(snap)

	for _, sk := range res.Skipped {
		if sk.Reason == "" {
			t.Errorf("rule %q was skipped with no reason; 'not looked at' must never be indistinguishable from 'clean'", sk.ID)
		}
	}
	if res.RulesEvaluated == 0 {
		t.Error("no rules were evaluated on a Linux snapshot")
	}
}

func TestPlatformGatingExcludesForeignRulesWithAReason(t *testing.T) {
	e := NewEngine(Builtin(), testTarget())
	snap := testSnapshot(t)
	snap.Env = &platform.Env{Platform: models.PlatformWindows, GOOS: "windows"}

	res := e.Evaluate(snap)
	var sawDarwinOnly bool
	for _, sk := range res.Skipped {
		if !strings.Contains(sk.Reason, "not applicable on") {
			continue
		}
		sawDarwinOnly = true
	}
	if !sawDarwinOnly {
		t.Error("running on Windows should exclude the POSIX-only rules, and say so")
	}
	// A Linux-only rule must not fire on Windows.
	for _, f := range res.Findings {
		if f.RuleID == "RMT-002" { // PermitRootLogin, POSIX-only
			t.Errorf("POSIX-only rule %s fired on a Windows snapshot", f.RuleID)
		}
	}
}

func TestDepthGatingSkipsExpensiveRules(t *testing.T) {
	e := NewEngine(Builtin(), testTarget())
	snap := testSnapshot(t)
	snap.Depth = DepthQuick

	res := e.Evaluate(snap)

	// The reason must name the depth that rule actually requires, not a fixed
	// one: the catalogue has rules gated at more than one depth, and a skip
	// reason that always said "depth 2" would be misleading for a deep-only
	// rule.
	required := map[string]int{}
	for _, r := range Builtin() {
		required[r.ID] = r.MinimumDepth
	}
	checked := 0
	for _, sk := range res.Skipped {
		if !strings.Contains(sk.Reason, "requires depth") {
			continue
		}
		want, ok := required[sk.ID]
		if !ok {
			t.Fatalf("skipped rule %s is not in the catalogue", sk.ID)
		}
		if !strings.Contains(sk.Reason, fmt.Sprintf("depth %d", want)) {
			t.Errorf("depth skip reason should name the required depth: %q", sk.Reason)
		}
		checked++
	}
	if checked == 0 {
		t.Error("quick-depth evaluation skipped no depth-gated rule")
	}
	for _, f := range res.Findings {
		if f.RuleID == "NET-003" { // gated at DepthStandard
			t.Errorf("deep-only rule %s fired at quick depth", f.RuleID)
		}
	}
}

func TestUnauthorizedTargetBlocksEvaluation(t *testing.T) {
	target := testTarget()
	target.Auth = models.Authorization{Granted: false}
	e := NewEngine(Builtin(), target)
	res := e.Evaluate(testSnapshot(t))

	if res.RulesEvaluated != 0 {
		t.Errorf("%d rules ran against an unauthorized target", res.RulesEvaluated)
	}
	if len(res.Findings) != 0 {
		t.Errorf("%d findings were produced against an unauthorized target", len(res.Findings))
	}
}

// TestLoopbackListenerIsNotANetworkExposure is the framework's central negative
// guarantee: the classic port-scanner false positive must not exist here.
func TestLoopbackListenerIsNotANetworkExposure(t *testing.T) {
	e := NewEngine(Builtin(), testTarget())
	snap := testSnapshot(t)
	snap.Sockets = []platform.Socket{
		{Proto: "TCP", Addr: "127.0.0.1", Port: 8080, Scope: models.ScopeLoopback, Process: "node"},
		{Proto: "TCP", Addr: "::1", Port: 5432, Scope: models.ScopeLoopback, Process: "postgres"},
	}

	res := e.Evaluate(snap)
	for _, f := range res.Findings {
		switch f.RuleID {
		case "NET-001", "NET-002", "NET-004":
			t.Errorf("rule %s fired for a loopback-only listener: %s", f.RuleID, f.Title)
		}
	}
	// It should instead be reported as loopback context.
	var context bool
	for _, f := range res.Findings {
		if f.RuleID == "NET-003" {
			context = true
			if f.Severity != models.SeverityInformational {
				t.Errorf("loopback context reported as %s, want informational", f.Severity)
			}
		}
	}
	if !context {
		t.Error("loopback listeners should still be reported, as context")
	}
}

func TestWildcardListenerIsReported(t *testing.T) {
	e := NewEngine(Builtin(), testTarget())
	snap := testSnapshot(t)
	snap.Sockets = []platform.Socket{
		{Proto: "TCP", Addr: "0.0.0.0", Port: 22, Scope: models.ScopeWildcard, Wildcard: true, Process: "sshd", PID: 812},
	}

	res := e.Evaluate(snap)
	var wildcard, admin bool
	for _, f := range res.Findings {
		if f.RuleID == "NET-001" {
			wildcard = true
			if f.Exposure != models.ScopeWildcard {
				t.Errorf("wildcard bind reported as %q exposure", f.Exposure)
			}
			if f.Attributes["process"] != "sshd" {
				t.Errorf("finding lost its process attribution: %v", f.Attributes)
			}
		}
		if f.RuleID == "NET-002" {
			admin = true
		}
	}
	if !wildcard {
		t.Error("a wildcard-bound SSH listener did not raise NET-001")
	}
	if !admin {
		t.Error("a wildcard-bound SSH listener did not raise NET-002")
	}
}

func TestEvaluationIsDeterministic(t *testing.T) {
	build := func() *Snapshot {
		s := testSnapshot(t)
		s.Accounts = []models.Account{
			{Name: "amina", UID: "1000", Shell: "/bin/bash", Home: "/home/amina", AuthorizedKeys: 1},
			{Name: "nginx", UID: "998", Shell: "/usr/sbin/nologin", Service: true, NoLogin: true},
		}
		s.Sockets = []platform.Socket{
			{Proto: "TCP", Addr: "0.0.0.0", Port: 22, Scope: models.ScopeWildcard, Process: "sshd"},
			{Proto: "TCP", Addr: "0.0.0.0", Port: 6379, Scope: models.ScopeWildcard, Process: "redis-server"},
			{Proto: "TCP", Addr: "127.0.0.1", Port: 3000, Scope: models.ScopeLoopback, Process: "node"},
		}
		s.Provenance = []models.ProvenanceRecord{
			{Path: "/usr/local/bin/tool", State: models.ProvUnowned, Source: "ownership"},
		}
		return s
	}

	e := NewEngine(Builtin(), testTarget())
	first := e.Evaluate(build())
	for i := 0; i < 25; i++ {
		got := e.Evaluate(build())
		if len(got.Findings) != len(first.Findings) {
			t.Fatalf("run %d produced %d findings, first run produced %d",
				i, len(got.Findings), len(first.Findings))
		}
		for j := range got.Findings {
			if got.Findings[j].Fingerprint() != first.Findings[j].Fingerprint() {
				t.Fatalf("run %d finding %d differs:\n got %+v\nwant %+v",
					i, j, got.Findings[j], first.Findings[j])
			}
		}
	}
	if len(first.Findings) == 0 {
		t.Error("a snapshot with real exposures produced no findings at all")
	}
}

func TestFindingsCarryReproducibleScores(t *testing.T) {
	e := NewEngine(Builtin(), testTarget())
	s := testSnapshot(t)
	s.Sockets = []platform.Socket{
		{Proto: "TCP", Addr: "0.0.0.0", Port: 22, Scope: models.ScopeWildcard, Process: "sshd"},
	}
	for _, f := range e.Evaluate(s).Findings {
		if f.Attributes["risk_formula"] == "" {
			t.Errorf("finding %s carries no formula, so its score cannot be recomputed", f.RuleID)
		}
		if f.Attributes["risk_score"] == "" || f.Attributes["risk_band"] == "" {
			t.Errorf("finding %s carries no score: %v", f.RuleID, f.Attributes)
		}
		if f.Timestamp.IsZero() {
			t.Errorf("finding %s has no timestamp", f.RuleID)
		}
		if f.TargetID != testTarget().ID {
			t.Errorf("finding %s is attributed to target %q", f.RuleID, f.TargetID)
		}
		if len(f.Objects) == 0 {
			t.Errorf("finding %s names no object, so it cannot be acted on", f.RuleID)
		}
	}
}

func TestInferredFindingsAreMarkedInferred(t *testing.T) {
	e := NewEngine(Builtin(), testTarget())
	s := testSnapshot(t)
	s.Accounts = []models.Account{
		// No last-login record, raised at Possible confidence.
		{Name: "contractor", UID: "1042", Shell: "/bin/bash", Home: "/home/contractor"},
	}

	var found bool
	for _, f := range e.Evaluate(s).Findings {
		if f.RuleID != "ACC-003" {
			continue
		}
		found = true
		if f.State != models.StateInferred {
			t.Errorf("a Possible-confidence finding is in state %q, want inferred", f.State)
		}
		if f.Status == models.StatusConfirmed {
			t.Errorf("a Possible-confidence finding must not be marked confirmed")
		}
	}
	if !found {
		t.Error("an account with no last-login record raised no finding")
	}
}

func TestRulesDoNotMutateTheSnapshot(t *testing.T) {
	// A rule that reorders the snapshot's slices would make output depend on
	// evaluation order, which is exactly the determinism guarantee above.
	e := NewEngine(Builtin(), testTarget())
	s := testSnapshot(t)
	s.Sockets = []platform.Socket{
		{Proto: "TCP", Addr: "0.0.0.0", Port: 6379, Scope: models.ScopeWildcard, Process: "redis"},
		{Proto: "TCP", Addr: "0.0.0.0", Port: 22, Scope: models.ScopeWildcard, Process: "sshd"},
	}
	s.Accounts = []models.Account{
		{Name: "zoe", UID: "1001", Shell: "/bin/bash"},
		{Name: "adam", UID: "1002", Shell: "/bin/bash"},
	}

	before := snapshotOrder(s)
	e.Evaluate(s)
	e.Evaluate(s)
	after := snapshotOrder(s)
	if before != after {
		t.Errorf("rule evaluation mutated the snapshot ordering:\nbefore %s\nafter  %s", before, after)
	}
}

func snapshotOrder(s *Snapshot) string {
	var b strings.Builder
	for _, x := range s.Sockets {
		b.WriteString(x.Process)
		b.WriteByte(',')
	}
	for _, a := range s.Accounts {
		b.WriteString(a.Name)
		b.WriteByte(',')
	}
	return b.String()
}

func TestNilSnapshotIsSkippedNotPanicked(t *testing.T) {
	e := NewEngine(Builtin(), testTarget())
	res := e.Evaluate(nil)
	if res.RulesEvaluated != 0 {
		t.Errorf("%d rules ran against a nil snapshot", res.RulesEvaluated)
	}
	for _, sk := range res.Skipped {
		if sk.Reason == "" {
			t.Errorf("rule %q skipped with no reason", sk.ID)
		}
	}
}

func TestRemoteSnapshotIsMarked(t *testing.T) {
	b := NewBuilder(nil, testTarget(), DepthStandard) //nolint:staticcheck // nil ctx is never used by the builder
	s := b.WithRemote("filesystem not accessible on a remote target").Build()
	if !s.Remote || s.RemoteNote == "" {
		t.Error("a remote snapshot must carry a note explaining what could not be observed")
	}
}

func TestIdentityHeuristicBoundary(t *testing.T) {
	for _, tc := range identityShapedCases {
		if got := identityShaped(tc.token); got != tc.want {
			t.Errorf("identityShaped(%q) = %v, want %v (%s)",
				tc.token, got, tc.want, tc.why)
		}
	}
}

func TestIdentityHeuristicIsCaseAndSeparatorAgnostic(t *testing.T) {
	for _, v := range []string{"amina-laptop", "AMINA-LAPTOP", "Amina_Laptop", "amina.laptop", "amina laptop"} {
		if !identityShaped(v) {
			t.Errorf("identityShaped(%q) = false; the heuristic must not depend on case or separator", v)
		}
	}
}

func TestDaemonNamesAreNotFlaggedAsServiceAccounts(t *testing.T) {
	for _, n := range []string{"nobody", "daemon", "mysql", "redis", "sshd", "nginx", "messagebus", "redis6", "www-data"} {
		if !isDaemonName(n) {
			t.Errorf("isDaemonName(%q) = false; flagging distribution service accounts buries the real finding", n)
		}
	}
	for _, n := range []string{"amina", "contractor", "deploy"} {
		if isDaemonName(n) {
			t.Errorf("isDaemonName(%q) = true; a human account must not be treated as a daemon", n)
		}
	}
}

func TestGecosRoleValuesAreNotFlaggedAsNames(t *testing.T) {
	for _, g := range []string{"System Administrator", "root", "Unprivileged Account", "Web Server"} {
		if !looksLikeRole(g) {
			t.Errorf("looksLikeRole(%q) = false; role-only GECOS values are permanent noise", g)
		}
	}
	for _, g := range []string{"Fatima Zahra", "Aisha Bello"} {
		if looksLikeRole(g) {
			t.Errorf("looksLikeRole(%q) = true; a personal name must be caught", g)
		}
	}
}

func TestModeIsRestricted(t *testing.T) {
	for _, m := range []string{"0600", "400", "0700", "600"} {
		if !modeIsRestricted(m) {
			t.Errorf("modeIsRestricted(%q) = false", m)
		}
	}
	for _, m := range []string{"0644", "0640", "0666", "0755", "", "not-a-mode", "9999"} {
		if modeIsRestricted(m) {
			t.Errorf("modeIsRestricted(%q) = true", m)
		}
	}
}

func TestSensitivePathCoversBothFilesystemFamilies(t *testing.T) {
	for _, p := range []string{"/etc/passwd", "/usr/bin/ssh", "/bin/sh", "/opt/tool/run",
		`C:\Windows\System32\drivers\etc\hosts`, "/c:/program files/app/run.exe"} {
		if !sensitivePath(p) {
			t.Errorf("sensitivePath(%q) = false", p)
		}
	}
	for _, p := range []string{"/home/amina/notes.txt", "/tmp/build.log", "/var/tmp/x"} {
		if sensitivePath(p) {
			t.Errorf("sensitivePath(%q) = true", p)
		}
	}
}

func TestDepthParsingRoundTrips(t *testing.T) {
	for _, d := range []int{DepthQuick, DepthStandard, DepthDeep} {
		name := DepthName(d)
		got, ok := ParseDepth(name)
		if !ok || got != d {
			t.Errorf("ParseDepth(%q) = (%d, %v), want %d", name, got, ok, d)
		}
	}
	if _, ok := ParseDepth("exhaustive"); ok {
		t.Error("ParseDepth accepted an unpublished depth name")
	}
	if DepthName(99) != "unknown" {
		t.Error("an unpublished depth must render as unknown, not as an empty string")
	}
}

// TestServiceAccountRuleIgnoresOrdinaryUsers is a regression test for a rule that
// fired on every human account.
//
// ACC-001 asks whether a service identity can be logged into. Almost every
// ordinary account has an interactive shell, so matching on the shell alone
// produced the same finding for every user on the host — the fastest way to get
// a report switched off.
func TestServiceAccountRuleIgnoresOrdinaryUsers(t *testing.T) {
	snap := &Snapshot{
		Env:         &platform.Env{Platform: models.PlatformLinux},
		Depth:       2,
		CollectedAt: time.Unix(1700000000, 0).UTC(),
		Accounts: []models.Account{
			// An ordinary human account with a normal login shell.
			{Name: "aisha", UID: "1000", Shell: "/bin/bash", Classification: models.AccountStandard},
			// root having a shell is the default on Unix, not a finding.
			{Name: "root", UID: "0", Shell: "/bin/bash", Privileged: true, Classification: models.AccountStandard},
			// A machine identity that can be logged into is the real finding.
			{Name: "deploy", UID: "998", Shell: "/bin/bash", Service: true, Classification: models.AccountService},
		},
	}
	ev := NewEngine(Builtin(), snap.Target).Evaluate(snap)

	for _, f := range ev.Findings {
		if f.RuleID != "ACC-001" {
			continue
		}
		if len(f.Objects) == 1 && f.Objects[0] == "deploy" {
			return // the only ACC-001 is the service account
		}
	}
	t.Errorf("ACC-001 did not fire on the service account; findings: %v", ev.Findings)
}

// TestServiceAccountRuleIgnoresOrdinaryUsersByUID covers the classification
// signal being absent: the collector may not have run, so the UID range has to
// carry the decision on its own.
func TestServiceIdentityFallsBackToUIDRange(t *testing.T) {
	if !isServiceIdentity(models.Account{Name: "svc-app", UID: "101", Shell: "/bin/sh"}) {
		t.Error("a UID in the system range was not treated as a service identity")
	}
	if isServiceIdentity(models.Account{Name: "aisha", UID: "1000", Shell: "/bin/bash"}) {
		t.Error("an ordinary user account was treated as a service identity")
	}
	if isServiceIdentity(models.Account{Name: "aisha", UID: "", Shell: "/bin/bash"}) {
		t.Error("an account with no UID was treated as a service identity")
	}
}

// TestSoftwareRulesDoNotFireOncePerPackage is a regression test for a report with
// over five thousand findings.
//
// dpkg cannot report a package's origin, so the rule written against it matched
// every installed package. A rule whose output scales with the package count is
// a rule nobody reads: the first thing an operator does with a five-thousand
// finding report is stop running the tool.
func TestSoftwareRulesAggregateRatherThanEnumerate(t *testing.T) {
	var soft []models.Software
	for i := 0; i < 2000; i++ {
		soft = append(soft, models.Software{
			Name: fmt.Sprintf("libpkg%d", i), Version: "1.0", Provider: "dpkg", Origin: "unknown",
		})
	}
	snap := &Snapshot{
		Env: &platform.Env{Platform: models.PlatformLinux}, Depth: 2,
		CollectedAt: time.Unix(1700000000, 0).UTC(),
		Software:    soft,
		Sources:     []models.PackageSource{{ID: "apt", Provider: "apt", Trust: "official", Enabled: true}},
	}
	ev := NewEngine(Builtin(), snap.Target).Evaluate(snap)

	// One aggregate finding per provider is correct; 2000 is not. dpkg has no
	// configured source in this snapshot, so SW-001 legitimately fires once.
	if got := countRule(ev, "SW-001"); got > 1 {
		t.Errorf("SW-001 fired %d times for a single provider", got)
	}
	for _, f := range ev.Findings {
		if f.RuleID == "SW-001" && len(f.Objects) > 10 {
			t.Errorf("SW-001 listed %d objects, which is enumerating rather than aggregating", len(f.Objects))
		}
		if f.RuleID == "SW-002" {
			t.Errorf("SW-002 fired for names with no internal identifier: %v", f.Objects)
		}
	}
	if total := len(ev.Findings); total > 5 {
		t.Errorf("2000 unattributable packages produced %d findings", total)
	}
}

// TestUnattributedPackagesOnlyMatterWithoutAConfiguredSource is the other half:
// with no repository configured, the condition is real and must be reported.
func TestUnattributedPackagesOnlyMatterWithoutAConfiguredSource(t *testing.T) {
	base := func() *Snapshot {
		return &Snapshot{
			Env: &platform.Env{Platform: models.PlatformLinux}, Depth: 2,
			CollectedAt: time.Unix(1700000000, 0).UTC(),
			Software: []models.Software{
				{Name: "libfoo", Version: "1", Provider: "dpkg", Origin: "unknown"},
				{Name: "bar", Version: "2", Provider: "dpkg", Origin: "unknown"},
			},
		}
	}
	withSources := base()
	withSources.Sources = []models.PackageSource{{ID: "apt", Provider: "apt", Enabled: true}}
	if got := NewEngine(Builtin(), withSources.Target).Evaluate(withSources); countRule(got, "SW-001") != 0 {
		t.Error("SW-001 fired even though apt has a configured source")
	}

	without := base()
	if got := NewEngine(Builtin(), without.Target).Evaluate(without); countRule(got, "SW-001") != 1 {
		t.Error("SW-001 did not fire with no configured source for the provider")
	}
}

// TestInternalNamespaceIgnoresVersionSuffixes pins the narrower identifier test.
// Every Debian package carrying a version suffix looks unusual, and treating
// that as an internal identifier was what produced hundreds of findings.
func TestInternalNamespaceIgnoresVersionSuffixes(t *testing.T) {
	for _, name := range []string{
		"aspnetcore-runtime-6.0", "coinor-libcbc3.1", "libpython3.11-stdlib",
		"libc6", "fonts-dejavu-core", "python3-requests",
	} {
		if ns := internalNamespace(name); ns != "" {
			t.Errorf("%q was treated as an internal identifier (%q)", name, ns)
		}
	}
	for name, want := range map[string]string{
		"myorg-MyService": "MyService",
		// The leading label is the namespace; the suffix is the domain.
		"corp.example": "corp",
		"team_tool":    "team",
	} {
		if got := internalNamespace(name); got != want {
			t.Errorf("internalNamespace(%q) = %q, want %q", name, got, want)
		}
	}
}

func countRule(ev Evaluation, id string) int {
	n := 0
	for _, f := range ev.Findings {
		if f.RuleID == id {
			n++
		}
	}
	return n
}
