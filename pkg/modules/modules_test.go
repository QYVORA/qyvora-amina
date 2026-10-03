package modules

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-amina/internal/platform"
	"github.com/QYVORA/qyvora-amina/pkg/models"
	"github.com/QYVORA/qyvora-amina/pkg/rules"
)

func testTarget() models.Target {
	return models.Target{
		ID:       "t1",
		Type:     models.TargetHost,
		Value:    "local",
		Platform: models.PlatformLinux,
		Auth:     models.Authorization{Granted: true},
	}
}

func fixedClock() func() time.Time {
	t := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

// TestEveryRuleBelongsToARegisteredModule is the structural guarantee that the
// rule catalogue and the module registry describe the same framework. A rule
// pointing at a module that does not exist produces a finding no report can
// attribute, and a module with no rules produces a section that is always empty.
func TestEveryRuleBelongsToARegisteredModule(t *testing.T) {
	registered := map[string]bool{}
	for _, m := range All() {
		registered[m.ID] = true
	}

	used := map[string]bool{}
	for _, r := range rules.Builtin() {
		if r.ModuleID == "" {
			t.Errorf("rule %s names no module", r.ID)
			continue
		}
		if !registered[r.ModuleID] {
			t.Errorf("rule %s names module %q, which is not registered", r.ID, r.ModuleID)
		}
		used[r.ModuleID] = true
	}

	for _, m := range All() {
		if !used[m.ID] && m.Collect != nil {
			t.Errorf("module %q has a collector but no rules; it can only ever produce an empty section", m.ID)
		}
	}
}

func TestRegistryIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	sections := map[int]bool{}
	for _, m := range All() {
		if m.ID == "" || m.Name == "" || m.Purpose == "" {
			t.Errorf("module %+v is missing required metadata", m)
		}
		if seen[m.ID] {
			t.Errorf("duplicate module id %q", m.ID)
		}
		seen[m.ID] = true

		if m.SpecSection <= 0 {
			t.Errorf("module %q records no spec section", m.ID)
		}
		if sections[m.SpecSection] {
			t.Errorf("module %q reuses spec section %d", m.ID, m.SpecSection)
		}
		sections[m.SpecSection] = true

		if len(m.Platforms) == 0 {
			t.Errorf("module %q declares no platforms, so it would be skipped everywhere", m.ID)
		}
		if m.MinimumDepth < 1 || m.MinimumDepth > 3 {
			t.Errorf("module %q has an out-of-range depth gate %d", m.ID, m.MinimumDepth)
		}
		if m.Category == "" {
			t.Errorf("module %q declares no finding category", m.ID)
		}
	}
	// The specification's assessment domains run from section 8 to section 30.
	if len(All()) < 20 {
		t.Errorf("registry has %d modules; the specification names at least twenty domains", len(All()))
	}
}

// TestEveryModuleEitherWorksOrSaysWhy is the specification's "do not create fake
// modules" requirement, enforced. A module with no collector must report a
// reason, and a module with a collector must have actually run.
func TestEveryModuleEitherWorksOrSaysWhy(t *testing.T) {
	r := &Runner{Now: fixedClock()}
	res := r.Run(context.Background(), testTarget(), 3)

	if len(res.Statuses) != len(All()) {
		t.Fatalf("%d statuses for %d modules", len(res.Statuses), len(All()))
	}
	for _, st := range res.Statuses {
		switch st.Status {
		case models.ExposureSkipped:
			if st.Reason == "" {
				t.Errorf("module %q was skipped with no reason", st.ID)
			}
			if !strings.Contains(st.Reason, ReasonNotImplemented) &&
				!strings.Contains(st.Reason, ReasonUnsupported) &&
				!strings.Contains(st.Reason, ReasonBelowDepth) {
				t.Errorf("module %q was skipped for an unrecognised reason %q", st.ID, st.Reason)
			}
		case models.ExposureComplete, models.ExposurePartial, models.ExposureDegraded, models.ExposurePrivilege:
			// A module that ran must have a name, and a degraded or partial run
			// must explain itself.
			if st.Name == "" {
				t.Errorf("module %q reported status %q with no name", st.ID, st.Status)
			}
			if st.Status == models.ExposureDegraded && st.Reason == "" {
				t.Errorf("module %q is degraded with no reason", st.ID)
			}
		default:
			t.Errorf("module %q reported unknown status %q", st.ID, st.Status)
		}
	}
}

// TestUnimplementedModulesReportRatherThanDisappear is the same requirement seen
// from the report's side: a declared module that does not work must still be
// present in the snapshot's module status, so a reader can see the gap.
func TestUnimplementedModulesReportRatherThanDisappear(t *testing.T) {
	r := &Runner{Now: fixedClock()}
	res := r.Run(context.Background(), testTarget(), 3)

	inSnapshot := map[string]bool{}
	for _, st := range res.Snapshot.ModuleStatus {
		inSnapshot[st.ID] = true
	}
	for _, m := range All() {
		if !inSnapshot[m.ID] {
			t.Errorf("module %q is missing from the snapshot's module status", m.ID)
		}
	}

	var skipped, ran int
	for _, st := range res.Statuses {
		if st.Status == models.ExposureSkipped {
			skipped++
		} else {
			ran++
		}
	}
	if ran == 0 {
		t.Error("no module ran at all")
	}
	t.Logf("%d modules ran, %d reported a reason for not running", ran, skipped)
}

func TestDepthGateSkipsExpensiveModules(t *testing.T) {
	r := &Runner{Now: fixedClock()}
	res := r.Run(context.Background(), testTarget(), 1)

	for _, st := range res.Statuses {
		m, _ := ByID(st.ID)
		if m.MinimumDepth > 1 && st.Status != models.ExposureSkipped {
			t.Errorf("module %q needs depth %d but ran at quick depth", st.ID, m.MinimumDepth)
		}
	}
	for _, st := range res.Statuses {
		if st.Status == models.ExposureSkipped && strings.Contains(st.Reason, ReasonBelowDepth) {
			if !strings.Contains(st.Reason, "depth 1") {
				t.Errorf("depth skip reason should name the requested depth: %q", st.Reason)
			}
		}
	}
}

// TestGateRejectsWithAReason covers every disqualifying path, which is
// unreachable from a test running on one host without extracting the decision.
func TestGateRejectsWithAReason(t *testing.T) {
	posix := Module{ID: "posix-only", Platforms: []models.Platform{models.PlatformLinux},
		Collect: CollectorFunc(func(Input) (Result, error) { return Result{}, nil })}
	deep := Module{ID: "deep", Platforms: allDesktop, MinimumDepth: 3,
		Collect: CollectorFunc(func(Input) (Result, error) { return Result{}, nil })}
	unimplemented := Module{ID: "todo", Platforms: allDesktop, MinimumDepth: 1}
	windows := Module{ID: "binary-integrity", Platforms: allDesktop, MinimumDepth: 1,
		Collect: CollectorFunc(func(Input) (Result, error) { return Result{}, nil })}

	linux := &platform.Env{Platform: models.PlatformLinux}
	win := &platform.Env{Platform: models.PlatformWindows}

	for _, tc := range []struct {
		name       string
		mod        Module
		in         Input
		wantStatus models.ExposureLevel
		wantReason string
	}{
		{"not implemented", unimplemented, Input{Env: linux, Depth: 3},
			models.ExposureSkipped, ReasonNotImplemented},
		{"platform mismatch", posix, Input{Env: win, Depth: 3},
			models.ExposureSkipped, ReasonUnsupported},
		{"below depth", deep, Input{Env: linux, Depth: 1},
			models.ExposureSkipped, ReasonBelowDepth},
		{"no environment", posix, Input{Env: nil, Depth: 3},
			models.ExposureSkipped, ReasonUnavailable},
		{"needs elevation", windows, Input{Env: win, Depth: 3},
			models.ExposurePrivilege, ReasonPrivilege},
		{"elevated windows is allowed", windows, Input{Env: &platform.Env{Platform: models.PlatformWindows, Privileged: true}, Depth: 3},
			models.ExposureComplete, ""},
		{"unprivileged linux is allowed", windows, Input{Env: linux, Depth: 3},
			models.ExposureComplete, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, gated := gate(tc.mod, tc.in)
			if tc.wantReason == "" {
				if gated {
					t.Fatalf("module was gated (%q) but should have run", st.Reason)
				}
				return
			}
			if !gated {
				t.Fatal("module ran when it should have been gated")
			}
			if st.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q", st.Status, tc.wantStatus)
			}
			if !strings.Contains(st.Reason, tc.wantReason) {
				t.Errorf("reason = %q, want it to mention %q", st.Reason, tc.wantReason)
			}
			if st.ID != tc.mod.ID || st.Name != tc.mod.Name {
				t.Errorf("gated status lost its identity: %+v", st)
			}
		})
	}
}

// TestGateReasonNamesThePlatform makes the unsupported message useful rather
// than merely present: an operator on Windows needs to know what the module
// would have covered.
func TestGateReasonNamesThePlatform(t *testing.T) {
	m := Module{ID: "posix-only", Platforms: []models.Platform{models.PlatformLinux, models.PlatformDarwin},
		Collect: CollectorFunc(func(Input) (Result, error) { return Result{}, nil })}
	st, gated := gate(m, Input{Env: &platform.Env{Platform: models.PlatformWindows}, Depth: 3})
	if !gated {
		t.Fatal("expected the gate to reject a Windows run")
	}
	if !strings.Contains(st.Reason, "linux") || !strings.Contains(st.Reason, "windows") {
		t.Errorf("reason does not name both sides: %q", st.Reason)
	}
}

func TestPlatformSupportIsCheckedBeforeRunning(t *testing.T) {
	m := Module{ID: "x", Platforms: []models.Platform{models.PlatformDarwin}}
	if m.Supports(models.PlatformLinux) {
		t.Error("a Darwin-only module claims to support Linux")
	}
	if !m.Supports(models.PlatformDarwin) {
		t.Error("a Darwin-only module does not claim to support Darwin")
	}
	empty := Module{ID: "y"}
	if empty.Supports(models.PlatformLinux) {
		t.Error("a module with no declared platforms claims to support everything")
	}
}

func TestAFailingModuleDoesNotStopTheRun(t *testing.T) {
	boom := func(Input) (Result, error) { return Result{}, errFake }
	r := &Runner{
		Now: fixedClock(),
		Modules: []Module{
			{ID: "before", Name: "Before", MinimumDepth: 1, Platforms: allDesktop,
				Collect: CollectorFunc(func(Input) (Result, error) { return Result{}, nil })},
			{ID: "boom", Name: "Boom", MinimumDepth: 1, Platforms: allDesktop, Collect: CollectorFunc(boom)},
			{ID: "after", Name: "After", MinimumDepth: 1, Platforms: allDesktop,
				Collect: CollectorFunc(func(Input) (Result, error) { return Result{}, nil })},
		},
	}
	res := r.Run(context.Background(), testTarget(), 3)

	if len(res.Statuses) != 3 {
		t.Fatalf("%d statuses, want 3: a failing module aborted the run", len(res.Statuses))
	}
	if res.Statuses[1].Status != models.ExposureDegraded {
		t.Errorf("failed module status = %q, want degraded", res.Statuses[1].Status)
	}
	if !strings.Contains(res.Statuses[1].Reason, "collection failed") {
		t.Errorf("failure reason lost: %q", res.Statuses[1].Reason)
	}
	if res.Statuses[0].Status != models.ExposureComplete || res.Statuses[2].Status != models.ExposureComplete {
		t.Error("a module failure prevented its neighbours from reporting")
	}
}

var errFake = errFakeType{}

type errFakeType struct{}

func (errFakeType) Error() string { return "synthetic failure" }

func TestDegradedModuleNamesWhatItCouldNotRead(t *testing.T) {
	r := &Runner{
		Now: fixedClock(),
		Modules: []Module{{
			ID: "partial", Name: "Partial", MinimumDepth: 1, Platforms: allDesktop,
			Collect: CollectorFunc(func(Input) (Result, error) {
				return Result{Degraded: true, Note: "two of three sources readable", Unavailable: []string{platform.CapProcesses}}, nil
			}),
		}},
	}
	res := r.Run(context.Background(), testTarget(), 3)
	st := res.Statuses[0]
	if st.Status != models.ExposureDegraded {
		t.Errorf("status = %q, want degraded", st.Status)
	}
	if len(st.Unavailable) != 1 || st.Unavailable[0] != platform.CapProcesses {
		t.Errorf("Unavailable = %v, want the missing capability named", st.Unavailable)
	}
	if st.Reason == "" {
		t.Error("degraded module gave no reason")
	}
}

func TestResultsAreSortedDeterministically(t *testing.T) {
	r := &Runner{Now: fixedClock()}
	first := r.Run(context.Background(), testTarget(), 3).Snapshot

	for i := 0; i < 5; i++ {
		got := r.Run(context.Background(), testTarget(), 3).Snapshot
		if len(got.Assets) != len(first.Assets) {
			t.Fatalf("run %d produced %d assets, first run %d", i, len(got.Assets), len(first.Assets))
		}
		for j := range got.Assets {
			if got.Assets[j].ID != first.Assets[j].ID || got.Assets[j].Name != first.Assets[j].Name {
				t.Fatalf("run %d asset %d differs: %q/%q vs %q/%q", i, j,
					got.Assets[j].ID, got.Assets[j].Name, first.Assets[j].ID, first.Assets[j].Name)
			}
		}
		for j := range got.ModuleStatus {
			if got.ModuleStatus[j].ID != first.ModuleStatus[j].ID {
				t.Fatalf("module status order differs on run %d", i)
			}
		}
	}
}

func TestModuleStatusIsSortedByID(t *testing.T) {
	r := &Runner{Now: fixedClock()}
	res := r.Run(context.Background(), testTarget(), 3)
	ids := make([]string, 0, len(res.Snapshot.ModuleStatus))
	for _, st := range res.Snapshot.ModuleStatus {
		ids = append(ids, st.ID)
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("module status is not sorted: %v", ids)
	}
}

func TestRemoteTargetIsNotFilledWithLocalObservations(t *testing.T) {
	remote := testTarget()
	remote.Type = models.TargetSnapshot
	remote.Value = "captured-elsewhere"

	r := &Runner{Now: fixedClock()}
	res := r.Run(context.Background(), remote, 3)

	if !res.Snapshot.Remote {
		t.Error("snapshot does not record that the target was not inspected locally")
	}
	if res.Snapshot.RemoteNote == "" {
		t.Error("remote snapshot gives no explanation of what could not be observed")
	}
	if len(res.Snapshot.Sockets) != 0 {
		t.Errorf("%d local sockets leaked into a report about another machine", len(res.Snapshot.Sockets))
	}
	if len(res.Snapshot.Accounts) != 0 {
		t.Errorf("%d local accounts leaked into a report about another machine", len(res.Snapshot.Accounts))
	}
}

func TestHostIdentityCollectorProducesIdentitySignals(t *testing.T) {
	var res Result
	var err error
	res, err = collectHostIdentity(Input{Env: &platform.Env{
		Platform: models.PlatformLinux, Hostname: "amina-laptop",
		User: "amina", Home: "/home/amina", Distro: "Ubuntu 24.04",
	}})
	if err != nil {
		t.Fatalf("collectHostIdentity: %v", err)
	}
	if len(res.Identities) == 0 {
		t.Error("host identity produced no identity signals, so correlation has nothing to join")
	}
	if len(res.Assets) == 0 {
		t.Error("host identity produced no assets")
	}
	// A blank field must not become a blank asset: it would read as "this value
	// is the empty string" rather than "not present".
	for _, a := range res.Assets {
		if a.Attributes["value"] == "" {
			t.Errorf("asset %q carries an empty value", a.Name)
		}
	}
}

func TestCollectorIsGivenOnlyItsInput(t *testing.T) {
	// A collector that reaches for a shared global could see another module's
	// results, which would make module order significant.
	var seen Input
	rec := CollectorFunc(func(in Input) (Result, error) { seen = in; return Result{}, nil })
	if _, err := rec.Collect(Input{Depth: 2, Target: testTarget()}); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if seen.Depth != 2 {
		t.Errorf("collector saw depth %d", seen.Depth)
	}
}

func TestWeakestSupportSelectsTheLeastCapable(t *testing.T) {
	for _, tc := range []struct {
		in   []models.SupportLevel
		want models.SupportLevel
	}{
		{nil, models.SupportNone},
		{[]models.SupportLevel{models.SupportFull}, models.SupportFull},
		{[]models.SupportLevel{models.SupportFull, models.SupportPartial}, models.SupportPartial},
		{[]models.SupportLevel{models.SupportFull, models.SupportPrivilege, models.SupportLimited}, models.SupportPrivilege},
	} {
		if got := weakestSupport(tc.in); got != tc.want {
			t.Errorf("weakestSupport(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIDsAndByIDAgreeWithTheRegistry(t *testing.T) {
	ids := IDs()
	if len(ids) != len(All()) {
		t.Fatalf("IDs() returned %d, All() %d", len(ids), len(All()))
	}
	for _, id := range ids {
		m, ok := ByID(id)
		if !ok {
			t.Errorf("IDs() lists %q but ByID cannot find it", id)
		}
		if m.ID != id {
			t.Errorf("ByID(%q) returned %q", id, m.ID)
		}
	}
	if _, ok := ByID("no-such-module"); ok {
		t.Error("ByID invented a module")
	}
}
