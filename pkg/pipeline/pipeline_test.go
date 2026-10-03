package pipeline

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/QYVORA/qyvora-amina/internal/config"
	"github.com/QYVORA/qyvora-amina/internal/events"
	"github.com/QYVORA/qyvora-amina/internal/output"
	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// fixedClock makes every run in this file produce byte-identical output. Without
// it, generated-at timestamps alone would make any golden comparison fail.
func newTestStream(w *bytes.Buffer) *events.Stream { return events.NewStream(w) }

func fixedClock() func() time.Time {
	t := time.Unix(1700000000, 0).UTC()
	return func() time.Time { return t }
}

func simConfig() config.Config {
	c := config.Default()
	c.Depth = 2
	c.Simulate = true
	c.Fixture = "builtin"
	c.Format = config.FormatJSON
	return c
}

func runSim(t *testing.T, cfg config.Config) *Result {
	t.Helper()
	res, err := New(Options{Config: cfg, Now: fixedClock()}).Run(context.Background())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return res
}

func TestSimulationRunProducesAReport(t *testing.T) {
	res := runSim(t, simConfig())
	rep := res.Report
	if rep == nil {
		t.Fatal("no report")
	}
	if rep.Target.Type != models.TargetSimulation {
		t.Errorf("target type = %q, want %q", rep.Target.Type, models.TargetSimulation)
	}
	if rep.Integrity == "" {
		t.Error("report has no integrity stamp")
	}
	if rep.Host.Platform == "" {
		t.Error("report has no host platform")
	}
	if len(rep.Limitations) == 0 {
		t.Error("a simulation run reported no limitations; every module is skipped by design, so this must be non-empty")
	}
}

func TestSimulationIsDeterministic(t *testing.T) {
	first := runSim(t, simConfig()).Report
	second := runSim(t, simConfig()).Report

	if first.ID != second.ID {
		t.Errorf("report IDs differ across runs: %s vs %s", first.ID, second.ID)
	}
	if first.Integrity != second.Integrity {
		t.Errorf("integrity differs across runs:\n%s\n%s", first.Integrity, second.Integrity)
	}
	if first.Summary.Total != second.Summary.Total {
		t.Errorf("finding counts differ: %d vs %d", first.Summary.Total, second.Summary.Total)
	}
}

func TestBuiltinFixtureProducesFindings(t *testing.T) {
	rep := runSim(t, simConfig()).Report
	// The fixture deliberately contains a world-bound SSH listener and a token
	// in a dotfile. If neither produces a finding, the fixture is not exercising
	// the rule engine and a passing golden test would be meaningless.
	var net, cred bool
	for _, f := range rep.Findings {
		if f.Category == models.CategoryNetwork {
			net = true
		}
		// A stored token is reported under credentials; only key material is
		// reported under secrets, which is why the fixture asserts both.
		if f.Category == models.CategoryCredentials || f.Category == models.CategorySecrets {
			cred = true
		}
	}
	if !net {
		t.Error("no network finding from a world-bound listener in the fixture")
	}
	if !cred {
		t.Error("no credential finding from a token in the fixture")
	}
}

func TestEveryFindingCarriesARiskScore(t *testing.T) {
	rep := runSim(t, simConfig()).Report
	for _, f := range rep.Findings {
		if _, ok := f.Attributes["risk_score"]; !ok {
			t.Errorf("finding %s has no risk_score attribute", f.RuleID)
		}
		if _, ok := f.Attributes["risk_band"]; !ok {
			t.Errorf("finding %s has no risk_band attribute", f.RuleID)
		}
		if f.RiskScore() <= 0 {
			t.Errorf("finding %s reports risk score %d", f.RuleID, f.RiskScore())
		}
	}
}

func TestExcludedModulesDoNotRun(t *testing.T) {
	cfg := simConfig()
	cfg.Include = []string{"network"}
	res := runSim(t, cfg)
	for _, st := range res.Report.Modules {
		if st.ID == "network" {
			continue
		}
		if st.Status != models.ExposureSkipped {
			t.Errorf("module %s ran despite the include filter (status %q)", st.ID, st.Status)
		}
	}
}

func TestDepthGatingIsReportedAsALimitation(t *testing.T) {
	cfg := simConfig()
	cfg.Depth = 1
	res := runSim(t, cfg)

	var gated bool
	for _, st := range res.Report.Modules {
		if st.Status == models.ExposureSkipped && strings.Contains(st.Reason, "depth") {
			gated = true
		}
	}
	if !gated {
		t.Error("no module was depth-gated at depth 1, but deep modules exist")
	}
}

func TestRemoteTargetIsRefused(t *testing.T) {
	cfg := simConfig()
	cfg.Simulate = false
	cfg.Remote = true
	_, err := New(Options{Config: cfg, Now: fixedClock()}).Run(context.Background())
	if err == nil {
		t.Fatal("a remote target was accepted; amina must assess the local host only")
	}
	if !strings.Contains(err.Error(), "remote") {
		t.Errorf("error %q does not mention remote", err)
	}
}

func TestEventsAreEmittedOnTheStream(t *testing.T) {
	var buf bytes.Buffer
	cfg := simConfig()
	cfg.Events = true
	if _, err := New(Options{Config: cfg, Now: fixedClock(),
		Events: newTestStream(&buf)}).Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"assessment.started", "assessment.completed",
		`"schema_version"`, `"execution_id"`, `"framework":"amina"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("event stream missing %q\n%s", want, out)
		}
	}
}

func TestRenderedOutputIsStableAcrossRuns(t *testing.T) {
	var first, second bytes.Buffer
	for i, buf := range []*bytes.Buffer{&first, &second} {
		rep := runSim(t, simConfig()).Report
		if err := output.Render(buf, rep, config.FormatJSON, false); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if first.String() != second.String() {
		t.Error("two runs over the same fixture rendered different JSON")
	}
}

// TestParallelismDoesNotChangeTheReport is the guard on concurrency.
//
// Collectors run on several goroutines, so the only thing standing between
// "faster" and "two reports of the same host disagree" is that assembly replays
// outcomes in registry order. If that ever breaks, one worker finishing first
// reorders the module list, and the finding order with it.
func TestParallelismDoesNotChangeTheReport(t *testing.T) {
	render := func(workers int) string {
		cfg := simConfig()
		cfg.Parallelism = workers
		var buf bytes.Buffer
		rep := runSim(t, cfg).Report
		if err := output.Render(&buf, rep, config.FormatJSON, false); err != nil {
			t.Fatalf("parallelism %d: %v", workers, err)
		}
		return buf.String()
	}

	sequential := render(1)
	for _, workers := range []int{2, 4, maxParallelCollectors, 64} {
		if got := render(workers); got != sequential {
			t.Errorf("parallelism %d produced a different report than parallelism 1", workers)
		}
	}
}

// TestParallelismKeepsModuleOrder checks the ordering guarantee directly rather
// than through rendered bytes, so a failure names the cause.
func TestParallelismKeepsModuleOrder(t *testing.T) {
	order := func(workers int) []string {
		cfg := simConfig()
		cfg.Parallelism = workers
		var ids []string
		for _, s := range runSim(t, cfg).Report.Modules {
			ids = append(ids, s.ID)
		}
		return ids
	}

	want := order(1)
	if len(want) == 0 {
		t.Fatal("no modules reported")
	}
	for _, workers := range []int{2, 8} {
		got := order(workers)
		if len(got) != len(want) {
			t.Fatalf("parallelism %d reported %d modules, want %d", workers, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("parallelism %d position %d = %q, want %q", workers, i, got[i], want[i])
			}
		}
	}
}

// TestParallelismResolvesTheDefault documents what zero means, since the flag
// help promises a default without saying what it is.
func TestParallelismResolvesTheDefault(t *testing.T) {
	p := New(Options{Config: simConfig()})
	got := p.parallelism(23)
	if got < 1 || got > maxParallelCollectors {
		t.Errorf("default parallelism = %d, want 1..%d", got, maxParallelCollectors)
	}
	if got > 23 {
		t.Errorf("parallelism %d exceeds the module count 23", got)
	}
	if n := p.parallelism(2); n != 2 {
		t.Errorf("parallelism with 2 modules = %d, want 2", n)
	}
	if n := p.parallelism(0); n != 1 {
		t.Errorf("parallelism with no modules = %d, want 1", n)
	}
}
