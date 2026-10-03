// Package pipeline orchestrates one assessment end to end.
//
// The pipeline is the only place that knows the order of operations. Everything
// below it is independent: collectors do not call each other, rules do not read
// the filesystem, and renderers do not collect. That is deliberate — it is what
// lets a recorded snapshot produce byte-identical output to a live host.
//
// The order is fixed and every step is observable:
//
//	detect platform -> authorize -> collect modules -> correlate identities
//	  -> evaluate rules -> correlate findings -> finalize -> render
//
// Each step emits a JSONL event, because a run that takes thirty seconds and
// produces one report at the end gives an operator no way to tell whether it is
// working or stuck.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/QYVORA/qyvora-amina/internal/config"
	"github.com/QYVORA/qyvora-amina/internal/events"
	"github.com/QYVORA/qyvora-amina/internal/platform"
	"github.com/QYVORA/qyvora-amina/internal/version"
	"github.com/QYVORA/qyvora-amina/pkg/correlation"
	"github.com/QYVORA/qyvora-amina/pkg/models"
	"github.com/QYVORA/qyvora-amina/pkg/modules"
	"github.com/QYVORA/qyvora-amina/pkg/risk"
	"github.com/QYVORA/qyvora-amina/pkg/rules"
	"github.com/QYVORA/qyvora-amina/pkg/simulation"
)

// Options configures one run.
type Options struct {
	Config config.Config
	// Events receives the JSONL stream. It may be nil, in which case no events
	// are produced and the run stays silent.
	Events *events.Stream
	// Now supplies the clock. Tests substitute a fixed clock so that two runs
	// produce identical reports; without that seam, determinism could not be
	// tested at all.
	Now func() time.Time
	// Output is where the rendered report goes.
	Output OutputWriter
}

// OutputWriter receives a finished report.
type OutputWriter interface {
	Write(rep *models.Report, format config.Format) error
}

// Pipeline runs one assessment.
type Pipeline struct {
	opts   Options
	now    func() time.Time
	events *events.Stream
}

// Result is what a completed run produced.
type Result struct {
	Report *models.Report
	// Errors holds per-module collection failures. A module that fails does not
	// abort the run; it is recorded as a limitation, because a partial report
	// that names what it missed is more useful than no report at all.
	Errors map[string]error
	// Elapsed is the wall-clock duration of the run.
	Elapsed time.Duration
}

// New builds a pipeline from options.
func New(opts Options) *Pipeline {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Pipeline{opts: opts, now: opts.Now, events: opts.Events}
}

// Run performs the assessment and returns the finalized report.
func (p *Pipeline) Run(ctx context.Context) (*Result, error) {
	started := p.now()

	p.emit("assessment.started", map[string]any{
		"depth": p.opts.Config.Depth,
		"mode":  p.mode(),
	})

	env, target, fx, err := p.acquire(ctx)
	if err != nil {
		return nil, err
	}

	engine := rules.NewEngine(rules.Builtin(), target)
	collected, mErrs := p.collect(ctx, env, target, fx)

	res := &Result{Errors: mErrs}

	snap := rules.NewBuilder(ctx, target, p.depth()).
		WithEnv(env).
		At(p.now().UTC()).
		Build()

	// A simulation starts from the recorded snapshot's own observations, not
	// from an empty host. The collectors are bypassed because the fixture
	// already holds what they would have returned; seeding from it is what makes
	// the rule engine see the simulated machine instead of nothing at all.
	if fx != nil {
		seed := fx.SnapshotOrDefaults()
		// The report is stamped with the fixture's collection time, not the
		// wall clock. A simulated report that carried the current time would
		// differ on every run and on every machine, which defeats the only
		// property simulation has: that it produces the same report everywhere.
		snap.CollectedAt = seed.CollectedAt
		snap.Accounts = seed.Accounts
		snap.Sockets = seed.Sockets
		snap.Interfaces = seed.Interfaces
		snap.Processes = seed.Processes
		snap.Services = seed.Services
		snap.Packages = seed.Packages
		snap.Software = seed.Software
		snap.Sources = seed.Sources
		snap.Provenance = seed.Provenance
		snap.Secrets = seed.Secrets
		snap.Identities = seed.Identities
		snap.Assets = seed.Assets
	}

	// Every collector's results are folded into one snapshot. Folding is a
	// merge, not a filter: a later module may add to a list another module
	// already populated, and the rule engine sees one view of the host rather
	// than twenty-three partial ones.
	mergeResult(&snap, collected)
	snap.ModuleStatus = collected.Statuses

	// Identity correlation runs before the rules, because several rules match
	// on correlated identities. Running it afterwards would mean those rules
	// silently never fired.
	corr := correlation.Correlate(snap.Identities, correlation.Options{At: p.now().UTC()})
	snap.Correlated = corr.Identities
	p.emit("identity.correlated", map[string]any{
		"signals":    len(snap.Identities),
		"identities": len(corr.Identities),
	})

	evaluation := engine.Evaluate(&snap)
	snap.Findings = evaluation.Findings

	p.emit("finding.discovered", map[string]any{
		"count":           len(evaluation.Findings),
		"rules_evaluated": evaluation.RulesEvaluated,
		"rules_skipped":   len(evaluation.Skipped),
	})

	p.measure(&snap, evaluation)

	rep := p.report(&snap, &collected, evaluation)
	p.emit("assessment.completed", map[string]any{
		"report_id":   rep.ID,
		"findings":    rep.Summary.Total,
		"risk_band":   rep.Summary.RiskBand,
		"integrity":   rep.Integrity,
		"limitations": len(rep.Limitations),
		"elapsed_ms":  p.now().Sub(started).Milliseconds(),
	})

	res.Report = rep
	res.Elapsed = p.now().Sub(started)
	return res, nil
}

// acquire resolves the data source. A simulation reads a fixture; a host
// detects its own platform. Remote targets are refused here rather than deep in
// a collector, because the refusal needs to be visible as a usage error.
func (p *Pipeline) acquire(ctx context.Context) (*platform.Env, models.Target, *simulation.Fixture, error) {
	cfg := p.opts.Config

	if p.mode() == "simulation" {
		fx, err := simulation.LoadNamed(cfg.Fixture)
		if err != nil {
			return nil, models.Target{}, nil, fmt.Errorf("load fixture: %w", err)
		}
		p.emit("simulation.loaded", map[string]any{
			"fixture": fx.Name, "schema": fx.Schema, "description": fx.Description,
		})
		target := fx.Target()
		return fx.SnapshotOrDefaults().Env, target, fx, nil
	}

	if cfg.Remote {
		return nil, models.Target{}, nil, ErrRemoteUnsupported
	}

	env := platform.Detect(ctx)
	p.emit("host.detected", map[string]any{
		"platform": string(env.Platform), "hostname": env.Hostname,
		"user": env.User, "privileged": env.Privileged,
		"virtual": env.Virtual, "container": env.Container,
	})

	target := models.Target{
		ID:        models.NewID("tgt"),
		Type:      models.TargetHost,
		Value:     env.Hostname,
		Platform:  env.Platform,
		Auth:      models.Authorization{Granted: true, Scope: "local host", GrantedAt: p.now().UTC()},
		CreatedAt: p.now().UTC(),
	}
	target.Name = target.Value
	return env, target, nil, nil
}

// collection is the merged result of every module in the run.
type collection struct {
	Accounts   []models.Account
	Sockets    []platform.Socket
	Interfaces []platform.Interface
	Processes  []platform.Process
	Services   []platform.Service
	Packages   []platform.PackageQuery
	Software   []models.Software
	Sources    []models.PackageSource
	Provenance []models.ProvenanceRecord
	Secrets    []models.SecretRecord
	Identities []models.IdentitySignal
	Assets     []models.Asset
	Statuses   []models.ModuleStatus
}

// moduleOutcome is everything one collector produced, kept apart from the
// collection so that assembly can happen in a fixed order.
//
// The split matters: a collector must be free to run whenever a worker picks it
// up, but the report and the event stream must not depend on which worker
// finished first. Buffering the outcome is what makes concurrency invisible.
type moduleOutcome struct {
	module    modules.Module
	cancelled error
	skipped   bool
	reason    string
	result    modules.Result
	err       error
}

// maxParallelCollectors caps concurrent collectors.
//
// Amina is I/O bound rather than CPU bound, so the useful limit is small. A
// wide machine should not open hundreds of directory handles at once to read
// files that are individually tiny.
const maxParallelCollectors = 8

// collect runs every selected module and assembles the result in registry
// order.
//
// Collectors are independent — none calls another, and each reads a different
// slice of the host — so they run concurrently up to the configured bound.
// The output does not move: outcomes are buffered per module and replayed in
// registry order here, so two reports of the same host agree whether the run
// used one worker or eight.
func (p *Pipeline) collect(ctx context.Context, env *platform.Env, target models.Target, fx *simulation.Fixture) (collection, map[string]error) {
	var out collection
	errs := map[string]error{}

	for _, oc := range p.runCollectors(ctx, env, target, fx) {
		m := oc.module

		if oc.cancelled != nil {
			errs[m.ID] = oc.cancelled
			p.emit("module.skipped", map[string]any{
				"module_id": m.ID, "reason": "cancelled",
			})
			continue
		}

		if oc.skipped {
			out.Statuses = append(out.Statuses, models.ModuleStatus{
				ID: m.ID, Name: m.Name, Status: models.ExposureSkipped, Reason: oc.reason,
			})
			p.emit("module.skipped", map[string]any{"module_id": m.ID, "reason": oc.reason})
			continue
		}

		p.emit("module.started", map[string]any{"module_id": m.ID, "depth": p.depth()})

		if oc.err != nil {
			// A module error is recorded and the run continues. Aborting would
			// mean one unreadable file loses the entire assessment.
			errs[m.ID] = oc.err
			out.Statuses = append(out.Statuses, models.ModuleStatus{
				ID: m.ID, Name: m.Name, Status: models.ExposureDegraded,
				Reason:      "collection failed: " + oc.err.Error(),
				Unavailable: []string{"collector"},
			})
			p.emit("module.failed", map[string]any{
				"module_id": m.ID, "error": oc.err.Error(),
			})
			continue
		}

		res := oc.result
		mergeOne(&out, res)
		status := models.ModuleStatus{
			ID: m.ID, Name: m.Name,
			Status:      models.ExposureComplete,
			Assets:      len(res.Assets),
			Reason:      res.Note,
			Unavailable: res.Unavailable,
		}
		if res.Degraded {
			status.Status = models.ExposurePartial
			if status.Reason == "" {
				status.Reason = "partial coverage"
			}
		}
		out.Statuses = append(out.Statuses, status)

		p.emit("module.completed", map[string]any{
			"module_id": m.ID, "assets": len(res.Assets),
			"degraded": res.Degraded, "unavailable": res.Unavailable,
		})
		for _, a := range res.Assets {
			p.emit("asset.discovered", map[string]any{
				"module_id": m.ID, "kind": string(a.Kind), "name": a.Name,
			})
		}
	}

	return out, errs
}

// runCollectors executes the selected modules and returns one outcome per
// module, in selection order.
func (p *Pipeline) runCollectors(ctx context.Context, env *platform.Env, target models.Target, fx *simulation.Fixture) []moduleOutcome {
	selected := p.selectedModules()
	outcomes := make([]moduleOutcome, len(selected))

	limit := p.parallelism(len(selected))
	if limit <= 1 {
		// One worker: the common case for --parallelism 1, and the easiest path
		// to reason about when a collector is misbehaving.
		for i, m := range selected {
			outcomes[i] = p.collectOne(ctx, m, env, target, fx)
		}
		return outcomes
	}

	// Modules are claimed from a shared cursor rather than being pre-partitioned
	// across workers. A partition would leave one worker holding all the slow
	// filesystem modules while the others finish early; a cursor keeps every
	// worker busy until the module list is empty.
	var next int
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(limit)
	for w := 0; w < limit; w++ {
		go func() {
			defer wg.Done()
			for {
				mu.Lock()
				i := next
				next++
				mu.Unlock()
				if i >= len(selected) {
					return
				}
				outcomes[i] = p.collectOne(ctx, selected[i], env, target, fx)
			}
		}()
	}
	wg.Wait()

	return outcomes
}

// collectOne runs a single collector and reports what happened to it.
func (p *Pipeline) collectOne(ctx context.Context, m modules.Module, env *platform.Env, target models.Target, fx *simulation.Fixture) moduleOutcome {
	oc := moduleOutcome{module: m}

	if err := ctx.Err(); err != nil {
		oc.cancelled = err
		return oc
	}
	if reason := p.skipReason(m, env, target); reason != "" {
		oc.skipped, oc.reason = true, reason
		return oc
	}

	res, err := p.runModule(ctx, m, env, target, fx)
	oc.result, oc.err = res, err
	return oc
}

// parallelism resolves how many collectors may run at once.
//
// Zero means "choose a default": one worker per CPU, capped. A negative value is
// rejected during configuration validation, so anything below one here means the
// module list is empty.
func (p *Pipeline) parallelism(moduleCount int) int {
	n := p.opts.Config.Parallelism
	if n <= 0 {
		n = runtime.NumCPU()
		if n > maxParallelCollectors {
			n = maxParallelCollectors
		}
	}
	if n > moduleCount {
		n = moduleCount
	}
	if n < 1 {
		n = 1
	}
	return n
}

// runModule executes one collector, routing simulation data around it.
func (p *Pipeline) runModule(ctx context.Context, m modules.Module, env *platform.Env, target models.Target, fx *simulation.Fixture) (modules.Result, error) {
	if fx != nil {
		// In simulation the fixture already holds every observation, so
		// collectors are bypassed. They still ran when the fixture was recorded,
		// which is what makes the fixture faithful.
		return modules.Result{}, nil
	}
	if m.Collect == nil {
		return modules.Result{}, errors.New("collector is not implemented")
	}
	return m.Collect.Collect(modules.Input{Ctx: ctx, Env: env, Target: target, Depth: p.depth()})
}

// mergeOne folds one module's result into the run's collection.
func mergeOne(out *collection, r modules.Result) {
	out.Accounts = append(out.Accounts, r.Accounts...)
	out.Sockets = append(out.Sockets, r.Sockets...)
	out.Interfaces = append(out.Interfaces, r.Interfaces...)
	out.Processes = append(out.Processes, r.Processes...)
	out.Services = append(out.Services, r.Services...)
	out.Packages = append(out.Packages, r.Packages...)
	out.Software = append(out.Software, r.Software...)
	out.Sources = append(out.Sources, r.Sources...)
	out.Provenance = append(out.Provenance, r.Provenance...)
	out.Secrets = append(out.Secrets, r.Secrets...)
	out.Identities = append(out.Identities, r.Identities...)
	out.Assets = append(out.Assets, r.Assets...)
}

// mergeResult folds the collection into a snapshot.
func mergeResult(snap *rules.Snapshot, c collection) {
	snap.Accounts = append(snap.Accounts, c.Accounts...)
	snap.Sockets = append(snap.Sockets, c.Sockets...)
	snap.Interfaces = append(snap.Interfaces, c.Interfaces...)
	snap.Processes = append(snap.Processes, c.Processes...)
	snap.Services = append(snap.Services, c.Services...)
	snap.Packages = append(snap.Packages, c.Packages...)
	snap.Software = append(snap.Software, c.Software...)
	snap.Sources = append(snap.Sources, c.Sources...)
	snap.Provenance = append(snap.Provenance, c.Provenance...)
	snap.Secrets = append(snap.Secrets, c.Secrets...)
	snap.Identities = append(snap.Identities, c.Identities...)
	snap.Assets = append(snap.Assets, c.Assets...)
}

// report assembles the final report from the snapshot.
func (p *Pipeline) report(snap *rules.Snapshot, c *collection, ev rules.Evaluation) *models.Report {
	rep := models.NewReport(snap.Target, p.depth(), rules.DepthName(p.depth()))
	rep.GeneratedAt = snap.CollectedAt
	if snap.Env != nil {
		host := platform.HostSummary(snap.Env)
		rep.Host = &host
	}
	rep.FrameworkVersion = version.Version
	rep.Configuration = p.configMap()
	rep.Findings = filterSeverity(snap.Findings, p.opts.Config.MinSeverity)
	rep.Identities = snap.Correlated
	rep.Secrets = snap.Secrets
	rep.Sources = snap.Sources
	rep.Software = snap.Software
	rep.Assets = snap.Assets
	rep.Modules = c.Statuses
	rep.Skipped = skippedFrom(ev.Skipped)

	// Limitations are computed from module statuses and from skipped rules.
	// A rule that never ran is as much a gap as a module that never ran, and
	// the report has to say so in the same place for both.
	rep.Limitations = models.Limitations(rep.Modules)
	rep.Limitations = append(rep.Limitations, ruleLimitations(ev.Skipped)...)

	rep.Finalize()
	return &rep
}

// filterSeverity drops findings below the configured floor.
//
// The default is low, which is the lowest severity that exists, so the default
// keeps everything. Filtering happens here rather than in the renderer so that
// every consumer of the report - terminal, file, CI gate - sees the same set,
// and so that the finding counts in the events stream match the report.
func filterSeverity(in []models.Finding, floor models.Severity) []models.Finding {
	if floor == "" || floor.Rank() <= models.SeverityLow.Rank() {
		return in
	}
	out := make([]models.Finding, 0, len(in))
	for _, f := range in {
		if f.Severity.Rank() >= floor.Rank() {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// skippedFrom converts skipped rules into the report's skipped form.
func skippedFrom(in []rules.SkippedRule) []models.Skipped {
	if len(in) == 0 {
		return nil
	}
	out := make([]models.Skipped, 0, len(in))
	for _, s := range in {
		out = append(out, models.Skipped{ID: s.ID, Reason: s.Reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// ruleLimitations summarises skipped rules, grouping by reason so the list stays
// short when a whole depth tier was gated.
func ruleLimitations(in []rules.SkippedRule) []string {
	if len(in) == 0 {
		return nil
	}
	byReason := map[string][]string{}
	for _, s := range in {
		byReason[s.Reason] = append(byReason[s.Reason], s.ID)
	}
	reasons := make([]string, 0, len(byReason))
	for r := range byReason {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)

	var out []string
	for _, r := range reasons {
		ids := byReason[r]
		sort.Strings(ids)
		out = append(out, fmt.Sprintf("%d rule(s) not evaluated (%s): %s",
			len(ids), r, joinSample(ids, 6)))
	}
	return out
}

// joinSample lists at most n identifiers and says how many were left out.
func joinSample(ids []string, n int) string {
	if len(ids) <= n {
		return strings.Join(ids, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(ids[:n], ", "), len(ids)-n)
}

// measure stamps each finding with its computed risk.
//
// Risk is computed here rather than in the rule engine so that the formula
// exists in exactly one place for every finding, whether it came from a rule,
// a collector or a simulation fixture.
func (p *Pipeline) measure(snap *rules.Snapshot, ev rules.Evaluation) {
	for i := range snap.Findings {
		f := &snap.Findings[i]
		score := risk.Compute(risk.Input{
			Impact:      f.Severity,
			Exposure:    f.Exposure,
			Privilege:   f.Privilege,
			Sensitivity: f.Sensitivity,
			Confidence:  f.Confidence,
		})
		if f.Attributes == nil {
			f.Attributes = map[string]string{}
		}
		f.Attributes["risk_score"] = fmt.Sprintf("%.1f", score.Final)
		f.Attributes["risk_band"] = string(score.Band)
		f.Attributes["risk_raw"] = fmt.Sprintf("%.1f", score.Raw)
		f.Attributes["risk_formula"] = risk.Formula()
	}
	p.emit("risk.calculated", map[string]any{
		"findings": len(snap.Findings), "formula": risk.Formula(),
	})
}

func (p *Pipeline) emit(name string, data map[string]any) {
	if p.events == nil {
		return
	}
	p.events.Info(name, data)
}

// selectedModules applies the include and exclude filters.
func (p *Pipeline) selectedModules() []modules.Module {
	all := modules.All()
	if len(p.opts.Config.Include) == 0 && len(p.opts.Config.Exclude) == 0 {
		return all
	}
	var out []modules.Module
	for _, m := range all {
		if p.isSelected(m.ID) {
			out = append(out, m)
		}
	}
	return out
}

// isSelected applies the include and exclude filters to one module.
func (p *Pipeline) isSelected(id string) bool {
	include, exclude := toSet(p.opts.Config.Include), toSet(p.opts.Config.Exclude)
	if len(include) > 0 && !include[id] {
		return false
	}
	return !exclude[id]
}

func toSet(list []string) map[string]bool {
	if len(list) == 0 {
		return nil
	}
	out := make(map[string]bool, len(list))
	for _, v := range list {
		out[v] = true
	}
	return out
}

// skipReason explains why a module will not run, or returns "" to run it.
//
// Every non-empty return is a limitation the report must carry. The distinction
// matters: "unsupported on this platform" is a fact about the host, while
// "requires depth 3" is a fact about the operator's request, and a reader needs
// to know which one produced the gap.
func (p *Pipeline) skipReason(m modules.Module, env *platform.Env, target models.Target) string {
	if !m.Implemented() {
		return "module not implemented in this build"
	}
	if !p.isSelected(m.ID) {
		return "excluded by configuration"
	}
	if env != nil && env.Platform != "" && !m.Supports(env.Platform) {
		return fmt.Sprintf("unsupported on %s", env.Platform)
	}
	if m.MinimumDepth > p.depth() {
		return fmt.Sprintf("requires depth %d (running at %d)", m.MinimumDepth, p.depth())
	}
	return ""
}

func (p *Pipeline) depth() int {
	if p.opts.Config.Depth <= 0 {
		return 1
	}
	return p.opts.Config.Depth
}

func (p *Pipeline) mode() string {
	if p.opts.Config.Simulate || p.opts.Config.Offline {
		return "simulation"
	}
	return "live"
}

func (p *Pipeline) configMap() map[string]string {
	m := map[string]string{}
	for k, v := range p.opts.Config.Source {
		if v != "" {
			m[k] = v
		}
	}
	return m
}

// ErrRemoteUnsupported is returned when a remote target is requested.
var ErrRemoteUnsupported = errors.New("remote targets are not supported: amina assesses the local host only")
