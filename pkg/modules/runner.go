package modules

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/QYVORA/qyvora-amina/internal/platform"
	"github.com/QYVORA/qyvora-amina/pkg/models"
	"github.com/QYVORA/qyvora-amina/pkg/rules"
)

// Status constants for modules that cannot run at all. They are defined here
// rather than in models because they describe a *run*, not a finding.
//
// The specification's requirement (PROMPT.md, "Every module must either work or
// explicitly report") is why these exist: a module that is silently absent
// produces a report indistinguishable from a clean host, which is the single
// most dangerous thing this tool could do.
const (
	ReasonNotImplemented = "not implemented"
	ReasonUnsupported    = "unsupported on this platform"
	ReasonUnavailable    = "unavailable"
	ReasonPrivilege      = "requires privilege"
	ReasonBelowDepth     = "requires a deeper scan"
	ReasonFailed         = "collection failed"
)

// Runner executes the registry and assembles a snapshot.
type Runner struct {
	// Modules defaults to All().
	Modules []Module
	// Now supplies timestamps. A fixed clock keeps simulation output
	// reproducible; the zero value means time.Now.
	Now func() time.Time
	// OnModule is called after each module, with its status. It is the hook the
	// pipeline uses to emit module.completed events, and the test suite uses to
	// assert that every module reported.
	OnModule func(models.ModuleStatus)
}

// RunResult is a completed run.
type RunResult struct {
	Snapshot rules.Snapshot
	Statuses []models.ModuleStatus
}

// Run executes every applicable module and returns the assembled snapshot.
//
// Modules run in registry order and are independent: one module's failure
// cannot prevent another's results from being reported, because a partial
// assessment that says which parts are missing is worth more than an aborted
// one.
func (r *Runner) Run(ctx context.Context, target models.Target, depth int) RunResult {
	mods := r.Modules
	if mods == nil {
		mods = All()
	}
	now := time.Now
	if r.Now != nil {
		now = r.Now
	}

	env := platform.Detect(ctx)
	b := rules.NewBuilder(ctx, target, depth).
		WithEnv(env).
		At(now())

	// A target that is not this machine cannot be inspected from here. No
	// collector runs, because a report about a remote host that quietly contains
	// the local host's accounts and sockets is worse than no report at all: the
	// reader has no way to tell which half came from where. Every module reports
	// why it did not run.
	if target.Type != models.TargetHost {
		note := fmt.Sprintf("target %q was not inspected: Amina assesses the local host only", target.Value)
		statuses := make([]models.ModuleStatus, 0, len(mods))
		for _, m := range mods {
			statuses = append(statuses, models.ModuleStatus{
				ID:     m.ID,
				Name:   m.Name,
				Domain: string(m.Category),
				Status: models.ExposureSkipped,
				Reason: note,
			})
		}
		snap := b.WithRemote(note).
			WithModuleStatus(copyStatuses(statuses)).
			Build()
		sortSnapshot(&snap)
		return RunResult{Snapshot: snap, Statuses: statuses}
	}

	statuses := make([]models.ModuleStatus, 0, len(mods))
	for _, m := range mods {
		st := r.runOne(ctx, b, m, Input{Env: env, Target: target, Depth: depth}, now)
		statuses = append(statuses, st)
		if r.OnModule != nil {
			r.OnModule(st)
		}
	}

	snap := b.WithModuleStatus(copyStatuses(statuses)).Build()

	// Collection order varies with the host; report order must not. Every slice
	// is sorted here so that two runs over the same host serialise identically.
	sortSnapshot(&snap)

	return RunResult{Snapshot: snap, Statuses: statuses}
}

// runOne executes a single module and converts whatever happened into a status.
func (r *Runner) runOne(ctx context.Context, b *rules.Builder, m Module, in Input, now func() time.Time) models.ModuleStatus {
	st := models.ModuleStatus{
		ID:     m.ID,
		Name:   m.Name,
		Domain: string(m.Category),
	}

	// The gate is a pure function so that every disqualifying path can be tested
	// without needing a host that exhibits it.
	if skip, gated := gate(m, in); gated {
		return skip
	}

	in.Ctx = ctx
	start := now()
	res, err := m.Collect.Collect(in)
	st.DurationMS = now().Sub(start).Milliseconds()

	if err != nil {
		// A failed module reports the failure. It does not report zero findings,
		// and it does not stop the run.
		st.Status = models.ExposureDegraded
		st.Reason = fmt.Sprintf("%s: %v", ReasonFailed, err)
		return st
	}

	st.Assets = len(res.Assets)
	st.Unavailable = mergeUnique(st.Unavailable, res.Unavailable)
	switch {
	case res.Degraded:
		st.Status = models.ExposureDegraded
		st.Reason = res.Note
		if st.Reason == "" {
			st.Reason = ReasonUnavailable
		}
	case len(res.Unavailable) > 0:
		st.Status = models.ExposurePartial
		st.Reason = res.Note
	default:
		st.Status = models.ExposureComplete
		st.Reason = res.Note
	}

	applyResult(b, res)
	return st
}

// applyResult folds one module's observations into the snapshot builder.
func applyResult(b *rules.Builder, res Result) {
	if b == nil {
		return
	}
	b.WithAccounts(res.Accounts).
		WithInterfaces(res.Interfaces).
		WithSockets(res.Sockets).
		WithProcesses(res.Processes).
		WithServices(res.Services).
		WithPackages(res.Packages).
		WithSoftware(res.Software).
		WithSources(res.Sources).
		WithProvenance(res.Provenance).
		WithSecrets(res.Secrets).
		WithIdentities(res.Identities).
		WithAssets(res.Assets)
}

// gate decides whether a module may run, and if not, records why.
//
// The order of the checks is deliberate: the cheapest disqualifiers come first,
// so a module that cannot run on this platform costs nothing. Every path returns
// a reason, because the whole point of the gate is that a module which did not
// look must say so.
func gate(m Module, in Input) (models.ModuleStatus, bool) {
	st := models.ModuleStatus{ID: m.ID, Name: m.Name, Domain: string(m.Category)}

	switch {
	case m.Collect == nil:
		st.Status = models.ExposureSkipped
		st.Reason = ReasonNotImplemented
		return st, true

	case in.Env == nil:
		st.Status = models.ExposureSkipped
		st.Reason = ReasonUnavailable + ": environment could not be detected"
		st.Unavailable = []string{platform.CapHostIdentity}
		return st, true

	case !m.Supports(in.Env.Platform):
		st.Status = models.ExposureSkipped
		st.Reason = fmt.Sprintf("%s: this module covers %s, not %s",
			ReasonUnsupported, platformSummary(m.Platforms), in.Env.Platform)
		return st, true

	case m.MinimumDepth > in.Depth:
		st.Status = models.ExposureSkipped
		st.Reason = fmt.Sprintf("%s: depth %d requested, this needs %d",
			ReasonBelowDepth, in.Depth, m.MinimumDepth)
		return st, true

	case in.Env.Platform == models.PlatformWindows && !in.Env.Privileged && requiresPrivilege(m.ID):
		// Reported rather than attempted: a permission error surfacing as a crash
		// or as silence both mislead the reader.
		st.Status = models.ExposurePrivilege
		st.Reason = ReasonPrivilege
		st.Unavailable = unavailableFor(m.ID)
		return st, true
	}
	return st, false
}

// requiresPrivilege names the modules whose Windows implementation genuinely
// needs elevation. It is a list rather than a detection because the honest
// answer is that we have not run them unelevated, not that we cannot.
func requiresPrivilege(id string) bool {
	switch id {
	case "binary-integrity", "persistence", "os-posture", "process-service":
		return true
	}
	return false
}

func unavailableFor(id string) []string {
	switch id {
	case "binary-integrity":
		return []string{platform.CapAuthenticode, platform.CapCodesign}
	case "persistence":
		return []string{platform.CapSystemd}
	case "os-posture":
		return []string{platform.CapRegistry}
	case "process-service":
		return []string{platform.CapProcesses}
	}
	return nil
}

// copyStatuses detaches the snapshot's module status from the run's.
//
// Without this the snapshot and the returned slice share one array, so sorting
// the snapshot into report order silently reorders the run-order result that the
// event stream has already been emitting from.
func copyStatuses(in []models.ModuleStatus) []models.ModuleStatus {
	out := make([]models.ModuleStatus, len(in))
	copy(out, in)
	return out
}

func mergeUnique(a, b []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(a)+len(b))
	for _, x := range append(append([]string{}, a...), b...) {
		if x == "" || seen[x] {
			continue
		}
		seen[x] = true
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

// sortSnapshot imposes a canonical order on everything a run collected.
//
// Collection order is not a property of the host: it depends on the order
// readdir returned, on which package manager answered first, and on goroutine
// scheduling. Reporting it would make two runs over an unchanged machine
// produce different bytes, which breaks diffing, breaks the golden tests, and
// makes an operator unable to tell a real change from noise.
func sortSnapshot(s *rules.Snapshot) {
	accounts := s.Accounts
	sort.SliceStable(accounts, func(i, j int) bool {
		if accounts[i].Name != accounts[j].Name {
			return accounts[i].Name < accounts[j].Name
		}
		return accounts[i].UID < accounts[j].UID
	})

	sockets := s.Sockets
	sort.SliceStable(sockets, func(i, j int) bool {
		if sockets[i].Port != sockets[j].Port {
			return sockets[i].Port < sockets[j].Port
		}
		if sockets[i].Addr != sockets[j].Addr {
			return sockets[i].Addr < sockets[j].Addr
		}
		return sockets[i].Process < sockets[j].Process
	})

	ifaces := s.Interfaces
	sort.SliceStable(ifaces, func(i, j int) bool { return ifaces[i].Name < ifaces[j].Name })

	procs := s.Processes
	sort.SliceStable(procs, func(i, j int) bool {
		if procs[i].Name != procs[j].Name {
			return procs[i].Name < procs[j].Name
		}
		return procs[i].PID < procs[j].PID
	})

	platform.SortServices(s.Services)
	platform.SortPackages(s.Packages)

	software := s.Software
	sort.SliceStable(software, func(i, j int) bool {
		if software[i].Name != software[j].Name {
			return software[i].Name < software[j].Name
		}
		return software[i].Version < software[j].Version
	})

	sources := s.Sources
	sort.SliceStable(sources, func(i, j int) bool {
		if sources[i].ID != sources[j].ID {
			return sources[i].ID < sources[j].ID
		}
		return sources[i].URI < sources[j].URI
	})

	prov := s.Provenance
	sort.SliceStable(prov, func(i, j int) bool { return prov[i].Path < prov[j].Path })

	models.SortAssets(s.Assets)
	models.SortIdentitySignals(s.Identities)

	statuses := s.ModuleStatus
	sort.SliceStable(statuses, func(i, j int) bool { return statuses[i].ID < statuses[j].ID })
}
