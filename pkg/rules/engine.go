// Package rules evaluates collected evidence against a catalogue of
// operational-security rules and emits findings.
//
// The split between collection and evaluation is the load-bearing decision in
// this package. Collectors gather what is observable on a host and say how
// completely they managed to do it; rules interpret that evidence and never
// touch the filesystem. The consequences are worth stating, because they are the
// reason the split exists:
//
//   - Rules are testable against a constructed snapshot, so every rule can be
//     regression-tested without needing a host that happens to be exposed.
//   - A rule cannot accidentally become platform-dependent, because it has no
//     platform access at all.
//   - Simulation can feed a synthetic snapshot through the identical rule set,
//     so a simulated report is produced by the same code that produces a real
//     one rather than by a parallel implementation that can drift.
package rules

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-amina/pkg/models"
	"github.com/QYVORA/qyvora-amina/pkg/risk"
)

// Severity overrides let a rule declare a default that a Match may lower or
// raise per occurrence. The default is the common case; the override exists for
// the genuinely conditional rules, where the same condition is critical in one
// context and informational in another.
type SeverityOverride struct {
	Severity    models.Severity
	Exposure    models.ExposureScope
	Privilege   models.Privilege
	Sensitivity models.Sensitivity
	Confidence  models.Confidence
	Impact      string
}

// Match is one rule occurrence: the finding skeleton plus the evidence that
// produced it. A rule that matches the same condition on three objects returns
// three Matches rather than one Match listing three objects, because each may
// differ in exposure and would otherwise be forced to share one score.
type Match struct {
	Title            string
	Description      string
	Impact           string
	Objects          []string
	Evidence         []models.Evidence
	Attributes       map[string]string
	SeverityOverride *SeverityOverride
}

// Rule is one check in the catalogue.
type Rule struct {
	ID             string
	Title          string
	Category       models.Category
	ModuleID       string
	Description    string
	Recommendation string
	References     []string

	// Severity is the default impact for every Match. Critical and High share
	// the same numeric weight in the risk engine, so the distinction between
	// them is carried by exposure and exploitability rather than by a larger
	// impact value.
	Severity    models.Severity
	Exposure    models.ExposureScope
	Privilege   models.Privilege
	Sensitivity models.Sensitivity
	Confidence  models.Confidence

	// Platforms restricts the rule to specific platforms. An empty list means
	// every platform, which is the correct default for rules that are genuinely
	// platform-independent; anything else would silently skip a platform and
	// read in a report as a clean host.
	Platforms []models.Platform

	// MinimumDepth gates a rule behind a --depth setting, so that a fast scan
	// can skip the expensive sweeps without pretending they found nothing.
	MinimumDepth int

	// Match is the check itself. It must be pure with respect to the snapshot:
	// no clock reads, no filesystem access, no map iteration order dependence.
	Match func(*Snapshot) []Match
}

// Engine holds the active rule set and evaluates it against snapshots.
type Engine struct {
	rules  []Rule
	byID   map[string]Rule
	order  []string
	target models.Target
}

// NewEngine builds an engine from a catalogue and a target. The target is
// carried because a remote-assessed target legitimately produces different
// scores than the local host, and rules must be able to see which they are
// reasoning about.
func NewEngine(rules []Rule, target models.Target) *Engine {
	e := &Engine{byID: map[string]Rule{}, target: target}
	for _, r := range rules {
		if _, dup := e.byID[r.ID]; dup {
			panic("duplicate rule id " + r.ID)
		}
		e.byID[r.ID] = r
		e.order = append(e.order, r.ID)
	}
	e.rules = rules
	return e
}

// Rules returns the catalogue in a stable order.
func (e *Engine) Rules() []Rule {
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Rule returns one rule by ID.
func (e *Engine) Rule(id string) (Rule, bool) {
	r, ok := e.byID[id]
	return r, ok
}

// IDs returns every rule id, sorted.
func (e *Engine) IDs() []string {
	out := make([]string, len(e.order))
	copy(out, e.order)
	sort.Strings(out)
	return out
}

// Evaluation is the outcome of running the catalogue over one snapshot.
type Evaluation struct {
	Findings []models.Finding
	// Skipped records every rule that did not run and why. Without this a
	// report cannot distinguish "no exposure found" from "not looked at", which
	// is the difference between a clean bill of health and an absence of data.
	Skipped []SkippedRule
	// RulesEvaluated is how many rules actually ran.
	RulesEvaluated int
}

// SkippedRule explains why a rule did not run.
type SkippedRule struct {
	ID     string
	Reason string
}

// Evaluate runs every applicable rule over the snapshot.
func (e *Engine) Evaluate(snap *Snapshot) Evaluation {
	var out Evaluation
	seen := map[string]bool{}

	rules := e.Rules()
	for _, r := range rules {
		if reason, ok := e.applies(r, snap); !ok {
			out.Skipped = append(out.Skipped, SkippedRule{ID: r.ID, Reason: reason})
			continue
		}
		out.RulesEvaluated++

		matches := r.Match(snap)
		for _, m := range matches {
			f := e.build(r, m, snap.CollectedAt)
			// A rule may return the same occurrence twice when two matchers
			// converge on one object. Deduplicating on the fingerprint keeps
			// the count honest instead of inflating the finding total.
			fp := f.Fingerprint()
			if seen[fp] {
				continue
			}
			seen[fp] = true
			out.Findings = append(out.Findings, f)
		}
	}

	sortFindings(out.Findings)
	return out
}

// applies decides whether a rule runs on this host, at this depth, for this
// target. Every rejection carries a reason that is safe to print.
func (e *Engine) applies(r Rule, snap *Snapshot) (string, bool) {
	if snap == nil {
		return "no snapshot collected", false
	}
	if len(r.Platforms) > 0 {
		match := false
		for _, p := range r.Platforms {
			if p == snap.Env.Platform {
				match = true
				break
			}
		}
		if !match {
			return fmt.Sprintf("not applicable on %s", snap.Env.Label()), false
		}
	}
	if snap.Depth < r.MinimumDepth {
		return fmt.Sprintf("requires depth %d, running at %d", r.MinimumDepth, snap.Depth), false
	}
	if e.target.Type != "" && !e.target.Authorized() {
		return "target authorization not granted", false
	}
	return "", true
}

// build materialises one Match into a scored finding.
func (e *Engine) build(r Rule, m Match, collectedAt time.Time) models.Finding {
	sev, expo, priv, sens, conf := r.Severity, r.Exposure, r.Privilege, r.Sensitivity, r.Confidence
	impactText := m.Impact
	if impactText == "" {
		impactText = r.Description
	}
	title := m.Title
	if title == "" {
		title = r.Title
	}
	desc := m.Description
	if desc == "" {
		desc = r.Description
	}
	if o := m.SeverityOverride; o != nil {
		if o.Severity != "" {
			sev = o.Severity
		}
		if o.Exposure != "" {
			expo = o.Exposure
		}
		if o.Privilege != "" {
			priv = o.Privilege
		}
		if o.Sensitivity != "" {
			sens = o.Sensitivity
		}
		if o.Confidence != "" {
			conf = o.Confidence
		}
		if o.Impact != "" {
			impactText = o.Impact
		}
	}

	score := risk.Compute(risk.Input{
		Impact:      sev,
		Exposure:    expo,
		Privilege:   priv,
		Sensitivity: sens,
		Confidence:  conf,
	})

	objects := m.Objects
	if len(objects) == 0 {
		objects = []string{r.ID}
	}
	sort.Strings(objects)

	rec := m.Attributes
	if rec == nil {
		rec = map[string]string{}
	}
	rec["risk_score"] = fmt.Sprintf("%.1f", score.Final)
	rec["risk_band"] = string(score.Band)
	rec["risk_formula"] = risk.Formula()

	f := models.Finding{
		TargetID:       e.target.ID,
		RuleID:         r.ID,
		ModuleID:       r.ModuleID,
		Title:          title,
		Category:       r.Category,
		Description:    desc,
		Impact:         impactText,
		Recommendation: r.Recommendation,
		Severity:       sev,
		Confidence:     conf,
		Status:         statusFor(conf),
		State:          stateFor(conf),
		Exposure:       expo,
		Privilege:      priv,
		Sensitivity:    sens,
		Objects:        objects,
		Evidence:       m.Evidence,
		Attributes:     rec,
		References:     r.References,
		Timestamp:      collectedAt,
	}
	return f
}

// statusFor maps confidence onto the finding lifecycle. A finding raised on an
// inference is marked inferred rather than detected, because "we think this is
// happening" and "we saw this" are different claims and a report that merges
// them cannot be triaged.
func statusFor(c models.Confidence) models.FindingStatus {
	switch c {
	case models.ConfidenceConfirmed:
		return models.StatusConfirmed
	case models.ConfidenceUnknown, models.ConfidenceNotObserved:
		return models.StatusInformational
	default:
		return models.StatusDetected
	}
}

func stateFor(c models.Confidence) models.State {
	switch c {
	case models.ConfidenceConfirmed, models.ConfidenceObserved:
		return models.StateObserved
	case models.ConfidenceProbable, models.ConfidencePossible:
		return models.StateInferred
	default:
		return models.StateUnknown
	}
}

// sortFindings imposes a total order on the output. Without it, map iteration
// inside a single rule could reorder findings between runs and two reports of
// an unchanged host would differ — which destroys the ability to diff them.
func sortFindings(in []models.Finding) {
	sort.SliceStable(in, func(i, j int) bool {
		a, b := in[i], in[j]
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Title != b.Title {
			return a.Title < b.Title
		}
		return strings.Join(a.Objects, "\x00") < strings.Join(b.Objects, "\x00")
	})
}
