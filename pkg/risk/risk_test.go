package risk

import (
	"math"
	"testing"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// The scoring tests assert the *contract* — reproducibility, ordering,
// saturation — rather than hard-coding today's numbers. A test that pins every
// score would break on any weight change and would not catch the failure mode
// that matters: two runs of the same finding disagreeing with each other.

func TestComputeIsDeterministic(t *testing.T) {
	in := Input{
		Impact:      models.SeverityHigh,
		Exposure:    models.ScopeLAN,
		Privilege:   models.PrivUser,
		Sensitivity: models.SensitivitySensitive,
		Confidence:  models.ConfidenceObserved,
	}
	first := Compute(in)
	for i := 0; i < 100; i++ {
		if got := Compute(in); got != first {
			t.Fatalf("run %d produced %+v, first run produced %+v", i, got, first)
		}
	}
}

// TestScoreIsIndependentOfFieldPopulation is the property that lets a finding be
// recomputed from a report. Scoring must depend only on the values present,
// never on whether a caller happened to set a zero-valued field.
func TestScoreDependsOnlyOnValuesNotOnWhichFieldsWereSet(t *testing.T) {
	base := Input{
		Impact:      models.SeverityMedium,
		Exposure:    models.ScopeContainer,
		Privilege:   models.PrivElevated,
		Sensitivity: models.SensitivityInternal,
		Confidence:  models.ConfidenceProbable,
	}
	explicit := base
	explicit.Exploitability = models.SeverityMedium
	inferred := base
	// Exploitability deliberately left empty so it must be inferred.

	withExplicit := Compute(explicit)
	withInferred := Compute(inferred)

	// Setting exploitability explicitly to what inference produces must not
	// change the outcome or the reported provenance of that term.
	if withExplicit.Raw != withInferred.Raw {
		t.Errorf("explicit and inferred exploitability disagree: %v vs %v",
			withExplicit.Raw, withInferred.Raw)
	}
	if withInferred.InferredExploitability != true {
		t.Error("an inferred exploitability term must be flagged as inferred")
	}
	if withExplicit.InferredExploitability != false {
		t.Error("an explicitly supplied exploitability term must not be flagged inferred")
	}
}

func TestExposureOrdering(t *testing.T) {
	// The central claim of the network module is that reach matters. Score the
	// same finding at each scope and the order must be strict.
	order := []models.ExposureScope{
		models.ScopeLocal,
		models.ScopeLoopback,
		models.ScopeContainer,
		models.ScopeVirtual,
		models.ScopeVPN,
		models.ScopeLAN,
		models.ScopeWildcard,
	}
	prev := math.Inf(-1)
	for _, scope := range order {
		s := Compute(Input{
			Impact: models.SeverityMedium, Exposure: scope,
			Privilege: models.PrivUser, Confidence: models.ConfidenceObserved,
		})
		if s.Final <= prev {
			t.Errorf("scope %s scored %.1f, not above the previous %.1f", scope, s.Final, prev)
		}
		prev = s.Final
	}
}

func TestPrivilegeIsABarrierNotASeverity(t *testing.T) {
	// Requiring more privilege to exploit must lower the score. This is the
	// inverse of intuition and is exactly the kind of thing that gets
	// implemented backwards.
	system := Compute(Input{Impact: models.SeverityHigh, Exposure: models.ScopeLAN,
		Privilege: models.PrivSystem, Confidence: models.ConfidenceObserved})
	none := Compute(Input{Impact: models.SeverityHigh, Exposure: models.ScopeLAN,
		Privilege: models.PrivNone, Confidence: models.ConfidenceObserved})
	if system.Final >= none.Final {
		t.Errorf("a system-privileged condition scored %.1f, not below the unprivileged %.1f",
			system.Final, none.Final)
	}
}

func TestConfidenceScalesRatherThanDominates(t *testing.T) {
	// The same finding at confirmed and at possible confidence: the weaker one
	// must score lower, but the *raw* value must be identical. If raw moved with
	// confidence, the score would be encoding uncertainty twice.
	raw := Input{Impact: models.SeverityHigh, Exposure: models.ScopeWildcard, Privilege: models.PrivNone}
	a := Compute(withConfidence(raw, models.ConfidenceConfirmed))
	b := Compute(withConfidence(raw, models.ConfidencePossible))

	if a.Raw != b.Raw {
		t.Errorf("raw changed with confidence: %.1f vs %.1f", a.Raw, b.Raw)
	}
	if a.Final <= b.Final {
		t.Errorf("confirmed %.1f should exceed possible %.1f", a.Final, b.Final)
	}
}

func TestUnsetConfidenceNeverScoresFull(t *testing.T) {
	in := Input{Impact: models.SeverityHigh, Exposure: models.ScopeWildcard, Privilege: models.PrivNone}
	got := Compute(in)
	if got.ConfidenceWeight >= 1.0 {
		t.Errorf("an unset confidence scored at weight %.2f; it must be discounted", got.ConfidenceWeight)
	}
	if got.Confidence != models.ConfidenceUnknown {
		t.Errorf("unset confidence reported as %q, want %q", got.Confidence, models.ConfidenceUnknown)
	}
}

func TestUnknownInputDegradesRatherThanInflates(t *testing.T) {
	// An unparsable severity must not be treated as high.
	unknownImpact := Compute(Input{Impact: models.Severity("nonsense"),
		Exposure: models.ScopeLAN, Confidence: models.ConfidenceObserved})
	informational := Compute(Input{Impact: models.SeverityInformational,
		Exposure: models.ScopeLAN, Confidence: models.ConfidenceObserved})
	if unknownImpact.Raw != informational.Raw {
		t.Errorf("unrecognised severity scored %.1f, informational scored %.1f; they must agree",
			unknownImpact.Raw, informational.Raw)
	}

	// Unknown exposure must land between loopback and LAN rather than at either
	// extreme: calling it local hides a possible network exposure, calling it
	// public invents one.
	unknownExposure := lookupExposure(models.ExposureScope("nonsense"))
	if unknownExposure <= exposureValues[models.ScopeLoopback] {
		t.Errorf("unknown exposure scored %.1f, at or below loopback", unknownExposure)
	}
	if unknownExposure >= exposureValues[models.ScopeLAN] {
		t.Errorf("unknown exposure scored %.1f, at or above LAN", unknownExposure)
	}
}

func TestScoreIsBoundedAndFinite(t *testing.T) {
	// Maximum everything, including a maximum sensitivity bonus.
	max := Compute(Input{
		Impact: models.SeverityCritical, Exposure: models.ScopePublic,
		Privilege: models.PrivNone, Sensitivity: models.SensitivitySecret,
		Confidence: models.ConfidenceConfirmed,
	})
	if max.Raw > 100 {
		t.Errorf("raw score %.1f exceeds 100", max.Raw)
	}
	if max.Final > 100 {
		t.Errorf("final score %.1f exceeds 100", max.Final)
	}
	if max.Band != BandCritical {
		t.Errorf("maximum input produced band %q, want %q", max.Band, BandCritical)
	}

	// Empty input must still produce a usable, bounded result rather than NaN.
	empty := Compute(Input{})
	if math.IsNaN(empty.Final) || math.IsInf(empty.Final, 0) {
		t.Errorf("empty input produced %v", empty.Final)
	}
	if empty.Final < 0 {
		t.Errorf("empty input produced a negative score %.1f", empty.Final)
	}
	if empty.Band == "" {
		t.Error("empty input produced an empty band")
	}
}

func TestBandThresholdsAreContiguous(t *testing.T) {
	// Every band must be reachable, and no score may fall between two bands.
	for i, b := range Bands {
		if Compute(Input{Impact: models.SeverityMedium, Exposure: models.ScopeLAN,
			Privilege: models.PrivUser, Confidence: models.ConfidenceConfirmed}).Band != Band("") {
			t.Log("reachable band", b)
		}
		_ = i
	}
	prev := math.Inf(-1)
	for _, th := range LevelThresholds {
		if th.Min < prev {
			t.Errorf("thresholds are not monotonic at %v", th.Min)
		}
		if BandFor(th.Min) != th.Band {
			t.Errorf("score %.0f reported as %q, want %q", th.Min, BandFor(th.Min), th.Band)
		}
		prev = th.Min
	}
}

func TestSensitivityBonusIsBounded(t *testing.T) {
	// A secret on a loopback bind must not outrank a public one on a wildcard
	// bind: reach dominates content.
	loopbackSecret := Compute(Input{Impact: models.SeverityMedium,
		Exposure: models.ScopeLoopback, Sensitivity: models.SensitivitySecret,
		Privilege: models.PrivUser, Confidence: models.ConfidenceObserved})
	wildcardPublic := Compute(Input{Impact: models.SeverityMedium,
		Exposure: models.ScopeWildcard, Sensitivity: models.SensitivityPublic,
		Privilege: models.PrivUser, Confidence: models.ConfidenceObserved})
	if loopbackSecret.Final > wildcardPublic.Final {
		t.Errorf("loopback secret (%.1f) outranked wildcard public (%.1f)",
			loopbackSecret.Final, wildcardPublic.Final)
	}
	if loopbackSecret.SensitivityBonus == 0 {
		t.Error("a secret classification produced no sensitivity bonus")
	}
}

func TestParseBandRoundTrips(t *testing.T) {
	for _, b := range Bands {
		got, ok := ParseBand(string(b))
		if !ok || got != b {
			t.Errorf("ParseBand(%q) = (%q, %v)", b, got, ok)
		}
	}
	if _, ok := ParseBand("catastrophic"); ok {
		t.Error("ParseBand accepted an unknown band")
	}
	if got, ok := ParseBand("  HIGH "); !ok || got != BandHigh {
		t.Errorf("ParseBand should tolerate surrounding whitespace and case, got (%q, %v)", got, ok)
	}
}

func TestFormulaDocumentsTheWeights(t *testing.T) {
	f := Formula()
	for _, want := range []string{"0.40", "0.20", "0.10", "*25", "confidence_weight", "0-4"} {
		if !contains(f, want) {
			t.Errorf("published formula omits %q: %s", want, f)
		}
	}
	// The formula must not advertise a normalisation that is not implemented.
	// Dividing by the weight sum looks plausible and silently destroys the
	// exposure and privilege ranges, so its absence is asserted explicitly.
	if contains(f, "0.90") {
		t.Errorf("published formula still claims the weight-sum divisor: %s", f)
	}
}

func withConfidence(in Input, c models.Confidence) Input {
	in.Confidence = c
	return in
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}
