// Package risk turns a finding's explicit inputs into a score that any two
// people — and any two Amina versions — can reproduce from the finding itself.
//
// The design constraint that shaped this package is reproducibility. There is no
// hidden state, no learned weighting, and no dependence on collection order or
// on how many other findings happened to fire. Every term below is a published
// constant and every intermediate value is retained on the returned Score, so a
// report can show the arithmetic instead of asking to be trusted.
//
// Note the deliberate separation between Band here and models.RiskLevel. The
// latter is the S1–S4 operational tier of an *action Amina takes* — whether a
// command is read-only, whether it can escalate, whether it is destructive.
// This package's Band is the severity of a *condition Amina found*. Merging
// them would produce a report whose severity scale changes meaning halfway down
// the page, so they are kept as two types with two vocabularies.
package risk

import (
	"fmt"
	"math"
	"strings"

	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// The published weights. They are exported so a report can print the formula it
// used and a reviewer can check the arithmetic without reading this file.
const (
	// WeightImpact dominates: what actually follows if the condition is
	// exercised. It outweighs everything else because the operational question
	// is never "how unusual is this" but "what does it cost me if it is used
	// against me".
	WeightImpact = 0.40
	// WeightExploitability is how reachable the condition is by someone other
	// than the operator.
	WeightExploitability = 0.20
	// WeightExposure is how far the condition reaches. A loopback-bound
	// service and a wildcard-bound one are different exposures, not different
	// phrasings of the same one.
	WeightExposure = 0.20
	// WeightPrivilege is the barrier an attacker must clear first.
	WeightPrivilege = 0.10

	// InputScale is the maximum of the 0–4 dimension scores. The weights sum to
	// 1, so a weighted total is itself a 0–4 value and multiplying by
	// 100/InputScale maps it onto 0–100.
	//
	// Dividing by the weight *sum* here would be wrong and looks plausible:
	// because the weights happen to total 0.90, it rescales every score upward
	// until the clamp at 100 swallows the entire exposure and privilege range,
	// and a loopback service scores exactly what a world-reachable one does.
	InputScale = 4.0

	// scaleTo100 converts a 0–4 weighted total into a 0–100 score.
	scaleTo100 = 100.0 / InputScale

	// SensitivityBonus is the additive weight of a sensitivity bonus point.
	// It is deliberately small: sensitivity describes the content at stake, not
	// the reachability of the leak, and it must not lift a loopback-only
	// finding above a world-reachable one.
	SensitivityBonus = 10.0
)

// Band is the severity bucket a final score falls into. It is distinct from
// models.RiskLevel, which classifies Amina's own operations rather than its
// findings.
type Band string

const (
	BandMinimal  Band = "minimal"
	BandLow      Band = "low"
	BandModerate Band = "moderate"
	BandElevated Band = "elevated"
	BandHigh     Band = "high"
	BandCritical Band = "critical"
)

// Bands lists every band in increasing severity.
var Bands = []Band{BandMinimal, BandLow, BandModerate, BandElevated, BandHigh, BandCritical}

// confidenceWeight scales the whole score rather than acting as a fifth
// weighted term. An uncertain finding is not a smaller finding; it is the same
// finding with a weaker claim attached, and scoring it low would let the engine
// bury something real behind its own uncertainty.
var confidenceWeight = map[models.Confidence]float64{
	models.ConfidenceConfirmed: 1.00,
	models.ConfidenceObserved:  0.90,
	models.ConfidenceProbable:  0.70,
	models.ConfidencePossible:  0.40,
	models.ConfidenceUnknown:   0.15,
	// Explicit non-observation is not evidence of a condition. It still gets a
	// non-zero weight because a finding raised on an explicit absence ("this
	// control is absent") is a real observation, not a guess.
	models.ConfidenceNotObserved: 0.25,
}

// Input is the scoring input for one finding. It is a plain struct rather than
// models.Finding so that scoring can be exercised, regression-tested and
// documented without constructing an entire finding.
type Input struct {
	Impact      models.Severity
	Exposure    models.ExposureScope
	Privilege   models.Privilege
	Sensitivity models.Sensitivity
	Confidence  models.Confidence
	// Exploitability is optional. Most findings can infer it from exposure and
	// privilege; when it is absent the inferred value is used and
	// InferredExploitability is set so the report can say which terms were
	// assumed rather than presenting them as observed.
	Exploitability models.Severity
}

// Score is a computed risk retaining every intermediate value.
type Score struct {
	// Raw is the weighted total before confidence scaling, 0–100.
	Raw float64 `json:"raw"`
	// Final is the confidence-scaled score, 0–100.
	Final float64 `json:"final"`
	// Band buckets Final.
	Band Band `json:"band"`

	Impact           float64 `json:"impact"`
	Exploitability   float64 `json:"exploitability"`
	Exposure         float64 `json:"exposure"`
	Privilege        float64 `json:"privilege"`
	SensitivityBonus float64 `json:"sensitivity_bonus"`

	Confidence             models.Confidence `json:"confidence"`
	ConfidenceWeight       float64           `json:"confidence_weight"`
	InferredExploitability bool              `json:"inferred_exploitability"`
}

// impactValues scores each severity on a 0–4 scale, published rather than
// derived so a rule author can predict the result before running anything.
var impactValues = map[models.Severity]float64{
	models.SeverityInformational: 1.0,
	models.SeverityLow:           2.0,
	models.SeverityMedium:        3.0,
	models.SeverityHigh:          4.0,
	// Critical is deliberately capped at the same 4.0 as High. The difference
	// between "severe" and "actively exploitable right now" is carried by
	// exposure and exploitability, which is exactly where that distinction
	// lives; giving it a fifth impact point would count the same judgement
	// twice and inflate every critical finding.
	models.SeverityCritical: 4.0,
}

// exposureValues scores how far a finding reaches.
var exposureValues = map[models.ExposureScope]float64{
	models.ScopeLocal:     0.5,
	models.ScopeLoopback:  1.0,
	models.ScopeContainer: 2.0,
	models.ScopeVirtual:   2.5,
	models.ScopeVPN:       3.0,
	models.ScopeLAN:       3.5,
	models.ScopeWildcard:  4.0,
	models.ScopePublic:    4.0,
	// Unknown reachability is scored at the middle of the scale. Both extremes
	// would be a claim Amina has not earned: calling an unclassified bind
	// "local" hides a possible network exposure, and calling it "public"
	// invents one.
	models.ScopeUnknown: 2.0,
}

// privilegeValues scores the barrier to entry. The direction is the opposite of
// what the name suggests at first glance: a condition that *requires* system
// privileges to exploit scores lower, because this term measures the barrier,
// not the severity of what lies behind it.
var privilegeValues = map[models.Privilege]float64{
	models.PrivNone:     4.0,
	models.PrivUser:     3.0,
	models.PrivElevated: 2.0,
	models.PrivSystem:   1.0,
}

// sensitivityValues weight the content at stake, independent of reach.
var sensitivityValues = map[models.Sensitivity]float64{
	models.SensitivityPublic:    0.0,
	models.SensitivityInternal:  0.25,
	models.SensitivitySensitive: 0.5,
	models.SensitivitySecret:    1.0,
}

// LevelThresholds are published because "why is this moderate" is the first
// question an operator asks of any score.
var LevelThresholds = []struct {
	Min  float64
	Band Band
}{
	{0, BandMinimal},
	{15, BandLow},
	{35, BandModerate},
	{55, BandElevated},
	{75, BandHigh},
	{90, BandCritical},
}

// Compute scores a finding.
//
//	weighted = 0.40*impact + 0.20*exploitability
//	         + 0.20*exposure + 0.10*privilege        // weights total 1.0
//	raw      = weighted * 25 + sensitivity_bonus * 10
//	final    = raw * confidence_weight
//
// The weights total 1.0, so the weighted sum is itself on the 0-4 input scale
// and the factor of 25 is what maps it onto 0-100. Every dimension at 4.0
// therefore reaches exactly 100 before the bonus and the confidence multiplier.
func Compute(in Input) Score {
	impact := lookupImpact(in.Impact)

	exploit, inferred := in.Exploitability, false
	if exploit == "" {
		exploit = InferExploitability(in.Exposure, in.Privilege)
		inferred = true
	}
	exploitVal := lookupImpact(exploit)

	exposure := lookupExposure(in.Exposure)
	privilege := lookupPrivilege(in.Privilege)
	sensBonus := lookupSensitivity(in.Sensitivity)

	raw := (WeightImpact*impact +
		WeightExploitability*exploitVal +
		WeightExposure*exposure +
		WeightPrivilege*privilege) * scaleTo100

	raw += sensBonus * SensitivityBonus
	if raw > 100 {
		raw = 100
	}

	cw, ok := confidenceWeight[in.Confidence]
	if !ok {
		// An unset confidence must never score at full weight.
		cw = confidenceWeight[models.ConfidenceUnknown]
	}
	if in.Confidence == "" {
		in.Confidence = models.ConfidenceUnknown
	}

	final := raw * cw
	return Score{
		Raw:                    round1(raw),
		Final:                  round1(final),
		Band:                   BandFor(final),
		Impact:                 impact,
		Exploitability:         exploitVal,
		Exposure:               exposure,
		Privilege:              privilege,
		SensitivityBonus:       sensBonus,
		Confidence:             in.Confidence,
		ConfidenceWeight:       cw,
		InferredExploitability: inferred,
	}
}

// InferExploitability derives exploitability from exposure and privilege.
//
// Reachability dominates, because something bound to a wildcard address is
// reachable by anyone who can route to it whatever privilege is needed
// afterwards, while something reachable only over loopback requires local access
// first — a materially harder bar that exposure alone would miss.
func InferExploitability(exposure models.ExposureScope, privilege models.Privilege) models.Severity {
	e := lookupExposure(exposure)
	p := lookupPrivilege(privilege)
	switch {
	case e >= 3.5:
		return models.SeverityHigh
	case e >= 2.0 && p >= 2.0:
		return models.SeverityMedium
	case e >= 2.0 || p >= 3.0:
		return models.SeverityMedium
	default:
		return models.SeverityLow
	}
}

// BandFor buckets a final score. Unknown input still yields a band, because a
// blank band downstream is indistinguishable from a parsing failure.
func BandFor(score float64) Band {
	band := BandMinimal
	for _, t := range LevelThresholds {
		if score >= t.Min {
			band = t.Band
		}
	}
	return band
}

// ParseBand converts a case-insensitive string into a Band.
func ParseBand(s string) (Band, bool) {
	want := Band(strings.ToLower(strings.TrimSpace(s)))
	for _, b := range Bands {
		if b == want {
			return b, true
		}
	}
	return Band(""), false
}

// Formula returns the published formula for inclusion in reports, so a report
// states the arithmetic it used rather than asking to be trusted.
func Formula() string {
	return fmt.Sprintf(
		"score = (%.2f*impact + %.2f*exploitability + %.2f*exposure + %.2f*privilege)*%.0f "+
			"+ sensitivity_bonus*%.0f; then * confidence_weight. Inputs scored 0-4.",
		WeightImpact, WeightExploitability, WeightExposure, WeightPrivilege,
		scaleTo100, SensitivityBonus)
}

func lookupImpact(s models.Severity) float64 {
	if v, ok := impactValues[s]; ok {
		return v
	}
	// An unrecognised severity is scored as informational. Guessing "medium"
	// would inflate the score of anything that failed to parse.
	return impactValues[models.SeverityInformational]
}

func lookupExposure(s models.ExposureScope) float64 {
	if v, ok := exposureValues[s]; ok {
		return v
	}
	return exposureValues[models.ScopeUnknown]
}

func lookupPrivilege(p models.Privilege) float64 {
	if v, ok := privilegeValues[p]; ok {
		return v
	}
	// Unrecognised privilege is treated as an elevated barrier. Assuming no
	// barrier would inflate the score of anything unparsed; assuming maximum
	// would hide it.
	return privilegeValues[models.PrivElevated]
}

func lookupSensitivity(s models.Sensitivity) float64 {
	if v, ok := sensitivityValues[s]; ok {
		return v
	}
	return 0
}

func round1(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return math.Round(v*10) / 10
}
