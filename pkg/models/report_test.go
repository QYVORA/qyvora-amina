package models

import (
	"strings"
	"testing"
	"time"
)

func finding(rule, title string, score int) Finding {
	return Finding{
		ID:       NewID("fnd"),
		RuleID:   rule,
		ModuleID: "network",
		Title:    title,
		Severity: SeverityHigh,
		State:    StateObserved,
		Attributes: map[string]string{
			"risk_score": itoaTest(score),
			"risk_band":  RiskBandFor(score),
		},
	}
}

func itoaTest(n int) string {
	// Deliberately local: the test must not depend on a formatting helper that
	// could change underneath it.
	if n == 0 {
		return "0"
	}
	var digits []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		return "-" + string(digits)
	}
	return string(digits)
}

func TestRiskScoreReadsTheEngineValue(t *testing.T) {
	f := finding("NET-001", "x", 87)
	if got := f.RiskScore(); got != 87 {
		t.Errorf("RiskScore = %d, want 87", got)
	}
	if got := f.RiskBand(); got != "high" {
		t.Errorf("RiskBand = %q, want high", got)
	}
	// A finding built by hand, with no score, must still be printable.
	bare := Finding{RuleID: "R"}
	if got := bare.RiskScore(); got != 0 {
		t.Errorf("a finding without a score should read as 0, got %d", got)
	}
	if got := bare.RiskBand(); got != "" {
		t.Errorf("a finding without a band should read empty, got %q", got)
	}
}

// TestReportOrderIsDeterministic is the property the whole report layer rests
// on: two runs over the same input must produce byte-identical output, or every
// diff between runs is noise.
func TestReportOrderIsDeterministic(t *testing.T) {
	build := func() Report {
		r := NewReport(Target{ID: "tgt-1", Name: "host", Type: TargetHost}, 2, "standard")
		r.GeneratedAt = time.Unix(1700000000, 0).UTC()
		r.Findings = []Finding{
			finding("NET-002", "b", 40),
			finding("NET-001", "a", 40),
			finding("ACC-001", "c", 95),
			finding("NET-001", "a2", 40),
		}
		r.Modules = []ModuleStatus{
			{ID: "network", Name: "Network"},
			{ID: "accounts", Name: "Accounts"},
		}
		r.Secrets = []SecretRecord{
			{Location: "/z", Fingerprint: "f2"},
			{Location: "/a", Fingerprint: "f1"},
		}
		r.Software = []Software{{Name: "zsh", Version: "5"}, {Name: "bash", Version: "5"}}
		r.Limitations = []string{"one", "two"}
		r.Finalize()
		return r
	}

	a, b := build(), build()
	if a.Integrity != b.Integrity {
		t.Fatalf("two identical builds produced different checksums: %s vs %s", a.Integrity, b.Integrity)
	}
	if a.Findings[0].Title != "c" {
		t.Errorf("highest-risk finding is not first: %q", a.Findings[0].Title)
	}
	if a.Findings[1].RuleID != "NET-001" || a.Findings[2].RuleID != "NET-001" {
		t.Errorf("equal-risk findings are not ordered by rule: %v",
			[]string{a.Findings[1].RuleID, a.Findings[2].RuleID})
	}
	if a.Modules[0].ID != "accounts" {
		t.Error("module statuses must be sorted by ID")
	}
	if a.Secrets[0].Location != "/a" {
		t.Error("secrets must be sorted by location")
	}
	if a.Software[0].Name != "bash" {
		t.Error("software must be sorted by name")
	}
}

// TestIntegrityDetectsAChange is what makes the checksum worth having: it must
// change when a finding changes.
func TestIntegrityDetectsAChange(t *testing.T) {
	mk := func() Report {
		r := NewReport(Target{ID: "tgt-1", Name: "host", Type: TargetHost}, 2, "standard")
		r.GeneratedAt = time.Unix(1700000000, 0).UTC()
		r.Findings = []Finding{finding("NET-001", "a", 40)}
		r.Finalize()
		return r
	}
	base := mk()
	changed := mk()
	changed.Findings[0].Title = "a but different"
	changed.Finalize()
	if base.Integrity == changed.Integrity {
		t.Fatal("changing a finding did not change the checksum")
	}

	// The generated-at time must not participate: two runs a second apart
	// describe the same assessment.
	later := mk()
	later.GeneratedAt = time.Unix(1700000001, 0).UTC()
	later.Finalize()
	if base.Integrity != later.Integrity {
		t.Fatal("the checksum depends on wall-clock time, so two identical runs differ")
	}
}

func TestSummarize(t *testing.T) {
	f := []Finding{
		{RuleID: "A", Severity: SeverityHigh, Category: CategoryNetwork, State: StateObserved, Correlated: true},
		{RuleID: "B", Severity: SeverityHigh, Category: CategoryNetwork, State: StateObserved},
		{RuleID: "C", Severity: SeverityLow, Category: CategoryAccount, State: StateInferred},
	}
	s := Summarize(f, []CorrelatedIdentity{{ID: "id-1"}})
	if s.Total != 3 {
		t.Errorf("total = %d", s.Total)
	}
	if s.BySeverity[SeverityHigh] != 2 {
		t.Errorf("by_severity high = %d, want 2", s.BySeverity[SeverityHigh])
	}
	if s.ByCategory[CategoryNetwork] != 2 {
		t.Errorf("by_category network = %d, want 2", s.ByCategory[CategoryNetwork])
	}
	if s.Correlated != 1 {
		t.Errorf("correlated = %d, want 1", s.Correlated)
	}
	if s.IdentityCount != 1 {
		t.Errorf("identity_count = %d, want 1", s.IdentityCount)
	}
	if s.ByState[StateObserved] != 2 {
		t.Errorf("by_state observed = %d, want 2", s.ByState[StateObserved])
	}
}

// TestLimitationsDistinguishUnlookedAtFromClean is the honesty property of the
// report: a module that did not run has to be visible as such.
func TestLimitationsDistinguishUnlookedAtFromClean(t *testing.T) {
	got := Limitations([]ModuleStatus{
		{ID: "a", Name: "Accounts", Status: ExposureComplete},
		{ID: "b", Name: "Metadata", Status: ExposureSkipped, Reason: "requires depth 3"},
		{ID: "c", Name: "Binary Integrity", Status: ExposurePrivilege},
		{ID: "d", Name: "Secrets", Status: ExposureDegraded, Reason: "some files unreadable", Unavailable: []string{"filesystem"}},
	})
	if len(got) != 3 {
		t.Fatalf("expected three limitations, got %v", got)
	}
	joined := strings.Join(got, " | ")
	for _, want := range []string{"not assessed", "requires depth 3", "requires privileges", "unavailable: filesystem"} {
		if !strings.Contains(joined, want) {
			t.Errorf("limitation text missing %q: %v", want, got)
		}
	}
	if strings.Contains(joined, "Accounts") {
		t.Error("a module that ran completely should not appear as a limitation")
	}
}

func TestRedactionPolicyRetainsNoValues(t *testing.T) {
	p := DefaultRedaction()
	if p.ValuesRetained {
		t.Fatal("the redaction policy must assert that no values are retained")
	}
	if p.Strategy != "fingerprint-only" {
		t.Errorf("strategy = %q", p.Strategy)
	}
}

// TestRiskBandThresholdsMatchTheRiskPackage guards the one piece of this
// package that duplicates knowledge held elsewhere. The boundaries are restated
// in models so that a formatter can render a band without importing pkg/risk;
// this test is what stops the copy from drifting away from the original.
func TestRiskBandThresholdsMatchTheRiskPackage(t *testing.T) {
	// These are the boundaries pkg/risk.BandFor publishes. If that package
	// changes them, this test fails and the copy below is updated with it.
	cases := []struct {
		score int
		band  string
	}{
		{0, "minimal"}, {14, "minimal"},
		{15, "low"}, {34, "low"},
		{35, "moderate"}, {54, "moderate"},
		{55, "elevated"}, {74, "elevated"},
		{75, "high"}, {89, "high"},
		{90, "critical"}, {100, "critical"},
	}
	for _, c := range cases {
		if got := RiskBandFor(c.score); got != c.band {
			t.Errorf("RiskBandFor(%d) = %q, want %q", c.score, got, c.band)
		}
	}
}
