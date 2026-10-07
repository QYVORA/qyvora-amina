package models

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
	"time"
)

// FindingStatus tracks where a finding sits in the assessment lifecycle.
type FindingStatus string

const (
	StatusDetected      FindingStatus = "detected"
	StatusConfirmed     FindingStatus = "confirmed"
	StatusFalsePositive FindingStatus = "false-positive"
	StatusResolved      FindingStatus = "resolved"
	StatusInformational FindingStatus = "informational"
)

// Tier represents the capability tier that generated a finding
type Tier string

const (
	TierRecon        Tier = "recon"        // Tier 1: Discovery and enumeration
	TierTechnique    Tier = "technique"    // Tier 2: Vulnerability identification
	TierExploitation Tier = "exploitation" // Tier 3: Active exploitation
)

// Finding is the normalized representation of an operational-security
// condition. Beyond the ecosystem baseline it carries the explicit risk inputs
// (exposure scope, privilege, sensitivity) so every score is reproducible from
// the finding itself rather than from hidden engine state.
type Finding struct {
	ID             string            `json:"id"`
	TargetID       string            `json:"target_id"`
	RuleID         string            `json:"rule_id"`
	ModuleID       string            `json:"module_id"`
	Title          string            `json:"title"`
	Category       Category          `json:"category"`
	Description    string            `json:"description"`
	Impact         string            `json:"impact,omitempty"`
	Recommendation string            `json:"recommendation,omitempty"`
	Severity       Severity          `json:"severity"`
	Confidence     Confidence        `json:"confidence"`
	Status         FindingStatus     `json:"status"`
	State          State             `json:"state"`
	Tier           Tier              `json:"tier,omitempty"` // Capability tier that generated this finding
	Exposure       ExposureScope     `json:"exposure"`
	Privilege      Privilege         `json:"privilege"`
	Sensitivity    Sensitivity       `json:"sensitivity"`
	Correlated     bool              `json:"correlated"` // produced by identity correlation
	Objects        []string          `json:"objects,omitempty"`
	Evidence       []Evidence        `json:"evidence,omitempty"`
	Attributes     map[string]string `json:"attributes,omitempty"`
	References     []string          `json:"references,omitempty"`
	Timestamp      time.Time         `json:"timestamp"`
}

// TierPrefix returns a display prefix for the finding's tier
func (f *Finding) TierPrefix() string {
	switch f.Tier {
	case TierRecon:
		return "[RECON]"
	case TierTechnique:
		return "[TECHNIQUE]"
	case TierExploitation:
		return "[EXPLOIT]"
	default:
		return ""
	}
}

// Fingerprint returns a stable identity key for the finding (SHA-256 of
// rule/category/title/objects/attributes). Two findings with the same
// fingerprint describe the same underlying issue, which is what lets the rule
// sink merge corroborating observations into one finding instead of five
// near-identical ones.
func (f *Finding) Fingerprint() string {
	var b strings.Builder
	b.WriteString(f.RuleID)
	b.WriteString("\x00")
	b.WriteString(string(f.Category))
	b.WriteString("\x00")
	b.WriteString(f.Title)

	objs := append([]string(nil), f.Objects...)
	sort.Strings(objs)
	for _, o := range objs {
		b.WriteString("\x00obj=")
		b.WriteString(o)
	}

	keys := make([]string, 0, len(f.Attributes))
	for k := range f.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		b.WriteString("\x00")
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(f.Attributes[k])
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// RedactSecrets strips secret-shaped values from a finding before it is
// written to any output surface. It is field-scoped, not blanket: structural
// fields (rule, category, description, recommendation, objects, references)
// are preserved verbatim, and only attribute values and evidence payloads that
// look like credential material are replaced. Keeping non-secret evidence
// readable is what makes the report actionable; the values that would make it
// dangerous never appear in the first place.
func (f *Finding) RedactSecrets() {
	for k, v := range f.Attributes {
		if looksSecretKey(k) || LooksSecretValue(v) {
			f.Attributes[k] = "<redacted>"
		}
	}
	for i := range f.Evidence {
		if LooksSecretValue(f.Evidence[i].Data) {
			f.Evidence[i].Data = "<redacted>"
			f.Evidence[i].Redaction.Mode = RedactionFull
			f.Evidence[i].Redaction.Reason = "secret-shaped value stripped at render"
		}
	}
}

// RedactSecretData redacts secret-shaped payloads from an evidence slice in
// place, so result-level evidence lists are also safe to persist.
func RedactSecretData(list []Evidence) {
	for i := range list {
		if LooksSecretValue(list[i].Data) {
			list[i].Data = "<redacted>"
			list[i].Redaction.Mode = RedactionFull
			list[i].Redaction.Reason = "secret-shaped value stripped at render"
		}
	}
}

// looksSecretKey classifies attribute keys that must never be emitted verbatim.
func looksSecretKey(k string) bool {
	l := strings.ToLower(k)
	for _, prefix := range []string{"secret", "token", "password", "passwd", "key", "credential", "private", "auth"} {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return strings.Contains(l, "secret") ||
		strings.Contains(l, "password") ||
		strings.Contains(l, "credential") ||
		strings.Contains(l, "apikey")
}

// secretKeyPrefixRx matches `password`, `api_key`, `access_token` and similar
// assignment keys anywhere in a payload.
var secretKeyPrefixRx = regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?access[_-]?key|client[_-]?secret|private[_-]?key|auth[_-]?token|bearer)\b\s*[=:]\s*`)

// secretValueRx detects credential-shaped values wherever they appear in a
// payload: AWS access key ids, GitHub and GitLab tokens, JWTs, private key
// blocks, Google API keys, Slack tokens, Stripe keys and assignment-form
// secrets. High-entropy guessing is deliberately avoided so evidence quality
// is not destroyed by false positives.
var secretValueRx = regexp.MustCompile(`(?is)\bAKIA[0-9A-Z]{16}\b|\bASIA[0-9A-Z]{16}\b|\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b|\bglpat-[A-Za-z0-9_-]{16,}\b|-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----|\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}|\bAIza[0-9A-Za-z_-]{35}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}\b|\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b|\bya29\.[A-Za-z0-9_-]{20,}\b|-----BEGIN CERTIFICATE-----`)

// LooksSecretValue reports whether a payload contains credential-shaped
// material. It is exported because the collectors, the renderers and the tests
// must all agree on one definition; three separate definitions is how a
// redaction rule eventually stops covering the thing it was written for.
func LooksSecretValue(s string) bool {
	if s == "" || s == "<redacted>" {
		return false
	}
	l := strings.ToLower(strings.TrimSpace(s))
	for _, p := range []string{
		"-----begin", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
		"glpat-", "sk_live_", "pk_live_", "sk_test_", "pk_test_", "xoxb-",
		"xoxp-", "xoxa-", "xoxs-", "ya29.", "eyj", "akia", "asia",
	} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	if secretValueRx.MatchString(s) {
		return true
	}
	// Assignment form: a secret-named key followed by a long opaque value.
	if loc := secretKeyPrefixRx.FindStringIndex(s); loc != nil {
		rest := s[loc[1]:]
		rest = strings.TrimLeft(rest, "\"'` \t")
		if len(strings.TrimSpace(rest)) >= 8 {
			return true
		}
	}
	return false
}
