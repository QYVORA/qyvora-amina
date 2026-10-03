package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/QYVORA/qyvora-amina/internal/config"
	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// MarkdownRenderer writes a GitHub-flavoured Markdown report.
//
// Markdown is the format this tool's reports are most often shared in, so it is
// written for two readers at once: a person skimming it in a pull request
// comment, and a person grepping it six months later. That means findings in a
// table with stable columns, every path in backticks, and the limitations
// section before the findings rather than at the bottom.
//
// Everything that could be interpreted as markup is escaped. The report carries
// strings lifted from configuration files — a package name, a git remote, a
// path — and none of them may be allowed to inject structure into the document.
type MarkdownRenderer struct{}

func (MarkdownRenderer) Format() config.Format { return config.FormatMarkdown }

func (r MarkdownRenderer) Write(w io.Writer, rep *models.Report) error {
	out := &mdWriter{w: w}

	out.raw("# Amina Operational Security Assessment")
	out.blank()
	out.kv("Host", hostLabel(rep))
	out.kv("Assessed", formatTime(rep.GeneratedAt))
	out.kv("Depth", rep.DepthName)
	if rep.DurationMS > 0 {
		out.kv("Duration", fmt.Sprintf("%d ms", rep.DurationMS))
	}
	out.kv("Report ID", rep.ID)
	out.kv("Integrity", "`"+rep.Integrity+"`")
	out.blank()

	// The summary table is the part that survives being quoted into a ticket,
	// so it is a table rather than prose.
	out.raw("## Summary")
	out.blank()
	out.raw("| Metric | Value |")
	out.raw("| --- | --- |")
	out.raw(fmt.Sprintf("| Findings | %d |", rep.Summary.Total))
	out.raw(fmt.Sprintf("| Scope assessed | %s depth |", rep.DepthName))
	out.raw(fmt.Sprintf("| Highest risk | %s (%d) |", strings.ToUpper(rep.Summary.RiskBand), rep.Summary.MaxRisk))
	out.raw(fmt.Sprintf("| Mean risk | %d |", rep.Summary.MeanRisk))
	out.raw(fmt.Sprintf("| Correlated findings | %d |", rep.Summary.Correlated))
	out.raw(fmt.Sprintf("| Operator identities | %d |", rep.Summary.IdentityCount))
	for _, sev := range []models.Severity{
		models.SeverityCritical, models.SeverityHigh, models.SeverityMedium,
		models.SeverityLow, models.SeverityInformational,
	} {
		if n := rep.Summary.BySeverity[sev]; n > 0 {
			out.raw(fmt.Sprintf("| %s severity | %d |", severityLabel(sev), n))
		}
	}
	out.blank()

	if len(rep.Limitations) > 0 {
		out.raw("## What this run did not see")
		out.blank()
		out.raw("A finding is only as good as the coverage behind it. The following were not fully assessed:")
		out.blank()
		for _, l := range rep.Limitations {
			out.raw("- " + l)
		}
		out.blank()
	}

	if len(rep.Identities) > 0 {
		out.raw("## Correlated operator identities")
		out.blank()
		out.raw("Signals from different modules that resolve to the same operator:")
		out.blank()
		out.raw("| Identity | Strength | Signals | Domains |")
		out.raw("| --- | --- | --- | --- |")
		for _, id := range rep.Identities {
			out.raw(fmt.Sprintf("| `%s` | %d | %d | %s |",
				mdEscape(id.Canonical), id.Strength, id.SignalCount, mdEscape(strings.Join(id.Domains, ", "))))
		}
		out.blank()
	}

	out.raw("## Findings")
	out.blank()
	if len(rep.Findings) == 0 {
		out.raw("No findings within the areas that were assessed.")
		out.blank()
	} else {
		for _, f := range rep.Findings {
			out.raw(fmt.Sprintf("### %s %s", severityLabel(f.Severity), mdEscape(f.Title)))
			out.blank()
			out.kv("Rule", fmt.Sprintf("`%s`", f.RuleID))
			out.kv("Module", fmt.Sprintf("`%s`", f.ModuleID))
			out.kv("Category", string(f.Category))
			out.kv("Risk", fmt.Sprintf("%d (%s)", f.RiskScore(), f.RiskBand()))
			out.kv("Confidence", string(f.Confidence))
			out.kv("State", string(f.State))
			out.kv("Exposure", string(f.Exposure))
			out.kv("Privilege", string(f.Privilege))
			out.kv("Sensitivity", string(f.Sensitivity))
			if len(f.Objects) > 0 {
				out.blank()
				out.raw("**Applies to**")
				out.blank()
				for _, o := range f.Objects {
					out.raw("- `" + mdEscapeCode(o) + "`")
				}
			}
			if f.Description != "" {
				out.blank()
				out.raw(mdEscape(f.Description))
			}
			if f.Impact != "" {
				out.blank()
				out.raw("**Impact.** " + mdEscape(f.Impact))
			}
			if f.Recommendation != "" {
				out.blank()
				out.raw("**Recommendation.** " + mdEscape(f.Recommendation))
			}
			if len(f.References) > 0 {
				out.blank()
				out.raw("**References.** " + mdEscape(strings.Join(f.References, ", ")))
			}
			out.blank()
		}
	}

	if len(rep.Secrets) > 0 {
		out.raw("## Secret material on disk")
		out.blank()
		out.raw("Values are not stored in this report. Each is recorded as a salted fingerprint.")
		out.blank()
		out.raw("| Type | Location | Field | Fingerprint | Length |")
		out.raw("| --- | --- | --- | --- | --- |")
		for _, s := range rep.Secrets {
			loc := s.Location
			if s.Line > 0 {
				loc = fmt.Sprintf("%s:%d", loc, s.Line)
			}
			out.raw(fmt.Sprintf("| %s | `%s` | `%s` | `%s` | %d |",
				string(s.Type), mdEscapeCode(loc), mdEscapeCode(s.Field), s.Fingerprint, s.Length))
		}
		out.blank()
	}

	if len(rep.Sources) > 0 {
		out.raw("## Package sources")
		out.blank()
		out.raw("| Provider | URI | Trust | Keys | Enabled |")
		out.raw("| --- | --- | --- | --- | --- |")
		for _, s := range rep.Sources {
			out.raw(fmt.Sprintf("| %s | `%s` | %s | %d | %t |",
				mdEscape(s.Provider), mdEscapeCode(s.URI), s.Trust, s.Keys, s.Enabled))
		}
		out.blank()
	}

	if len(rep.Modules) > 0 {
		out.raw("## Module coverage")
		out.blank()
		out.raw("| Module | Status | Assets | Findings | Detail |")
		out.raw("| --- | --- | --- | --- | --- |")
		for _, m := range rep.Modules {
			detail := m.Reason
			if len(m.Unavailable) > 0 {
				if detail != "" {
					detail += "; "
				}
				detail += "unavailable: " + strings.Join(m.Unavailable, ", ")
			}
			out.raw(fmt.Sprintf("| %s | %s | %d | %d | %s |",
				mdEscape(m.Name), m.Status, m.Assets, m.Findings, mdEscape(detail)))
		}
		out.blank()
	}

	out.raw("---")
	out.blank()
	out.raw(fmt.Sprintf("_Redaction: %s. %s_", rep.Redaction.Strategy, mdEscape(rep.Redaction.Note)))
	out.raw(fmt.Sprintf("_Generated by %s %s on %s._",
		mdEscape(rep.Framework), mdEscape(rep.FrameworkVersion), formatTime(rep.GeneratedAt)))

	if err := out.err; err != nil {
		return fmt.Errorf("write markdown report: %w", err)
	}
	return nil
}

// mdWriter accumulates the first write error.
type mdWriter struct {
	w   io.Writer
	err error
}

func (m *mdWriter) raw(s string) {
	if m.err != nil {
		return
	}
	_, m.err = io.WriteString(m.w, s+"\n")
}

func (m *mdWriter) blank() { m.raw("") }

// kv writes a definition-list entry. It is not a table row: the top block uses
// kv before any table exists, and a pipe-delimited line with no header row
// renders as a stray line rather than as a table.
func (m *mdWriter) kv(key, value string) {
	m.raw("- **" + key + ":** " + value)
}

// mdEscape neutralises the characters that would change a document's structure.
func mdEscape(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			b.WriteString("\\\\")
		case '`':
			b.WriteString("\\`")
		case '*':
			b.WriteString("\\*")
		case '_':
			b.WriteString("\\_")
		case '[':
			b.WriteString("\\[")
		case ']':
			b.WriteString("\\]")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '|':
			b.WriteString("\\|")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// mdEscapeCode escapes text destined for a code span, where the delimiter
// differs from the surrounding text's escaping rules.
func mdEscapeCode(s string) string {
	if s == "" {
		return ""
	}
	if strings.Contains(s, "`") {
		// A code span containing a backtick needs a longer delimiter.
		return "``" + strings.ReplaceAll(s, "`", "`` ` ``") + "``"
	}
	return strings.ReplaceAll(s, "|", "\\|")
}
