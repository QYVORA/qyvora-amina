package output

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/QYVORA/qyvora-amina/internal/config"
	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// TerminalRenderer writes the human-readable report.
//
// The layout is designed around one judgement: an operator running an
// operational-security assessment on their own machine is looking for three
// things, in this order — what did this find, what did it not look at, and what
// can I do about it. Everything else in the report is supporting detail.
//
// So the terminal output leads with the findings, states the limitations
// immediately after them rather than at the bottom, and never prints a wall of
// data before the reader has seen either.
type TerminalRenderer struct {
	// Color enables ANSI sequences.
	Color bool
	// Width is the terminal width for wrapping. Zero means no wrapping, which
	// is what a non-terminal consumer of this renderer wants.
	Width int
}

func (TerminalRenderer) Format() config.Format { return config.FormatTerminal }

func (r TerminalRenderer) Write(w io.Writer, rep *models.Report) error {
	p := &palette{enabled: r.Color}
	out := &errWriter{w: w}

	out.line(p.bold("Amina ") + p.dim("operational security assessment"))
	out.line(p.dim(strings.Repeat("─", 60)))
	out.kv("Host", hostLabel(rep))
	out.kv("Assessed", formatTime(rep.GeneratedAt))
	out.kv("Depth", rep.DepthName)
	if rep.DurationMS > 0 {
		out.kv("Duration", fmt.Sprintf("%d ms", rep.DurationMS))
	}
	if rep.Target.Type.Offline() {
		out.kv("Mode", string(rep.Target.Type)+" — no live host was read for this report")
	}
	out.blank()
	r.summary(out, p, rep)

	if len(rep.Limitations) > 0 {
		out.blank()
		out.line(p.bold("What this run did not see"))
		for _, l := range rep.Limitations {
			out.line("  " + p.yellow("!") + " " + l)
		}
	}

	if len(rep.Identities) > 0 {
		out.blank()
		r.identities(out, p, rep)
	}

	if len(rep.Findings) > 0 {
		out.blank()
		r.findings(out, p, rep)
	} else {
		out.blank()
		out.line(p.green("No findings within the areas that were assessed.") +
			p.dim(" See the coverage section below for what was not examined."))
	}

	if len(rep.Secrets) > 0 {
		out.blank()
		r.secrets(out, p, rep)
	}

	if len(rep.Modules) > 0 {
		out.blank()
		r.modules(out, p, rep)
	}

	out.blank()
	out.line(p.dim(fmt.Sprintf("report %s  ·  integrity %s  ·  no secret values are stored in this report",
		rep.ID, short(rep.Integrity))))
	if len(rep.Configuration) > 0 {
		out.line(p.dim("configuration: " + configLine(rep.Configuration)))
	}
	if err := out.err; err != nil {
		return fmt.Errorf("write terminal report: %w", err)
	}
	return nil
}

func (r TerminalRenderer) summary(out *errWriter, p *palette, rep *models.Report) {
	s := rep.Summary
	out.line(p.bold("Summary") + "  " +
		p.bold(itoa(s.Total)) + " " + plural(s.Total, "finding", "findings") +
		p.dim(fmt.Sprintf("  ·  highest risk %s (%d)  ·  mean %d",
			strings.ToUpper(s.RiskBand), s.MaxRisk, s.MeanRisk)))

	if len(s.BySeverity) > 0 {
		// Fixed severity order rather than map order: a summary that reshuffles
		// itself between runs is one nobody learns to read.
		var parts []string
		for _, sev := range []models.Severity{
			models.SeverityCritical, models.SeverityHigh, models.SeverityMedium,
			models.SeverityLow, models.SeverityInformational,
		} {
			if n := s.BySeverity[sev]; n > 0 {
				parts = append(parts, p.severity(sev)+" "+severityLabel(sev)+" "+p.bold(itoa(n)))
			}
		}
		out.line("  " + strings.Join(parts, p.dim("  ·  ")))
	}
	if s.Correlated > 0 {
		out.line("  " + p.dim(fmt.Sprintf("%d correlated across %d operator identities", s.Correlated, s.IdentityCount)))
	}
}

func (r TerminalRenderer) findings(out *errWriter, p *palette, rep *models.Report) {
	out.line(p.bold("Findings"))

	// Grouped by severity so the reader sees the worst first as a block, then
	// each finding with what it applies to and what to do about it.
	for _, sev := range []models.Severity{
		models.SeverityCritical, models.SeverityHigh, models.SeverityMedium,
		models.SeverityLow, models.SeverityInformational,
	} {
		var group []models.Finding
		for _, f := range rep.Findings {
			if f.Severity == sev {
				group = append(group, f)
			}
		}
		if len(group) == 0 {
			continue
		}
		out.blank()
		out.line(p.severity(sev) + p.bold(severityLabel(sev)) +
			p.dim(fmt.Sprintf("  (%d)", len(group))))
		for _, f := range group {
			out.line("  " + p.bold(f.Title))
			out.line("    " + p.dim(fmt.Sprintf("%s · %s · risk %d (%s) · %s",
				f.RuleID, f.ModuleID, f.RiskScore(), f.RiskBand(), f.State)))
			if len(f.Objects) > 0 {
				for i, o := range f.Objects {
					if i >= 5 {
						out.line("    " + p.dim(fmt.Sprintf("… and %d more", len(f.Objects)-5)))
						break
					}
					out.line("    " + p.dim("· ") + o)
				}
			}
			if f.Impact != "" {
				out.line("    " + p.dim("impact: ") + f.Impact)
			}
			if f.Recommendation != "" {
				out.line("    " + p.dim("fix: ") + f.Recommendation)
			}
		}
	}
}

func (r TerminalRenderer) identities(out *errWriter, p *palette, rep *models.Report) {
	out.line(p.bold("Correlated operator identities"))
	for _, id := range rep.Identities {
		out.line("  " + p.bold(id.Canonical) +
			p.dim(fmt.Sprintf("  strength %d · %d %s from %s", id.Strength, id.SignalCount,
				plural(id.SignalCount, "signal", "signals"), strings.Join(id.Domains, ", "))))
		if id.Summary != "" {
			out.line("    " + p.dim(id.Summary))
		}
	}
}

func (r TerminalRenderer) secrets(out *errWriter, p *palette, rep *models.Report) {
	out.line(p.bold("Secret material on disk") + " " +
		p.dim(fmt.Sprintf("(%d found, values not read into this report)", len(rep.Secrets))))
	byType := map[models.SecretType][]models.SecretRecord{}
	for _, s := range rep.Secrets {
		byType[s.Type] = append(byType[s.Type], s)
	}
	types := make([]models.SecretType, 0, len(byType))
	for t := range byType {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })
	for _, t := range types {
		records := byType[t]
		out.line("  " + p.bold(string(t)) + p.dim(fmt.Sprintf("  %d", len(records))))
		for i, s := range records {
			if i >= 5 {
				out.line("    " + p.dim(fmt.Sprintf("… and %d more", len(records)-5)))
				break
			}
			out.line("    " + s.Location + p.dim(fmt.Sprintf("  %s… %d bytes", s.Fingerprint, s.Length)))
		}
	}
}

func (r TerminalRenderer) modules(out *errWriter, p *palette, rep *models.Report) {
	out.line(p.bold("Module coverage") + " " + p.dim("(a module that did not run is reported, not hidden)"))

	// The report's module order is the registry order; the terminal shows them
	// grouped by status because "what did not run" is the question a reader
	// arrives at.
	byStatus := map[models.ExposureLevel][]models.ModuleStatus{}
	var order []models.ExposureLevel
	for _, m := range rep.Modules {
		if _, seen := byStatus[m.Status]; !seen {
			order = append(order, m.Status)
		}
		byStatus[m.Status] = append(byStatus[m.Status], m)
	}
	sort.SliceStable(order, func(i, j int) bool { return statusRank(order[i]) > statusRank(order[j]) })

	for _, st := range order {
		items := byStatus[st]
		out.line("  " + statusLabel(p, st) + p.dim(fmt.Sprintf("  %d", len(items))))
		for _, m := range items {
			detail := ""
			if len(m.Unavailable) > 0 {
				detail = p.dim("  missing: " + strings.Join(m.Unavailable, ", "))
			} else if m.Reason != "" {
				detail = p.dim("  " + m.Reason)
			}
			out.line("    " + m.Name + p.dim(fmt.Sprintf("  %s · %d %s · %d %s",
				m.ID, m.Assets, plural(m.Assets, "asset", "assets"),
				m.Findings, plural(m.Findings, "finding", "findings"))) + detail)
		}
	}
}

func statusRank(s models.ExposureLevel) int {
	switch s {
	case models.ExposureComplete:
		return 0
	case models.ExposurePartial:
		return 1
	case models.ExposureDegraded:
		return 2
	case models.ExposurePrivilege:
		return 3
	case models.ExposureSkipped:
		return 4
	}
	return -1
}

func statusLabel(p *palette, s models.ExposureLevel) string {
	switch s {
	case models.ExposureComplete:
		return p.green("● ") + "complete"
	case models.ExposurePartial:
		return p.yellow("◐ ") + "partial"
	case models.ExposureDegraded:
		return p.yellow("◑ ") + "degraded"
	case models.ExposurePrivilege:
		return p.red("○ ") + "needs privileges"
	case models.ExposureSkipped:
		return p.dim("– ") + "not assessed"
	}
	return string(s)
}

func hostLabel(rep *models.Report) string {
	name := rep.Target.DisplayName()
	if rep.Host != nil {
		if rep.Host.Hostname != "" && !strings.Contains(name, rep.Host.Hostname) {
			name += " (" + rep.Host.Hostname + ")"
		}
		if rep.Host.Platform != "" {
			name += " · " + rep.Host.Platform
		}
	}
	return name
}

func configLine(m map[string]string) string {
	keys := sortedKeys(m)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+m[k])
	}
	return strings.Join(parts, " ")
}

// errWriter accumulates the first write error so the renderers can check once at
// the end instead of after every line.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) line(s string) {
	if e.err != nil {
		return
	}
	_, e.err = io.WriteString(e.w, s+"\n")
}

func (e *errWriter) blank() { e.line("") }

func (e *errWriter) kv(key, value string) { e.line("  " + key + ": " + value) }

// palette emits ANSI sequences, or nothing when colour is disabled.
//
// Colour is a field-level switch rather than a global, because a single report
// must be printable both to a terminal and to a file, and because NO_COLOR must
// be able to suppress it without the caller having to re-render.
type palette struct {
	enabled bool
}

func (p palette) wrap(code, s string) string {
	if !p.enabled || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p palette) bold(s string) string   { return p.wrap("1", s) }
func (p palette) dim(s string) string    { return p.wrap("2", s) }
func (p palette) red(s string) string    { return p.wrap("31", s) }
func (p palette) green(s string) string  { return p.wrap("32", s) }
func (p palette) yellow(s string) string { return p.wrap("33", s) }

func (p palette) severity(s models.Severity) string {
	switch s {
	case models.SeverityCritical:
		return p.red("▲")
	case models.SeverityHigh:
		return p.red("▲")
	case models.SeverityMedium:
		return p.yellow("▲")
	case models.SeverityLow:
		return p.dim("▲")
	}
	return p.dim("·")
}

func short(s string) string {
	s = strings.TrimPrefix(s, "sha256:")
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// plural picks the singular or plural form for a count.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
