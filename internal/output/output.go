// Package output renders an assessment report.
//
// Five formats are supported, and the reason they share one model rather than
// five independent code paths is that they must never disagree. A finding that
// appears in the terminal output must appear in the HTML output and in the
// JSON, with the same severity and the same objects. When each format is
// written separately, they drift, and a tool that reports differently depending
// on how you ask it cannot be trusted with any of its answers.
//
// Every renderer here is a pure function of the report. That is what makes the
// determinism guarantee testable, and it is why none of them reads the clock,
// the environment or the filesystem.
package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/QYVORA/qyvora-amina/internal/config"
	"github.com/QYVORA/qyvora-amina/pkg/models"
)

// Renderer writes a report to a writer.
type Renderer interface {
	// Format is the name the renderer answers to.
	Format() config.Format
	// Write renders the report. It returns an error if the underlying writer
	// fails, so a full disk or a closed pipe is reported rather than swallowed.
	Write(w io.Writer, r *models.Report) error
}

// Writer is the destination a report is written to.
type Writer struct {
	// Path is where the report goes, or "-" for stdout.
	Path string
	// Format selects the renderer.
	Format config.Format
	// Color enables ANSI sequences. Only the terminal renderer honours it.
	Color bool
	// Stdout is where "-" goes. It is a field so tests can capture output
	// without touching the process's own stdout.
	Stdout io.Writer
}

// For returns the renderer for a format.
func For(f config.Format) (Renderer, bool) {
	switch f {
	case config.FormatTerminal:
		return TerminalRenderer{}, true
	case config.FormatJSON:
		return JSONRenderer{}, true
	case config.FormatYAML:
		return YAMLRenderer{}, true
	case config.FormatMarkdown:
		return MarkdownRenderer{}, true
	case config.FormatHTML:
		return HTMLRenderer{}, true
	}
	return nil, false
}

// FormatNames lists every supported format.
func FormatNames() string { return config.FormatNames() }

// Render writes a report in the given format.
func Render(w io.Writer, r *models.Report, format config.Format, color bool) error {
	renderer, ok := For(format)
	if !ok {
		return fmt.Errorf("no renderer for format %q", format)
	}
	return renderer.Write(w, r)
}

// humanBytes renders a byte count for humans.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// titleCase upper-cases the first letter of a string for headings.
func titleCase(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// sortedKeys returns a map's keys in sorted order.
//
// Every renderer that walks a map goes through this. Map iteration order in Go
// is randomised, so a renderer that ranged over a map directly would produce a
// different report on every run — which is precisely the failure the
// determinism guarantee exists to prevent.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// formatTime renders a timestamp in the report's standard form.
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// severityLabel gives a severity a readable name for the formats that have no
// colour to carry the distinction.
func severityLabel(s models.Severity) string {
	return titleCase(string(s))
}

// mustFormat is a test-only helper for the format table.
func mustFormat(s string) config.Format { f, _ := config.ValidFormat(s); return f }
