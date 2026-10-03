package output_test

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/QYVORA/qyvora-amina/internal/config"
	"github.com/QYVORA/qyvora-amina/internal/output"
	"github.com/QYVORA/qyvora-amina/pkg/pipeline"
)

// update regenerates the committed reports instead of comparing against them.
//
//	go test ./internal/output/ -run Golden -update
//
// It is a flag rather than an environment variable so that regenerating the
// expectation is a visible, deliberate part of the test invocation.
var update = flag.Bool("update", false, "rewrite the golden reports")

// formats are the renderings Amina promises. Every one of them is pinned,
// because the point of a report format is that a consumer can rely on it: a
// field that quietly disappears from the JSON is a broken contract even when the
// terminal output still looks right.
var formats = []struct {
	name   string
	format config.Format
	file   string
}{
	{"terminal", config.FormatTerminal, "report.terminal.txt"},
	{"json", config.FormatJSON, "report.json"},
	{"yaml", config.FormatYAML, "report.yaml"},
	{"markdown", config.FormatMarkdown, "report.markdown"},
	{"html", config.FormatHTML, "report.html"},
}

func TestGoldenReports(t *testing.T) {
	for _, tc := range formats {
		t.Run(tc.name, func(t *testing.T) {
			got := render(t, tc.format)

			path := filepath.Join("..", "..", "testdata", "golden", tc.file)
			if *update {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				t.Logf("wrote %s (%d bytes)", path, len(got))
				return
			}

			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden report: %v (run: go test ./internal/output/ -run Golden -update)", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s output does not match %s\n\n%s", tc.name, tc.file, firstDiff(want, got))
			}
		})
	}
}

// render produces one format's bytes from the built-in dataset.
func render(t *testing.T, format config.Format) []byte {
	t.Helper()

	cfg := config.Default()
	cfg.Simulate = true
	cfg.Fixture = "builtin"
	cfg.Format = format

	res, err := pipeline.New(pipeline.Options{Config: cfg}).Run(context.Background())
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}
	rep := res.Report

	// Wall-clock duration is the one field that cannot be reproduced, because it
	// measures the machine rather than the data. It is zeroed so the expectation
	// describes the report's content rather than the speed of the machine that
	// happened to generate it. Nothing else in the report varies: the collection
	// timestamp comes from the fixture, the identifiers are derived from content,
	// and the ordering is total.
	//
	// Zeroing is not a way of hiding a regression. If the rule set changes, the
	// findings change and the diff below says so immediately.
	rep.DurationMS = 0

	var buf bytes.Buffer
	if err := output.Render(&buf, rep, format, false); err != nil {
		t.Fatalf("render %s: %v", format, err)
	}
	return buf.Bytes()
}

// firstDiff reports where two renderings parted company.
//
// A byte-count mismatch alone is not enough to act on. The point of a golden
// test is to tell you what changed, and "line 214" saves the reader from
// diffing 15k characters by eye.
func firstDiff(want, got []byte) string {
	wl := splitLines(want)
	gl := splitLines(got)
	for i := 0; i < len(wl) || i < len(gl); i++ {
		var w, g string
		if i < len(wl) {
			w = wl[i]
		}
		if i < len(gl) {
			g = gl[i]
		}
		if w != g {
			return "line " + itoa(i+1) + ":\n  want: " + truncate(w) + "\n  got:  " + truncate(g)
		}
	}
	return "outputs differ only in trailing content: " +
		itoa(len(want)) + " vs " + itoa(len(got)) + " bytes"
}

func splitLines(b []byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == '\n' {
			out = append(out, string(b[start:i]))
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, string(b[start:]))
	}
	return out
}

func truncate(s string) string {
	const max = 160
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
