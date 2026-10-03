package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tui "github.com/QYVORA/qyvora-tui"

	"github.com/QYVORA/qyvora-amina/internal/config"
	"github.com/QYVORA/qyvora-amina/internal/exitcode"
	"github.com/QYVORA/qyvora-amina/internal/version"
	"github.com/QYVORA/qyvora-amina/pkg/modules"
)

// runCapabilities prints the capability registry.
//
// The registry is generated from the module table rather than maintained by
// hand. A hand-written list would drift: a module added to the framework and not
// to the registry is invisible in the interface, which is precisely the failure
// mode that makes a tool feel incomplete without anyone noticing why.
func runCapabilities(args []string) int {
	asJSON := false
	for _, a := range args {
		switch a {
		case "-o", "--output":
			// The next argument is the destination.
			continue
		case "json":
			asJSON = true
		case "-h", "--help":
			fmt.Println("usage: amina capabilities [-o json]")
			return exitcode.Success
		default:
			if strings.HasPrefix(a, "-o=") || strings.HasPrefix(a, "--output=") {
				asJSON = strings.Contains(a, "json")
			}
		}
	}
	// `-o json` in its separated form.
	for i, a := range args {
		if (a == "-o" || a == "--output") && i+1 < len(args) {
			asJSON = args[i+1] == "json"
		}
	}

	doc := Capabilities()
	if !asJSON {
		fmt.Printf("%s %s\n\n", version.Framework, version.Version)
		for _, e := range doc.Capabilities {
			// An entry that is not implemented is shown but not hidden. A
			// capability that silently disappears is indistinguishable from one
			// that was never built.
			mark := " "
			if !e.Implemented {
				mark = "-"
			}
			line := fmt.Sprintf("%s %-28s %s", mark, e.ID, e.Name)
			if e.Description != "" {
				line += "\n    " + e.Description
			}
			fmt.Println(line)
		}
		return exitcode.Success
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		fmt.Fprintf(os.Stderr, "amina: %v\n", err)
		return exitcode.Runtime
	}
	return exitcode.Success
}

// capabilityDocument is the machine-readable registry.
//
// The field names are part of the contract. Two things depend on them: the
// shared interface, which finds the capability list under "capabilities" and
// matches records carrying "id" and "name", and anything else that consumes
// `amina capabilities -o json`. Marshalling Go field names instead produced a
// document no reader recognised, and the symptom was an interface that opened
// with an empty capability list and no error to explain it.
type capabilityDocument struct {
	Tool         string             `json:"tool"`
	Framework    string             `json:"framework"`
	Version      string             `json:"version"`
	Capabilities []capabilityRecord `json:"capabilities"`
}

// capabilityRecord is one registry entry.
type capabilityRecord struct {
	ID                    string                `json:"id"`
	Name                  string                `json:"name"`
	Description           string                `json:"description"`
	Category              string                `json:"category"`
	Risk                  string                `json:"risk,omitempty"`
	AuthorizationRequired bool                  `json:"authorization_required"`
	ConfirmationRequired  bool                  `json:"confirmation_required"`
	Reversible            bool                  `json:"reversible"`
	ChangesState          bool                  `json:"changes_state"`
	Implemented           bool                  `json:"implemented"`
	TargetTypes           []string              `json:"target_types,omitempty"`
	Produces              []string              `json:"output_schema,omitempty"`
	ExpectedDuration      string                `json:"expected_duration,omitempty"`
	Input                 []capabilityParameter `json:"input,omitempty"`
}

// capabilityParameter describes one input a capability accepts.
type capabilityParameter struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Default     string `json:"default,omitempty"`
}

// Capabilities builds the registry the shared TUI and `capabilities -o json`
// both read.
//
// Every entry is generated from the module table rather than maintained by hand.
// A hand-written list would drift: a module added to the framework and not to
// the registry is invisible in the interface, which is precisely the failure
// mode that makes a tool feel incomplete without anyone noticing why.
//
// AuthorizationRequired is false for every assessment entry, which is the
// honest answer: the tool reads the machine it is already running on and asks
// nobody's permission to do it.
func Capabilities() *capabilityDocument {
	doc := &capabilityDocument{
		Tool:      version.Framework,
		Framework: version.Framework,
		Version:   version.Version,
	}

	for _, m := range modules.All() {
		doc.Capabilities = append(doc.Capabilities, capabilityRecord{
			ID:          "amina.assess." + m.ID,
			Name:        m.Name,
			Description: m.Purpose,
			Category:    "assessment",
			// Reversible is true and stated, not merely absent: an assessment
			// cannot be undone because it changes nothing.
			Reversible:       true,
			ChangesState:     false,
			Implemented:      m.Implemented(),
			TargetTypes:      []string{"host", "simulation"},
			Produces:         []string{"report"},
			ExpectedDuration: durationHint(m.MinimumDepth),
		})
	}

	// The simulation and self-update entry points are capabilities in their own
	// right: they are things an operator can ask for, not implementation
	// details of the assessment above.
	doc.Capabilities = append(doc.Capabilities,
		capabilityRecord{
			ID:           "amina.simulate.run",
			Name:         "Simulated assessment",
			Description:  "Run the identical rule set against the built-in synthetic dataset.",
			Category:     "assessment",
			Reversible:   true,
			ChangesState: false,
			Implemented:  true,
			TargetTypes:  []string{"simulation"},
			Produces:     []string{"report"},
			Input: []capabilityParameter{
				{Name: "fixture", Type: "string", Description: "Fixture name or path to a recorded snapshot", Default: "builtin"},
			},
		},
		capabilityRecord{
			ID:           "amina.selfupdate.apply",
			Name:         "Self-update",
			Description:  "Replace this binary from a checksum-verified release. The only operation that changes the host.",
			Category:     "maintenance",
			Risk:         "S2",
			Reversible:   false,
			ChangesState: true,
			// AuthorizationRequired and ConfirmationRequired are true here and
			// false everywhere else: this is the one capability that writes to
			// the machine, so the interface makes the operator look at it twice.
			AuthorizationRequired: true,
			ConfirmationRequired:  true,
			Implemented:           true,
			Produces:              []string{"binary"},
			Input: []capabilityParameter{
				{Name: "version", Type: "string", Description: "Release tag to install", Default: "latest"},
				{Name: "check", Type: "bool", Description: "Verify and report without installing", Default: "false"},
				{Name: "yes", Type: "bool", Description: "Skip the confirmation prompt", Default: "false"},
			},
		},
	)
	return doc
}

// durationHint gives the interface an honest estimate.
//
// No percentage is invented anywhere: a fabricated progress figure is worse than
// none, and a deep module genuinely takes longer than a quick one.
func durationHint(minDepth int) string {
	switch {
	case minDepth >= 3:
		return "slow"
	case minDepth == 2:
		return "moderate"
	default:
		return "fast"
	}
}

// runTUI launches the shared interactive interface.
//
// A non-terminal is not an error. Being piped is a normal way to run a tool, so
// the TUI falls back to a one-shot assessment that produces exactly the output
// the command line would have produced.
func runTUI(args []string) int {
	// The registry is normalised through the same function the TUI would use on
	// `amina capabilities -o json`, so there is no second hand-maintained list.
	//
	// The list is handed to CapabilitiesFrom rather than to NormalizeCapabilities
	// over an encoded document: this registry is already the tool's own shape,
	// and encoding it into a document only to decode it again is how a tool ends
	// up normalising something it already normalised.
	caps, err := tui.CapabilitiesFrom(version.Framework, Capabilities().Capabilities)
	if err != nil {
		fmt.Fprintf(os.Stderr, "amina: %v\n", err)
		return exitcode.Runtime
	}

	noColor := os.Getenv("NO_COLOR") != ""
	runner := &tui.InProcessRunner{
		Execute:   ExecuteArgs,
		ToolName:  version.Framework,
		Prefix:    []string{"assess"},
		EventFlag: "--events", EventValue: "stdout",
		Meta: commands(),
	}
	code, runErr := tui.Run(tui.Config{
		Runner:       runner,
		Title:        "QYVORA / " + strings.ToUpper(version.Framework),
		Version:      version.Version,
		NoColor:      noColor,
		Capabilities: caps,
	})
	if runErr != nil {
		if tui.IsNotInteractive(runErr) {
			// Not a terminal. Fall back rather than fail.
			return runAssess(context.Background(), args)
		}
		fmt.Fprintf(os.Stderr, "amina: %v\n", runErr)
		return exitcode.Runtime
	}
	return code
}

// commands describes the invocations the TUI offers.
//
// Subs are argument vectors, not usage strings: the TUI runs them verbatim, so
// this is a list of things a user can press rather than documentation.
func commands() []tui.Command {
	return []tui.Command{
		{Name: "assess", Short: "Assess this host"},
		{Name: "assess", Short: "Quick assessment", Subs: []string{"--depth", "quick"}},
		{Name: "assess", Short: "Deep assessment", Subs: []string{"--depth", "deep"}},
		{Name: "assess", Short: "Report as JSON", Subs: []string{"--format", "json"}},
		{Name: "assess", Short: "Report as Markdown", Subs: []string{"--format", "markdown", "-o", "report.md"}},
		{Name: "assess", Short: "Report as HTML", Subs: []string{"--format", "html", "-o", "report.html"}},
		{Name: "assess", Short: "Simulated assessment", Subs: []string{"--simulate"}},
		{Name: "capabilities", Short: "List assessment capabilities", Subs: []string{"-o", "json"}},
		{Name: "version", Short: "Print the version"},
	}
}

// exeDir is the directory containing the running executable.
func exeDir(exe string) string { return filepath.Dir(exe) }

// ensure the config import is used by the capabilities command's flag handling.
var _ = config.FormatNames
