// Command amina assesses the operational security posture of the local host.
//
// Amina is read-only. It reads, it reports, and it exits. The only thing it
// will ever change on the host is its own binary, and only when explicitly
// asked to update itself against a checksum-verified release.
//
// Exit codes follow the shared QYVORA contract:
//
//	0   the assessment completed
//	1   a runtime failure prevented the assessment
//	2   the command line was wrong
//	3   a requested capability does not exist on this platform
//	130 interrupted
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/QYVORA/qyvora-amina/internal/config"
	"github.com/QYVORA/qyvora-amina/internal/events"
	"github.com/QYVORA/qyvora-amina/internal/exitcode"
	"github.com/QYVORA/qyvora-amina/internal/output"
	"github.com/QYVORA/qyvora-amina/internal/version"
	"github.com/QYVORA/qyvora-amina/pkg/models"
	"github.com/QYVORA/qyvora-amina/pkg/modules"
	"github.com/QYVORA/qyvora-amina/pkg/pipeline"
)

// init installs the module registry's name validator.
//
// This is an init rather than a line in main because ExecuteArgs is not only
// the command line: it is the in-process entry point the shared TUI calls, and
// the TUI has its own ways to reach the same flags. Validating in one place that
// every entry point passes through is what keeps a misspelled --include a usage
// error everywhere instead of only on the terminal.
func init() {
	config.SetModuleLookup(modules.IsKnown)
}

func main() {
	// Ctrl+C is handled inside ExecuteArgs so that an interrupted run exits 130
	// rather than dying on the default signal behaviour.
	os.Exit(ExecuteArgs(context.Background(), os.Args[1:]))
}

// ExecuteArgs runs one invocation and returns the process exit code.
//
// It is the in-process entry point the shared TUI calls. Keeping the whole CLI
// behind this function is what lets `amina tui` execute assessments in-process
// while the same code path serves a plain command line.
func ExecuteArgs(ctx context.Context, args []string) int {
	if len(args) == 0 {
		// No arguments at all is the fleet's "let me look around" invocation.
		// Without a terminal it is a plain assessment, so `amina > report.txt`
		// still produces a report rather than a screenful of escape codes.
		if isTerminal(os.Stdout) {
			return runTUI(nil)
		}
		return runAssess(ctx, nil)
	}

	switch args[0] {
	case "help", "-h", "--help":
		usage(os.Stdout)
		return exitcode.Success
	case "version", "--version", "-V":
		return runVersion(args[1:])
	case "capabilities":
		return runCapabilities(args[1:])
	case "update":
		return runUpdate(ctx, args[1:])
	case "tui":
		return runTUI(args[1:])
	case "assess", "scan", "report":
		return runAssess(ctx, args[1:])
	default:
		if strings.HasPrefix(args[0], "-") {
			return runMaybeTUI(ctx, args)
		}
		fmt.Fprintf(os.Stderr, "amina: unknown command %q\n\n", args[0])
		usage(os.Stderr)
		return exitcode.Usage
	}
}

// runMaybeTUI decides between the interactive session and a one-shot assessment
// for an invocation that names no subcommand.
//
// A bare `amina` on a terminal opens the interactive session. That is the
// convention across the QYVORA fleet, and it is the right default here: the
// report is the answer, and the session is the faster route to it.
//
// Machine output has to be asked for explicitly, because it cannot be inferred
// from a terminal: `--format json`, `-o file`, `--simulate` or `--fixture` all
// say "give me the report, not a screen". Everything else on a terminal opens
// the session, where the same flags are available per command.
//
// When stdout is not a terminal this is an assessment and never a session.
// Drawing a full-screen interface into a pipe fills it with escape codes and
// destroys the machine-readable output the tool exists to produce.
func runMaybeTUI(ctx context.Context, args []string) int {
	if !isTerminal(os.Stdout) {
		return runAssess(ctx, args)
	}

	// A machine event destination and the session are contradictory: one screen
	// cannot hand the same bytes to a renderer and to a file. The destination
	// used to be accepted and silently ignored, so `--events out.jsonl` opened
	// a session and wrote no file.
	//
	// This is checked before anything opens the destination. Refusing after
	// opening it would leave an empty file behind, and would truncate the
	// previous run's events.
	if dest, asked := requestedEventsDestination(args); asked {
		if config.EventsDisabled(dest) {
			return runTUI(args)
		}
		fmt.Fprintf(os.Stderr,
			"amina: cannot open the interactive session with a machine event destination (--events %s); "+
				"the session transcript is already its event stream. "+
				"Run a command for machine output, or drop --events to use the session.\n", dest)
		return exitcode.Usage
	}

	if requestsMachineOutput(args) {
		return runAssess(ctx, args)
	}
	return runTUI(args)
}

// requestsMachineOutput reports whether args ask for a report rather than a
// session.
func requestsMachineOutput(args []string) bool {
	for i := 0; i < len(args); i++ {
		name, value, hasValue := strings.Cut(args[i], "=")

		switch name {
		case "--simulate", "--fixture":
			return true
		case "-o", "--output":
			// A bare -o is still an explicit request for a file.
			return true
		case "--format", "-f":
			if hasValue {
				if value != "" && value != string(config.FormatTerminal) {
					return true
				}
				continue
			}
			if i+1 < len(args) && args[i+1] != string(config.FormatTerminal) {
				return true
			}
			i++
		}
	}
	return false
}

// requestedEventsDestination finds the value given to --events, and whether the
// flag was given at all.
//
// The flag must have been asked for rather than merely being set: --events off
// means no stream and is a perfectly ordinary interactive run.
func requestedEventsDestination(args []string) (string, bool) {
	for i := 0; i < len(args); i++ {
		name, value, hasValue := strings.Cut(args[i], "=")
		if name != "--events" && name != "-events" {
			continue
		}
		if hasValue {
			return value, true
		}
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			return args[i+1], true
		}
		return config.EventStreamStdout, true
	}
	return "", false
}

// runVersion prints the build identity.
//
// Plain `amina version` prints one line for a human; `--format json` prints the
// full identity.
//
// Both --format and -o select the format here. They are the same thing in this
// position because the shared QYVORA contract asks every tool for
// `version -o json`, and an orchestrator that has to know which of the two
// spellings a given tool honours is not a contract. The report's -o names a
// file; nothing is written to a file from `version`, so there is no ambiguity to
// resolve here.
func runVersion(args []string) int {
	var format string
	fs := flag.NewFlagSet("amina version", flag.ContinueOnError)
	fs.StringVar(&format, "format", "", "version format: text (default) or json")
	fs.StringVar(&format, "f", "", "shorthand for --format")
	fs.StringVar(&format, "output", "", "shorthand for --format, matching the shared contract")
	fs.StringVar(&format, "o", "", "shorthand for --format, matching the shared contract")
	if err := fs.Parse(args); err != nil {
		return exitcode.Usage
	}
	if rest := fs.Args(); len(rest) > 0 {
		fmt.Fprintf(os.Stderr, "amina version: unexpected argument %q\n", rest[0])
		return exitcode.Usage
	}

	switch format {
	case "", "text", "plain":
		_, _ = fmt.Fprintln(os.Stdout, version.String())
		return exitcode.Success
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(version.GetInfo()); err != nil {
			fmt.Fprintf(os.Stderr, "amina version: %v\n", err)
			return exitcode.Runtime
		}
		return exitcode.Success
	default:
		fmt.Fprintf(os.Stderr, "amina version: unknown format %q; use text or json\n", format)
		return exitcode.Usage
	}
}

// runAssess is the whole product.
func runAssess(ctx context.Context, args []string) int {
	flags := config.Flags{}
	fs := config.FlagSet(&flags)
	if err := fs.Parse(config.NormalizeArgs(args)); err != nil {
		fmt.Fprintf(os.Stderr, "amina: %v\n", err)
		return exitcode.Usage
	}
	if rest := fs.Args(); len(rest) > 0 {
		fmt.Fprintf(os.Stderr, "amina: unexpected argument %q\n", rest[0])
		return exitcode.Usage
	}

	// The configuration file is optional and its absence is not an error; an
	// unreadable file that was explicitly requested is.
	filePath := flags.ConfigPath
	if filePath == "" {
		if found, err := config.Discover(binaryDir()); err == nil {
			filePath = found
		}
	}
	var file config.File
	if filePath != "" {
		loaded, err := config.Load(filePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "amina: %v\n", err)
			return exitcode.Usage
		}
		file = loaded
	} else if flags.ConfigPath != "" {
		fmt.Fprintf(os.Stderr, "amina: config file %s not found\n", flags.ConfigPath)
		return exitcode.Usage
	}

	cfg, err := config.Resolve(flags, file, filePath, config.FromEnviron())
	if err != nil {
		fmt.Fprintf(os.Stderr, "amina: %v\n", err)
		return exitcode.Usage
	}

	// Event routing is decided before anything is collected. With events on
	// stdout, the report moves to stderr so that stdout stays parseable JSONL.
	// The two cannot share a stream without corrupting both.
	var (
		stream   *events.Stream
		reportTo = os.Stdout
	)
	if cfg.Events {
		// The two streams cannot share one file descriptor. When events take
		// stdout the report moves to stderr, so `amina --events stdout` stays
		// fully machine-parseable.
		if cfg.EventsOut == config.EventStreamStdout {
			reportTo = os.Stderr
		}
		stream = events.NewStream(eventsDestination(cfg.EventsOut))
	}

	// A remote target is unsupported, not a usage error. The command line was
	// perfectly valid; the platform simply cannot do this, which is exactly
	// what exit code 3 means.
	if cfg.Remote {
		fmt.Fprintf(os.Stderr, "amina: %v\n", pipeline.ErrRemoteUnsupported)
		return exitcode.Unsupported
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	if timeout := time.Duration(cfg.TimeoutSeconds) * time.Second; timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	pipe := pipeline.New(pipeline.Options{Config: cfg, Events: stream})
	res, err := pipe.Run(ctx)
	if err != nil {
		if errors.Is(err, pipeline.ErrRemoteUnsupported) {
			fmt.Fprintf(os.Stderr, "amina: %v\n", err)
			return exitcode.Unsupported
		}
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "amina: interrupted")
			return exitcode.Interrupted
		}
		if errors.Is(err, context.DeadlineExceeded) {
			fmt.Fprintf(os.Stderr, "amina: assessment exceeded %ds\n", cfg.TimeoutSeconds)
			return exitcode.Runtime
		}
		fmt.Fprintf(os.Stderr, "amina: %v\n", err)
		return exitcode.Runtime
	}

	// A module that failed is reported in the report's limitations, and echoed
	// here so an operator watching the terminal is not left with a report that
	// silently omits a domain.
	for id, mErr := range res.Errors {
		fmt.Fprintf(os.Stderr, "amina: module %s: %v\n", id, mErr)
	}

	rep := res.Report
	rep.DurationMS = res.Elapsed.Milliseconds()

	if err := writeReport(rep, cfg, reportTo); err != nil {
		fmt.Fprintf(os.Stderr, "amina: %v\n", err)
		return exitcode.Runtime
	}

	return failOn(rep, cfg.FailOn)
}

// writeReport renders the report to its destination.
//
// -o is the report's destination; the events stream has its own. A report file
// is created with 0600 because it names accounts, paths and secret locations, so
// a world-readable assessment file would itself be the finding this tool exists
// to report.
func writeReport(rep *models.Report, cfg config.Config, to *os.File) error {
	colour := useColour(cfg)

	// "-" is the conventional spelling for stdout, and it is the default, so it
	// must not be mistaken for a file named "-".
	//
	// The decision is made from the configured path alone. It must not depend on
	// which stream `to` happens to be: when --events takes stdout the report is
	// pushed onto stderr, and keying off the stream would silently ignore -o and
	// dump the report into the event stream's companion output instead of the
	// file the operator asked for.
	if path := strings.TrimSpace(cfg.Output); path != "" && path != "-" {
		return writeReportFile(rep, cfg, path)
	}

	if err := output.Render(to, rep, cfg.Format, colour); err != nil {
		return err
	}
	if colour && cfg.Format == config.FormatTerminal {
		_, _ = fmt.Fprintln(to)
	}
	return nil
}

// writeReportFile writes the report to a path.
func writeReportFile(rep *models.Report, cfg config.Config, path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open report file: %w", err)
	}
	defer func() { _ = f.Close() }()
	// Colour is never written to a file: an escape sequence inside a saved
	// report is noise in every reader that will ever open it.
	if err := output.Render(f, rep, cfg.Format, false); err != nil {
		return err
	}
	_, err = fmt.Fprintf(os.Stderr, "amina: report written to %s\n", path)
	return err
}

// failOn applies the CI gate.
//
// The comparison is "at or above" the configured severity, and it defaults to
// never failing. A tool that exits non-zero on findings by default turns every
// pipeline into a red build and gets switched off within a week.
func failOn(rep *models.Report, threshold models.Severity) int {
	if threshold == "" {
		return exitcode.Success
	}
	for _, f := range rep.Findings {
		if f.Severity.Rank() >= threshold.Rank() {
			return exitcode.Runtime
		}
	}
	return exitcode.Success
}

// eventsDestination resolves --events to a stream.
func eventsDestination(dest string) *os.File {
	switch dest {
	case "", config.EventStreamStdout:
		return os.Stdout
	case config.EventStreamStderr:
		return os.Stderr
	default:
		f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return os.Stderr
		}
		return f
	}
}

// useColour decides whether to emit ANSI colour.
//
// NO_COLOR wins over everything, then an explicit flag, then whether stdout is
// actually a terminal. The last of those is what stops escape codes from ending
// up in a piped log.
func useColour(cfg config.Config) bool {
	if cfg.NoColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	if cfg.Color {
		return true
	}
	if !isTerminal(os.Stdout) {
		return false
	}
	return true
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// binaryDir is the directory the executable lives in, used to find a config file
// shipped alongside it.
func binaryDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return exeDir(exe)
}

var _ = config.FormatNames

func usage(w *os.File) {
	_, _ = fmt.Fprint(w, `amina — operational security assessment for the local host

USAGE
  amina [assess] [flags]
  amina tui
  amina capabilities [-o json]
  amina update [flags]
  amina version

Amina reads the host and reports what it found. It never modifies the host.

FLAGS
  --depth string          quick | standard | deep | numeric level (default "standard")
  --format string         terminal | json | yaml | markdown | html (default "terminal")
  -o, --output string     write the report to a file instead of stdout
  --target string         label recorded in the report
  --profile string        operator profile recorded in the report
  --events string         JSONL event stream: stdout, stderr, or a file path
  --min-severity string   omit findings below this severity
  --fail-on string        exit non-zero when a finding reaches this severity
  --include string        comma-separated modules to run only
  --exclude string        comma-separated modules to skip
  --simulate              assess the built-in synthetic dataset instead of this host
  --fixture string        fixture to simulate, or a path to a recorded snapshot
  --offline               make no network access
  --parallelism int       concurrent collectors (0 selects a default)
  --remote                assess a remote host (unsupported; always refused)
  --color / --no-color    force colour on or off (NO_COLOR is always honoured)
  --timeout int           abort the assessment after N seconds
  --config string         configuration file (default: discovered alongside the binary)
  --version               print the version

EXIT CODES
  0 success   1 runtime failure   2 usage error   3 unsupported   130 interrupted
`)
}
