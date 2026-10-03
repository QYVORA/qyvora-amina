package config

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
)

// FlagSet binds the command line to a Flags struct.
//
// The flags live here rather than in cmd/amina so that the flag names, the
// AMINA_* environment variables and the configuration-file keys cannot drift
// apart: they are the same vocabulary expressed three ways, and a second copy
// of the list is where that starts going wrong.
//
// Flags register with empty defaults. A flag that was not given must not
// overwrite a value from the file or the environment, so presence is recorded
// separately and precedence is decided in Resolve.
func FlagSet(flags *Flags) *flag.FlagSet {
	fs := flag.NewFlagSet("amina", flag.ContinueOnError)
	fs.Usage = func() { _, _ = fmt.Fprint(fs.Output(), flagUsage) }

	str := func(target *string, name, short, usage string) {
		if short != "" {
			fs.StringVar(target, short, "", usage)
			fs.Lookup(short).DefValue = ""
		}
		fs.StringVar(target, name, "", usage)
	}

	str(&flags.Depth, "depth", "", "assessment depth: quick, standard, deep, or a numeric level")
	str(&flags.Format, "format", "", "report format: terminal, json, yaml, markdown, html")
	str(&flags.Output, "output", "o", "write the report to this file instead of stdout")
	str(&flags.Target, "target", "", "target label recorded in the report")
	str(&flags.Profile, "profile", "", "operator profile recorded in the report")
	str(&flags.Include, "include", "", "comma-separated modules to run exclusively")
	str(&flags.Exclude, "exclude", "", "comma-separated modules to skip")
	str(&flags.MinSeverity, "min-severity", "", "omit findings below this severity")
	str(&flags.FailOn, "fail-on", "", "exit non-zero when a finding reaches this severity")
	str(&flags.Fixture, "fixture", "", "fixture to simulate, or a path to a recorded snapshot")
	str(&flags.ConfigPath, "config", "", "configuration file (default: discovered alongside the binary)")

	fs.BoolVar(&flags.Simulate, "simulate", false, "assess the synthetic dataset instead of this host")
	fs.BoolVar(&flags.Offline, "offline", false, "make no network access")
	fs.BoolVar(&flags.Remote, "remote", false, "assess a remote host over SSH (unsupported; always refused)")
	fs.IntVar(&flags.Timeout, "timeout", 0, "abort the assessment after this many seconds")
	fs.IntVar(&flags.Parallelism, "parallelism", 0, "concurrent collectors (0 selects a default)")

	// --events takes a destination rather than being a boolean. JSONL and the
	// report text cannot share a stream without corrupting both, so where the
	// events go is part of the flag's meaning: "stdout", "stderr", or a path.
	// A bare --events means stdout, which is what the shared TUI relies on.
	fs.Var(&eventsFlag{flags: flags}, "events", "emit JSONL events to stdout, stderr, or a file path")

	// --color and --no-color are booleans that also have to record that they
	// were given. A plain BoolVar cannot do that, and without the presence bit
	// an unset --color would overwrite a config file that asked for colour.
	fs.Var(boolFlag(func(v bool) { flags.Color = v; flags.ColorSet = true }),
		"color", "force colour output on")
	fs.Var(boolFlag(func(v bool) {
		flags.NoColor = v
		if v {
			flags.Color = false
			flags.ColorSet = true
		}
	}), "no-color", "force colour output off (NO_COLOR is always honoured)")

	return fs
}

// eventsFlag parses --events, which is either a bare flag or a destination.
//
// A bare "--events" reaches Set as the string "true" and a destination reaches
// it verbatim, so the distinction that matters is carried by the value itself
// rather than by a flag saying which form was used on the command line.
type eventsFlag struct {
	flags *Flags
}

func (e *eventsFlag) String() string { return "" }

func (e *eventsFlag) Set(v string) error {
	e.flags.Events = true
	e.flags.EventsSet = true
	v = strings.TrimSpace(v)
	if v == "" || v == "true" {
		// A bare --events means stdout, which is the convention the shared TUI
		// depends on when it captures the stream.
		e.flags.EventsOut = EventStreamStdout
		return nil
	}
	if v == "false" || v == EventStreamOff || v == "none" {
		// An explicit "no stream". The flag is still recorded as given, so this
		// is distinguishable from never having mentioned --events at all.
		e.flags.Events = false
		e.flags.EventsOut = ""
		return nil
	}
	if v != EventStreamStdout && v != EventStreamStderr && !strings.ContainsAny(v, "/\\.:") {
		return fmt.Errorf("--events: %q must be %q, %q, or a file path",
			v, EventStreamStdout, EventStreamStderr)
	}
	e.flags.EventsOut = v
	return nil
}

// IsBoolFlag is deliberately false.
//
// Returning true makes the flag package treat "-events" as a boolean that is
// implicitly true, so "-events stdout" parses as "-events" followed by a stray
// positional argument "stdout" and the destination is thrown away. NormalizeArgs
// rewrites a bare "--events" into "--events=stdout" beforehand, which keeps both
// spellings working without lying to the parser about the flag's arity.
func (e *eventsFlag) IsBoolFlag() bool { return false }

// NormalizeArgs rewrites the flags that have an optional value.
//
// Only --events has one. The flag package offers no way to express "a flag that
// may or may not take the next argument", so a bare "--events" is turned into
// "--events=stdout" here, before parsing. Anything that already carries a value,
// with "=" or as the next argument, is left alone.
//
// This has to run on the argument list rather than inside Set, because by the
// time Set is called the flag package has already decided where the arguments
// end.
func NormalizeArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]

		name := arg
		hasInlineValue := false
		if idx := strings.IndexByte(arg, '='); idx >= 0 && strings.HasPrefix(arg, "-") {
			name, hasInlineValue = arg[:idx], true
		}

		if name != "-events" && name != "--events" {
			out = append(out, arg)
			continue
		}
		if hasInlineValue {
			out = append(out, arg)
			continue
		}
		// A following argument is the destination, unless it is itself a flag.
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			out = append(out, arg+"="+args[i+1])
			i++
			continue
		}
		out = append(out, arg+"="+EventStreamStdout)
	}
	return out
}

// boolFlag is a boolean flag that also reports its own presence through a
// setter. The flag package calls Set for both "-flag" and "-flag=false".
type boolFlag func(bool)

func (b boolFlag) String() string { return "false" }

func (b boolFlag) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return fmt.Errorf("expected true or false, got %q", s)
	}
	b(v)
	return nil
}

// IsBoolFlag lets the flag be written without a value.
func (b boolFlag) IsBoolFlag() bool { return true }

const flagUsage = `usage: amina [assess] [flags]

  amina [assess] [flags]      assess this host and write a report
  amina tui                   interactive interface
  amina capabilities [-o json] print the capability registry
  amina version                print the version

Amina reads the host and reports what it found. It never modifies the host.

flags:
  --depth string          quick | standard | deep | numeric level
  --format string         terminal | json | yaml | markdown | html
  -o, --output string     write the report to a file instead of stdout
  --events string         JSONL events to stdout, stderr, or a file path
  --min-severity string   omit findings below this severity
  --fail-on string        exit non-zero when a finding reaches this severity
  --include strings       run only these modules
  --exclude strings       skip these modules
  --simulate              assess the built-in synthetic dataset
  --fixture string        fixture name or path to a recorded snapshot
  --color / --no-color    force colour on or off (NO_COLOR always wins)
  --timeout int           abort the assessment after N seconds
  --config string         configuration file
`
