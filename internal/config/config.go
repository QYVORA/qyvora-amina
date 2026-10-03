// Package config resolves the settings a run uses.
//
// The precedence is fixed and stated in one place because getting it wrong is
// how a security tool surprises its operator: defaults, then the config file,
// then environment variables, then command-line flags, with the last source
// winning. That order means a flag always beats a file, so an operator who
// passes a flag can rely on it, and a file can override a shipped default
// without anyone editing the binary.
//
// Nothing here reaches the network and nothing here writes to the host.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/QYVORA/qyvora-amina/internal/platform"
	"github.com/QYVORA/qyvora-amina/pkg/models"
	"github.com/QYVORA/qyvora-amina/pkg/rules"
	"github.com/QYVORA/qyvora-amina/pkg/simulation"
)

// Format is a report rendering format.
type Format string

const (
	FormatTerminal Format = "terminal"
	FormatJSON     Format = "json"
	FormatYAML     Format = "yaml"
	FormatMarkdown Format = "markdown"
	FormatHTML     Format = "html"
)

// Formats lists every supported output format.
var Formats = []Format{
	FormatTerminal, FormatJSON, FormatYAML, FormatMarkdown, FormatHTML,
}

// ValidFormat reports whether a string names a supported format.
func ValidFormat(s string) (Format, bool) {
	for _, f := range Formats {
		if string(f) == s {
			return f, true
		}
	}
	return "", false
}

// Config is the resolved configuration of one run.
type Config struct {
	// Depth is the scan depth: quick, standard or deep.
	Depth int
	// Format is the report format written to Output.
	Format Format
	// Output is the report destination. "-" means stdout. A terminal report
	// cannot be written to a file, because it contains colour and cursor
	// control; that is reported rather than silently degraded.
	Output string
	// Events enables the JSONL progress stream.
	Events bool
	// EventsOut is where the stream goes: EventStreamStdout, EventStreamStderr,
	// or a file path. The JSONL stream and the report text cannot share a
	// stream, so the destination is part of the configuration rather than an
	// implicit consequence of enabling events.
	EventsOut string
	// Color requests colour even when stdout is not a terminal.
	Color bool
	// NoColor disables colour and is set by NO_COLOR.
	NoColor bool
	// Target names the host to assess. Empty means this host.
	Target string
	// Remote marks a non-local assessment.
	Remote bool
	// Profile narrows the rule set; empty means everything.
	Profile string
	// Include and Exclude are module ID filters.
	Include []string
	Exclude []string
	// MinSeverity suppresses findings below a severity.
	MinSeverity models.Severity
	// FailOn makes the run exit non-zero when findings reach a severity.
	FailOn models.Severity
	// Simulate runs against a fixture instead of this host.
	Simulate bool
	// Fixture is the simulation fixture path.
	Fixture string
	// Offline refuses any network access, including self-update.
	Offline bool
	// OutputDir is where multiple reports are written when --output names a
	// directory.
	OutputDir string
	// TimeoutSeconds bounds the whole run. Zero means no bound, which is the
	// correct default for a local read-only scan and the wrong one for a
	// pipeline that must not hang.
	TimeoutSeconds int
	// Parallelism bounds concurrent module execution.
	Parallelism int
	// ConfigPath records where the configuration was loaded from, if anywhere.
	ConfigPath string
	// Source records, per setting, which layer supplied the value. A report
	// includes this so an operator can see why the run behaved as it did.
	Source map[string]string
}

// Default returns the configuration used when nothing else is specified.
func Default() Config {
	return Config{
		Depth:       rules.DepthStandard,
		Format:      FormatTerminal,
		Output:      "-",
		MinSeverity: models.SeverityLow,
		FailOn:      "",
		Parallelism: 0,
		Source:      map[string]string{},
	}
}

// File is the on-disk configuration format.
//
// It is JSON rather than YAML because the tool already depends on JSON and a
// security tool should not gain a parser it does not otherwise need. Both
// spellings are accepted on read, since operators type .yaml and .yml out of
// habit.
type File struct {
	Depth       string   `json:"depth,omitempty"`
	Format      string   `json:"format,omitempty"`
	Output      string   `json:"output,omitempty"`
	Events      *bool    `json:"events,omitempty"`
	EventsOut   string   `json:"events_out,omitempty"`
	Color       *bool    `json:"color,omitempty"`
	Profile     string   `json:"profile,omitempty"`
	Include     []string `json:"include,omitempty"`
	Exclude     []string `json:"exclude,omitempty"`
	MinSeverity string   `json:"min_severity,omitempty"`
	FailOn      string   `json:"fail_on,omitempty"`
	Offline     *bool    `json:"offline,omitempty"`
	Parallelism *int     `json:"parallelism,omitempty"`
	Target      string   `json:"target,omitempty"`
	Remote      *bool    `json:"remote,omitempty"`
}

// SearchPaths returns the candidate configuration file locations, in the order
// they are consulted.
//
// Only the user's own configuration and the directory the binary sits in are
// consulted. A system-wide location is deliberately absent: a tool that reads
// its configuration from a machine-wide path lets anyone who can write that
// path decide what the assessment does.
func SearchPaths(binaryDir string) []string {
	var out []string
	if dir := os.Getenv("AMINA_CONFIG_DIR"); dir != "" {
		out = append(out, filepath.Join(dir, "amina.yaml"))
		out = append(out, filepath.Join(dir, "amina.json"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		out = append(out,
			filepath.Join(home, ".config", "amina", "config.json"),
			filepath.Join(home, ".config", "amina", "config.yaml"),
			filepath.Join(home, ".amina.yaml"),
			filepath.Join(home, ".amina", "config.json"),
		)
	}
	if binaryDir != "" {
		out = append(out,
			filepath.Join(binaryDir, "amina.yaml"),
			filepath.Join(binaryDir, "amina.json"),
		)
	}
	return out
}

// Discover finds the first configuration file that exists.
func Discover(binaryDir string) (string, error) {
	for _, p := range SearchPaths(binaryDir) {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p, nil
		}
	}
	return "", nil
}

// Load reads a configuration file.
//
// An unreadable or malformed file is an error rather than a warning. Silently
// running with defaults after the operator supplied a file that did not parse
// would produce a report that looks authoritative and is not.
func Load(path string) (File, error) {
	var f File
	data, err := os.ReadFile(path)
	if err != nil {
		return f, fmt.Errorf("read configuration %s: %w", path, err)
	}
	// JSON is a subset of what this accepts; YAML's simple key/value form is
	// accepted too so the .yaml names in SearchPaths are not a lie.
	if err := json.Unmarshal(data, &f); err == nil {
		return f, nil
	}
	lines := strings.Split(string(data), "\n")
	for n, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, ok := strings.Cut(trimmed, ":")
		if !ok {
			return f, fmt.Errorf("%s:%d: expected key: value", path, n+1)
		}
		if err := f.apply(key, value); err != nil {
			return f, fmt.Errorf("%s:%d: %w", path, n+1, err)
		}
	}
	return f, nil
}

// apply folds one key/value pair into the file struct.
func (f *File) apply(key, value string) error {
	key = strings.ToLower(strings.TrimSpace(key))
	value = strings.Trim(strings.TrimSpace(value), `"'`)
	switch key {
	case "depth":
		f.Depth = value
	case "format":
		f.Format = value
	case "output":
		f.Output = value
	case "events":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		f.Events = &b
	case "color":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		f.Color = &b
	case "profile":
		f.Profile = value
	case "include":
		f.Include = splitList(value)
	case "exclude":
		f.Exclude = splitList(value)
	case "min_severity":
		f.MinSeverity = value
	case "fail_on":
		f.FailOn = value
	case "offline":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		f.Offline = &b
	case "parallelism":
		n, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("parallelism must be a number, got %q", value)
		}
		f.Parallelism = &n
	case "target":
		f.Target = value
	case "remote":
		b, err := parseBool(value)
		if err != nil {
			return err
		}
		f.Remote = &b
	default:
		return fmt.Errorf("unknown configuration key %q", key)
	}
	return nil
}

// Env is the environment-variable layer.
//
// The prefix is AMINA_ so the variables are namespaced and cannot collide with
// an application's own configuration.
type Env map[string]string

// FromEnviron reads the AMINA_ variables from the process environment.
func FromEnviron() Env {
	out := Env{}
	for _, kv := range os.Environ() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !strings.HasPrefix(k, "AMINA_") {
			continue
		}
		out[strings.ToLower(strings.TrimPrefix(k, "AMINA_"))] = v
	}
	return out
}

// Event stream destinations.
const (
	EventStreamStdout = "stdout"
	EventStreamStderr = "stderr"
	// EventStreamOff asks for no stream at all. It is a value rather than the
	// absence of the flag, so an interactive run can say "no machine events"
	// explicitly instead of failing on a destination it cannot use.
	EventStreamOff = "off"
)

// EventsDisabled reports whether a destination means "no stream".
//
// Every spelling of "off" the ecosystem uses is accepted, because the shared
// test suite drives `--events off` and a tool that rejects it looks broken next
// to the twelve that accept it.
func EventsDisabled(dest string) bool {
	switch strings.ToLower(strings.TrimSpace(dest)) {
	case "", EventStreamOff, "none", "false", "0", "no":
		return true
	}
	return false
}

// Flags is the command-line layer.
type Flags struct {
	Depth       string
	Format      string
	Output      string
	Events      bool
	EventsSet   bool
	EventsOut   string
	Color       bool
	ColorSet    bool
	NoColor     bool
	Target      string
	Remote      bool
	Profile     string
	Include     string
	Exclude     string
	MinSeverity string
	FailOn      string
	Simulate    bool
	Fixture     string
	Offline     bool
	Timeout     int
	Parallelism int
	ConfigPath  string
}

// Layer names, used in Config.Source.
const (
	SourceDefault = "default"
	SourceFile    = "file"
	SourceEnv     = "env"
	SourceFlag    = "flag"
)

// Resolve merges the four layers and validates the result.
func Resolve(flags Flags, file File, filePath string, env Env) (Config, error) {
	cfg := Default()
	cfg.ConfigPath = filePath

	// Layer 1: the file.
	if filePath != "" {
		if d, ok := rules.ParseDepth(file.Depth); ok {
			cfg.Depth = d
			cfg.Source["depth"] = SourceFile
		}
		if file.Format != "" {
			if f, ok := ValidFormat(file.Format); ok {
				cfg.Format = f
				cfg.Source["format"] = SourceFile
			}
		}
		if file.Output != "" {
			cfg.Output = file.Output
			cfg.Source["output"] = SourceFile
		}
		if file.EventsOut != "" {
			cfg.EventsOut = file.EventsOut
			cfg.Events = true
			cfg.Source["events"] = SourceFile
		}
		if file.Events != nil {
			cfg.Events = *file.Events
			cfg.Source["events"] = SourceFile
		}
		if file.Color != nil {
			cfg.Color = *file.Color
			cfg.Source["color"] = SourceFile
		}
		if file.Profile != "" {
			cfg.Profile = file.Profile
			cfg.Source["profile"] = SourceFile
		}
		if len(file.Include) > 0 {
			cfg.Include = file.Include
			cfg.Source["include"] = SourceFile
		}
		if len(file.Exclude) > 0 {
			cfg.Exclude = file.Exclude
			cfg.Source["exclude"] = SourceFile
		}
		if file.MinSeverity != "" {
			if s, err := parseSeverityStrict(file.MinSeverity); err == nil {
				cfg.MinSeverity = s
				cfg.Source["min_severity"] = SourceFile
			} else {
				return cfg, err
			}
		}
		if file.FailOn != "" {
			if s, err := parseSeverityStrict(file.FailOn); err == nil {
				cfg.FailOn = s
				cfg.Source["fail_on"] = SourceFile
			} else {
				return cfg, err
			}
		}
		if file.Offline != nil {
			cfg.Offline = *file.Offline
			cfg.Source["offline"] = SourceFile
		}
		if file.Parallelism != nil {
			cfg.Parallelism = *file.Parallelism
			cfg.Source["parallelism"] = SourceFile
		}
		if file.Target != "" {
			cfg.Target = file.Target
			cfg.Source["target"] = SourceFile
		}
		if file.Remote != nil {
			cfg.Remote = *file.Remote
			cfg.Source["remote"] = SourceFile
		}
	}

	// Layer 2: the environment.
	if err := applyEnv(&cfg, env); err != nil {
		return cfg, err
	}

	// Layer 3: the command line, which always wins.
	if flags.Depth != "" {
		d, ok := rules.ParseDepth(flags.Depth)
		if !ok {
			return cfg, fmt.Errorf("unknown depth %q: use quick, standard or deep", flags.Depth)
		}
		cfg.Depth = d
		cfg.Source["depth"] = SourceFlag
	}
	if flags.Format != "" {
		f, ok := ValidFormat(flags.Format)
		if !ok {
			return cfg, fmt.Errorf("unknown format %q: use one of %s", flags.Format, FormatNames())
		}
		cfg.Format = f
		cfg.Source["format"] = SourceFlag
	}
	if flags.Output != "" {
		cfg.Output = flags.Output
		cfg.Source["output"] = SourceFlag
	}
	if flags.EventsOut != "" {
		cfg.EventsOut = flags.EventsOut
		cfg.Events = true
		cfg.Source["events"] = SourceFlag
	}
	if flags.EventsSet {
		cfg.Events = flags.Events
		cfg.Source["events"] = SourceFlag
	}
	if flags.ColorSet {
		cfg.Color = flags.Color
		cfg.Source["color"] = SourceFlag
	}
	if flags.NoColor {
		cfg.NoColor = true
		cfg.Color = false
	}
	if flags.Target != "" {
		cfg.Target = flags.Target
		cfg.Source["target"] = SourceFlag
	}
	if flags.Remote {
		cfg.Remote = true
		cfg.Source["remote"] = SourceFlag
	}
	if flags.Profile != "" {
		cfg.Profile = flags.Profile
		cfg.Source["profile"] = SourceFlag
	}
	if flags.Include != "" {
		cfg.Include = splitList(flags.Include)
		cfg.Source["include"] = SourceFlag
	}
	if flags.Exclude != "" {
		cfg.Exclude = splitList(flags.Exclude)
		cfg.Source["exclude"] = SourceFlag
	}
	if flags.MinSeverity != "" {
		s, err := parseSeverityStrict(flags.MinSeverity)
		if err != nil {
			return cfg, err
		}
		cfg.MinSeverity = s
		cfg.Source["min_severity"] = SourceFlag
	}
	if flags.FailOn != "" {
		s, err := parseSeverityStrict(flags.FailOn)
		if err != nil {
			return cfg, err
		}
		cfg.FailOn = s
		cfg.Source["fail_on"] = SourceFlag
	}
	if flags.Simulate {
		cfg.Simulate = true
		cfg.Source["simulate"] = SourceFlag
	}
	if flags.Fixture != "" {
		cfg.Fixture = flags.Fixture
		cfg.Simulate = true
		cfg.Source["simulate"] = SourceFlag
	}
	if flags.Offline {
		cfg.Offline = true
		cfg.Source["offline"] = SourceFlag
	}
	if flags.Timeout != 0 {
		cfg.TimeoutSeconds = flags.Timeout
		cfg.Source["timeout"] = SourceFlag
	}
	if flags.Parallelism != 0 {
		cfg.Parallelism = flags.Parallelism
		cfg.Source["parallelism"] = SourceFlag
	}
	if flags.ConfigPath != "" {
		cfg.ConfigPath = flags.ConfigPath
	}

	if err := cfg.finish(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func applyEnv(cfg *Config, env Env) error {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := env[k]
		switch k {
		case "depth":
			if d, ok := rules.ParseDepth(v); ok {
				cfg.Depth = d
				cfg.Source["depth"] = SourceEnv
			}
		case "format":
			if f, ok := ValidFormat(v); ok {
				cfg.Format = f
				cfg.Source["format"] = SourceEnv
			}
		case "output":
			cfg.Output = v
			cfg.Source["output"] = SourceEnv
		case "events":
			// AMINA_EVENTS takes a destination, matching --events: a bare
			// "true" means stdout.
			if v == "" || v == "true" {
				cfg.Events, cfg.EventsOut = true, EventStreamStdout
			} else if v == "false" {
				cfg.Events, cfg.EventsOut = false, ""
			} else if b, err := parseBool(v); err == nil {
				cfg.Events = b
			} else {
				cfg.Events, cfg.EventsOut = true, v
			}
			cfg.Source["events"] = SourceEnv
		case "color":
			if b, err := parseBool(v); err == nil {
				cfg.Color = b
				cfg.Source["color"] = SourceEnv
			}
		case "no_color":
			if b, err := parseBool(v); err == nil {
				cfg.NoColor = b
				if b {
					cfg.Color = false
				}
			}
		case "profile":
			cfg.Profile = v
			cfg.Source["profile"] = SourceEnv
		case "include":
			cfg.Include = splitList(v)
			cfg.Source["include"] = SourceEnv
		case "exclude":
			cfg.Exclude = splitList(v)
			cfg.Source["exclude"] = SourceEnv
		case "min_severity":
			s, err := parseSeverityStrict(v)
			if err != nil {
				return err
			}
			cfg.MinSeverity = s
			cfg.Source["min_severity"] = SourceEnv
		case "fail_on":
			s, err := parseSeverityStrict(v)
			if err != nil {
				return err
			}
			cfg.FailOn = s
			cfg.Source["fail_on"] = SourceEnv
		case "offline":
			if b, err := parseBool(v); err == nil {
				cfg.Offline = b
				cfg.Source["offline"] = SourceEnv
			}
		case "parallelism":
			if n, err := strconv.Atoi(v); err == nil {
				cfg.Parallelism = n
				cfg.Source["parallelism"] = SourceEnv
			}
		case "target":
			cfg.Target = v
			cfg.Source["target"] = SourceEnv
		case "remote":
			if b, err := parseBool(v); err == nil {
				cfg.Remote = b
				cfg.Source["remote"] = SourceEnv
			}
		case "no_config":
			// Handled by the caller: it decides whether to search at all.
		default:
			return fmt.Errorf("unknown AMINA_%s environment variable", strings.ToUpper(k))
		}
	}
	return nil
}

// finish applies the derived rules and validates the resolved configuration.
func (c *Config) finish() error {
	// NO_COLOR is honoured even when nothing set it explicitly, because the
	// variable exists so that a user can turn colour off for every tool at once.
	if _, set := os.LookupEnv("NO_COLOR"); set {
		c.NoColor = true
		c.Color = false
		c.Source["no_color"] = "NO_COLOR"
	}
	// A report format that is not a terminal report cannot be written to a
	// terminal with colour; colour is disabled when writing one to a file.
	if c.Format != FormatTerminal {
		c.Color = false
	}
	if c.Output != "-" && c.Format == FormatTerminal {
		return errors.New("the terminal format cannot be written to a file; use --format json, yaml, markdown or html")
	}
	// --simulate with no fixture is the built-in dataset, which is what the flag
	// advertises. Demanding --fixture as well would make the documented one-word
	// invocation an error and force every user to learn a name for the default.
	if c.Simulate && strings.TrimSpace(c.Fixture) == "" {
		c.Fixture = simulation.BuiltinFixture
	}
	if c.Parallelism < 0 {
		return errors.New("--parallelism cannot be negative")
	}
	if c.TimeoutSeconds < 0 {
		return errors.New("--timeout cannot be negative")
	}
	if c.FailOn != "" && c.FailOn.Rank() < c.MinSeverity.Rank() {
		return fmt.Errorf("--fail-on %s is below --min-severity %s, so the run could never fail on it",
			c.FailOn, c.MinSeverity)
	}
	for _, id := range c.Include {
		if !knownModule(id) {
			return fmt.Errorf("unknown module %q in --include: run 'amina capabilities' for the module list", id)
		}
	}
	for _, id := range c.Exclude {
		if !knownModule(id) {
			return fmt.Errorf("unknown module %q in --exclude: run 'amina capabilities' for the module list", id)
		}
	}
	return nil
}

// knownModule answers whether an ID names a real module.
//
// It is a function variable rather than a call into pkg/modules because the
// collection layer is built on top of this package. Importing it here would make
// configuration depend on every collector, which is a dependency cycle waiting
// to happen the first time a collector needs a flag.
//
// The default is permissive so that a bare Config still validates: tests and
// embedded callers that never install a registry are checking the shape of a
// configuration, not the names in it. main installs the real registry, which is
// what makes a misspelled --include an error instead of an empty report.
var knownModule = func(string) bool { return true }

// SetModuleLookup installs the module registry's validator. It must be called
// once during startup, before Resolve.
func SetModuleLookup(fn func(string) bool) {
	if fn != nil {
		knownModule = fn
	}
}

// Modules returns the modules that survive the include and exclude filters,
// preserving registry order.
func (c Config) Modules(all []string) []string {
	include := toSet(c.Include)
	exclude := toSet(c.Exclude)
	var out []string
	for _, id := range all {
		if len(include) > 0 && !include[id] {
			continue
		}
		if exclude[id] {
			continue
		}
		out = append(out, id)
	}
	return out
}

func toSet(list []string) map[string]bool {
	out := make(map[string]bool, len(list))
	for _, id := range list {
		if id = strings.TrimSpace(id); id != "" {
			out[id] = true
		}
	}
	return out
}

// String renders the resolved configuration for the report's provenance block.
//
// Secrets are not settings this package handles, so nothing here needs
// redaction; the one field that could carry a hostname is printed as given,
// because naming the assessed host is the point of a report.
func (c Config) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "depth: %s\n", rules.DepthName(c.Depth))
	fmt.Fprintf(&b, "format: %s\n", c.Format)
	fmt.Fprintf(&b, "output: %s\n", c.Output)
	fmt.Fprintf(&b, "target: %s\n", c.targetLabel())
	fmt.Fprintf(&b, "min_severity: %s\n", c.MinSeverity)
	if c.FailOn != "" {
		fmt.Fprintf(&b, "fail_on: %s\n", c.FailOn)
	}
	if c.Profile != "" {
		fmt.Fprintf(&b, "profile: %s\n", c.Profile)
	}
	if len(c.Include) > 0 {
		fmt.Fprintf(&b, "include: %s\n", strings.Join(c.Include, ","))
	}
	if len(c.Exclude) > 0 {
		fmt.Fprintf(&b, "exclude: %s\n", strings.Join(c.Exclude, ","))
	}
	fmt.Fprintf(&b, "offline: %t\n", c.Offline)
	if c.Parallelism > 0 {
		fmt.Fprintf(&b, "parallelism: %d\n", c.Parallelism)
	}
	if c.TimeoutSeconds > 0 {
		fmt.Fprintf(&b, "timeout: %ds\n", c.TimeoutSeconds)
	}
	if c.Simulate {
		fmt.Fprintf(&b, "simulate: %s\n", c.Fixture)
	}
	if c.ConfigPath != "" {
		fmt.Fprintf(&b, "config: %s\n", c.ConfigPath)
	}
	return b.String()
}

func (c Config) targetLabel() string {
	if c.Target == "" {
		return "local"
	}
	if c.Remote {
		return c.Target + " (remote)"
	}
	return c.Target
}

// SourceLines renders the setting provenance, sorted, for the report.
func (c Config) SourceLines() []string {
	keys := make([]string, 0, len(c.Source))
	for k := range c.Source {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+c.Source[k])
	}
	return out
}

// Validate performs the checks that need the platform, and is separate from
// finish because it needs to know what the host supports.
func (c Config) Validate(env *platform.Env) error {
	if c.Depth < rules.DepthQuick || c.Depth > rules.DepthDeep {
		return fmt.Errorf("depth %d is outside the supported range", c.Depth)
	}
	if c.Remote && env != nil && !platform.HasCommand("ssh") {
		return errors.New("remote assessment requires an ssh client on this host, and none was found on the PATH")
	}
	return nil
}

// parseSeverityStrict rejects an unknown severity rather than defaulting.
//
// models.ParseSeverity falls back to informational, which is the right
// behaviour for reading stored data and the wrong one for validating what an
// operator just typed: a typo in --min-severity would silently change what the
// run reports instead of being reported as a mistake.
func parseSeverityStrict(v string) (models.Severity, error) {
	candidate := models.Severity(strings.ToLower(strings.TrimSpace(v)))
	for _, s := range models.Severities {
		if s == candidate {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("unknown severity %q: use critical, high, medium, low or informational", v)
}

func parseBool(v string) (bool, error) {
	b, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return false, fmt.Errorf("expected true or false, got %q", v)
	}
	return b, nil
}

func splitList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// FormatNames renders the supported formats for help text and error messages.
func FormatNames() string {
	names := make([]string, 0, len(Formats))
	for _, f := range Formats {
		names = append(names, string(f))
	}
	return strings.Join(names, ", ")
}
