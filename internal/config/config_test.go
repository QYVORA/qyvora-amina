package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/QYVORA/qyvora-amina/pkg/models"
	"github.com/QYVORA/qyvora-amina/pkg/simulation"
)

func TestDefaultsAreValid(t *testing.T) {
	cfg := Default()
	if err := cfg.finish(); err != nil {
		t.Fatalf("the shipped defaults must be valid: %v", err)
	}
	if cfg.Depth != 2 {
		t.Errorf("default depth = %d, want 2", cfg.Depth)
	}
	if cfg.Format != FormatTerminal {
		t.Errorf("default format = %q, want terminal", cfg.Format)
	}
}

// TestPrecedenceIsFlagsThenEnvThenFile is the property an operator relies on
// when they pass a flag and it does not take effect.
func TestPrecedenceIsFlagsThenEnvThenFile(t *testing.T) {
	file := File{Depth: "quick", Format: "json", Profile: "from-file"}

	t.Run("file only", func(t *testing.T) {
		cfg, err := Resolve(Flags{}, file, "amina.json", Env{})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Depth != 1 || cfg.Format != FormatJSON || cfg.Profile != "from-file" {
			t.Errorf("file layer not applied: depth=%d format=%q profile=%q", cfg.Depth, cfg.Format, cfg.Profile)
		}
		if cfg.Source["depth"] != SourceFile {
			t.Errorf("depth provenance = %q, want %q", cfg.Source["depth"], SourceFile)
		}
	})

	t.Run("env beats file", func(t *testing.T) {
		cfg, err := Resolve(Flags{}, file, "amina.json", Env{"depth": "deep", "format": "yaml"})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Depth != 3 || cfg.Format != FormatYAML {
			t.Errorf("env did not beat the file: depth=%d format=%q", cfg.Depth, cfg.Format)
		}
		if cfg.Source["depth"] != SourceEnv {
			t.Errorf("depth provenance = %q, want %q", cfg.Source["depth"], SourceEnv)
		}
	})

	t.Run("flag beats env", func(t *testing.T) {
		cfg, err := Resolve(Flags{Depth: "standard"}, file, "amina.json", Env{"depth": "deep"})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Depth != 2 {
			t.Errorf("flag did not beat env: depth=%d", cfg.Depth)
		}
		if cfg.Source["depth"] != SourceFlag {
			t.Errorf("depth provenance = %q, want %q", cfg.Source["depth"], SourceFlag)
		}
	})
}

func TestInvalidValuesAreRejected(t *testing.T) {
	cases := []struct {
		name  string
		flags Flags
		env   Env
	}{
		{"unknown depth", Flags{Depth: "exhaustive"}, Env{}},
		{"unknown format", Flags{Format: "pdf"}, Env{}},
		// A typo must not silently become "informational", which would change
		// what the run reports without saying so.
		{"misspelled severity", Flags{MinSeverity: "critcal"}, Env{}},
		{"misspelled fail-on", Flags{FailOn: "hgh"}, Env{}},
		{"negative parallelism", Flags{Parallelism: -1}, Env{}},
		{"unknown env severity", Flags{}, Env{"min_severity": "critcal"}},
		{"unknown env key", Flags{}, Env{"depht": "quick"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := c.env
			if env == nil {
				env = Env{}
			}
			if _, err := Resolve(c.flags, File{}, "", env); err == nil {
				t.Error("expected an error, got none")
			}
		})
	}
}

func TestTerminalFormatCannotBeWrittenToAFile(t *testing.T) {
	_, err := Resolve(Flags{Output: "report.txt"}, File{}, "", Env{})
	if err == nil {
		t.Fatal("writing a terminal report to a file must be refused: the output contains control sequences")
	}
	// A machine format to a file is the supported combination.
	if _, err := Resolve(Flags{Output: "report.json", Format: "json"}, File{}, "", Env{}); err != nil {
		t.Errorf("json to a file must be allowed: %v", err)
	}
}

func TestSimulateDefaultsToTheBuiltinFixture(t *testing.T) {
	// --simulate is documented as running the built-in dataset, so it has to work
	// on its own. Requiring --fixture as well would make the flag's own help text a
	// lie and force every user to learn the name of the default.
	cfg, err := Resolve(Flags{Simulate: true}, File{}, "", Env{})
	if err != nil {
		t.Fatalf("--simulate on its own must be accepted: %v", err)
	}
	if cfg.Fixture != simulation.BuiltinFixture {
		t.Errorf("Fixture = %q, want %q", cfg.Fixture, simulation.BuiltinFixture)
	}
	if _, err := Resolve(Flags{Fixture: "snap.json"}, File{}, "", Env{}); err != nil {
		t.Errorf("--fixture implies simulation and must be accepted: %v", err)
	}
}

func TestFailOnBelowMinSeverityIsRejected(t *testing.T) {
	_, err := Resolve(Flags{MinSeverity: "high", FailOn: "low"}, File{}, "", Env{})
	if err == nil {
		t.Error("a fail-on threshold below min-severity can never trigger and should be refused")
	}
}

func TestNoColorEnvironmentDisablesColour(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	cfg, err := Resolve(Flags{Color: true}, File{}, "", Env{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Color {
		t.Error("NO_COLOR must disable colour even when --color was passed")
	}
}

func TestMachineFormatsDisableColour(t *testing.T) {
	cfg, err := Resolve(Flags{Format: "json", Color: true}, File{}, "", Env{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Color {
		t.Error("a machine-readable report must not contain colour")
	}
}

func TestLoadJSONAndSimpleYAML(t *testing.T) {
	dir := t.TempDir()

	jsonPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(jsonPath, []byte(`{"depth":"deep","format":"markdown","events":true,"include":["network","accounts"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Load(jsonPath)
	if err != nil {
		t.Fatalf("json config: %v", err)
	}
	if f.Depth != "deep" || f.Format != "markdown" || f.Events == nil || !*f.Events || len(f.Include) != 2 {
		t.Errorf("json config not parsed: %+v", f)
	}

	yamlPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(yamlPath, []byte("# amina\ndepth: standard\nformat: json\noffline: true\nexclude: metadata, tooling\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err = Load(yamlPath)
	if err != nil {
		t.Fatalf("yaml config: %v", err)
	}
	if f.Depth != "standard" || f.Format != "json" || f.Offline == nil || !*f.Offline || len(f.Exclude) != 2 {
		t.Errorf("yaml config not parsed: %+v", f)
	}
}

// TestMalformedConfigIsAnError matters more than it looks: a config file that
// does not parse must stop the run, because the alternative is a report that
// looks like the operator's configuration was applied when it was not.
func TestMalformedConfigIsAnError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(p, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p); err == nil {
		t.Error("a malformed config must be an error")
	}

	p2 := filepath.Join(dir, "unknown.yaml")
	if err := os.WriteFile(p2, []byte("depht: quick\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(p2); err == nil {
		t.Error("an unknown configuration key must be an error")
	}
}

func TestDiscoverFindsAConfigFile(t *testing.T) {
	dir := t.TempDir()
	dirs := filepath.Join(dir, "amina")
	if err := os.MkdirAll(dirs, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirs, "amina.yaml"), []byte("depth: quick\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AMINA_CONFIG_DIR", dirs)

	found, err := Discover("")
	if err != nil {
		t.Fatal(err)
	}
	if found == "" {
		t.Fatal("Discover did not find the configuration")
	}
	if _, err := Resolve(Flags{}, File{Depth: "quick"}, found, Env{}); err != nil {
		t.Errorf("discovered config must resolve: %v", err)
	}
}

func TestModuleFiltersPreserveRegistryOrder(t *testing.T) {
	cfg := Config{Include: []string{"network", "accounts"}}
	all := []string{"host-identity", "accounts", "network", "software"}
	got := cfg.Modules(all)
	if len(got) != 2 || got[0] != "accounts" || got[1] != "network" {
		t.Errorf("filter changed registry order: %v", got)
	}

	cfg = Config{Exclude: []string{"accounts"}}
	got = cfg.Modules(all)
	if len(got) != 3 || got[1] != "network" {
		t.Errorf("exclude filter: %v", got)
	}

	cfg = Config{Include: []string{"network"}, Exclude: []string{"network"}}
	if got := cfg.Modules(all); len(got) != 0 {
		t.Errorf("exclude must win over include: %v", got)
	}
}

func TestSeverityComparisonUsesRanks(t *testing.T) {
	if models.SeverityHigh.Rank() <= models.SeverityMedium.Rank() {
		t.Fatal("severity ranks are inverted")
	}
	cfg, err := Resolve(Flags{MinSeverity: "low", FailOn: "high"}, File{}, "", Env{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FailOn.Rank() < cfg.MinSeverity.Rank() {
		t.Error("resolved thresholds are inconsistent")
	}
}

func TestSourceLinesAreSorted(t *testing.T) {
	cfg, err := Resolve(Flags{Depth: "deep"}, File{Format: "json"}, "f.json", Env{})
	if err != nil {
		t.Fatal(err)
	}
	lines := cfg.SourceLines()
	if len(lines) < 2 {
		t.Fatalf("expected several provenance lines, got %v", lines)
	}
	for i := 1; i < len(lines); i++ {
		if lines[i-1] > lines[i] {
			t.Errorf("provenance lines are not sorted: %v", lines)
			break
		}
	}
}

func TestEventsAcceptsBothSpellings(t *testing.T) {
	// The flag may be written bare, with "=", or with the destination as a
	// separate argument. Getting the third form wrong used to parse "stdout" as
	// a stray positional argument and silently send events to the wrong place.
	for _, args := range [][]string{
		{"--events"},
		{"--events=stdout"},
		{"--events", "stdout"},
		{"-events", "stderr"},
		{"--events", "stderr"},
	} {
		var flags Flags
		fs := FlagSet(&flags)
		if err := fs.Parse(NormalizeArgs(args)); err != nil {
			t.Errorf("Parse(%v): %v", args, err)
			continue
		}
		if rest := fs.Args(); len(rest) != 0 {
			t.Errorf("Parse(%v) left unconsumed arguments %v", args, rest)
		}
		if !flags.Events {
			t.Errorf("Parse(%v) did not enable events", args)
		}
		want := "stderr"
		if len(args) == 1 || args[1] == "stdout" {
			want = EventStreamStdout
		}
		if flags.EventsOut != want {
			t.Errorf("Parse(%v): EventsOut = %q, want %q", args, flags.EventsOut, want)
		}
	}
}

func TestEventsDoesNotSwallowTheNextFlag(t *testing.T) {
	// "--events --simulate" must not swallow --simulate as a destination.
	var flags Flags
	fs := FlagSet(&flags)
	if err := fs.Parse(NormalizeArgs([]string{"--events", "--simulate"})); err != nil {
		t.Fatal(err)
	}
	if flags.EventsOut != EventStreamStdout {
		t.Errorf("EventsOut = %q, want %q", flags.EventsOut, EventStreamStdout)
	}
	if !flags.Simulate {
		t.Error("--simulate was consumed by --events")
	}
}

// TestUnknownModuleIsRejected covers the validation that only fires once a
// registry is installed.
//
// Without SetModuleLookup the permissive default accepts anything, which is
// right for a bare Config but wrong for the real CLI: a typo in --include has to
// be a usage error, not a report that quietly contains nothing.
func TestUnknownModuleIsRejected(t *testing.T) {
	restore := knownModule
	t.Cleanup(func() { knownModule = restore })

	SetModuleLookup(func(id string) bool { return id == "host-identity" })

	cfg := Default()
	cfg.Include = []string{"host-identity"}
	if err := cfg.finish(); err != nil {
		t.Errorf("a known module was rejected: %v", err)
	}

	cfg.Include = []string{"host-idenity"}
	err := cfg.finish()
	if err == nil {
		t.Fatal("a misspelled module was accepted")
	}
	if !strings.Contains(err.Error(), "host-idenity") {
		t.Errorf("error does not name the bad module: %v", err)
	}
	if !strings.Contains(err.Error(), "amina capabilities") {
		t.Errorf("error does not say where to find the module list: %v", err)
	}

	cfg.Include = nil
	cfg.Exclude = []string{"nope"}
	if err := cfg.finish(); err == nil {
		t.Error("a misspelled module in --exclude was accepted")
	}
}

// TestNilLookupKeepsTheDefault guards the seam against a caller passing nil and
// silently disabling validation.
func TestNilLookupKeepsTheDefault(t *testing.T) {
	restore := knownModule
	t.Cleanup(func() { knownModule = restore })

	SetModuleLookup(func(string) bool { return false })
	SetModuleLookup(nil)

	// The installed lookup must survive a nil, rather than the permissive
	// default coming back and quietly disabling validation.
	if knownModule("anything-at-all") {
		t.Error("a nil lookup reset the installed one, so validation is off again")
	}
}
