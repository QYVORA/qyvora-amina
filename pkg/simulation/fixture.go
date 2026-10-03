// Package simulation loads and saves assessment fixtures.
//
// A fixture is a recorded snapshot. Loading one feeds synthetic data through
// exactly the same rule engine, correlation and report code that a live run
// uses, so it exercises the pipeline rather than a parallel imitation of it.
//
// This is what makes "the same rules fire on the same data" testable at all:
// a live host changes between runs, so a golden report can only be compared
// against a recorded host.
package simulation

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/QYVORA/qyvora-amina/internal/platform"
	"github.com/QYVORA/qyvora-amina/pkg/models"
	"github.com/QYVORA/qyvora-amina/pkg/rules"
)

// SchemaVersion identifies the fixture format.
const SchemaVersion = "1.0"

// Fixture is the on-disk envelope.
//
// It is a thin wrapper around rules.Snapshot rather than a parallel struct,
// because a second copy of the snapshot's fields would drift from the first and
// a fixture would then silently stop describing what the engine consumes.
type Fixture struct {
	Schema      string         `json:"schema"`
	Name        string         `json:"name,omitempty"`
	Description string         `json:"description,omitempty"`
	Snapshot    rules.Snapshot `json:"snapshot"`
}

// Load reads a fixture from disk.
//
// A fixture is untrusted input in the sense that matters here: it is a file
// that may have been copied from another machine, so it is size-limited and its
// declared schema is checked before it is used. Size limiting matters because
// the loader allocates in proportion to the file.
func Load(path string) (*Fixture, error) {
	const maxFixtureBytes = 64 << 20

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open fixture: %w", err)
	}
	defer func() { _ = f.Close() }()

	limited := io.LimitReader(f, maxFixtureBytes)
	dec := json.NewDecoder(limited)
	dec.DisallowUnknownFields()

	var fx Fixture
	if err := dec.Decode(&fx); err != nil {
		return nil, fmt.Errorf("decode fixture %s: %w", path, err)
	}
	if fx.Schema != SchemaVersion {
		return nil, fmt.Errorf("fixture %s: schema %q is not supported (want %q)", path, fx.Schema, SchemaVersion)
	}
	if fx.Snapshot.Target.Type == "" {
		return nil, fmt.Errorf("fixture %s: snapshot has no target type", path)
	}
	if fx.Snapshot.Env == nil {
		return nil, fmt.Errorf("fixture %s: snapshot has no environment", path)
	}
	if fx.Snapshot.CollectedAt.IsZero() {
		fx.Snapshot.CollectedAt = time.Unix(0, 0).UTC()
	}
	return &fx, nil
}

// Save writes a fixture. Tests use it to record a snapshot and compare the
// report derived from it later.
func Save(path string, snap rules.Snapshot) error {
	fx := Fixture{Schema: SchemaVersion, Snapshot: snap}
	data, err := json.MarshalIndent(fx, "", "  ")
	if err != nil {
		return fmt.Errorf("encode fixture: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("write fixture: %w", err)
	}
	return nil
}

// Target converts a fixture into the target the report is written against.
//
// A simulation is always reported as a simulation. If it were labelled as a
// host, a reader would reasonably assume the findings describe a machine they
// can go and look at.
func (f *Fixture) Target() models.Target {
	t := f.Snapshot.Target
	if t.Type == "" {
		t.Type = models.TargetSimulation
	}
	t.Type = models.TargetSimulation
	if f.Name != "" && t.Name == "" {
		t.Name = f.Name
	}
	t.Auth = models.Authorization{Granted: true, Scope: "simulation fixture"}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Unix(0, 0).UTC()
	}
	return t
}

// Snapshot returns the recorded snapshot, defaulted so that a hand-written
// fixture is still usable. The defaults are conservative: an absent depth means
// the shallowest, not the deepest, because a fixture that silently ran every
// deep rule would report coverage its data does not support.
func (f *Fixture) SnapshotOrDefaults() rules.Snapshot {
	snap := f.Snapshot
	if snap.Depth <= 0 {
		snap.Depth = 1
	}
	if snap.CollectedAt.IsZero() {
		snap.CollectedAt = time.Unix(0, 0).UTC()
	}
	if snap.Target.Type == "" {
		snap.Target.Type = models.TargetSimulation
	}
	return snap
}

// Builtin returns the deterministic dataset shipped with the tool.
//
// It is a deliberately messy machine: a world-bound SSH listener, a token in a
// dotfile, an unpinned package source, a stale authorized key and two identity
// signals that should correlate. It exists so that `--simulate` produces the
// same report on every machine and every run, which is what makes the golden
// test meaningful.
func Builtin() *Fixture {
	env := &platform.Env{
		Platform:   models.PlatformLinux,
		GOOS:       "linux",
		GOARCH:     "amd64",
		Kernel:     "6.8.0-generic",
		Distro:     "Ubuntu 24.04",
		Hostname:   "build-01",
		User:       "aisha",
		UID:        "1000",
		Home:       "/home/aisha",
		Shell:      "/bin/bash",
		Container:  false,
		Privileged: false,
		Locale:     "en_US.UTF-8",
		Timezone:   "UTC",
		Support:    map[string]models.SupportLevel{},
	}
	env.Paths.Home = env.Home
	env.Paths.Etc = "/etc"
	env.Paths.Passwd = "/etc/passwd"
	env.Paths.ShellRC = []string{"/home/aisha/.bashrc", "/home/aisha/.profile"}
	env.Paths.HistoryFiles = []string{"/home/aisha/.bash_history"}
	env.Paths.GitConfig = "/home/aisha/.gitconfig"
	env.Paths.Temp = "/tmp"

	return &Fixture{
		Schema:      SchemaVersion,
		Name:        "builtin-workstation",
		Description: "Synthetic workstation used for --simulate and the golden report test.",
		Snapshot: rules.Snapshot{
			Target: models.Target{
				ID:        "sim-builtin",
				Name:      "build-01",
				Type:      models.TargetSimulation,
				Value:     "builtin",
				Platform:  models.PlatformLinux,
				Auth:      models.Authorization{Granted: true, Scope: "simulation fixture"},
				CreatedAt: time.Unix(0, 0).UTC(),
			},
			Env:         env,
			CollectedAt: time.Unix(1700000000, 0).UTC(),
			Depth:       2,
			Accounts: []models.Account{
				{Name: "root", UID: "0", GID: "0", Home: "/root", Shell: "/bin/bash",
					Privileged: true, Classification: models.AccountStandard, Source: "passwd"},
				{Name: "aisha", UID: "1000", GID: "1000", Home: "/home/aisha", Shell: "/bin/bash",
					Classification: models.AccountStandard, Source: "passwd"},
			},
			Sockets: []platform.Socket{
				{Proto: "tcp", Addr: "0.0.0.0", Port: 22, Scope: models.ScopePublic,
					Process: "sshd", Wildcard: true},
				{Proto: "tcp", Addr: "127.0.0.1", Port: 5432, Scope: models.ScopeLocal,
					Process: "postgres"},
			},
			Sources: []models.PackageSource{
				{ID: "src-apt", Provider: "apt", Kind: "apt", URI: "http://archive.ubuntu.com/ubuntu",
					Trust: "official", Keys: 3, Enabled: true},
				{ID: "src-pypi", Provider: "pip", Kind: "pip", URI: "https://pypi.org/simple",
					Trust: "official", Enabled: true},
			},
			Secrets: []models.SecretRecord{
				{
					Type: models.SecretToken, Location: "/home/aisha/.aws/credentials",
					Line: 3, Field: "aws_secret_access_key",
					Fingerprint: "0a1b2c3d4e5f60718293a4b5c6d7e8f", Length: 40,
					Source: "secrets", Redaction: models.RedactionFingerprint,
				},
			},
			Identities: []models.IdentitySignal{
				{Type: "git_name", Value: "Aisha Rahman", Source: "git.user.name", Domain: "git",
					Module: "developer-identity", At: time.Unix(1700000000, 0).UTC()},
				{Type: "email", Value: "aisha@corp.example", Source: "email", Domain: "mail",
					Module: "developer-identity", At: time.Unix(1700000000, 0).UTC()},
			},
			Assets: []models.Asset{
				{ID: "asset-1", Kind: models.KindListeningSocket, Domain: "network", Name: "0.0.0.0:22",
					Platform: models.PlatformLinux, Source: "network", Exposure: models.ScopePublic,
					Timestamp: time.Unix(1700000000, 0).UTC()},
			},
			Remote: false,
		},
	}
}

// Load resolves a fixture name to a loaded fixture.
//
// The empty name and the builtin name both return the builtin dataset, which
// is what makes `--simulate` work with no arguments.
// BuiltinFixture is the name that selects the built-in synthetic dataset.
const BuiltinFixture = "builtin"

func LoadNamed(name string) (*Fixture, error) {
	switch name {
	case "", BuiltinFixture:
		return Builtin(), nil
	}
	fx, err := Load(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("fixture %q not found; use \"builtin\" or a path to a recorded snapshot", name)
		}
		return nil, err
	}
	return fx, nil
}
