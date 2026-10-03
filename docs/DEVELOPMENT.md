# Development

## Prerequisites

- Go **1.26.5** or later (`go.mod` pins the toolchain).
- No C dependencies. `CGO_ENABLED=0` is the default for every release build, so
  all collectors and the TUI are pure Go.
- `golangci-lint` for the lint gate, `bash` for the generated installers.

## Build

```sh
# Local development build (reports "dev" identity)
go build -o amina ./cmd/amina

# Release-equivalent build, with the identity stamped in
BUILD_DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
go build -trimpath -ldflags="-s -w \
  -X github.com/QYVORA/qyvora-amina/internal/version.Version=v0.1.0 \
  -X github.com/QYVORA/qyvora-amina/internal/version.Commit=$(git rev-parse HEAD) \
  -X github.com/QYVORA/qyvora-amina/internal/version.Date=$BUILD_DATE \
  -X github.com/QYVORA/qyvora-amina/internal/version.BuildUser=$(whoami)" \
  -o amina ./cmd/amina
```

The version, commit, date and build user are compile-time defaults in
`internal/version`. Unstamped builds report `dev`; release artifacts must never
report a dev build, which is why the conformance stage asserts semver.

## Test

```sh
gofmt -l .          # must print nothing
go vet ./...        # must be clean
go test ./... -count=1
go test -race ./... -count=1
```

`go test -race` includes a live-host run, so it exercises the real collectors.

The suite includes:

- **Determinism tests** — the same fixture at `--parallelism` 1, 2, 4, 8 and 64
  must render identical bytes, and module order is checked directly so a failure
  names the cause.
- **Golden output suite** — all five formats byte-compared against
  `testdata/golden/`.
- **Rule and risk-threshold tests** — including one that asserts the summary's
  band boundaries match `pkg/risk`, so the two copies cannot drift silently.

## Lint

```sh
golangci-lint run ./...
```

## Cross-compiling

The binary cross-compiles to the release matrix with no `replace` directives:

```sh
for goos in linux darwin windows android; do
  for goarch in amd64 arm64; do
    CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build ./cmd/amina || exit 1
  done
done
```

`internal/platform` keeps capability at runtime rather than behind build tags, so
cross-compilation does not silently remove a domain from the binary. Build tags
are used only for parsing that genuinely cannot compile elsewhere and for files
only one platform has.

The shared TUI dependency (`github.com/QYVORA/qyvora-tui v0.7.1`) is
cross-build-safe; earlier v0.7.0 had a missing build tag and a `syscall.Dup2`
usage that broke Windows and non-`Dup2` Unix targets.

## Repository layout

```
cmd/amina/            CLI entry and subcommands
internal/config/      flags, file, env, precedence
internal/platform/    cross-platform collectors + capability matrix
internal/safety/      operation safety metadata
internal/evidence/    evidence records
internal/events/      JSONL event envelope
internal/output/      terminal/json/yaml/markdown/html renderers
internal/exitcode/    exit-code contract
internal/update/      self-update
internal/version/     build identity
pkg/models/           report, finding, enums
pkg/modules/          the 23-module registry
pkg/rules/            the 52-rule catalogue + engine
pkg/correlation/      identity correlation
pkg/risk/             risk scoring
pkg/simulation/       fixtures
pkg/pipeline/         orchestration
scripts/              verify-artifact.sh
testdata/golden/      golden reports for all five formats
install.sh            generated zero-config installer
.goreleaser.yaml      generated release config
.github/workflows/release.yml  generated publishing workflow
```

## Generated files

Several files are rendered from the shared `qyvora-dist` templates and
`tools.def` metadata in the parent workspace and carry a header saying so:

- `install.sh`
- `scripts/verify-artifact.sh`
- `.goreleaser.yaml`
- `.github/workflows/release.yml`

Do not edit them by hand. Change the template and `tools.def`, then run
`qyvora-dist/generate.sh`, so the artifact naming and target matrix cannot drift
between the installer, GoReleaser and the publishing workflow.

## Releasing

A release is triggered by pushing a `v*` tag (or by running the workflow with an
explicit tag). The workflow:

1. vets and tests, syntax-checks the generated shell scripts, and self-tests the
   artifact verifier;
2. builds every matrix target with the ldflags above;
3. verifies each artifact's container format, machine/arch word, and — for
   Android — that it is `ET_DYN`;
4. smoke-tests the native artifact;
5. refuses to publish unless the exact expected asset list is present;
6. generates `checksums.txt` over the binaries and icons;
7. creates the GitHub release.

See [UPDATING.md](UPDATING.md) for the published asset list.

## Contributing rules of thumb

- A rule's `Match` must be pure with respect to the snapshot: no clock reads, no
  filesystem access, no map-iteration-order dependence. Determinism is a product
  feature, not a test convenience.
- A collector must fingerprint secret material itself; the renderer is downstream
  of the redaction boundary and must never be given a value to leak.
- Prefer reporting a status over omitting a domain. "Not applicable here" is a
  truthful statement; silence reads as a clean host.
- Never add a write, remediation or privilege-escalation path. The safety model
  in `internal/safety` is the contract, and a change to it is a change to what
  the tool *is*.
