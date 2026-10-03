# CLI reference

```
amina [assess] [flags]        one-shot assessment, or the interactive session
amina assess|scan|report [flags]   one-shot assessment (assess is the default)
amina tui                     open the shared QYVORA console
amina capabilities [-o json]  list what this build can do
amina update [flags]          replace this binary from a verified release
amina version [-o json]       print the build identity
amina help                    print usage
```

## Choosing a face

A bare `amina` on a terminal opens the interactive session. Machine output has
to be asked for — `--format json`, `-o <file>`, `--simulate` or `--fixture` all
select a one-shot assessment instead. When stdout is not a terminal (a pipe, a
CI job, a redirect) Amina always assesses and never draws the session.

The session and a machine event destination cannot coexist: one screen cannot
hand the same bytes both to a renderer and to a file. Asking for both is a usage
error (exit `2`), not a silent no-op.

## Commands

### `assess` (aliases: `scan`, `report`)

Runs the full pipeline and renders a report. This is what the bare flags do too.

### `capabilities [-o json]`

Prints the capability registry. Plain output is one line per capability with a
leading `-` marking entries that are not implemented on this platform. With
`-o json` (or `-o=json`, `--output json`) it prints the machine-readable
document the shared TUI also consumes:

```json
{
  "tool": "amina",
  "framework": "amina",
  "version": "v0.1.0",
  "capabilities": [
    {
      "id": "amina.assess.host-identity",
      "name": "Host Identity",
      "description": "…",
      "category": "assessment",
      "authorization_required": false,
      "confirmation_required": false,
      "reversible": true,
      "changes_state": false,
      "implemented": true,
      "target_types": ["host", "simulation"],
      "output_schema": ["report"],
      "expected_duration": "fast"
    }
  ]
}
```

The registry contains **25** entries: one `amina.assess.<module>` per module
(23), plus `amina.simulate.run` and `amina.selfupdate.apply`. Every assessment
entry is reversible and changes no state. `amina.selfupdate.apply` is the only
entry with `changes_state: true`, `reversible: false`, and both authorization
and confirmation required.

### `update [flags]`

Replaces the running binary from a checksum-verified GitHub release. See
[UPDATING.md](UPDATING.md).

| Flag | Meaning |
|---|---|
| `--check` | report whether a newer verified release exists, then stop |
| `--dry-run` | download and verify the release without installing it |
| `--yes` | skip the confirmation prompt |
| `--version <tag>` | install a specific release tag (default: latest) |
| `--base-url <url>` | override release discovery (mirrors and testing) |
| `--offline` | refuse to update |
| `--insecure` | allow a plain-HTTP release; local mirrors only |

### `version [-f\|--format\|-o\|--output json]`

Plain `amina version` prints one line (`v0.1.0`). Any of `-f`, `--format`,
`--output` or `-o` set to `json` prints the full build identity. The four
spellings are accepted because the shared QYVORA contract asks every tool for
`version -o json`.

### `tui`

Opens the shared `qyvora-tui` console with Amina's capability registry and an
in-process runner, so assessments run without spawning a subprocess. Piped (not
a terminal cut-out), it falls back to a one-shot assessment.

## Flags for `assess`

| Flag | Short | Default | Meaning |
|---|---|---|---|
| `--depth` | | `standard` | `quick`, `standard`, `deep`, or a numeric level `1`–`3` |
| `--format` | | `terminal` | `terminal`, `json`, `yaml`, `markdown`, `html` |
| `--output` | `-o` | stdout | write the report to this file (created `0600`) |
| `--target` | | hostname | label recorded in the report |
| `--profile` | | | operator profile recorded in the report |
| `--include` | | | comma-separated modules to run exclusively |
| `--exclude` | | | comma-separated modules to skip |
| `--min-severity` | | | omit findings below this severity |
| `--fail-on` | | never | exit non-zero when a finding reaches this severity |
| `--fixture` | | | fixture name, or a path to a recorded snapshot |
| `--config` | | discovered | configuration file (see [CONFIGURATION.md](CONFIGURATION.md)) |
| `--simulate` | | off | assess the built-in synthetic dataset instead of this host |
| `--offline` | | off | make no network access |
| `--remote` | | off | assess a remote host (unsupported; always refused) |
| `--timeout` | | `0` | abort after this many seconds (`0` = no timeout) |
| `--parallelism` | | `0` | concurrent collectors (`0` = automatic) |
| `--events` | | off | JSONL event stream: `stdout`, `stderr`, or a file path |
| `--color` / `--no-color` | | auto | force colour on or off |

`--include` and `--exclude` each take a single comma-separated list
(`--include a,b,c`), not repeated flags. Unknown module names are a usage error
(exit `2`), not silently ignored.

`--include` is authoritative: when it names modules, only those run. `--exclude`
is then applied on top.

### Semantics worth knowing

- **`--depth`** gates rules. A rule with a higher `MinimumDepth` than the
  selected level is recorded as skipped, not as a clean pass. `quick` runs the
  six modules that are honest at depth 1; `deep` adds the filesystem-wide and
  binary-integrity sweeps.
- **`--min-severity`** filters the rendered report only; the risk score and the
  JSONL event stream still reflect every finding.
- **`--fail-on`** returns exit `1` when any surviving finding is at or above the
  threshold. It defaults to never failing; a tool that goes red on findings by
  default gets switched off.
- **`--offline`** makes the pipeline assert it performed no network access. This
  is the default posture anyway; the flag exists to make a policy explicit.
- **`--remote`** is valid on the command line but unsupported by design. It fails
  with exit `3`, not `2`: the command line was fine, the platform cannot do it.
- **`--events`** routes JSONL to its own destination. If events take stdout, the
  report moves to stderr so stdout stays parseable JSONL. Bare `--events` means
  stdout; `--events off` (or `none`) turns the stream off.

## Environment variables

Every flag has an `AMINA_*` equivalent; these are applied between the
configuration file and the flags. See [CONFIGURATION.md](CONFIGURATION.md) for
the full list and precedence.

`NO_COLOR` is always honoured and wins over `--color`.

## Exit codes

| Code | Name | Meaning |
|---|---|---|
| `0` | success | the assessment completed |
| `1` | runtime | a runtime failure, `--fail-on` tripped, or a timeout elapsed |
| `2` | usage | the command line was wrong, or a requested config file was missing |
| `3` | unsupported | a requested capability does not exist on this platform (`--remote`) |
| `130` | interrupted | interrupted with Ctrl+C or SIGTERM |

A module that fails is reported in the report's `limitations` array and echoed
on stderr, but does not by itself change the exit code: the other domains still
produced a usable report.

## Examples

```sh
# Assess this host and print a coloured terminal report
amina

# Quick, machine-readable report to a file
amina assess --depth quick --format json -o report.json

# In CI: fail the build on a high or critical finding
amina --format markdown -o report.md --fail-on high

# Pick specific domains
amina --include network,secret-material,remote-access

# Everything except the slow filesystem sweeps
amina --depth deep --exclude binary-integrity,metadata

# Emit the event stream to a file and the report to stdout
amina --events run.jsonl --format json

# Reproduce a known dataset instead of the live host
amina --simulate --fixture ssh-exposed

# Feed a previously recorded snapshot through the same rules
amina --fixture /path/to/snapshot.json --format json
```
