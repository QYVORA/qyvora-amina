# Configuration

Amina resolves every setting from three layers. Later layers win:

```
defaults  →  configuration file  →  AMINA_* environment  →  command-line flags
```

A flag that was not supplied never overrides a value from the file or the
environment. Presence is tracked separately from value, so `--color=false` and
an absent `--color` are different inputs.

## Defaults

| Setting | Default |
|---|---|
| depth | `standard` (level 2) |
| format | `terminal` |
| output | `-` (stdout) |
| events | off |
| min-severity | `low` |
| fail-on | never |
| parallelism | `0` (automatic) |
| colour | on only when stdout is a terminal |
| offline | off |
| target | the hostname |
| profile | empty |

> `min-severity` defaults to `low`, so `informational` findings are omitted from
> the rendered report unless you lower it. They still appear in the event stream
> and still contribute to the risk score.

A report in `terminal` format cannot be written to a file; selecting `-o` with
the terminal format is an error. Choose `json`, `yaml`, `markdown` or `html`.

## Configuration file

Amina reads JSON. Simple `key: value` YAML is also accepted on read, because
operators type `.yaml` out of habit — but JSON is the format to rely on.

An unreadable or malformed file that was found (or explicitly requested) is a
usage error, not a warning. Running with defaults after a file failed to parse
would produce a report that looks authoritative and is not.

### Discovery order

The first existing path wins:

1. `$AMINA_CONFIG_DIR/amina.yaml`, then `$AMINA_CONFIG_DIR/amina.json`
2. `~/.config/amina/config.json`
3. `~/.config/amina/config.yaml`
4. `~/.amina.yaml`
5. `~/.amina/config.json`
6. `<directory of the amina binary>/amina.yaml`
7. `<directory of the amina binary>/amina.json`

There is deliberately no system-wide path. A tool that reads its configuration
from a machine-wide location lets anyone who can write that path decide what the
assessment does.

Use `--config <path>` to name a file explicitly; if it does not exist that is an
error.

### Keys

```json
{
  "depth": "deep",
  "format": "json",
  "output": "reports/amina.json",
  "events": true,
  "events_out": "reports/amina.jsonl",
  "color": false,
  "profile": "baseline-2026-q1",
  "include": ["network", "secret-material"],
  "exclude": ["metadata"],
  "min_severity": "medium",
  "fail_on": "high",
  "offline": true,
  "parallelism": 4,
  "target": "build-runner-07",
  "remote": false
}
```

| Key | Type | Notes |
|---|---|---|
| `depth` | string | `quick`, `standard`, `deep`, or `1`–`3` |
| `format` | string | `terminal`, `json`, `yaml`, `markdown`, `html` |
| `output` | string | report path; `-` is stdout |
| `events` | bool | enable the JSONL event stream |
| `events_out` | string | event destination; implies `events: true` |
| `color` | bool | force colour on or off |
| `profile` | string | free-form label recorded in the report |
| `include` | string list | modules to run exclusively |
| `exclude` | string list | modules to skip |
| `min_severity` | string | `informational`, `low`, `medium`, `high`, `critical` |
| `fail_on` | string | severity threshold for a non-zero exit |
| `offline` | bool | assert that no network access is made |
| `parallelism` | int | concurrent collectors; `0` is automatic |
| `target` | string | label recorded in the report |
| `remote` | bool | unsupported; set to `true` to be refused with exit `3` |

In the file, `include` and `exclude` are JSON arrays (a comma-separated string is
also accepted). On the command line and in the environment they are a single
comma-separated list, not repeated flags.

## Environment variables

| Variable | Equivalent |
|---|---|
| `AMINA_DEPTH` | `--depth` |
| `AMINA_FORMAT` | `--format` |
| `AMINA_OUTPUT` | `--output` |
| `AMINA_EVENTS` | `--events` (destination: `true`/empty = stdout, `false` = off, else a path) |
| `AMINA_COLOR` | `--color` |
| `AMINA_NO_COLOR` | `--no-color` |
| `AMINA_PROFILE` | `--profile` |
| `AMINA_INCLUDE` | `--include` |
| `AMINA_EXCLUDE` | `--exclude` |
| `AMINA_MIN_SEVERITY` | `--min-severity` |
| `AMINA_FAIL_ON` | `--fail-on` |
| `AMINA_OFFLINE` | `--offline` |
| `AMINA_PARALLELISM` | `--parallelism` |
| `AMINA_TARGET` | `--target` |
| `AMINA_REMOTE` | `--remote` |
| `AMINA_CONFIG_DIR` | directory scanned first for a config file |
| `AMINA_NO_CONFIG` | reserved; skip config discovery |

An unrecognised `AMINA_*` variable is an error. This is intentional: a typo like
`AMINA_MIN_SEVERITYY` should not silently do nothing.

`NO_COLOR` is always honoured, even when nothing set it explicitly, and wins
over `--color`. It is recorded in the report's configuration provenance.

## Validation

The resolved configuration is rejected before any collection starts when:

- `--fail-on` is below `--min-severity`, so the run could never fail on it;
- `--parallelism` or `--timeout` is negative;
- an `--include` or `--exclude` value names a module that does not exist;
- `--events` names an unknown bare word (it must be `stdout`, `stderr`, a path,
  `off`, or `none`).

## Provenance

The resolved configuration carries a `source` map recording where each value
came from (`file`, `env`, `flag`, or `default`). This is what makes "why did it
use deep?" answerable without re-reading three layers of configuration.
