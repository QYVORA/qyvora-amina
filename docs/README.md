# Amina documentation

Amina is QYVORA's operational security and host exposure assessment framework.
It examines the machine it is already running on, records what that machine
reveals about itself and its operator, and produces a deterministic report.

> **Local host only, read-only.** Amina never modifies the host it assesses.
> The one exception is `amina update`, which replaces its own binary from a
> checksum-verified release and asks for confirmation first.

## Start here

| Document | Read it when you want to… |
|---|---|
| [CLI.md](CLI.md) | run Amina, look up a flag, or script it in CI |
| [CONFIGURATION.md](CONFIGURATION.md) | set defaults in a file or environment instead of typing flags |
| [MODULES.md](MODULES.md) | know which of the 23 assessment domains runs, and when |
| [RULES.md](RULES.md) | know exactly what the 52 rules detect and how severe each is |
| [OUTPUT.md](OUTPUT.md) | consume the report, the JSONL event stream, or the report schema |
| [ARCHITECTURE.md](ARCHITECTURE.md) | understand the pipeline and why the output is deterministic |
| [UPDATING.md](UPDATING.md) | self-update, or understand how releases are built and named |
| [DEVELOPMENT.md](DEVELOPMENT.md) | build, test and release from source |

## The one-paragraph version

Amina runs a nine-stage pipeline: detect the platform, authorize the target, run
the collectors, correlate identities, evaluate the rule catalogue, correlate
findings, finalize (sort, score, stamp integrity) and render. It supports five
output formats and a JSONL event stream, runs as a one-shot CLI or the shared
`qyvora-tui` console, and is deterministic by construction: two runs over the
same input produce byte-identical output apart from wall-clock duration.

## Boundaries

These are deliberate, not limitations waiting to be fixed:

- **Local host only.** `--remote` is refused with exit code `3`. Amina will not
  assess a machine it is not running on.
- **Read-only.** No collector writes to the host. `amina update` is the only
  operation that changes anything, and the only capability flagged
  `changes_state: true`.
- **No secret values in output.** A secret is reported as a salted fingerprint,
  its location, and its length. The value is discarded by the collector that
  read it.
- **Coverage reflects an unprivileged observer.** Findings describe what a local
  account could see; they are not a claim about what root could see.
