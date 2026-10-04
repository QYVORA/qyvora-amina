# QYVORA Amina

<!-- doc metadata
built from github.com/QYVORA/qyvora-amina  (Go; binary v0.1.0 baseline)
shared terminal: qyvora-tui v0.7.1  (F1 capability view, activity, forms, adaptive layout)
doc updated: 2026-10-03
-->

**Operational Security & Host Exposure Assessment Framework**

> Local host only, and read-only. Amina examines the machine it is already
> running on and never modifies it. The single exception is `amina update`,
> which replaces the binary from a checksum-verified release and asks first.

## Overview

Amina is QYVORA's open-source framework for **operational security and host
exposure assessment**. It answers one question — *what does this machine
reveal?* — by systematically collecting evidence about identity disclosure,
network and remote-access exposure, software provenance, binary integrity,
credential material, filesystem leakage, developer identity, cloud identity,
metadata, persistence, and OS hardening, then turning that evidence into
deterministic, machine-readable findings with an explicit risk score.

It runs as a one-shot CLI and as a shared interactive console, with the same
commands in both.

- Repository: https://github.com/QYVORA/qyvora-amina (Go 1.26.x, MIT)
- Status: **shipped**, v0.1.0 — 23 collectors, 52 rules, correlation, risk
  scoring, simulation mode, self-update, five output formats and reporting
  implemented and tested
- Platforms: Linux, macOS, Windows (per-OS collectors behind build tags;
  capabilities a platform cannot honour are reported as limitations rather
  than silently skipped)
- Version: `amina version` prints `v0.1.0`

## The assessment pipeline

Amina runs a nine-stage pipeline shared by its CLI and console:

```
DETECT PLATFORM → AUTHORIZE → COLLECT → CORRELATE IDENTITIES → EVALUATE RULES
  → CORRELATE FINDINGS → FINALIZE → RENDER
```

| Stage | What happens | Emitted event |
|---|---|---|
| Detect platform | identify OS, kernel, arch, capabilities | `platform.detected` |
| Authorize | confirm the target is the local host; refuse remote | `target.authorized` |
| Collect | run every selected collector over the host | `module.started` / `module.completed` / `module.skipped` / `module.failed` |
| Correlate identities | join observations about the same operator | `identity.correlated` |
| Evaluate rules | match the collected snapshot against the rule catalogue | `rule.evaluated` |
| Correlate findings | bridge findings that describe one exposure | `finding.correlated` |
| Finalize | sort deterministically, score risk, stamp integrity | `report.finalized` |
| Render | terminal, JSON, YAML, Markdown or HTML | — |

Collectors run concurrently up to `--parallelism` (default: one per CPU,
capped at 8). Concurrency is invisible in the output: outcomes are buffered per
module and replayed in registry order, so a run with one worker and a run with
eight produce the same report.

### Depth

| Depth | Effect |
|---|---|
| `--depth quick` | shallow scans, minimal I/O; deeper checks report as limitations |
| `--depth standard` (default) | normal assessment |
| `--depth deep` | exhaustive scans, materially slower |

Every stage that a depth limit skipped is listed in the report's
`limitations`, so a quiet section is never mistaken for a clean one.

### Simulation mode (`--simulate`)

`amina --simulate` runs the identical rule set against a built-in synthetic
dataset, offline. It exists so the pipeline, the rules, the renderers and the
TUI can be exercised without touching a real host.

Current simulation result: **5 findings, max risk 83, risk band high**.

## What makes it different

1. **Secrets are never recorded.** A credential found on disk is reported as a
   salted fingerprint, its location and its length. The value is discarded by
   the collector that read it, so a report can be shared without sharing the
   secret (`SEC-001`, `SEC-002`, `SEC-003`).
2. **Provenance, not just inventory.** `PRV-002` (critical) fires when a system
   binary has been modified relative to its package, and `PRV-001` when an
   executable in a system path has no package owner at all. "What is installed"
   is answered together with "where did it come from" and "can its integrity be
   verified".
3. **Operator identity is a first-class finding.** Hostname, GECOS field, git
   author identity, environment variables and document metadata are treated as
   disclosures in their own right (`IDN-001`, `ACC-004`, `IDN-003`, `META-001`).
4. **Partial reports are explicit.** A collector that cannot read something
   records *why*, and the module is marked partial or degraded. The report says
   what it did not see.
5. **Deterministic by construction.** Findings are sorted by a fixed key, the
   report ID is derived from report content, and the only volatile field is
   wall-clock duration. Two runs of the same fixture produce byte-identical
   output, which is what makes reports diffable, cacheable and signable.
6. **Read-only by construction.** Collectors open files to read and nothing else.
   The one write path in the tool is self-update, which is checksum-verified and
   gated behind a confirmation.

## Built-in rules

52 rules: **2 critical, 22 high, 14 medium, 12 low, 2 informational**.

| Rule | What it detects | Severity |
|---|---|---|
| SEC-001 | Private key material present | critical |
| PRV-002 | System binary modified relative to its package | critical |
| ACC-002 | Privileged account with authorized SSH keys | high |
| NET-001 | Service listening on a wildcard address | high |
| NET-002 | Administrative service exposed beyond this host | high |
| NET-004 | Service carrying credentials in the clear | high |
| RMT-001 | Password authentication permitted for SSH | high |
| RMT-002 | `PermitRootLogin` is not disabled | high |
| SEC-002 | Credential material present | high |
| SEC-003 | Secret material readable by other local users | high |
| PRV-001 | Executable in a system path with no package owner | high |
| PRV-004 | Package source configured without a signing key | high |
| FS-001 | World-writable file in a sensitive directory | high |
| FS-002 | Secret-material directory readable by other accounts | high |
| SHL-002 | Credential-shaped content in shell history | high |
| PER-001 | Startup entry runs a command from a user-writable location | high |
| PER-003 | Startup entry runs a hidden or obfuscated command | high |
| PRC-001 | Process command line exposes credentials or tokens | high |
| PRC-004 | Service definition references a path outside the standard locations | high |
| PST-002 | Full disk encryption not confirmed | high |
| PERM-001 | Private key file is readable by another account | high |
| PERM-002 | Credential or secret file is readable by another account | high |
| PERM-003 | Sensitive file is world-writable | high |
| CLD-002 | Cloud credential file present | high |
| ACC-001 | Interactive login shell for a service account | medium |
| ART-001 | Log or artifact directory readable beyond its owner | medium |
| IDN-003 | Git author identity configured | medium |
| META-001 | Document embeds author or organisation metadata | medium |
| META-002 | Document with embedded identity metadata is readable by other accounts | medium |
| NET-005 | Listener on a VPN or virtual interface | medium |
| PER-002 | Shell profile sources an external or generated file | medium |
| PRC-002 | Process running with an unexpected working directory | medium |
| PRC-003 | Enabled service runs as an interactive-capable account | medium |
| PRV-003 | Third-party package source configured | medium |
| PST-001 | Mandatory access control not enforcing | medium |
| SHL-001 | Shell history readable beyond its owner | medium |
| TMP-002 | Temporary directory is readable by other accounts | medium |
| TOOL-001 | Offensive security tooling is installed on this host | medium |
| APP-001 | Browser profile data is present on this host | low |
| APP-002 | Messenger or mail client data is present on this host | low |
| ART-002 | Container environment exposes the host's identity | low |
| CLD-001 | Cloud provider configuration present | low |
| IDN-001 | Hostname discloses a name or identifier | low |
| ACC-003 | Account with no last-login record | low |
| ACC-004 | Account with a human name in the GECOS field | low |
| SW-001 | Installed package records a generic or absent origin | low |
| SW-002 | Installed software is associated with a development project or employer | low |
| SW-003 | Software installed outside the system package manager | low |
| TMP-001 | Temporary directory holds a large volume of unreviewed data | low |
| TOOL-002 | Packet capture or intrusion detection tooling can observe all traffic | low |
| IDN-002 | Login name disclosed in the environment | informational |
| NET-003 | Service reachable only from this host | informational |

## Risk scoring

```
raw     = (0.40*impact + 0.20*exploitability + 0.20*exposure
           + 0.10*privilege) * 25 + sensitivity_bonus*10
raw     = clamp(raw, 0, 100)
final   = raw * confidence_weight
```

Findings are also labelled by evidence state (`observed` or `inferred`), so a
scored inference is never mistaken for a measured fact.

## Capability registry

`amina capabilities` prints the machine-readable contract; `amina capabilities
-o json` emits it as JSON with the capability list under `capabilities` and one
object per entry. The registry is generated from the module table rather than
maintained by hand, so a module cannot exist in the framework and be missing
from the interface.

All 25 capabilities are currently implemented:

| Capability | Purpose |
|---|---|
| `amina.assess.host-identity` | Decide whether the machine's own identity disclosures name its operator. |
| `amina.assess.accounts` | Decide which local accounts exist, which can log in, and which are left enabled. |
| `amina.assess.remote-access` | Decide how the host can be reached from elsewhere and how strongly it authenticates. |
| `amina.assess.network` | Decide which services are reachable from outside this host and from where. |
| `amina.assess.software` | Decide what is installed and which of it discloses the operator's work or tools. |
| `amina.assess.provenance` | Decide whether installed software is attributable to a package source. |
| `amina.assess.binary-integrity` | Decide whether executables are signed, owned by a package, or unexplained. |
| `amina.assess.package-sources` | Decide which repositories the host installs software from and which are unofficial. |
| `amina.assess.filesystem-exposure` | Decide what the filesystem layout reveals about the host and its operator. |
| `amina.assess.secret-material` | Decide which credentials exist on disk, without ever recording their values. |
| `amina.assess.shell-terminal` | Decide what shell configuration and terminal history disclose. |
| `amina.assess.environment` | Decide which environment variables disclose identity, tokens or infrastructure names. |
| `amina.assess.developer-identity` | Decide what developer tooling records about who wrote the code. |
| `amina.assess.cloud-identity` | Decide which cloud accounts, subscriptions and instance identities are configured. |
| `amina.assess.process-service` | Decide what is running, under which identity, and listening for work. |
| `amina.assess.persistence` | Decide what will run again after a reboot or login without anyone choosing it. |
| `amina.assess.tooling` | Decide which security and development tools disclose their presence or their history. |
| `amina.assess.artifacts-logs` | Decide what local logs and artifacts accumulate and who can read them. |
| `amina.assess.browser-apps` | Decide what user application data directories disclose by existing at all. |
| `amina.assess.os-posture` | Decide which host hardening settings would change the outcome of the other findings. |
| `amina.assess.file-permissions` | Decide which sensitive files are readable or writable by accounts that should not reach them. |
| `amina.assess.temp-cache` | Decide what survives in temporary directories that nobody intends to keep. |
| `amina.assess.metadata` | Decide what file and document metadata carries that the filenames do not. |
| `amina.simulate.run` | Run the identical rule set against the built-in synthetic dataset. |
| `amina.selfupdate.apply` | Replace this binary from a checksum-verified release. **The only operation that changes the host.** |

Every assessment capability reports `authorization_required: false`, which is
the honest answer: Amina reads the machine it is already running on and asks
nobody's permission to do it. `selfupdate.apply` is the single exception and is
marked `authorization_required: true` and `confirmation_required: true`.

## Self-update

```
amina update                # check, confirm, then install
amina update --check        # verify and report, install nothing
amina update --dry-run      # same, without contacting the network
amina update --version v0.2.0
```

The updater downloads `amina-<os>-<arch>` plus `checksums.txt` from the GitHub
release, verifies the SHA-256 before writing anything, refuses plain HTTP, and
replaces the binary atomically. Go's `darwin` maps to the release token `macos`,
matching the published artifact names. A checksum mismatch aborts the install.

## CLI

```
amina [assess] [flags]       run an assessment (default)
amina tui                    open the interactive console
amina capabilities [-o json] print the capability registry
amina update [flags]         checksum-verified self-update
amina version [-o json]      print the version
```

Flags: `--depth`, `--format`, `-o/--output`, `--events`, `--min-severity`,
`--fail-on`, `--include`, `--exclude`, `--parallelism`, `--simulate`,
`--fixture`, `--color/--no-color`, `--timeout`, `--config`, `--version`.

Exit codes: `0` success, `1` runtime failure, `2` usage error, `3` unsupported,
`130` interrupted.

A bare run on a terminal opens the TUI; the same run with stdout redirected
performs the assessment instead. Requesting a machine event destination while
running interactively is refused *before* the destination is created or
truncated, so a refused run never destroys an existing file.

Configuration precedence is defaults → file → environment → flags, and the
report records where each setting came from.

## TUI integration

Amina uses the shared `qyvora-tui` v0.7.1 console. A bare invocation opens the
interactive session; typed commands are executed in-process through the same
`ExecuteArgs` entry point the CLI uses, so the console and the command line
cannot drift apart. The registry above is the F1 capability view's data source.

## Output formats

`terminal`, `json`, `yaml`, `markdown`, `html`. All five are covered by
committed golden files, so a rendering change that alters a byte is a test
failure rather than a surprise.

The JSONL event stream follows the ecosystem output spec with `schema_version`,
`execution_id` and `framework` fields, and can go to stdout, stderr or a file —
independently of where the report itself is written.

## Boundaries (deliberate)

- **Local host only.** `--remote` is refused with exit `3`. Amina will not
  assess a machine it is not running on.
- **Read-only.** No collector writes to the host. `amina update` is the only
  exception and is the only capability flagged as changing state.
- **No secret values in output.** Fingerprints, locations and lengths only.
- **Coverage is the observer's.** Findings describe what an unprivileged local
  account could observe; they are not a statement about an attacker who has
  already obtained root.

## Verification

| Check | Result |
|---|---|
| `gofmt -l` | clean |
| `go vet ./...` | clean |
| `go test ./...` | all packages pass |
| `go test -race ./...` | all packages pass, including a live-host run |
| Golden output suite | 5 formats, byte-compared |
| `qyvora-conformance --bin amina:amina` | 1/1 frameworks fully conformant |
| `qyvora-dist` full suite | 1221 assertions, 0 failing suites (14 tools) |

Determinism is tested rather than asserted: the same fixture rendered at
`--parallelism` 1, 2, 4, 8 and 64 produces identical bytes, and module order is
checked directly so a failure names the cause.

## Known limitations

- Cloud and browser collectors read on-disk configuration and data directories.
  They do not call provider APIs and cannot report live account state.
- MAC metadata is read from container formats (e.g. OLE/Office); full EXIF and
  PDF inspection is out of scope.
- The risk model is a fixed weighting, not a calibrated probability. It is
  meant to rank findings within one report, not to predict exploitation.

## Future work

- Calibrate confidence weights against observed outcomes rather than defaults.
- Recorded host fixtures (`--fixture <path>`) to make live-host runs
  reproducible the way simulation already is.
- Remediation guidance per rule, emitted alongside the finding rather than
  inferred from it.

## Links

- Documentation index: [docs/](docs/README.md)
- CLI reference: [docs/CLI.md](docs/CLI.md)
- Configuration: [docs/CONFIGURATION.md](docs/CONFIGURATION.md)
- Modules: [docs/MODULES.md](docs/MODULES.md) · Rules: [docs/RULES.md](docs/RULES.md)
- Output and event stream: [docs/OUTPUT.md](docs/OUTPUT.md)
- Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Installing and updating: [docs/UPDATING.md](docs/UPDATING.md)
- Development: [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)
- QYVORA organisation: https://github.com/QYVORA

## About QYVORA

**QYVORA is an African cybersecurity company — built in Tamale, Ghana, serving the
whole continent.** Its mission is to build Africa's strongest cybersecurity
ecosystem and develop the talent to run it.

Amina is part of a fourteen-framework open-source offensive security toolkit. The
frameworks are unrestricted free software, published for defenders and researchers
across Africa and beyond.

- Company and services: https://qyvora.org
- All frameworks: https://github.com/QYVORA

## Contact

QYVORA OffSec — Tamale, Ghana
Website: https://qyvora.org · Security/Support: qyvorasec@gmail.com

---

Amina is the fourteenth QYVORA security framework. The ecosystem now contains
fourteen active frameworks: Aksum, Amanirenas, Amina, Anansi, Imhotep, Jabari,
Kush, Mansa, Nzinga, Sekhmet, Shaka, Sundiata, Timbuktu and Toha3ee.
