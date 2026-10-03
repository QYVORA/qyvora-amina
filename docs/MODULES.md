# Modules

Amina has **23 assessment modules**. Each is a named domain with a purpose, a
minimum depth at which it is honest, and a set of platforms it supports. All 23
are implemented in this build.

A module is not a script that runs a fixed command. It reads from the shared
snapshot, and its rules decide what the snapshot means. Running a module always
produces either findings or an explicit "nothing to report", never a silent gap.

## Depth gating

`--depth` selects a level; a module whose minimum depth is higher than the
selected level is recorded as **skipped** (visible in the report), not as clean.

| Level | Name | Modules that run |
|---|---|---|
| `1` | quick | the 6 depth-1 modules |
| `2` | standard (default) | depth-1 + depth-2 modules (21 total) |
| `3` | deep | all 23 |

The two depth-3 modules are the expensive filesystem-wide sweeps. A quick scan
skips them and says so, rather than implying the host is clean.

## Depth 1 — quick and above

| ID | Name | Category | Spec § | Platforms |
|---|---|---|---|---|
| `host-identity` | Host Identity | metadata | 8 | linux, darwin, windows, termux |
| `accounts` | User and Account Audit | account | 9 | linux, darwin, windows, termux |
| `remote-access` | SSH and Remote Access | remote_access | 10 | linux, darwin, windows, termux |
| `network` | Network Exposure | network | 11 | linux, darwin, windows, termux |
| `software` | Software Inventory | software | 12 | linux, darwin, windows, termux |
| `environment` | Environment Variables | exposure | 19 | linux, darwin, windows, termux |

- **Host Identity** — decides whether the machine's own identity disclosures name
  its operator.
- **User and Account Audit** — decides which local accounts exist, which can log
  in, and which are left enabled.
- **SSH and Remote Access** — decides how the host can be reached from elsewhere
  and how strongly it authenticates.
- **Network Exposure** — decides which services are reachable from outside this
  host and from where.
- **Software Inventory** — decides what is installed and which of it discloses
  the operator's work or tools.
- **Environment Variables** — decides which environment variables disclose
  identity, tokens or infrastructure names.

## Depth 2 — standard and above

| ID | Name | Category | Spec § | Platforms |
|---|---|---|---|---|
| `provenance` | Software Provenance | provenance | 13 | linux, darwin, windows, termux |
| `package-sources` | Package Source Audit | provenance | 15 | linux, darwin, windows, termux |
| `filesystem-exposure` | Filesystem Exposure | filesystem | 16 | linux, darwin, windows, termux |
| `secret-material` | Secret Detection | secrets | 17 | linux, darwin, windows, termux |
| `shell-terminal` | Shell and Terminal Exposure | shell | 18 | linux, darwin, termux |
| `developer-identity` | Git and Developer Identity | git | 20 | linux, darwin, windows, termux |
| `cloud-identity` | Cloud and Infrastructure Identity | cloud | 21 | linux, darwin, windows, termux |
| `process-service` | Process and Service Audit | process | 22 | linux, darwin, windows, termux |
| `tooling` | Development and Security Tooling | tooling | 24 | linux, darwin, windows, termux |
| `artifacts-logs` | Logging and Local Artifacts | logging | 25 | linux, darwin, windows, termux |
| `browser-apps` | Browser and User Application Exposure | privacy | 26 | linux, darwin, windows, termux |
| `os-posture` | OS Security Posture | configuration | 27 | linux, darwin, windows, termux |
| `file-permissions` | File Permissions | filesystem | 28 | linux, darwin, windows, termux |
| `temp-cache` | Temporary and Cache Data | privacy | 29 | linux, darwin, windows, termux |

- **Software Provenance** — decides whether installed software is attributable to
  a package source.
- **Package Source Audit** — decides which repositories the host installs
  software from and which are unofficial.
- **Filesystem Exposure** — decides what the filesystem layout reveals about the
  host and its operator.
- **Secret Detection** — decides which credentials exist on disk, without ever
  recording their values.
- **Shell and Terminal Exposure** — decides what shell configuration and terminal
  history disclose. Not available on Windows.
- **Git and Developer Identity** — decides what developer tooling records about
  who wrote the code.
- **Cloud and Infrastructure Identity** — decides which cloud accounts,
  subscriptions and instance identities are configured.
- **Process and Service Audit** — decides what is running, under which identity,
  and listening for work.
- **Development and Security Tooling** — decides which security and development
  tools disclose their presence or their history.
- **Logging and Local Artifacts** — decides what local logs and artifacts
  accumulate and who can read them.
- **Browser and User Application Exposure** — decides what user application data
  directories disclose by existing at all.
- **OS Security Posture** — decides which host hardening settings would change
  the outcome of the other findings.
- **File Permissions** — decides which sensitive files are readable or writable
  by accounts that should not reach them.
- **Temporary and Cache Data** — decides what survives in temporary directories
  that nobody intends to keep.

## Depth 3 — deep only

| ID | Name | Category | Spec § | Platforms |
|---|---|---|---|---|
| `binary-integrity` | Binary Integrity | integrity | 14 | linux, darwin, windows, termux |
| `persistence` | Persistence and Startup | persistence | 23 | linux, darwin, windows, termux |
| `metadata` | Metadata Exposure | metadata | 30 | linux, darwin, windows, termux |

- **Binary Integrity** — decides whether executables are signed, owned by a
  package, or unexplained. The system-wide sweep is what makes this a deep-only
  module.
- **Persistence and Startup** — decides what will run again after a reboot or
  login without anyone choosing it.
- **Metadata Exposure** — decides what file and document metadata carries that
  the filenames do not.

## Selecting modules

```sh
amina --include network,secret-material,remote-access
amina --exclude binary-integrity,metadata
amina --depth deep --exclude metadata
```

An unknown module name is a usage error. Run `amina capabilities` for the
authoritative list; the registry is generated from this table, so it cannot
drift from it.
