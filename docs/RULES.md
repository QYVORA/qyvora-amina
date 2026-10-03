# Rules

Amina ships **52 rules**. Each rule has an ID, a default severity, a category,
and a minimum depth. Every finding in a report names the rule that produced it,
so this list is the ground truth for what a report means.

## Severity

| Severity | Weight | Rank | Meaning |
|---|---|---|---|
| `critical` | 4 | 5 | Material is already exposed as a direct consequence of this condition |
| `high` | 3 | 4 | Exploitable with the access a local observer already has |
| `medium` | 2 | 3 | Strengthens an attack path or confirms a weaker exposure |
| `low` | 1 | 2 | Discloses information that is useful when combined with other findings |
| `informational` | 0 | 1 | A context observation, not a defect |

The default `--min-severity` is `low`, so `informational` findings are omitted
from the rendered report unless you pass `--min-severity informational`. A rule
can escalate a finding's severity when a match is worse than the default; it can
never be downgraded by a weaker observation of the same issue.

## Distribution

| Severity | Count |
|---|---|
| critical | 2 |
| high | 22 |
| medium | 14 |
| low | 12 |
| informational | 2 |
| **total** | **52** |

Domain is the finding category, not the module that owns the rule; the two
usually match but not always.

## Critical

| ID | Rule | Domain | Depth |
|---|---|---|---|
| `PRV-002` | System binary modified relative to its package | integrity | 1 |
| `SEC-001` | Private key material present | secrets | 1 |

## High

| ID | Rule | Domain | Depth |
|---|---|---|---|
| `ACC-002` | Privileged account with authorized SSH keys | account | 1 |
| `CLD-002` | Cloud credential file present | credentials | 1 |
| `FS-001` | World-writable file in a sensitive directory | filesystem | 1 |
| `FS-002` | Secret-material directory readable by other accounts | filesystem | 1 |
| `NET-001` | Service listening on a wildcard address | network | 1 |
| `NET-002` | Administrative service exposed beyond this host | remote_access | 1 |
| `NET-004` | Service carrying credentials in the clear | authentication | 1 |
| `PER-001` | Startup entry runs a command from a user-writable location | persistence | 3 |
| `PER-003` | Startup entry runs a hidden or obfuscated command | persistence | 3 |
| `PERM-001` | Private key file is readable by another account | filesystem | 1 |
| `PERM-002` | Credential or secret file is readable by another account | filesystem | 1 |
| `PERM-003` | Sensitive file is world-writable | filesystem | 1 |
| `PRC-001` | Process command line exposes credentials or tokens | process | 1 |
| `PRC-004` | Service definition references a path outside the standard locations | process | 1 |
| `PRV-001` | Executable in a system path with no package owner | provenance | 1 |
| `PRV-004` | Package source configured without a signing key | provenance | 1 |
| `PST-002` | Full disk encryption not confirmed | exposure | 1 |
| `RMT-001` | Password authentication permitted for SSH | remote_access | 1 |
| `RMT-002` | PermitRootLogin is not disabled | remote_access | 1 |
| `SEC-002` | Credential material present | credentials | 1 |
| `SEC-003` | Secret material readable by other local users | filesystem | 1 |
| `SHL-002` | Credential-shaped content in shell history | shell | 1 |

## Medium

| ID | Rule | Domain | Depth |
|---|---|---|---|
| `ACC-001` | Interactive login shell for a service account | account | 1 |
| `ART-001` | Log or artifact directory readable beyond its owner | logging | 1 |
| `IDN-003` | Git author identity configured | git | 1 |
| `META-001` | Document embeds author or organisation metadata | privacy | 3 |
| `META-002` | Document with embedded identity metadata is readable by other accounts | privacy | 3 |
| `NET-005` | Listener on a VPN or virtual interface | network | 1 |
| `PER-002` | Shell profile sources an external or generated file | persistence | 3 |
| `PRC-002` | Process running with an unexpected working directory | process | 1 |
| `PRC-003` | Enabled service runs as an interactive-capable account | process | 1 |
| `PRV-003` | Third-party package source configured | software | 1 |
| `PST-001` | Mandatory access control not enforcing | configuration | 1 |
| `SHL-001` | Shell history readable beyond its owner | shell | 1 |
| `TMP-002` | Temporary directory is readable by other accounts | privacy | 1 |
| `TOOL-001` | Offensive security tooling is installed on this host | tooling | 1 |

## Low

| ID | Rule | Domain | Depth |
|---|---|---|---|
| `ACC-003` | Account with no last-login record | account | 1 |
| `ACC-004` | Account with a human name in the GECOS field | metadata | 1 |
| `APP-001` | Browser profile data is present on this host | privacy | 1 |
| `APP-002` | Messenger or mail client data is present on this host | privacy | 1 |
| `ART-002` | Container environment exposes the host's identity | exposure | 1 |
| `CLD-001` | Cloud provider configuration present | cloud | 1 |
| `IDN-001` | Hostname discloses a name or identifier | identity | 1 |
| `SW-001` | Installed package records a generic or absent origin | software | 1 |
| `SW-002` | Installed software is associated with a development project or employer | software | 1 |
| `SW-003` | Software installed outside the system package manager | software | 1 |
| `TMP-001` | Temporary directory holds a large volume of unreviewed data | privacy | 1 |
| `TOOL-002` | Packet capture or intrusion detection tooling can observe all traffic | tooling | 1 |

## Informational

| ID | Rule | Domain | Depth |
|---|---|---|---|
| `IDN-002` | Login name disclosed in the environment | metadata | 1 |
| `NET-003` | Service reachable only from this host | exposure | 2 |

## Rule IDs and prefixes

The prefix names the original domain family, not the owning module: for example
`ACC-*` rules live under the **accounts** module while `PRV-*` rules are split
across **provenance**, **binary-integrity** and **package-sources**. Treat the
report's `rule_id` and `module_id` as independent fields.
