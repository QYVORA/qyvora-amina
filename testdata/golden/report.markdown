# Amina Operational Security Assessment

- **Host:** build-01 · linux
- **Assessed:** 2023-11-14T22:13:20Z
- **Depth:** standard
- **Report ID:** rep-196f434e264d42e79bee766f
- **Integrity:** `sha256:196f434e264d42e79bee766f4894709baaf3abaa1e876fe18a79275f5c593869`

## Summary

| Metric | Value |
| --- | --- |
| Findings | 5 |
| Scope assessed | standard depth |
| Highest risk | HIGH (83) |
| Mean risk | 58 |
| Correlated findings | 0 |
| Operator identities | 1 |
| High severity | 3 |
| Low severity | 1 |
| Informational severity | 1 |

## What this run did not see

A finding is only as good as the coverage behind it. The following were not fully assessed:

- Binary Integrity: not assessed (requires depth 3 (running at 2))
- Metadata Exposure: not assessed (requires depth 3 (running at 2))
- Persistence and Startup: not assessed (requires depth 3 (running at 2))
- 5 rule(s) not evaluated (requires depth 3, running at 2): META-001, META-002, PER-001, PER-002, PER-003

## Correlated operator identities

Signals from different modules that resolve to the same operator:

| Identity | Strength | Signals | Domains |
| --- | --- | --- | --- |
| `aisha@corp.example` | 23 | 1 | mail |

## Findings

### High Service sshd listening on all interfaces, port 22

- **Rule:** `NET-001`
- **Module:** `network`
- **Category:** network
- **Risk:** 83 (high)
- **Confidence:** observed
- **State:** observed
- **Exposure:** wildcard
- **Privilege:** none
- **Sensitivity:** internal

**Applies to**

- `0.0.0.0:22`

A socket bound to a wildcard address accepts connections from every network the host is attached to, not only from this machine.

**Impact.** A socket bound to a wildcard address accepts connections from every network the host is attached to, not only from this machine.

**Recommendation.** Bind to a specific interface or to loopback unless remote reachability is intended.

### High Secure Shell exposed on port 22

- **Rule:** `NET-002`
- **Module:** `network`
- **Category:** remote_access
- **Risk:** 83 (high)
- **Confidence:** observed
- **State:** observed
- **Exposure:** wildcard
- **Privilege:** none
- **Sensitivity:** internal

**Applies to**

- `0.0.0.0:22`

A remote-administration port bound to a wildcard address is reachable from every network the host touches.

**Impact.** A remote-administration port bound to a wildcard address is reachable from every network the host touches.

**Recommendation.** Restrict the listener to loopback or a VPN interface, and require a jump host for administrative access.

### High Credential material present

- **Rule:** `SEC-002`
- **Module:** `secret-material`
- **Category:** credentials
- **Risk:** 75 (high)
- **Confidence:** confirmed
- **State:** observed
- **Exposure:** local
- **Privilege:** user
- **Sensitivity:** secret

**Applies to**

- `/home/aisha/.aws/credentials`

A credential stored in a file is readable by every process running as that user and by anything that later obtains them.

**Impact.** A credential stored in a file is readable by every process running as that user and by anything that later obtains them.

**Recommendation.** Move the credential to a secret store or an agent, and rotate the exposed value.

### Informational Login name disclosed in the environment

- **Rule:** `IDN-002`
- **Module:** `environment`
- **Category:** metadata
- **Risk:** 33 (low)
- **Confidence:** observed
- **State:** observed
- **Exposure:** local
- **Privilege:** user
- **Sensitivity:** internal

**Applies to**

- `aisha`

The login name travels with many ordinary operations and appears in logs, prompts and process listings.

**Impact.** The login name travels with many ordinary operations and appears in logs, prompts and process listings.

**Recommendation.** Use a generic service account name for anything that runs unattended.

### Low Account with no last-login record

- **Rule:** `ACC-003`
- **Module:** `accounts`
- **Category:** account
- **Risk:** 19 (low)
- **Confidence:** possible
- **State:** inferred
- **Exposure:** local
- **Privilege:** user
- **Sensitivity:** internal

**Applies to**

- `aisha`

An interactive account with no observable last-login record may be dormant, which keeps an unnecessary authentication path alive.

**Impact.** An interactive account with no observable last-login record may be dormant, which keeps an unnecessary authentication path alive.

**Recommendation.** Confirm the account is still required; disable or remove it otherwise.

## Secret material on disk

Values are not stored in this report. Each is recorded as a salted fingerprint.

| Type | Location | Field | Fingerprint | Length |
| --- | --- | --- | --- | --- |
| token | `/home/aisha/.aws/credentials:3` | `aws_secret_access_key` | `0a1b2c3d4e5f60718293a4b5c6d7e8f` | 40 |

## Package sources

| Provider | URI | Trust | Keys | Enabled |
| --- | --- | --- | --- | --- |
| apt | `http://archive.ubuntu.com/ubuntu` | official | 3 | true |
| pip | `https://pypi.org/simple` | official | 0 | true |

## Module coverage

| Module | Status | Assets | Findings | Detail |
| --- | --- | --- | --- | --- |
| User and Account Audit | complete | 0 | 0 |  |
| Logging and Local Artifacts | complete | 0 | 0 |  |
| Binary Integrity | skipped | 0 | 0 | requires depth 3 (running at 2) |
| Browser and User Application Exposure | complete | 0 | 0 |  |
| Cloud and Infrastructure Identity | complete | 0 | 0 |  |
| Git and Developer Identity | complete | 0 | 0 |  |
| Environment Variables | complete | 0 | 0 |  |
| File Permissions | complete | 0 | 0 |  |
| Filesystem Exposure | complete | 0 | 0 |  |
| Host Identity | complete | 0 | 0 |  |
| Metadata Exposure | skipped | 0 | 0 | requires depth 3 (running at 2) |
| Network Exposure | complete | 0 | 0 |  |
| OS Security Posture | complete | 0 | 0 |  |
| Package Source Audit | complete | 0 | 0 |  |
| Persistence and Startup | skipped | 0 | 0 | requires depth 3 (running at 2) |
| Process and Service Audit | complete | 0 | 0 |  |
| Software Provenance | complete | 0 | 0 |  |
| SSH and Remote Access | complete | 0 | 0 |  |
| Secret Detection | complete | 0 | 0 |  |
| Shell and Terminal Exposure | complete | 0 | 0 |  |
| Software Inventory | complete | 0 | 0 |  |
| Temporary and Cache Data | complete | 0 | 0 |  |
| Development and Security Tooling | complete | 0 | 0 |  |

---

_Redaction: fingerprint-only. No secret value is stored in this report. Each secret is recorded as a salted fingerprint, its location and its length; the value itself is discarded by the collector that read it._
_Generated by amina v0.1.0 on 2023-11-14T22:13:20Z._
