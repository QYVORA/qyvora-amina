# Output

Amina has two output channels: the **report** (one document) and the **event
stream** (JSONL, zero or more lines). They are independent; either can go to
stdout, stderr, or a file.

## Report formats

| Format | Flag value | Intended reader |
|---|---|---|
| terminal | `terminal` (default) | a human at a terminal; coloured when stdout is a TTY |
| JSON | `json` | another program |
| YAML | `yaml` | configuration-management pipelines |
| Markdown | `markdown` | a ticket, a PR comment, a wiki |
| HTML | `html` | a standalone artefact to attach or archive |

The terminal format cannot be written to a file: a saved report with ANSI escape
sequences is noise in every reader that opens it. Use one of the other four with
`-o`.

Colour is emitted only for the terminal format, only when stdout is a terminal,
and only when not disabled. `NO_COLOR` always wins, then `--color`/`--no-color`,
then the terminal check.

## Report schema

Schema identifier: **`qyvora.amina.report/v1`** (the `schema` field).

| Field | Type | Notes |
|---|---|---|
| `schema` | string | `qyvora.amina.report/v1` |
| `id` | string | `rep-<24 hex>`; derived from the integrity digest, so the same assessment carries the same id |
| `framework` | string | `amina` |
| `framework_version` | string | the producing build |
| `generated_at` | RFC 3339 | when the report was produced |
| `target` | object | the assessed host |
| `configuration` | map | the resolved settings the run used |
| `depth` | int | numeric depth |
| `depth_name` | string | `quick` / `standard` / `deep` |
| `duration_ms` | int | wall-clock collection time |
| `host` | object | host identity summary, when that module ran |
| `findings` | array | normalised findings, ordered by risk |
| `summary` | object | aggregates (see below) |
| `modules` | array | per-module status: how a reader tells "nothing found" from "not looked at" |
| `identities` | array | correlated operator identities |
| `secrets` | array | detected secrets as fingerprints |
| `package_sources` | array | configured package repositories |
| `software` | array | installed-software inventory |
| `assets` | array | collected evidence inventory |
| `skipped` | array | rules and modules that did not run, with the reason |
| `limitations` | array | honest-degradation statements: what this run could not see |
| `warnings` | array | non-fatal problems encountered |
| `integrity` | string | `sha256:…` over the findings and summary |
| `redaction` | object | the secret-handling policy in force |

### Module status vocabulary

`modules[].status` is what makes an absence meaningful:

| Status | Means |
|---|---|
| `assessed` | the module ran to completion |
| `degraded` / `partial` | some sources could not be read; listed in `limitations` |
| `privilege` | the module needs privileges this run did not have |
| `skipped` | the module did not run (depth, include/exclude, or platform) |

### Summary block

| Field | Means |
|---|---|
| `total` | total findings |
| `by_severity`, `by_category`, `by_state` | counts keyed by the respective value |
| `max_risk` | highest final risk score (`0` when no findings) |
| `mean_risk` | mean of the final scores, rounded down |
| `risk_band` | band implied by `max_risk` |
| `correlated` | findings produced by identity correlation |
| `identity_count` | number of correlated identities |

## Finding fields

| Field | Notes |
|---|---|
| `id` | random per-record id; deliberately excluded from the integrity digest |
| `rule_id` | which of the 52 rules produced it (see [RULES.md](RULES.md)) |
| `module_id` | which module owns the rule |
| `title`, `description`, `impact`, `recommendation`, `references` | human-facing text |
| `severity` | possibly escalated above the rule default, never downgraded |
| `confidence` | how strong the observation is |
| `status`, `state` | the finding's lifecycle/observation state |
| `exposure`, `privilege`, `sensitivity` | the dimensions feeding the risk score |
| `correlated` | true when identity correlation produced it |
| `objects` | the specific objects the finding is about |
| `evidence` | supporting evidence records |
| `attributes` | string map; carries `risk_score` and `risk_band` as formatted values |
| `timestamp` | when the finding was built |

### Sorting

Findings are ordered by descending risk, then by rule id, module id, title,
joined objects, and fingerprint. The record `id` is never used as a tiebreak: it
is random by construction, and ordering on it would turn every diff between two
assessments into noise.

## Risk scoring

Each finding is scored 0–100 from five dimensions:

```
weighted = 0.40·impact + 0.20·exploitability + 0.20·exposure + 0.10·privilege
raw      = weighted · 25 + sensitivity_bonus · 10        (clamped to 100)
final    = raw · confidence_weight
```

Input scales:

| Severity → impact | informational 1.0 · low 2.0 · medium 3.0 · high 4.0 · critical 4.0 |
|---|---|
| **Exposure** | local 0.5 · loopback 1.0 · container 2.0 · virtual 2.5 · vpn 3.0 · lan 3.5 · wildcard 4.0 · public 4.0 · unknown 2.0 |
| **Privilege** | none 4.0 · user 3.0 · elevated 2.0 · system 1.0 |
| **Sensitivity bonus** | public 0.0 · internal 0.25 · sensitive 0.5 · secret 1.0 (×10) |
| **Confidence weight** | confirmed 1.00 · observed 0.90 · probable 0.70 · possible 0.40 · not-observed 0.25 · unknown 0.15 |

Critical and high share the same impact value (4.0): the difference between
"severe" and "actively exploitable now" is carried by exposure and
exploitability, not by an extra impact point that would count the same
judgement twice.

Exploitability is inferred from exposure and privilege when a rule does not
supply it; the inference is flagged in the score output so a reader can see
which terms were assumed.

### Risk bands

| Score | Band |
|---|---|
| ≥ 90 | critical |
| ≥ 75 | high |
| ≥ 55 | elevated |
| ≥ 35 | moderate |
| ≥ 15 | low |
| < 15 | minimal |

## Integrity and determinism

`integrity` is SHA-256 over the schema, framework/version, depth name, every
finding (rule, module, title, severity, state, exposure, privilege, sensitivity,
confidence, fingerprint, objects), every secret location/fingerprint, every
identity id/canonical, every module status, and every limitation.

The per-record random ids, the report id and the timestamp are excluded, as is
the target identifier. Two runs over the same input therefore produce the same
digest, the same report id, and byte-identical reports apart from `duration_ms`
and `generated_at`. This is asserted by the determinism tests.

## Event stream

`--events` (or `AMINA_EVENTS`) enables the shared QYVORA JSONL envelope. Each
line is one JSON object:

```json
{"schema_version":"1.0","timestamp":"2026-01-01T00:00:00Z","execution_id":"…","framework":"amina","level":"info","event":"module.completed","data":{}}
```

| Field | Notes |
|---|---|
| `schema_version` | `1.0` |
| `timestamp` | RFC 3339, UTC |
| `execution_id` | random 32-hex id, one per run |
| `framework` | `amina` |
| `level` | `info`, `warning`, or `error` |
| `event` | one of the declared names below |
| `data` | event-specific payload |

Consumers key on the `event` name, never on terminal output. A single run emits a
subset of the vocabulary, in an order that depends on which modules ran and
which were fast enough to start first. Consumers must tolerate any declared name
appearing at any point rather than assume a fixed sequence.

### Event vocabulary

```
assessment.started        assessment.completed
simulation.loaded         host.detected
module.started            module.completed
module.skipped            module.failed
asset.discovered          finding.discovered       evidence.collected
capability.degraded       privilege.required       warning
error                     report.generated
identity.discovered       account.discovered       remote_access.checked
network.examined          software.discovered      package_source.seen
binary.analyzed           provenance.checked       secret.detected
secret.redacted           shell.inspected          environment.scanned
git.inspected             cloud.inspected          process.enumerated
service.discovered        persistence.found        tooling.discovered
artifact.found            posture.checked          application.found
identity.correlated       metadata.observed        risk.calculated
```

### Routing

- `--events` (bare) or `--events stdout` → stdout. The report moves to **stderr**
  so stdout stays parseable JSONL.
- `--events stderr` → stderr.
- `--events <path>` → that file (opened `0600`, appended).
- `--events off` or `--events none` → no stream.
- The interactive session and a machine event destination cannot coexist; asking
  for both is a usage error.

## Redaction

Every report carries a `redaction` block:

```json
{
  "strategy": "fingerprint-only",
  "values_retained": false,
  "note": "No secret value is stored in this report…"
}
```

A detected secret is recorded as a **salted fingerprint**, its location, and its
length. The value is discarded by the collector that read it. `values_retained`
is always `false` and is present so a reader can assert it rather than infer it.

Report files written with `-o` are created mode `0600`: a report names accounts,
paths and secret locations, so a world-readable assessment file would itself be
the exposure the tool exists to report.
