# Architecture

Amina is one Go module (`github.com/QYVORA/qyvora-amina`) with a single binary
that cross-compiles to Linux, macOS, Windows and Android (Termux). The design
rests on three ideas: capability is a runtime property, the rule engine reads a
snapshot rather than the host, and output is deterministic.

## Package map

| Package | Responsibility |
|---|---|
| `cmd/amina` | CLI entry (`ExecuteArgs`), subcommands, stream routing, report writing |
| `internal/config` | flag/env/file vocabulary, precedence, validation, provenance |
| `internal/platform` | cross-platform collectors and the capability matrix |
| `internal/safety` | declarative safety metadata for every operation |
| `internal/evidence` | evidence record collection |
| `internal/events` | the shared QYVORA JSONL event envelope |
| `internal/output` | terminal, JSON, YAML, Markdown and HTML renderers |
| `internal/exitcode` | the shared exit-code contract |
| `internal/update` | checksum-verified self-update |
| `internal/version` | build identity stamped at link time |
| `pkg/models` | report, finding and enum types |
| `pkg/modules` | the 23-module registry |
| `pkg/rules` | the 52-rule catalogue and the evaluation engine |
| `pkg/correlation` | identity correlation across collectors |
| `pkg/risk` | the published risk-scoring model |
| `pkg/simulation` | fixtures and the built-in synthetic dataset |
| `pkg/pipeline` | orchestration |

## The pipeline

`pkg/pipeline.Run` is the whole product. The stages run in a fixed order:

1. **Intake** — first config is resolved (defaults → file → env → flags), then a
   `assessment.started` event is emitted.
2. **Acquire** — a simulation loads a fixture; a host detects its own platform.
   A remote target is refused here as unsupported (exit `3`).
3. **Collect** — the selected modules run concurrently, each producing a
   `modules.Result`. Module outcomes carry a status, so "nothing found" and "not
   looked at" stay distinguishable.
4. **Build and merge** — every collector result is folded into one
   `rules.Snapshot`. Folding is a merge, not a filter: the rule engine sees one
   view of the host, not twenty-three partial ones. In simulation, the fixture
   seeds the snapshot and the report is stamped with the fixture's collection
   time.
5. **Correlate** — identity correlation runs *before* the rules, because several
   rules match on correlated identities; running it afterwards would mean those
   rules silently never fired.
6. **Evaluate** — the rule engine matches the catalogue against the snapshot,
   gating by depth and platform and recording skipped rules with a reason.
7. **Measure** — each finding is scored by `pkg/risk`, and the score and band are
   written into the finding's attributes.
8. **Finalize** — findings are sorted, the summary is built, and the integrity
   digest is stamped. `Finalize` must be the last mutation: anything added after
   it is outside the checksum.
9. **Render** — `internal/output` writes the report; the event stream has already
   been emitting alongside. Module errors are echoed on stderr and recorded in
   `limitations`.

## Runtime capability, not build tags

The platform layer answers *what can be observed here*, at runtime. A collector
that cannot work on this host reports a status rather than being absent from the
binary. This is deliberate: a collector excluded by a build tag cannot say "not
applicable on Windows", and a report that silently omits a domain reads exactly
like a clean host. Build tags are still used where parsing genuinely cannot
compile elsewhere (Windows `net user` output, macOS `dscl`, Linux `/proc` and
`/etc/passwd`).

## Determinism

Two runs over the same input produce the same report. This is enforced, not
hoped for:

- Collectors never depend on map iteration order; keys are sorted before use.
- Rules are pure with respect to the snapshot: no clock reads, no filesystem
  access, no ordering dependence.
- Findings are sorted by content, never by the random per-record id.
- The integrity digest and report id exclude random ids, the timestamp and the
  target name, because those identify the run rather than the assessment.
- Simulation stamps the fixture's collection time, so a simulated report is the
  same on every machine.

The determinism tests assert byte-identical output across repeated runs, and a
golden fixture guards the exact rendered bytes.

## Concurrency

Modules run through a bounded worker pool. `--parallelism` sets the limit;
`0` selects a default derived from the module count. Each module writes into its
own result, and the fold that follows restores a deterministic order, so
scheduling cannot change the report.

## Read-only by design

`internal/safety` states the contract every operation must satisfy:

- Nothing implemented changes state. There is no remediation, cleanup or "fix"
  verb.
- Nothing reaches the network except the self-updater, which contacts only the
  project's release endpoint and verifies a checksum before installing.
- Nothing escalates privilege. Where elevation would help, the capability reports
  `requires_privilege` and the run continues without it.
- Nothing reads another machine.

Secret material is fingerprinted *inside the collector* and never stored, so the
redaction boundary is the collector, not the renderer. A renderer cannot leak a
value it was never given.
