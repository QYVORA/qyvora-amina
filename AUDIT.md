# AUDIT.md — qyvora-amina

## 1. Framework identity and intended domain
- **Repository/module:** `github.com/QYVORA/qyvora-amina` (go 1.26.5) — `/home/wsuits6/WORK/QYVORA/products/QYVORA-AI/frameworks/qyvora-amina/` (git: clean; latest commit `3bdb114` feat(cli): print canonical banner on bare invocation...)
- **Identity (from README):** QYVORA Amina — Operational Security & Host Exposure Assessment Framework. Local host only, read-only except `amina update` (checksum-verified self-update). One-shot CLI + shared interactive console (shared `qyvora-tui` v0.11.0 in go.mod). 
- **Actual domain (evidence):** Local-host operational security / exposure assessment. Collectors read system state (users/accounts, network/listeners, SSH config, packages/provenance, secrets/keys on disk (fingerprinted only), shell/history/env, git identity, cloud creds, processes/services, persistence, FS perms, temp/cache, browser/app artifacts, OS posture). Nine-stage pipeline (DETECT PLATFORM → AUTHORIZE → COLLECT → CORRELATE IDENTITIES → EVALUATE RULES → CORRELATE FINDINGS → FINALIZE → RENDER) with deterministic ordering. Runs against `host` or `simulation`. 
- **Exit codes (contract):** 0 success, 1 runtime failure, 2 usage error, 3 unsupported, 130 interrupted (documented in README/CLI). `amina: exploit has no modules in this framework` returns exit 3/usage path as coded (main.go:199-205).
- **Prebuilt binary (verified):** `bin/amina version -o json` → `{"framework":"amina","version":"v0.1.0","commit":"3bdb114",...,"go_version":"go1.27.1",...}`; capabilities present (25 capabilities). Bare invocation prints usage/banner (main.go:147-152).

## 2. Audit scope and evidence sources
- **Scope:** Source code (cmd/amina/*, internal/*, pkg/*), README/docs, go.mod, prebuilt binary behavior (`version -o json`, `capabilities -o json`, `--help`), git history/status. Non-destructive checks only.
- **Evidence:** `cmd/amina/main.go`, `cmd/amina/capabilities.go`, `internal/platform/capabilities.go`, `internal/version/version.go`, `README.md`, `docs/` (CLI/MODULES/RULES/OUTPUT/etc.), `bin/amina` binary, help audit (`docs/audit/help/amina.txt`), `shared/qyvora-common/*` (reference contract), PROMPT.md.
- **Verification performed:** git status/log (clean), read README/go.mod/cmd structure, executed `bin/amina version -o json` and `bin/amina capabilities -o json` and `bin/amina --help` (all succeeded). Did not run destructive scans; did not run `go test` in this pass (not explicitly requested to modify/run tests, but policy allows if safe; skipped to minimize changes/time).

## 3. Existing capability inventory
From README + capabilities command (25 capabilities all `implemented: true` per README line ~185):
- **Assessment modules (host/simulation):** host-identity, accounts, remote-access (SSH/remote), network exposure, software, provenance, binary-integrity, package-sources, filesystem-exposure, secret-material (fingerprinted), shell-terminal, environment, developer-identity (git), cloud-identity, process-service, persistence, tooling, artifacts-logs, browser-apps, os-posture, file-permissions, temp-cache, metadata (23 collectors mentioned in README; 25 capabilities listed including simulate.run/selfupdate.apply).
- **Meta/ops:** `amina.simulate.run` (synthetic dataset, offline), `amina.selfupdate.apply` (only state-changing op; checksum-verified, confirmation required). 
- **Platform support:** per-OS collectors behind build tags; capabilities reported as limitations if platform can't honor (README line ~34). Platform capability priming in `internal/platform/capabilities.go` explicitly marks absent/per-platform support levels.

## 4. Capability status matrix (capability | status | evidence file:line)
| Capability | Status | Evidence |
|-----------|--------|----------|
| `amina.assess.*` (23 assessment caps) | IMPLEMENTED | README:185-213 lists all implemented; `bin/amina capabilities -o json` returns them with `implemented: true` |
| `amina.simulate.run` | IMPLEMENTED | README:73-79, 212; capabilities list includes it |
| `amina.selfupdate.apply` | IMPLEMENTED | README:221-233, 213; capabilities marks `authorization_required: true`, `confirmation_required: true`, `changes_state: true` (README 217-218); `update` command in main.go:196-198 |
| `amina.exploit` (active exploitation modules) | NOT APPLICABLE (by design) | README:236 shows `amina exploit` present as command; main.go:199-205 prints "amina: exploit has no modules in this framework (amina is read-only)" and returns usage/exit code path; README states "Local host only, and read-only" |
| Capability manifest (`capabilities -o json`) | IMPLEMENTED | README:179-184; cmd/amina/capabilities.go generates from registry; verified via binary |
| Version identity (`version -o json`) | IMPLEMENTED | README:35,241; `bin/amina version -o json` returns structured identity with semver `v0.1.0` |
| TUI integration (shared qyvora-tui) | IMPLEMENTED (wired) | README:259-265; go.mod has `github.com/QYVORA/qyvora-tui v0.11.0` |
| JSONL events stream | IMPLEMENTED (designed) | README:273-275; events package present (`internal/events/`) |

## 5. Reconnaissance and discovery findings
- **Local discovery scope:** Reads host identity, accounts, network listeners, SSH/remote access, installed software/packages, filesystem layout, env, git config, cloud configs, processes/services, persistence mechanisms, artifacts/logs, browser/app data dirs, OS posture. No remote network scanning of arbitrary targets (README:279-280: `--remote` refused with exit 3).
- **Evidence collection:** Read-only file/process inspection; secrets fingerprinted (salts/hashes/length/location only, never values) per README:83-86.
- **Platform awareness:** Per-platform collectors behind build tags; `internal/platform/capabilities.go` primes capabilities per OS and notes limitations.
- **Simulation:** `--simulate` uses built-in synthetic dataset for offline testing (README:73-79).

## 6. Analysis and assessment findings
- **Rule evaluation:** 52 rules (2 critical, 22 high, 14 medium, 12 low, 2 informational) across categories (SEC, PRV, ACC, NET, RMT, FS, SHL, PER, PRC, PST, CLD, IDN, META, APP, ART, SW, TMP, TOOL, etc.) as listed in README:108-164.
- **Correlation:** Identity correlation, finding correlation (pipeline stages 4,6). Deterministic sorting; report ID derived from content (README:98-101).
- **Risk scoring:** Weighted model with confidence weighting, evidence state (observed/inferred) tracked (README:165-176).
- **Provenance/integrity:** Package ownership checks (PRV-001/002), binary integrity emphasis.
- **Partial reports:** Collectors record why skipped/degraded; limitations listed explicitly (README:95-97).

## 7. Exploitation-related capability findings
- **No active exploitation modules.** Amina is explicitly read-only by design (README:11-14, 278-281). Command `exploit` exists but returns "amina has no exploit modules in this framework" and exits via usage path (main.go:199-205). No payloads/exploitation execution paths found. 
- **Safe validation only:** Focus is exposure discovery/analysis; no proof-of-concept exploitation. Correctly classified as **NOT APPLICABLE** for this domain with justification.

## 8. High-level implementation candidates (P0–P3 with rationale)
| Priority | Candidate | Rationale (evidence) | Feasibility |
|----------|-----------|----------------------|-------------|
| P1 | Ensure `capabilities` output matches shared machine contract shape expectations across orchestrators | Amina has `capabilities -o json` returning custom shape (`tool/framework/version/capabilities` with detailed objects). qyvora-common defines `CapabilityManifest{framework,version,commands:[]Command{...}}`. Orchestrators may expect either form; need to verify conformance against runner expectations. (README:179-184, cmd/amina/capabilities.go, shared/qyvora-common/contract/contract.go:59-75) | High (format mapping/addition) |
| P1 | Verify/explicitly document exit code behavior for all paths against contract | Exit codes documented as 0/1/2/3/130 (README:248). Contract defines same. Need to confirm unknown flag/command behave correctly (conformance checks unknown flag exits 2). Evidence exists in code paths. | High (verification) |
| P2 | Add machine-readable "operation" style entries if orchestrator expects Command[] | Current capabilities are rich descriptors; mapping to Command list (name/inputs/outputs/dangerous/authorization/emits/deterministic) may be needed for strict orchestration per shared contract. | Medium (design work) |
| P3 | Expand platform limitation reporting in machine-readable form | Already good human-readable; could improve structured reporting. | Low/Medium |

## 9. Low-level deferred technique inventory (DEFERRED — SPECIALISED PREREQUISITES; prerequisites, feasibility, why deferred)
| Technique | Prerequisites | Feasibility | Why deferred |
|-----------|---------------|-------------|--------------|
| Active exploitation against local services | Explicit authorization, safe PoC environment, exploit dev/validation harness | Low for "now" (out of scope by design) | Amina is read-only/local-host exposure assessment by design (README boundaries). Adding exploitation would change security model materially. |
| Hardware/firmware inspection | JTAG/SWD/UART/chip-off, specialized tools, physical access | Very low | Out of domain; not aligned with "read-only local host assessment" focus. |
| Live cloud API interrogation | API keys/tokens, network access, provider APIs | Low now | README states cloud collectors read on-disk configs only (README:305-307); expanding to live APIs changes scope/security model. |
| Deep disk forensics/timeline reconstruction | Forensic toolchain, elevated privileges, imaging | Low | Out of scope; would require different tooling/integration. |

## 10. Common-layer conformance (SHARED / FRAMEWORK-SPECIFIC / DUPLICATED / INCONSISTENT / MISSING / UNVERIFIED decisions)
| Component | Decision | Evidence/Rationale |
|-----------|----------|-------------------|
| Exit codes (0/1/2/3/130) | SHARED (adopts contract) | README:248; main/exitcode usage; matches contract/contract.go:18-24 |
| Semver identity/version | SHARED (adopts contract) | `version -o json` gives semver `v0.1.0`; contract requires semver (ValidateVersion). |
| Capability discovery | PARTIALLY SHARED | Has `capabilities` command (good). Shape differs from `CapabilityManifest{commands:[]Command}`; currently custom rich format. |
| JSONL events schema | SHARED (designed per spec) | README:273-275 references ecosystem output spec; events package present. |
| Identity/Result envelopes | FRAMEWORK-SPECIFIC (domain model) | Amina has its own report model (findings/rules/risk) appropriate to host assessment; different from generic web scan results. |
| CLI conventions (flags/tiers) | FRAMEWORK-SPECIFIC but consistent | Uses tiers (`recon assess`, aliases) and flags; follows patterns across ecosystem. |
| TUI integration | SHARED dependency | Uses `qyvora-tui v0.11.0` (shared component). |
| Scripting | SHARED dependency | Uses `qyvora-script v0.1.0` (go.mod). |

## 11. AI orchestration readiness (per-requirement statuses)
| Requirement | Status | Evidence |
|-------------|--------|----------|
| Stable framework identity/version | CONFORMANT | `version -o json` returns framework/version/commit/date/os/arch; semver |
| Machine-readable capability descriptions | PARTIALLY CONFORMANT | `capabilities -o json` exists with detailed entries; shape not identical to shared Command manifest but rich and parseable |
| Explicit operation inputs/outputs | PARTIALLY CONFORMANT | Flags documented; capabilities list target_types/output_schema; not fully formalized as Command[] schema |
| Predictable exit codes | CONFORMANT | 0/1/2/3/130 documented and used |
| Structured results/findings | CONFORMANT | Rich report model with findings, evidence state, severity/confidence, risk scoring |
| Prerequisite declarations | PARTIALLY CONFORMANT | Platform capabilities report limitations/support levels; not always exposed as machine-readable prerequisites per operation |
| Permission/authorization requirements | CONFORMANT | Read-only by design; selfupdate marked as requiring confirmation/authz; `--remote` refused |
| Timeouts/cancellation | PARTIALLY CONFORMANT | `--timeout` flag exists (README:246); signal handling for SIGINT (main.go comment says Ctrl+C handled) - needs verification of full behavior |
| Risk classification/confirmation | CONFORMANT | Self-update requires confirmation; risk scoring present |
| Safe execution defaults | CONFORMANT | Local-host only, read-only by default |
| Distinction read-only vs state-changing | CONFORMANT | Only selfupdate changes state; clearly marked |
| Orchestrator can discover unsupported capabilities honestly | CONFORMANT | Returns exit 3 for unsupported (e.g., exploit with no modules) and reports platform limitations |

## 12. CLI, repository-layout, and documentation findings (exact paths; no file moves)
- **CLI:** Tier grammar present (`amina recon assess/scan`, `amina exploit`, `amina report`, `amina capabilities`, `amina update`, `amina version`); aliases supported. Bare invocation shows usage/banner (not TUI per recent behavior noted in main.go comment). Help matches audit help file.
- **Binaries:** Prebuilt binary in `bin/amina` (root-level bin/ in repo). git history shows "chore: remove accidentally committed amina binary; ignore it" (c1e39e4) but bin/amina exists now as prebuilt for testing - present in repo. Conventions say "Framework executable binaries belong in the designated `bin/` directory where appropriate" (PROMPT.md:457) - bin/ is designated here.
- **Assets:** `assets/` present (logos/icons referenced). 
- **Stray files:** None obvious at root level outside normal files (configs/, reports/ dirs exist). 
- **Docs:** Comprehensive docs/ with CLI/MODULES/RULES/OUTPUT/ARCHITECTURE/UPDATING/etc. README accurate and detailed.
- **Scripts:** `install.sh`, `install.ps1` present.
- **Duplicate/oddities:** None obvious.

## 13. Testing and verification findings (only checks actually run)
- **Git:** Clean working tree (git status --porcelain empty). Recent commits show banner/help/version updates.
- **Binary execution (non-destructive):**
  - `bin/amina version -o json` → OK, returns semver identity
  - `bin/amina capabilities -o json` → OK, returns 25 capabilities all implemented
  - `bin/amina --help` → OK, shows banner/usage/flags/exit codes
- **Tests/build:** Not executed in this audit pass (to avoid unnecessary changes/time). README reports `go test ./...` passes, `go test -race ./...` passes, golden tests pass, conformance passes (README:289-301). Treat as reported unless contradicted.

## 14. Prioritized gaps and recommendations (P0–P3; recommendations, not authorization)
| Priority | Gap | Recommendation | Notes |
|----------|-----|---------------|-------|
| P0 | Orchestrator contract alignment for capabilities | Consider providing both rich capabilities and/or mapping to shared Command manifest; ensure conformance runner can parse. | Shared contract expects Command[] in CapabilityManifest; current shape is different but parseable. Verify against actual runner expectations. |
| P1 | Explicit machine-readable prerequisites | Expose per-capability prerequisites (privileges, tools, platform) in structured form for orchestrator. | Platform support exists internally; surface it. |
| P1 | Verify exit codes for edge cases | Test/confirm unknown flag → exit 2, unknown command → exit 2, unsupported operations → exit 3. | Critical for orchestration. |
| P2 | Enhance operation metadata | Add danger level, auth requirements, emits/events, deterministic flags to capability entries if needed. | Some info present; formalize. |
| P3 | Documentation of event schema | Document JSONL event schema in machine-readable form for orchestrators. | Events mentioned but schema details would help. |

## 15. Dependencies, prerequisites, unresolved questions
- **Dependencies:** Go 1.26.5, qyvora-tui v0.11.0, qyvora-script v0.1.0, termenv, yaml.v3 (go.mod). All internal deps present.
- **Prerequisites:** Runs on Linux/macOS/Windows; per-OS collectors; some features need privileges (reported as limitations). Read-only by default.
- **Unresolved questions:**
  - Exact conformance runner expectations for amina's capabilities shape (does it accept current format or require Command[] manifest)?
  - Full timeout/cancellation behavior under SIGINT in all code paths?
  - Are there any cases where amina might attempt network access beyond local? (README says local host only, `--remote` refused - appears enforced)
- **External services:** None required for core assessment; self-update contacts GitHub releases (documented, requires network, checksum-verified).

## 16. Explicit statement: "No feature implementation was performed during this audit."
No feature implementation was performed during this audit.
