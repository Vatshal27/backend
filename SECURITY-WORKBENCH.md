# SentinelAI Security Workbench

The Security Workbench is additive: existing `/analyze-project`, `/sandbox/run`, and VS Code commands keep their current behavior. New local-only `/security/*` endpoints provide profile/capability discovery and bounded asynchronous jobs for the extension.

## Start and verify

1. Start the backend with `npm start` (listens on port 3000). Docker is required for Safe Simulation and Project Validation. The default scanner still depends on its existing image and scanner configuration.
2. Start the VS Code extension with the existing compile/watch workflow.
3. Open SentinelAI's existing report panel, select a scan profile, and follow job progress, findings, coverage, evidence, and provenance labels.
4. Network advisory lookup is opt-in; the extension sends only exact npm package name/version to OSV after explicit selection. A failed advisory request reports incomplete coverage, not a clean scan.

## Profiles

- `source`: existing Semgrep/Bandit + optional Ollama path.
- `dependencies`: parse exact npm versions from `package-lock.json`; OSV query only when network opt-in is enabled.
- `secrets`: offline credential-pattern findings; values are not returned.
- `infrastructure`: offline Dockerfile/config heuristics.
- `comprehensive`: combines these checks. API/auth/browser verification remains explicitly unsupported without the necessary target, identities, schema and browser.

Coverage marks unsupported, skipped and inconclusive checks distinctly; empty findings do not mean complete coverage.

## Workflow meanings

- Static Analysis finds common source patterns that may indicate vulnerabilities and provides the evidence used as a basis for findings.
- LLM Analysis explains the findings, their likely impact and ways to fix them. Treat its output as advisory analysis, not independent proof.
- Safe Simulation runs the scanner against isolated synthetic Docker fixtures, then shows which simulated attacks/data disclosures were observed. It exercises the scanner; its results are synthetic and never findings in the user's project.
- Project Validation targets the user's live local application with bounded runtime probes and displays observed behavior and exposed data. It is separate from Safe Simulation and only tests the checks the product actually supports.

## Safety and scope

- New job routes accept only local requests and allowlisted scan profiles.
- Job requests are bounded, reject traversal/credential paths, and do not execute client-supplied code.
- Job state is in-memory and bounded by concurrency, capacity, event count and retention; restarting the backend discards history.
- Source/external evidence is redacted before returning reports. OSV lookup transmits public package metadata only.
- Only test against systems you own or are authorized to test.

## Test commands

- Backend: `npm test` (unit/integration tests; Docker-based Safe Simulation/Project Validation require Docker).
- Extension: from `../SentialAi`, `npm run compile` and `npm test`.

## Unified project reporting and optional LLM — 2026-10-18

- Workspace Workbench scans now call the optional local LLM analyzer only when `LLM_ENABLED=true` and supported source files are present. Scan results carry explicit `llmEnabled`, `llmUsed`, `llmReason`, and isolated `llmFindings` fields. Static findings remain available independently if LLM analysis fails.
- Project report schema v2 stores Static Analysis, LLM Analysis, Safe Simulation, and Project Validation as four separate sections in the same `sentinelai-report.json` and generated `sentinelai-report.md`. Skipped runs have explicit reasons; previous successful results survive failed later attempts.
- The legacy integration-test hook now persists its static, LLM-skipped, and runtime Project Validation results through the shared report writer. Regular legacy simulation/validation paths also use that report writer.
- Dependency collection reads npm lockfiles whole up to 2 MiB, fails rather than truncating, orders manifests before source under file-count caps, and sends the expected lockfile list to the backend for omission validation.
- Extension readme `REPORTING.md` explains the report schema, paths, skipped behavior, migration and limitations.

Verification for this tranche: extension `npm test` PASS, 21/21; backend `npm test` PASS, 40 passed, 0 failed, 1 skipped; Docker paired SQL regression PASS, 1/1. The default backend suite skips its Docker-only test; explicit Docker result is above.

Remaining readiness gaps: only npm advisory resolution; rule-based/heuristic source, secrets, and infrastructure checks; authentication/API/browser plus broken-access-control/path-traversal lab cases unsupported; no hosted auth/durable jobs/production operations validation; and no desktop VS Code end-to-end acceptance run. The LLM-enabled/Ollama execution path has not been exercised against a running model in this tranche.

## Verification report — 2026-10-18 13:54 IST

Status: Workbench baseline below was verified on 2026-10-18. Follow-up sensitive-data exposure tests also pass (addendum below). A VS Code-host end-to-end session has not been run; do not treat this as full product acceptance.

### Work completed in this pass

- Mounted the local-only `/security` router in `server.js`. Scan jobs call the existing Docker static scanner and the selected supplementary profile; job results include findings, coverage, and source-analysis provenance. Lab jobs call the synthetic lab runner.
- Connected the existing extension panel to workbench capabilities, profile and lab selection, profile-aware local collection, bounded API calls, polling, cancellation, findings, coverage, evidence, and provenance. Legacy scan/sandbox handlers and commands remain in place.
- Implemented the digest-pinned paired SQL-injection lab. It runs a seeded dummy SQLite HTTP target in a Docker internal network, checks baseline behavior plus vulnerable disclosure and parameterized blocking, applies non-root/capability/resource/filesystem restrictions, and verifies cleanup. Its report explicitly says `projectVulnerabilityConfirmed: false`.
- Marked broken access control, path traversal, and browser XSS unsupported with reasons; only SQL injection is implemented.
- Replaced the backend placeholder test command and added an extension test command.

### Verification actually run

- Backend `npm test` at initial workbench verification: PASS, 25 passed, 0 failed, 1 skipped. Latest backend full-suite result is in the follow-up section below.
- `LAB_DOCKER_TESTS=1 node --test tests/lab.docker.test.js`: PASS, 1 passed, 0 failed. It exercised the vulnerable and fixed HTTP cases, inspected network/container restrictions, and verified cleanup.
- Extension `npm test` (includes `tsc -p ./`): PASS, 6 passed, 0 failed.
- Docker daemon/image checks succeeded. The Docker lab run used the local scanner image pinned by its observed immutable digest.

### Not verified / limitations

- No VS Code-host end-to-end test exercised the webview against a running backend. Automated extension tests cover the controller, API adapter, and collector, not an actual VS Code UI session.
- Router tests exercise the router through a test Express app. Later, after declaring nodemailer, a live server probe returned HTTP 200 from `/health`, `/security/capabilities`, and `/api/mail/status`; the configured mail test endpoint returned 200 with delivery skipped because mail is disabled. No actual email was sent.
- The SQL lab is a self-test against a synthetic fixture, not a scan or vulnerability confirmation for user project files.
- Dependency advisory lookups require explicit network consent; unsupported checks remain unsupported, and coverage limitations should be read with every result.

### Files changed in the implementation pass

Backend: `server.js`, `package.json`, `jobs/manager.js`, `lab/index.js`, `tests/lab.test.js`, `tests/lab.docker.test.js` (alongside the previously present workbench modules/tests).

Extension (`SentialAi/`): `package.json`, `src/extension.ts`, `src/services.ts`, `src/security-workbench.ts`, `src/webview.ts`, `src/webview/body.ts`, `src/webview/styles.ts`, `src/webview/script-workbench.ts` (alongside the previously present focused tests).

No commit or push was made. Existing mail/mailer.js, run.txt, `.hermes/`, and the untracked SentinelAI markdown files were not cleaned or deleted. This report updates the existing untracked `SECURITY-WORKBENCH.md` rather than removing or replacing it.

## Follow-up: project data exposure and safe probing

Goal: show when local project runtime responses expose likely credentials or personal data, while ensuring report surfaces never return raw matches. This is a passive, same-origin response inspection: it does not exfiltrate data, send secrets back to a server, or infer protected data from a synthetic lab. Findings are `observed_exposure`, not proof of exploitability, and baseline repeats are excluded.

Current implementation changes:

- `docker/evidence.js` detects common bearer/JWT/AWS/private-key/database credentials, JSON and assignment-style secrets, email addresses, and phone-like values. It reports masked snippets, response-relative offsets, and lengths. Full response bodies are passed through the existing redaction/compaction boundary before a report is built.
- `docker/validation/runtime-evidence.js` uses the same detector for sensitive-data runtime verdicts and compares against the baseline response. Only new categories/value fingerprints count as observed exposure.
- `docker/planner.js` excludes source secret findings from runtime requests and omits the generic uncorrelated sensitive-data probe. Project Validation only examines routes reached by existing safe runtime discovery and never prints raw sensitive response values.
- `docker/report.js` carries exposure location/length metadata through to the existing report. The VS Code sandbox UI renders exposure category, masked sample, and field/offset using escaped text.
- A regression test checks masked response evidence, differential runtime verdicts, and exclusion of source-secret findings from runtime plans.

### Follow-up verification — 2026-10-18

- Backend `npm test`: PASS, 28 passed, 0 failed, 1 skipped (Docker lab remains opt-in in the default suite).
- Targeted evidence/verdict tests: PASS, 7 passed, 0 failed. Covers JSON secret/email/phone/bearer detection, masking, field paths, no raw-value serialization, baseline differential verdicts, report redaction, and ensuring local source-secret findings do not become runtime requests.
- Docker paired lab: PASS, 1 passed, 0 failed. The vulnerable and fixed SQL cases, isolation restrictions, and resource cleanup were exercised.
- Extension `npm test`: PASS, 6 passed, 0 failed; includes TypeScript compilation. Generated webview HTML contains the masked exposure display.
- Live server startup initially failed because modified `mail/mailer.js` required undeclared `nodemailer`. Added `nodemailer@^10.1.2` to `package.json` and lockfile. The backend then started; `/health`, `/security/capabilities`, `/api/mail/status`, and `/api/mail/test` returned 200. `/api/mail/test` reported delivery disabled/skipped, so no email was delivered.

Detection uses heuristics and may miss secrets or flag examples; it does not validate credentials, identify ownership, or establish whether exposed data is accessible to an attacker. It records offsets/JSON field paths, category, length, and masked value only. Perform Project Validation only against an application/runtime you own or are authorized to test, and avoid collecting production secrets.

Dead-code status: no files deleted. The scoped review found `createEvidenceEvent` has no in-repository callers but is exported from `docker/evidence.js`; removing that export could break downstream consumers, so it was preserved. The existing `runner.js.backup`, Markdown notes, `run.txt`, `.hermes/`, mail/mailer.js changes, and other ambiguous artifacts were left intact. No unused code was removed because no safe-to-remove private implementation was proven in this pass.

Implementation files changed in the follow-up: backend `docker/evidence.js`, `docker/validation/runtime-evidence.js`, `docker/planner.js`, `docker/report.js`, `tests/evidence-redaction.test.js`, `package.json`, `package-lock.json`; extension `src/webview/script-sandbox.ts`. No commit or push was made.

## Hardening tranche — 2026-10-18

- Response previews now redact detected credential and PII matches as well as exposing only field/offset, category, length, and masked sample evidence. Regression coverage asserts raw emails/phone values do not remain in the compact preview.
- The production server now binds to loopback by default, rejects non-loopback sockets, hostile Host and cross-origin requests, and reduces JSON body limit to 5 MB. Runtime check inputs reuse the local target validator.
- The README's stale `/api/scan` and `/api/analyze` examples, nonexistent individual npm test scripts, old performance claims, and unsupported fixture CLI invocation were removed/replaced with current routes, commands, and capability caveats. Runtime reports and coverage are explicitly best-effort, not a security guarantee.
- Report and coverage outputs are ignored by git. No legacy scanner implementation was removed: the alternate scanner CLI remains documented as legacy/experimental, and aliases/backups/fixtures are preserved until migration and retention decisions are explicitly approved.

### Verification — hardening tranche

- Backend `npm test`: PASS, 29 passed, 0 failed, 1 skipped (opt-in Docker lab omitted by default).
- Extension `npm test`: PASS, 6 passed, 0 failed; includes TypeScript compilation.
- Explicit Docker paired SQL lab: PASS, 1 passed; verifies vulnerable/fixed cases, container restrictions, and cleanup.
- Targeted local-service smoke: `/health` and `/security/capabilities` returned HTTP 200 on loopback; the same capabilities endpoint returned 403 with an untrusted browser Origin.
- Sensitive response preview smoke: raw email and password did not appear in the compact response preview. Regression tests cover preview masking and report-level redaction.
- `git diff --check` on backend was not clean because the pre-existing user-modified `run.txt` has CRLF/whitespace diffs. Extension diff also reports CRLF as trailing whitespace in user-modified `src/services.ts`. These files were deliberately not normalized or rewritten.

No VS Code-host UI session or production deployment test was run. No legacy scanner code was deleted: the alternate scanner CLI is labeled legacy/experimental because README history references it and internal aliases still resolve to it; untracked notes/backups and user-owned files remain untouched. This was a safety-first dead-code audit, not broad cleanup.

## Product showcase and benchmark tranche — 2026-10-18

- Backend README now identifies the product as an early-stage local-first prototype, documents the actual route set, profile/capability source of truth, unsupported runtime/lab categories, synthetic-lab semantics, and honest limitations; outdated route, test-script, performance, and fixture commands were replaced.
- Extension workbench is being upgraded to render summary metrics, coverage, findings, masked exposure field locations, runtime verdicts/evidence, execution timeline, provenance/limitations, and JSON/Markdown report downloads. All dynamic result text is inserted as text nodes, not HTML.
- Targeted extension test covers the renderer feature markers and checks no findings are interpolated into `innerHTML`.
- A small labeled source-secret candidate corpus now covers one synthetic hardcoded candidate and two safe negatives. This is a narrow regression fixture, not an overall scanner precision/recall benchmark.

Verification:

- Backend `npm test`: PASS, 29 passed, 0 failed, 1 skipped (the default suite skips the opt-in Docker lab).
- Extension `npm test`: PASS, 7 passed, 0 failed; includes TypeScript compile and renderer-safe-output test.
- Explicit `LAB_DOCKER_TESTS=1 node --test tests/lab.docker.test.js`: PASS, 1 passed, 0 failed.
- No VS Code-host UI execution was performed; the workbench was verified by compile and renderer/controller/API tests only.
- Added a labelled source-secret candidate mini-corpus (synthetic vulnerable assignment, environment-variable fixed form, and placeholder/docs negatives). It verifies this heuristic check only; it is not a general scanner effectiveness/recall benchmark.
- UI flow test evaluates the compiled webview script with an in-memory DOM/event harness; no desktop/extension-host VS Code end-to-end environment was available/run.
- No legacy implementation was deleted. Existing mail, run.txt, .hermes and Markdown artifacts remain untouched. No commit/push.
