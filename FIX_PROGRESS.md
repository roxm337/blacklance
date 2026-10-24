# Review fixes — implementation progress

Current delivery order and new integrations: [INTEGRATION_PLAN.md](INTEGRATION_PLAN.md).

This tracks changes made after `Vulnscan_results.md`. Engagement scope enforcement is excluded at the operator's request. No target allowlist or new target-selection restriction was added. Existing operator changes to `modules/misconfig.py` and `tests/test_catch_all_server.py` were preserved.

## Implemented

| Review item | Change |
|---|---|
| S1: credential forwarding | Configured session headers are selected by canonical origin. Off-origin source-map requests continue without target credentials. Native HTTP and curl redirect handling removes sensitive/custom headers across origins. Browser subresource routing applies the same header rule. Curl fallback cookie jars are private temporary files separated by identity and origin. |
| D1: fallback policy bypass | Blocked generic probes retain a blocked result. An unsupported hypothesis no longer enters an unregistered direct-HTTP/XSS fallback. |
| D2: LLM active-mode bypass | The dispatcher checks the selected module's active flag after receiving the model decision. Existing explicit single-module execution behavior is preserved. |
| D3: false vulnerability promotion | Registered output metadata classifies observations separately from candidates and verification results. JWT discovery records an observation in agent and chain execution. Verification requires proof evidence; FIRM chain candidates are unverified and excluded from the proven count. Legacy HTML reflection cannot claim confirmed execution. Fallback results retain their actual action ID. |
| D4: cancellation | Subprocess helpers reap their managed process groups on cancellation and timeout. Docker tools receive unique managed names and request container removal during cleanup. CLI SIGTERM triggers graceful cancellation; GUI Stop allows cleanup time. |
| D6: graph path omission | Search uses path-local cycle detection, preserving stronger alternate paths. Expansion is bounded and truncation is recorded and displayed as partial coverage. |
| D7: installed distribution | Wheel resources include defaults, theme, knowledge packs, and scanner rules; tests are excluded. Defaults and rules can be located outside the checkout. The package extras include HTTP/2 support. CI builds and smoke-tests an installed wheel. |
| Audit/evidence foundation | Pipeline modules record audit start/end events, chain execution receives the audit log, action cancellation is recorded, and evidence indexes carry schema versions, byte counts, and SHA-256 digests. `StateManager.verify_evidence()` detects changed or missing evidence. |

Additional regression tests live in `tests/test_review_regressions.py`. `scripts/check_wheel.py` installs a supplied wheel into temporary storage and checks imports/resources from a working directory outside the repository.

## Verification — first batch

- Non-GUI suite: **1,195 passed, 33 skipped** in 138.57 seconds.
- GUI suite: **70 passed** in 45.91 seconds.
- Combined completed suites: **1,265 passed, 33 skipped**, including 14 added regression cases.
- The installed wheel smoke test passed outside the checkout. All four previously missing resource types are present and no test files are packaged.
- Changed Python files parse with Python 3.10 grammar; CI YAML parses; `git diff --check` passes. This is not a substitute for executing the full Python-version matrix.

The project graph was refreshed using AST extraction. `.graphifyignore` now excludes runtime dependencies and generated output from future extraction. No LLM API was used for the graph refresh.

## Remaining work

This batch does not close every architectural recommendation in the review:

- D5: origin/run isolation and explicit fresh/resume/retest behavior. Transactional
  snapshots and stale-writer protection are implemented in the second batch below.
- D6: causal chain preconditions, output/artifact bindings, and dependency-aware execution; the path-search defect is fixed separately.
- A common execution boundary for every module, complete accounting across transports, audit events for every refusal/failure path, and externally anchored evidence manifests.
- Endpoint-specific negative-retest collection and durable assessment IDs. Conservative
  resolved/untested semantics and repeat-export idempotence are implemented below.
- Secret-store references, credential expiry/revocation, and a durable mutation/cleanup ledger.
- Pinned scanner images/tool versions, SBOMs, real Docker/scanner compatibility gates, and multi-stack precision/recall benchmarks.
- Mission/scenario definitions, ATT&CK mappings, defensive telemetry correlation, and remediation retest workflows.
- Configuration schemas, broader code decomposition, release/version alignment, and operator-selected licensing.

Local process cancellation and HTTP redirect behavior have dedicated regression tests. Docker cleanup wiring does not substitute for a live Docker integration test. The advertised Python CI matrix and full live lab assessments have not been run locally.

## Second batch — persistence, history and plan consolidation

- `core/persistence.py` provides private unique temporary files, flushed atomic JSON
  replacement and cooperating-process locks. State commits all four stores in one
  versioned `snapshot.json`; revision checks reject stale writers. Legacy JSON exports
  remain available. Invalid snapshot/legacy state is not silently replaced with empty data.
- Evidence display IDs remain monotonic; unique filenames prevent a rejected stale
  writer from overwriting the winning writer's proof bytes. Rejected writers may leave
  unindexed evidence files; automated orphan cleanup is not implemented.
- GUI loads one committed generation and retains prior rows on snapshot corruption.
- Starting a module retest clears previous success/skip/block state. An unsuccessful
  run cannot retain an old success badge.
- History schema v2 deduplicates repeated observations, treats missing items as untested,
  and only resolves explicit negative-retest fingerprints/asset keys. Existing v1 histories
  load without resetting their baseline. Previously recorded resolutions are not reinterpreted.
- Report-only exports use a stable observation digest and per-item observation tokens
  (unrelated module activity does not increment an old finding), serialize history read-modify-write,
  reject stale state and persist the same finding annotations in summary/findings JSON.
  Corrupt history aborts export instead of discarding the baseline. Report artifacts as
  a whole are not yet an atomic multi-file transaction.
- Audit appends synchronize independent writers, refresh changed tails and verify
  contiguous sequences. This does not add signing or external anchoring.
- Wheel staging rejects unexpected leftover files without deleting them. The installed
  wheel smoke check exercises transactional state, evidence verification and reporting;
  clean builds must use a fresh staging directory when the old one is contaminated.
- `INTEGRATION_PLAN.md` is the versioned source of truth. Local historical roadmaps
  have redirects/status corrections; those files remain intentionally gitignored.

### Verification — second batch

- Final non-GUI suite: **1,221 passed, 33 skipped** in 141.68 seconds.
- GUI suite: **70 passed** in 55.14 seconds.
- Combined: **1,291 passed, 33 skipped**, including 26 additional regression cases.
- Process tests cover conflicting state saves and independent audit writers;
  failure-injection tests cover snapshot replacement and compatibility exports.
- A fresh-staging wheel built successfully and passed the installed smoke test
  outside the checkout, including state/evidence/report operations. The local
  `build` frontend was unavailable, so this build used setuptools' wheel command;
  CI still uses its installed build frontend. No build files were deleted.
- Four packaging tests cover clean staging and rejection of stale tests, local
  environment files, and OS metadata without deleting those fixture files.
- All 14 changed/new Python files parse with Python 3.10 grammar; local documentation
  links and `git diff --check` pass. Actual runtime verification was on local Python
  3.14, not the full advertised Python/OS matrix. Windows locking and network
  filesystem behavior have not been exercised here.
- The AST graph was refreshed without LLM calls. Graph JSON/report were updated;
  HTML regeneration was skipped by graphify's size limit.

This is a partial closure of D5/history gaps, not completion of every item in the
original review. Origin/run isolation, causal chains, full transport accounting,
cleanup lifecycle and real multi-stack assessment benchmarks remain explicitly open.
