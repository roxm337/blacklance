# Review fixes — first implementation batch

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

## Verification

- Non-GUI suite: **1,195 passed, 33 skipped** in 138.57 seconds.
- GUI suite: **70 passed** in 45.91 seconds.
- Combined completed suites: **1,265 passed, 33 skipped**, including 14 added regression cases.
- The installed wheel smoke test passed outside the checkout. All four previously missing resource types are present and no test files are packaged.
- Changed Python files parse with Python 3.10 grammar; CI YAML parses; `git diff --check` passes. This is not a substitute for executing the full Python-version matrix.

The project graph was refreshed using AST extraction. `.graphifyignore` now excludes runtime dependencies and generated output from future extraction. No LLM API was used for the graph refresh.

## Remaining work

This batch does not close every architectural recommendation in the review:

- D5: origin/run isolation, explicit fresh/resume/retest behavior, transactional state, and concurrent-writer protection.
- D6: causal chain preconditions, output/artifact bindings, and dependency-aware execution; the path-search defect is fixed separately.
- A common execution boundary for every module, complete accounting across transports, audit events for every refusal/failure path, and externally anchored evidence manifests.
- History/export idempotence and coverage-aware resolved/untested states.
- Secret-store references, credential expiry/revocation, and a durable mutation/cleanup ledger.
- Pinned scanner images/tool versions, SBOMs, real Docker/scanner compatibility gates, and multi-stack precision/recall benchmarks.
- Mission/scenario definitions, ATT&CK mappings, defensive telemetry correlation, and remediation retest workflows.
- Configuration schemas, broader code decomposition, release/version alignment, and operator-selected licensing.

Local process cancellation and HTTP redirect behavior have dedicated regression tests. Docker cleanup wiring does not substitute for a live Docker integration test. The advertised Python CI matrix and full live lab assessments have not been run locally.
