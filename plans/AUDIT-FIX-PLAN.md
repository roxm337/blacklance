# Audit Fix Plan — 2026-10-12 deep audit

Source: 5 parallel pipeline audits + spot-verified claims (marked ✓).
Doctrine: repro test first, fix second, full suite + CI green before commit.
Commit rule: prose body, no trailers, only when explicitly requested.

## Phase 1 — Crash / data-loss bugs (highest blast radius)
1.1 ✓ `core/budget_manager.py:61-78` + `core/chain_executor.py:432`
    - `check()` raises but is used as boolean; exception skips `state.save()` after prune.
    - Fix: make `check()` pure boolean; add explicit `raise_if_exceeded()` at controlled
      call sites that save state first. Repro: `tests/test_budget_manager.py` —
      budget-exceeded mid-execution preserves prior findings.
1.2 `tools/external.py:289` — `parse_nuclei_jsonl` `info:null` AttributeError kills whole parse.
    - Fix: `info = item.get("info") or {}`. Repro with `{"info": null}` line.
1.3 `tools/external.py:1319` — `semgrep_scan` `UnboundLocalError` when staging throws.
    - Fix: init `result = {}` before try. Repro: force staging exception.
1.4 `modules/idor_differ.py:169` — `CrossResult.severity` lowercase breaks schema.
    - Fix: return uppercase. Repro: assert in `tests/test_idor_differ.py`.

## Phase 2 — Toolchain + shipped config
2.1 ✓ `tools_requirements.txt:59` — dalfox v2 URL vs v3 engine/image.
    - Fix: replace with v3 Rust install line. Verify: `dalfox --help` shows `pipe`.
2.2 `config.yaml:107-111,126` — missing `kiterunner.delay_ms/connections`,
    `budget_limits`, `module_timeout`, `auth.identities`.
    - Fix: sync from `config.example.yaml`; add doctor test asserting shipped config
      has no missing keys (`--check-config` clean on `config.yaml`).
2.3 `tools/tool_manager.py:42` — `kiterunner` vs binary `kr` (`which` always misses).
    - Fix: definition name/binary split (`name="kiterunner", binary="kr"`).

## Phase 3 — Config-namespace unification + doctor (the `test_write_methods` class)
3.1 Unify `_cfg()` to `self.config["modules"][self.id]` in:
    `idor_differ` (✓ reads `modules.idor`, id is `idor_differ`),
    `xss_scan` (top-level `xss`), `nuclei_scan` (top-level `nuclei`),
    `fast_exposure_scan` (`fast_scan`), `misconfig` (`misconfig` vs id `misconfig_probes`),
    `rest_api` (id `rest_api_audit` vs file `rest_api.py`),
    `graphql_module` (id `graphql_audit` vs file `graphql_module.py`).
    - Migrate `config.example.yaml` + `config.yaml` + GUI keys in the same commit.
    - Repro per module: set namespaced key, assert `_cfg()` sees it; set legacy key,
      assert doctor flags it unknown.
3.2 `core/config_doctor.py:78-85` — warn on UNKNOWN keys, not just missing.
3.3 `core/config_doctor.py:15-65` — extend `KNOWN_KEYS` to every key the engine reads
    (`idor`, `mass_assignment`, `prototype_pollution`, `http_smuggling`, `open_redirect`,
    `cms_deep_scan`, `cors`, `auth_audit`, `auth.identities`, `module_timeout`,
    `budget_limits`, `rate_limits`, `waf`, `scoring`, `misconfig`, `fast_scan`,
    `crawl.browser.*`, `xss.*`, `nuclei.*`, `oob.*`).
    - Strengthen `tests/test_config_doctor.py:25-44` to enumerate keys from code.
3.4 `modules/deep_crawl.py:76` — `crawl.depth` vs `crawl.browser.depth`; unify to
    `crawl.browser.depth`.
3.5 `modules/subdomain.py:55` — top-level `urlscan_api_key` vs GUI `api_keys.*`; unify.
3.6 `modules/idor_differ.py:1116-1117` — dead `or ["PATCH","PUT","DELETE"]` fallback;
    remove or make reachable (contradicts `_write_enabled` gate).

## Phase 4 — Verification / severity integrity
4.1 `core/verification_oracle.py:400-419` — `verify_xss` naive `payload in body`.
    - Require encoding/executable-context check (reuse `looks_unsanitized` discipline).
4.2 `core/verification_oracle.py:265` — `enabled` ignores `oob.enabled:false`.
    - Honor kill-switch in oracle constructor.
4.3 `core/verification_oracle.py:117-118` — `b == 0: continue` drops baseline-zero signals.
4.4 `core/verification_oracle.py:142-148` — `response_time_ms` 15% differential signal
    (jitter → flaky FIRM). Raise threshold or drop timing from differential set.
4.5 `core/verification_oracle.py:267-283` — `md5(time:payload)[:12]` predictable corr IDs;
    use `secrets.token_hex`.
4.6 `core/chain_executor.py:477-500` — `_promote` evidence gate (require non-empty
    evidence for `verified=True`); lift CRITICAL cap; couple severity to proof strength.
4.7 `core/prioritization.py:47-51` — KEV substring match; require structured `kev` flag.
4.8 `core/prioritization.py:113-121` — lexical severity tie-break; use ordered rank.
4.9 `core/scoring.py` + `prioritization.py` — double confidence discount (0.65 then
    0.55/0.85); single discount path.
4.10 `core/auth_harness.py:328-386` — cookie-presence = verified; 404/500 pages verify.
    - Require positive marker or verify_url match; never verify on 4xx/5xx.
4.11 `core/validators.py:309-313` — `_rough_entropy` is bit_length, not entropy; real
    Shannon entropy. Plus `private_key` no-capture-group, `analyze_jwt` substring
    `test`, `is_public_target` IPv6/punycode gaps.
4.12 Scanner-laundered severity (each: require stated proof or downgrade):
    `nuclei_scan:287`, `cms_deep_scan:380,391`, `exploit_lookup:174`,
    `xss_scan:108,170,318`, `sqli_scan:83`, `ssti_scan:101`, `cors_audit:203,242`,
    `graphql_module:234,259`, `rest_api:167,225`, `headers_audit:115`,
    `error_audit:153`, `response_audit:118`, `mass_assignment:250`,
    `business_logic:293`, `http_smuggling:261`, `upload_audit:110`,
    `fast_exposure_scan:228`, `misconfig:170,259`, `ssrf_scan:334`.

## Phase 5 — Destructive-action safety
5.1 `modules/auth_audit.py:298` — rotate password back after probe (store + restore,
    verify restore).
5.2 `modules/mass_assignment.py:192` — failed restore must not file CRITICAL/HIGH;
    downgrade + flag `restored=False`.
5.3 `modules/auth_audit.py:134` — in-scope check on backend-bypass probes; document
    lockout risk; keep behind existing rate knobs.
5.4 `modules/auth_audit.py:230` — delete registration-oracle account or file cleanup
    finding; never silently leave.
5.5 `modules/idor_differ.py:1106` — cap write loop (`max_probes_per_template`-style).
5.6 `modules/idor_differ.py:1149-1163` — JSON-assumption guard (content-type check) +
    restore/verify like `business_logic`.
5.7 `modules/prototype_pollution.py:89` — default-off OR post-run cleanup.
5.8 `modules/business_logic.py:203,338,370` — never file HIGH when `restored=False`.
5.9 `modules/upload_audit.py:197` — delete uploaded probes (best-effort cleanup).

## Phase 6 — Injection hardening + secret hygiene
6.1 `tools/wrappers.py` — `shlex.quote` (or arg arrays) on all interpolated
    `dig/whois/nmap/openssl/curl/echo-pipe` builders (:392,:439,:913,:949-989,
    :1044-1128,:459-545,:1148-1177). Repro: single-quote payload stays inert.
6.2 Redact before persist: wpscan token (`external.py:1167`), sqlmap cookies/headers
    (`:927`), API keys in URLs (`wrappers.py:530,1148,838`), reflecting-endpoint
    credential echo (`wrappers.py:60`, `base.py:97`). Central `redact()` helper.
6.3 `tools/external.py:100` — `_rewrite_arg` must rewrite output paths even when they
    don't exist yet (ffuf/arjun `-o`).
6.4 OOB fail-closed: `callback_url("")` → `""`/`None` (`verification_oracle.py:291`,
    `external.py:1566`); fix direct callers (`actions/web/ssrf.py:103`,
    `agents/verification_agent.py:117` hardcoded burpcollaborator host);
    instant-skip blind loops on empty `corr_id` (`xss_scan:193`, `ssrf_scan:290`).
6.5 `tools/external.py:185` — `await proc.wait()` after kill (zombie containers);
    add retries on transient connection errors for dalfox/sqlmap/kiterunner.
6.6 Parser hardening: dalfox empty-URL lines (`:688`), kiterunner schema/`"200 OK"`
    (`:761,778`), jsluice non-JSON lines (`:1275`), wpscan/whatweb/nikto/droopescan/
    graphql-cop/gitleaks shape flips (`:1129-1367`), httpx/gowitness dropped `-stats`
    lines (`:492,643`).
6.7 Availability guards: `_tool_available` on dig/whois/rdap/nmap/cert/tls/wayback/ssl/
    shodan paths; fix `openredirex` advertise-vs-image gap; document httpx
    shadowing on local hosts.
6.8 `tools/http_engine.py` — plumb `tls.verify` config; per-host allowlist instead of
    global `ssl=False`; fix `_tls_summary` ALPN field.

## Phase 7 — Recon coverage + correctness
7.1 `modules/subdomain.py:139-165` — wildcard check BEFORE storing CONFIRMED assets.
7.2 `modules/subdomain.py:147` — IPv6/AAAA handling (no `isdigit` drop).
7.3 `modules/origin_discovery.py:320-324` — require body equality for `confirmed` origin.
7.4 `modules/cloud_enum.py:58` — follow redirects on 301 (re-probe regional endpoint);
    honor full prefix/suffix lists (`:328-329`); 429 backoff (`:103-104`).
7.5 `modules/content_discovery.py:418-420` — length-invariant wildcard detection.
7.6 `modules/js_analysis.py:459-462` — proper domain-boundary + `.mjs`/query handling.
7.7 Truncation with priority/shuffle + logged skip counts: `asn_expansion`,
    `dns_takeover:289`, `wayback` live-check window, `port_scan:144`,
    `tech_detect` plugin probing (concurrency + full paths).
7.8 `modules/waf_module.py` — run all 6 bypass techniques; honor `waf.block_codes`;
    treat 429 as rate-limit, not block.
7.9 POST/JSON injection paths: `xss/sqli/ssti` (`method==GET` filters), `nosql` +
    `$where`/`$or`/type-juggling, `ssrf` POST JSON URL fields.
7.10 `modules/dom_xss_scan.py:123` — test all 3 payloads.
7.11 `modules/http_smuggling.py` — TE.CL/TE.TE/H2 techniques; decouple oracle from
    `smuggler`-installed gate where possible.
7.12 `modules/mass_assignment.py:169` — test already-visible fields (the `user→admin`
    case); per-field type probing.
7.13 `modules/sitemap.py:56-57` — cap sub-sitemap fetches + per-fetch timeout/try.
7.14 `modules/tls_audit.py:78-83` — per-endpoint try/timeout; fix `TLS1_1` mangling (`:124`).
7.15 Error swallowing: `subdomain:105-119` (log fallback counts), `dns_takeover:308-315`,
    `mobile_assets` redirects, `port_scan` 53/80/443 findings, `keyed_subdomains`
    scope filter.
7.16 `modules/browser_crawl.py:57,355` — clamp `wait_ms`, add module time-box.

## Phase 8 — GUI + tests + CI
8.1 `gui/app.py:3836-3843` — warn (don't silently clamp) on out-of-range spin values.
8.2 `gui/app.py:3870-3876` — split lists on newlines only (commas corrupt URLs).
8.3 `gui/app.py:3850-3861` — surface dropped header lines instead of silent drop.
8.4 `gui/app.py:3522` — kiterunner `.update()`, not wholesale replace.
8.5 Missing Scanner controls: `crawl.browser.wait_ms`, `business_logic.endpoints`,
    full `misconfig.*` section, `idor.object_probe.*`/`collection_paths`/
    `api_prefixes`/`account_endpoint`/`resources`, `prototype_pollution.*`,
    `ssti/nosql max_points`, `dom_xss max_pages`, `parameter_discovery.seed_*`,
    `nuclei max_seconds/batch_seconds`.
8.6 Round-trip tests for every Phase-8 control + currently unasserted paths
    (`redirect/cors/cms/content enables`, OOB fields, `crawl.wait_ms`).
8.7 `config.example.yaml` — document `auth_audit.test_registration_oracle`,
    `ssti/nosql/dom_xss/parameter_discovery` sections, `nuclei.max_seconds/
    batch_seconds`.
8.8 CI: un-ignore `test_gui_app.py`/`test_gui_graph.py` (fix offscreen issues first),
    add `--check-config` + YAML lint jobs, align lean-deps with `requirements.txt`
    or document drift; fix `theme.qss` dead selectors (`QRadioButton`,
    `#metricCard[tone="info"]`, `#verdictChip[verdict="none"]`).

## Phase 9 — Validation + commit
9.1 Full local suite: `.venv/bin/python -m pytest -q -p no:cacheprovider` →
    target 0 failures (baseline 862 passed, 30 skipped).
9.2 Lean-container 3.10/3.11 collection check (whole-tree `py_compile` + lean-deps pytest).
9.3 Live re-verification on Juice Shop: benchmark 5/5 + business-logic restore-clean.
9.4 Single commit per phase (prose body), push only when explicitly requested.

## Status log
- [x] Phase 1 — crash/data-loss (check() pure bool + raise_if_exceeded, executor
  pre-prune budget gate, nuclei null-info, semgrep staging degrade, IDOR
  severity uppercase; 7 repro tests, old lowercase assertions corrected)
- [x] Phase 2 — toolchain/config (dalfox v3 install docs, nuclei -update dropped,
  ToolInfo.binary kr fix, config.yaml blocks added + regression test)
- [x] Phase 3 — namespace + doctor
  - [x] 3a idor + misconfig; 3b xss/nuclei/fast_scan; 3c (above)
- [x] Phase 4a-oracle (see Phase 4 section note)
- [x] Phase 4b scoring/promotion/KEV/auth-harness/validators
  (single discount; KEV exact category; verified+TENTATIVE discounted;
  severity-rank tie-break; _promote evidence gate + CRITICAL path +
  CONFIRMED floor; harness error-page rejection + assumed flag + fresh
  cookie wins + write guard; Shannon entropy; PEM body required;
  alg:none unsigned tier; word-boundary markers; IPv6/punycode.
  Accepted: max() ratchet, context bumps, label bands, exposure
  blanket, verify_sqli TENTATIVE path, blind-poll degradation.)
- [ ] Phase 4c — scanner-laundered severities (triaged below)
- [x] Phase 5 — safety (idor JSON-gate + write cap + assumed-session
  write guard; password recovery in evidence + loud log; registration
  loud log; upload best-effort DELETE cleanup. Accepted: mass/business
  unrestored loud-flagging (correct severity), ratelimit probes (bounded
  fake-email), proto canary-scoped.)
- [x] Phase 6 — injection/secrets (shlex quoting on all shell sites +
  nmap alphabet validation; _rewrite_arg output paths; dalfox/kr/jsluice
  parser hardening; redact_for_log + sqlmap/wpscan scrub; urlscan/shodan
  off shell; strip_global_auth on 23 third-party calls; OOB instant-empty
  polls; zombie reaps; missing-binary errors; openredirex in image;
  httpx shadowing doc. Deferred: TLS verify plumbing (config+GUI design),
  command retries, full availability-guard sweep.)
- [ ] Phase 7 — recon
- [x] Phase 8 — GUI/CI (spin-clamp warnings, newline lists, dropped
  headers surfaced, kr merge-save; all missing Scanner controls:
  crawl.wait_ms, logic endpoints, misconfig section, idor bounds/paths/
  prefixes/account/resources/radius/max, proto reflect/methods/payloads,
  nuclei batch/max seconds, ssti/nosql/dom/parameter box; round-trip
  tests; CI gui job + check-config + yaml lint + py_compile; QSS
  completed (info/none rules, radio block removed). Accepted:
  test-mock style notes.)
- [x] Phase 9 — validation (full suite 929 passed / 30 skipped;
  lean 3.10 container 869 passed / 52 skipped; Juice benchmark all
  expectations met; --check-config 2 informative warnings; no strays)
