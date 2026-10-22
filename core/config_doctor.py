"""Config doctor — warn when the loaded config predates known features.

Every key the engine reads has a code default (`.get(..., default)`), so a
stale config never crashes: it silently runs Tier-2 tools on defaults the
operator cannot see or tune. `doctor()` lists what the file does not say,
with the default that applies and one line on why it matters. `--check-config`
prints the full coverage; normal runs print only the warnings.
"""

from __future__ import annotations


# dotted path -> (default, why it matters). Operator-facing switches and
# safety gates, not wordlists or tuning dicts (rate_limits.*, scoring.*):
# the point is surfacing invisible behavior, especially the write/safety
# gates that default closed.
KNOWN_KEYS: tuple[tuple[str, object, str], ...] = (
    ("tools.backend", "local",
     "local uses host binaries, docker runs the toolchain image instead"),
    ("tools.image", "osint-tools:latest",
     "image the docker backend executes tool binaries in"),
    ("tools.network", "bridge",
     "Docker network used by external scanners"),
    ("tools.memory", "2g",
     "hard memory ceiling for each external scanner container"),
    ("tools.cpus", 2,
     "CPU ceiling for each external scanner container"),
    ("tools.pids_limit", 512,
     "process-count ceiling for each external scanner container"),
    ("module_timeout", 300,
     "wall-clock ceiling per module; exceeded modules record timeout"),
    ("budget_limits.max_requests", 0,
     "total HTTP-request cap for agent actions (0 = unlimited)"),
    ("budget_limits.max_wall_clock_seconds", 0,
     "total runtime cap for agent actions (0 = unlimited)"),
    ("budget_limits.max_llm_calls", 0,
     "LLM-inference cap for agent actions (0 = unlimited)"),
    ("budget_limits.max_external_commands", 0,
     "external scanner/tool process-launch cap (0 = unlimited)"),
    ("budget_limits.resume", False,
     "explicitly restore counters from the target budget checkpoint"),
    ("budget_limits.max_concurrent_actions", 5,
     "throughput knob for agent actions"),
    ("auth.identities", {},
     "named sessions for cross-account (IDOR) testing"),
    ("auth.probe_backoff_seconds", 10,
     "pause between login probes (lockout politeness)"),
    ("waf.block_codes", [503, 429],
     "status codes recorded as WAF-block signals"),
    ("waf.honeypot_codes", [500],
     "status codes recorded as honeypot signals"),
    ("waf.payload_block_codes", [403, 406, 429, 501, 503],
     "edge rejection of a payload; adaptive probes retry mutated"),
    ("semgrep.enabled", True,
     "SAST over downloaded JS bundles (repo-local rules, offline)"),
    ("semgrep.rules", "rules/semgrep",
     "rule directory semgrep scans with"),
    ("crawl.browser.enabled", True,
     "rendered crawling, one context per verified identity"),
    ("crawl.browser.depth", 1,
     "same-origin link-following depth (cap 3)"),
    ("crawl.browser.max_identities", 2,
     "verified identities rendered per run (cap 5)"),
    ("crawl.browser.max_targets", 8,
     "rendered pages per run (cap 50)"),
    ("crawl.browser.wait_ms", 1500,
     "render wait per page in ms"),
    ("oob.mode", "",
     "empty stays dormant, public uses the free interactsh mesh, "
     "wrapper uses a self-hosted shim"),
    ("oob.enabled", True,
     "off disables OOB everywhere without deleting the settings"),
    ("oob.callback_domain", "",
     "operator domain for self-hosted OOB callbacks"),
    ("oob.server_url", "",
     "self-hosted OOB server URL (public mesh when empty)"),
    ("oob.poll_url", "",
     "self-hosted OOB poll endpoint"),
    ("oob.token", "",
     "self-hosted OOB auth token"),
    ("oob.poll_interval", 2,
     "seconds between OOB callback polls"),
    ("oob.poll_timeout", 30,
     "seconds to wait for an OOB callback per probe"),
    ("modules.auto_run", True,
     "run discovery modules automatically"),
    ("modules.max_consecutive_empty", 5,
     "stop a module after N empty probes"),
    ("modules.record_http_evidence", True,
     "persist HTTP evidence for findings"),
    ("modules.content_discovery.enabled", True,
     "ffuf content discovery over high-signal paths"),
    ("modules.content_discovery.kiterunner.enabled", True,
     "API-route brute force over assetnote wordlists"),
    ("modules.content_discovery.kiterunner.wordlist", "apiroutes-260227",
     "remote list name (`kr wordlist list` shows current names)"),
    ("modules.content_discovery.kiterunner.max_routes", 1500,
     "routes tried per target (cap 20000)"),
    ("modules.content_discovery.kiterunner.max_targets", 2,
     "base URL plus api_endpoint origins (cap 10)"),
    ("modules.content_discovery.kiterunner.delay_ms", 100,
     "delay between requests to one host (1000+ for live scopes)"),
    ("modules.content_discovery.kiterunner.connections", 3,
     "parallel connections per host (1 for live scopes)"),
    ("modules.xss_scan.max_points", 80,
     "injection points probed per run"),
    ("modules.xss_scan.browser_confirm", True,
     "confirm reflections with warriors headless browser"),
    ("modules.xss_scan.dalfox_timeout", 600,
     "seconds allowed per dalfox pass"),
    ("modules.xss_scan.dalfox_blind_oob", False,
     "dalfox runs its own interactsh session (findings stay FIRM)"),
    ("modules.xss_scan.dalfox_rate_limit", 0,
     "global outbound cap for dalfox in requests/second (0 = unlimited)"),
    ("modules.sqli_scan.oast", True,
     "hands sqlmap an interactsh server so blind injections get proof"),
    ("modules.sqli_scan.escalate", True,
     "re-run promising points with heavier sqlmap tamper sets"),
    ("modules.sqli_scan.max_escalations", 3,
     "cap on sqlmap escalation re-runs per point"),
    ("modules.ssrf_scan.enabled", True,
     "generic SSRF: OOB-graded probes of URL-bearing parameters"),
    ("modules.ssrf_scan.max_points", 6,
     "URL parameters probed per run (cap 30)"),
    ("modules.ssrf_scan.params", "built-in list",
     "parameter names treated as URL-bearing"),
    ("modules.ssti_scan.max_points", 40,
     "template-injection points probed per run"),
    ("modules.ssti_scan.error_based", True,
     "blind fallback: trigger and parse template exceptions"),
    ("modules.ssti_scan.error_max_points", 8,
     "points that get the error-probe budget"),
    ("modules.ssti_scan.waf_adaptive", True,
     "retry a blocked template payload with safe mutations"),
    ("modules.nosql_scan.max_points", 40,
     "NoSQL-injection points probed per run"),
    ("modules.dom_xss_scan.max_pages", 25,
     "rendered pages sunk-checked for DOM XSS"),
    ("modules.parameter_discovery.seed_when_empty", True,
     "seed reflection probes when no parameters were discovered"),
    ("modules.parameter_discovery.seed_targets", 10,
     "pages seeded with reflection probes"),
    ("modules.parameter_discovery.seed_params", [],
     "extra parameter names to seed"),
    ("modules.auth_audit.test_registration_oracle", False,
     "OPT-IN: create a real account to test registration (never deleted)"),
    ("modules.auth_audit.test_password_change", False,
     "OPT-IN: rotate the test account password (never rotated back)"),
    ("modules.business_logic.enabled", True,
     "own-account logic flaws: surface recon plus cart tamper probes"),
    ("modules.business_logic.max_probes", 12,
     "hostile values sent per run (cap 40)"),
    ("modules.business_logic.endpoints", [],
     "explicit cart/order endpoints (discovered ones win when present)"),
    ("modules.idor_differ.endpoints", [],
     "explicit object endpoints (derived from recon when empty)"),
    ("modules.idor_differ.max_probes_per_template", 15,
     "cross-account probes per endpoint template"),
    ("modules.idor_differ.object_probe.enabled", True,
     "fetch disclosed references against unlisted shapes"),
    ("modules.idor_differ.object_probe.max_refs", 12,
     "references fetched per unlisted shape"),
    ("modules.idor_differ.object_probe.max_fetches", 24,
     "fetch cap per shape before stopping"),
    ("modules.idor_differ.object_probe.max_total_fetches", 240,
     "fetch cap for the whole object-probe phase"),
    ("modules.idor_differ.object_probe.stop_after_misses", 6,
     "stop a shape after N consecutive misses"),
    ("modules.idor_differ.probe_collections", True,
     "probe the built-in collection wordlist"),
    ("modules.idor_differ.max_collections", 60,
     "collection paths probed per run"),
    ("modules.idor_differ.collection_paths", [],
     "extra collection paths beyond the built-in wordlist"),
    ("modules.idor_differ.api_prefixes", "built-in list",
     "API prefixes tried when shaping collection URLs"),
    ("modules.idor_differ.resources", "built-in list",
     "resource names tried when shaping collection URLs"),
    ("modules.idor_differ.account_endpoint", "",
     "own-account URL used to verify a session is live"),
    ("modules.idor_differ.test_anonymous", False,
     "also test with no session (widens surface beyond your accounts)"),
    ("modules.idor_differ.test_write_methods", [],
     "mutating verbs echoed back safely (empty = read-only)"),
    ("modules.idor_differ.allow_destructive", False,
     "OPT-IN: send real DELETEs (explicit authorisation only)"),
    ("modules.idor_differ.id_probing.enabled", False,
     "OPT-IN: probe neighbouring IDs (other people's records)"),
    ("modules.idor_differ.id_probing.radius", 3,
     "how far from each known reference to try"),
    ("modules.idor_differ.id_probing.max", 20,
     "hard ceiling on neighbouring-ID requests"),
    ("modules.cors_audit.enabled", True,
     "CORS misconfiguration audit"),
    ("modules.cors_audit.endpoints", [],
     "explicit endpoints (discovered ones win when present)"),
    ("modules.cors_audit.max_endpoints", 20,
     "endpoints audited per run"),
    ("modules.open_redirect.enabled", True,
     "open-redirect audit"),
    ("modules.open_redirect.endpoints", [],
     "explicit endpoints (discovered ones win when present)"),
    ("modules.open_redirect.max_targets", 40,
     "redirect targets probed per run"),
    ("modules.open_redirect.params", "built-in list",
     "parameter names treated as redirect-bearing"),
    ("modules.http_smuggling.enabled", True,
     "request-smuggling oracle (needs the smuggler tool)"),
    ("modules.http_smuggling.max_targets", 10,
     "front-end URLs desync-tested per run"),
    ("modules.http_smuggling.te_cl", True,
     "also probe the TE.CL framing disagreement"),
    ("modules.llm_surface.enabled", True,
     "inventory chat/completion/embedding endpoints"),
    ("modules.llm_surface.max_endpoints", 25,
     "AI endpoint candidates fingerprinted per run"),
    ("modules.llm_surface.probe_common_paths", True,
     "GET the usual /v1 and /api LLM paths"),
    ("modules.llm_surface.probe_completion", False,
     "send one benign prompt to test anonymous completion"),
    ("modules.llm_surface.model", "",
     "fallback model id when /v1/models is unavailable"),
    ("modules.prototype_pollution.enabled", True,
     "prototype-pollution probes (mutates process state, no cleanup)"),
    ("modules.prototype_pollution.endpoints", [],
     "explicit endpoints (discovered ones win when present)"),
    ("modules.prototype_pollution.reflect_endpoint", "",
     "endpoint whose echo proves pollution"),
    ("modules.prototype_pollution.methods", ["POST", "PUT"],
     "verbs carrying pollution payloads"),
    ("modules.prototype_pollution.payloads", "built-in list",
     "pollution payloads sent per endpoint"),
    ("modules.mass_assignment.enabled", False,
     "OPT-IN: send hostile fields to your own account (can elevate it)"),
    ("modules.mass_assignment.endpoints", [],
     "explicit account endpoints (discovered ones win when present)"),
    ("modules.mass_assignment.fields", None,
     "extra writable fields to try (role-like names auto-detected)"),
    ("modules.mass_assignment.method", "PATCH",
     "verb carrying mass-assignment probes"),
    ("modules.mass_assignment.probe_type", "bool",
     "value type for probe fields"),
    ("modules.mass_assignment.write_endpoint", "",
     "override target for write probes"),
    ("modules.cms_deep_scan.enabled", True,
     "CMS deep scan (wpscan/joomscan/droopescan/cmseek)"),
    ("modules.cms_deep_scan.max_targets", 5,
     "CMS roots scanned per run"),
    ("modules.fast_exposure_scan.timeout", 4,
     "seconds per fast-scan request"),
    ("modules.fast_exposure_scan.concurrency", 8,
     "parallel fast-scan requests"),
    ("modules.fast_exposure_scan.max_paths", 20,
     "paths checked per run"),
    ("modules.fast_exposure_scan.paths", "built-in list",
     "high-signal paths checked"),
    ("modules.misconfig_probes.concurrency", 12,
     "parallel misconfiguration probes"),
    ("modules.misconfig_probes.timeout", 5,
     "seconds per misconfiguration probe"),
    ("modules.misconfig_probes.max_paths", 160,
     "paths checked per run"),
    ("modules.misconfig_probes.max_consecutive_empty", 60,
     "stop after N consecutive misses"),
    ("modules.misconfig_probes.progress_every", 25,
     "log progress every N paths"),
    ("modules.nuclei_scan.max_seconds", "deadline minus 60s",
     "time-box for the nuclei pass"),
    ("modules.nuclei_scan.batch_seconds", 150,
     "time-box per template batch"),
    ("modules.nuclei_scan.full_cve", "not set",
     "legacy kill-switch for the CVE pass (still honored)"),
    ("modules.nuclei_scan.full_cve_on_confirmed_apex", True,
     "full CVE pass once an apex finding confirms"),
    ("modules.nuclei_scan.max_age_days", 30,
     "warn past this template age; stale sets miss CVEs"),
    ("modules.client_proto_pollution.enabled", True,
     "prove client-side prototype pollution in a headless browser"),
    ("modules.client_proto_pollution.max_pages", 3,
     "pages loaded for prototype-pollution probes"),
    ("modules.client_proto_pollution.timeout_ms", 15000,
     "navigation timeout per probe"),
    ("modules.client_proto_pollution.wait_ms", 800,
     "settle time after DOMContentLoaded"),
    ("modules.cache_deception.enabled", True,
     "prove authenticated responses are cacheable as static assets"),
    ("modules.cache_deception.max_paths", 4,
     "private paths probed per run"),
    ("modules.cache_deception.max_shapes", 3,
     "path-confusion shapes per private path"),
    ("modules.cache_deception.private_paths", [],
     "override the built-in private path list"),
    ("modules.nuclei_scan.update_templates", False,
     "refresh templates before scanning (downloads, opt-in)"),
    ("modules.nuclei_scan.per_cve", True,
     "target confirmed CVE ids directly instead of the whole cve set"),
    ("modules.nuclei_scan.per_cve_max", 6,
     "CVE ids to target per run"),
    ("modules.nuclei_scan.per_cve_seconds", 90,
     "time-box for the per-CVE pass"),
    ("modules.exploit_lookup.kev_cache_hours", 24,
     "CISA KEV catalog cache lifetime"),
    ("modules.cve_validation.enabled", True,
     "run curated CVE validation playbooks"),
    ("modules.cve_validation.delay_seconds", 0.5,
     "pause between CVE playbooks"),
)


# Namespaces that moved. A config still using one runs on defaults while
# the operator believes it is tuned — exactly the write_methods class.
RETIRED_KEYS: tuple[tuple[str, str], ...] = (
    ("xss", "moved to modules.xss_scan"),
    ("nuclei", "moved to modules.nuclei_scan"),
    ("fast_scan", "moved to modules.fast_exposure_scan"),
    ("misconfig", "moved to modules.misconfig_probes"),
    ("modules.idor", "renamed to modules.idor_differ"),
    ("modules.misconfig", "renamed to modules.misconfig_probes"),
    ("modules.xss", "renamed to modules.xss_scan"),
    ("modules.nuclei", "renamed to modules.nuclei_scan"),
    ("modules.fast_scan", "renamed to modules.fast_exposure_scan"),
)


def _lookup(config: dict, dotted: str) -> tuple[bool, object]:
    """(present, value) for a dotted path; non-dict hops mean absent."""
    node: object = config if isinstance(config, dict) else {}
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return False, None
        node = node[part]
    return True, node


def doctor(config: dict) -> list[str]:
    """Human-readable warnings for known keys missing from the config,
    retired namespaces still present, and unknown keys under modules.*
    (probable typos — the check that catches the next write_methods)."""
    warnings = []
    for dotted, default, why in KNOWN_KEYS:
        present, _ = _lookup(config or {}, dotted)
        if not present:
            warnings.append(f"{dotted} (default {default!r}): {why}")
    warnings.extend(retired_warnings(config or {}))
    warnings.extend(unknown_warnings(config or {}))
    return warnings


def retired_warnings(config: dict) -> list[str]:
    """Namespaces that moved: present in config, no longer read."""
    found = []
    for dotted, where in RETIRED_KEYS:
        present, _ = _lookup(config, dotted)
        if present:
            found.append(f"{dotted}: retired namespace ({where}); "
                         f"these settings have no effect")
    return found


def unknown_warnings(config: dict) -> list[str]:
    """Unknown leaves under modules.* — probable typos in tuned keys.

    Pack-injected `extra_*` keys are always allowed. Anything else under
    a known module section that the engine never reads is one rename
    away from silently doing nothing.
    """
    known = {dotted for dotted, _, _ in KNOWN_KEYS}
    found = []

    def walk(node: object, prefix: str) -> None:
        if not isinstance(node, dict):
            return
        for key, value in node.items():
            dotted = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, dict) and value:
                walk(value, dotted)
            else:
                if not prefix.startswith("modules."):
                    continue
                if dotted in known:
                    continue
                leaf = str(key)
                if leaf.startswith("extra_"):
                    continue
                # Known intermediate namespaces (e.g. modules.<id>) are
                # structural, not tuned keys — only flag real leaves.
                parent_known = any(
                    k == dotted or k.startswith(dotted + ".") for k in known)
                if parent_known and isinstance(value, dict):
                    continue
                found.append(f"{dotted}: unknown key (typo?); "
                             f"the engine never reads it")

    walk(config, "")
    return found


def coverage(config: dict) -> list[tuple[str, bool, object, str]]:
    """(dotted, present, effective value, why) for every known key."""
    rows = []
    for dotted, default, why in KNOWN_KEYS:
        present, value = _lookup(config or {}, dotted)
        rows.append((dotted, present, value if present else default, why))
    return rows
