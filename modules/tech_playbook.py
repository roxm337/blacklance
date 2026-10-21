"""Stage 4: Technology-specific playbooks.

Generic recon checks the same paths on every target. This module does the
opposite: it fingerprints the stack (Next.js, Laravel, Spring Boot, Django,
Rails, WordPress, …) and runs only that stack's high-signal probes — the
checks that matter for *this* technology and would be noise on any other.

It also feeds the CVE engine: each matched profile's CPE product names (with
a version when detection has one) are written to the webapp's
`product_versions`, so `exploit_lookup` can version-confirm the stack's CVEs
instead of treating it generically.

The profiles are data (`core/tech_profiles`); this is the executor. Passive
probes are plain GETs to known paths; probes that send a payload or an
auth-bypass header run only under `--active`.
"""

import re
import uuid

from core.cve_sources import parse_osv_vulns, sort_advisories, worst_severity
from core.response_fingerprint import fingerprint
from core.site_profile import get_profile
from core.tech_intel import (
    extract_next_routes,
    next_data_route,
    parse_laravel_debug,
    parse_next_data,
    scan_sensitive_json,
)
from core.tech_profiles import match_profiles
from core.version_match import version_in_range
from modules.base import BaseModule
from tools.wrappers import (
    curl, curl_json_with_status, curl_with_status, osv_query)


class TechPlaybook(BaseModule):
    id = "tech_playbook"
    name = "Technology Playbook"
    stage = 4
    detectability = "low"
    depends_on = ["tech_detection"]

    async def run(self) -> str:
        base = self.base_url

        # Evidence already costs one request: homepage headers + body + cookies,
        # plus the coarse hint tech_detection recorded.
        home = await curl(base, output="full")
        headers_text = home.get("headers", "") or ""
        body = home.get("body", "") or ""
        cookies = "\n".join(
            line for line in headers_text.split("\n")
            if line.lower().startswith("set-cookie:"))
        webapp = self._webapp_asset(base)
        attrs = (webapp or {}).get("attrs", {}) or {}
        hint = " ".join(str(attrs.get(k, "")) for k in
                        ("cms", "framework", "server")) + " " \
            + " ".join(str(x) for x in (attrs.get("httpx_tech") or []))

        matched = match_profiles({"header": headers_text, "body": body,
                                  "cookie": cookies, "hint": hint})
        if not matched:
            self.state.skip_module(self.id, "no specific technology identified")
            return "skipped"

        # Baseline so a catch-all server (200 to everything) cannot
        # manufacture a finding per probe: a probe response that matches the
        # site's answer-to-anything is not proof the path exists.
        self._profile = await self._establish_profile(base)
        # Versions discovered by analyzers (e.g. Laravel from its debug page),
        # keyed by package/product name, feed the current-CVE correlation.
        self._discovered_versions = {}

        active_mode = bool(self.target.get("active")) if isinstance(
            self.target, dict) else False
        labels = [p.label for p, _, _ in matched]
        self.log(f"  Stack: {', '.join(labels)} "
                 f"({'active' if active_mode else 'passive'} probes)")

        # Record the identified stack and feed CVE correlation.
        self._register_stack(base, matched, attrs)

        probe_count = 0
        for profile, confidence, _signals in matched:
            for probe in profile.probes:
                if self.should_stop(reserve=8):
                    self.log("  Deadline near — stopping playbook probes.")
                    break
                if probe.active and not active_mode:
                    continue
                probe_count += 1
                await self._run_probe(base, profile, probe)

        # Deep, technique-level analysis per stack — the layer above path
        # probes: parse the framework's own data/debug surfaces for what they
        # leak. Only runs for stacks that have an analyzer.
        for profile, _c, _s in matched:
            analyzer = getattr(self, f"_analyze_{profile.name}", None)
            if analyzer and not self.should_stop(reserve=10):
                try:
                    await analyzer(base, body, active_mode)
                except Exception as exc:  # noqa: BLE001
                    self.log(f"  [{profile.name}] analyzer error: "
                             f"{type(exc).__name__}")

        # Current CVE correlation: for each matched stack's packages, pull live
        # OSV / GHSA advisories filtered to the detected version.
        if not self.should_stop(reserve=10):
            await self._correlate_current_cves(base, matched, attrs)

        self.state.complete_module(self.id)
        self.log(f"Tech playbook: {len(matched)} stack(s), {probe_count} probe(s)")
        return "done"

    async def _establish_profile(self, base: str):
        async def fetch(path: str):
            r = await curl_with_status(base.rstrip("/") + path,
                                       follow_redirects=True)
            return (r.get("status", 0), r.get("body", "") or "",
                    r.get("content_type", "") or "")
        try:
            return await get_profile(base, fetch)
        except Exception:  # noqa: BLE001 - baseline is best-effort
            return None

    def _is_catch_all(self, status: int, body: str) -> bool:
        """True when this response is the site's answer-to-everything, so it
        proves nothing about the probed path."""
        if self._profile is None:
            return False
        try:
            return self._profile.baseline.catch_all(fingerprint(status, body, ""))
        except Exception:  # noqa: BLE001
            return False

    def _webapp_asset(self, base: str):
        for asset in self.state.get_assets_by_type("webapp"):
            if str(asset.get("value", "")).rstrip("/") == base.rstrip("/"):
                return asset
        webapps = self.state.get_assets_by_type("webapp")
        return webapps[0] if webapps else None

    def _register_stack(self, base: str, matched: list, attrs: dict) -> None:
        """Record the stack as an asset and push CPE products (with versions
        where known) into product_versions so exploit_lookup correlates them."""
        versions = dict(attrs.get("product_versions", {}) or {})
        known = {
            "wordpress": attrs.get("wordpress_version", ""),
            "php": attrs.get("php_version", ""),
        }
        tech_products = []
        for profile, confidence, _ in matched:
            for product in profile.cpe_products:
                tech_products.append(product)
                v = known.get(product, "")
                if v and product not in versions:
                    versions[product] = re.sub(r"[^0-9.].*$", "", str(v)).strip(".")
        self.state.add_asset(
            "tech_stack", f"tech_stack:{base}", base,
            confidence="FIRM", sources=[self.id],
            attrs={
                "stacks": [p.name for p, _, _ in matched],
                "labels": [p.label for p, _, _ in matched],
                "confidence": {p.name: c for p, c, _ in matched},
                "cpe_products": sorted(set(tech_products)),
            },
        )
        # Merge back onto the webapp so the CVE engine (which reads webapp
        # product_versions) sees the stack's products.
        webapp = self._webapp_asset(base)
        if webapp is not None and versions:
            webapp.setdefault("attrs", {})["product_versions"] = versions
            self.state._dirty = True

    # ── Deep analyzers ───────────────────────────────────────────────

    async def _analyze_nextjs(self, base: str, home_body: str,
                              active: bool) -> None:
        """Mine the Next.js data bridge: __NEXT_DATA__ leaks, the build
        manifest's full route map, and SSR data endpoints."""
        nd = parse_next_data(home_body)
        if not nd.get("found"):
            return
        build_id = nd.get("build_id", "")
        router = nd.get("router", "?")
        self.log(f"  [nextjs] {router} router, buildId={build_id or 'unknown'}, "
                 f"{len(nd.get('leaked') or [])} leaked field(s)")
        if nd.get("leaked"):
            source = ("__NEXT_DATA__ props" if router == "pages"
                      else "RSC flight stream")
            self.state.add_finding(
                title=f"Next.js server data leak ({router} router)",
                severity="HIGH", confidence="FIRM",
                category="Information Disclosure",
                description=f"[Next.js] The server→client {source} carries "
                            f"sensitive fields exposed to any visitor viewing "
                            f"source.",
                evidence=[f"{item['kind']} at {item['path']}: {item['preview']}"
                          for item in nd["leaked"][:12]],
                remediation="Never pass secrets/tokens through getServerSideProps "
                            "/ getStaticProps into pageProps; scope server data.",
                asset_keys=[f"webapp:{base}"],
                verification={"method": "next_data_parse"})

        if not build_id:
            return
        # Route map from the build manifest = the app's page surface.
        man = await curl_with_status(
            f"{base}/_next/static/{build_id}/_buildManifest.js")
        routes = []
        if man.get("status") == 200:
            routes = extract_next_routes(man.get("body", ""))
            for route in routes[:60]:
                self.state.add_asset(
                    "url", f"url:{base}{route}", f"{base}{route}",
                    confidence="FIRM", sources=[self.id],
                    attrs={"source": "next_build_manifest", "route": route})
            if routes:
                self.log(f"  [nextjs] {len(routes)} routes from build manifest")

        # Sample SSR data endpoints for leaked props.
        for route in (routes or [nd.get("page", "/")])[:6]:
            if self.should_stop(reserve=8):
                break
            url = base + next_data_route(build_id, route)
            status, data = await curl_json_with_status(url)
            if status == 200 and data and not self._is_catch_all(status, str(data)):
                leaked = scan_sensitive_json(data)
                if leaked:
                    self.state.add_finding(
                        title="Next.js SSR data endpoint leaks sensitive data",
                        severity="HIGH", confidence="FIRM",
                        category="Information Disclosure",
                        description=f"[Next.js] {next_data_route(build_id, route)} "
                                    f"returns SSR JSON containing sensitive fields "
                                    f"without authentication.",
                        evidence=[f"{i['kind']} at {i['path']}: {i['preview']}"
                                  for i in leaked[:8]],
                        remediation="Gate SSR data by session; do not serve "
                                    "privileged props to anonymous requests.",
                        asset_keys=[f"webapp:{base}"],
                        verification={"method": "next_data_endpoint",
                                      "url": url})

    async def _analyze_laravel(self, base: str, home_body: str,
                               active: bool) -> None:
        """Confirm Laravel debug mode from an error page and decide whether the
        version makes Ignition RCE (CVE-2021-3129) applicable."""
        probe_url = f"{base}/{uuid.uuid4().hex[:10]}"
        r = await curl_with_status(probe_url)
        info = parse_laravel_debug(r.get("body", ""))
        if not info.get("is_debug"):
            return
        evidence = ["APP_DEBUG=true — application errors render a full debug page"]
        if info.get("laravel_version"):
            evidence.append(f"Laravel {info['laravel_version']}")
            # Feed the version to the current-CVE correlation.
            self._discovered_versions["laravel/framework"] = info["laravel_version"]
            self._discovered_versions["laravel"] = info["laravel_version"]
        if info.get("php_version"):
            evidence.append(f"PHP {info['php_version']}")
        if info.get("app_path"):
            evidence.append(f"App path: {info['app_path']}")
        for e in info.get("env", [])[:10]:
            evidence.append(f"env {e['key']}={e['value']}")

        # CVE-2021-3129: Ignition RCE on Laravel < 8.4.2 with debug on.
        ver = info.get("laravel_version", "")
        ignition_applicable = bool(ver) and version_in_range(ver, end_excl="8.4.2")
        desc = ("[Laravel] Debug mode is enabled in what appears to be "
                "production: error pages disclose the framework/PHP version, "
                "absolute paths and environment values.")
        if ignition_applicable:
            desc += (" The detected version is in the range affected by the "
                     "Ignition RCE (CVE-2021-3129) — confirm facade/ignition "
                     "version and test safely.")
        self.state.add_finding(
            title="Laravel debug mode enabled (configuration disclosure)",
            severity="HIGH" if ignition_applicable else "MEDIUM",
            confidence="FIRM", category="Information Disclosure",
            description=desc, evidence=evidence[:14],
            remediation="Set APP_DEBUG=false in production; upgrade "
                        "facade/ignition; ensure APP_ENV=production.",
            asset_keys=[f"webapp:{base}"],
            verification={"method": "laravel_debug_page", "url": probe_url})

    async def _analyze_spring_boot(self, base: str, home_body: str,
                                   active: bool) -> None:
        """Walk the actuator surface for the high-impact endpoints a path list
        misses: Jolokia (JMX → RCE), Spring Cloud Gateway (SSRF/RCE), and the
        actual secrets inside /actuator/env."""
        status, index = await curl_json_with_status(f"{base}/actuator")
        links = {}
        if status == 200 and isinstance(index, dict):
            links = (index.get("_links") or {})
        # Jolokia: JMX over HTTP — a well-known RCE pivot when writable.
        if "jolokia" in links or await self._exists(f"{base}/actuator/jolokia"):
            self.state.add_finding(
                title="Spring Boot Jolokia (JMX) endpoint exposed",
                severity="HIGH", confidence="FIRM",
                category="Remote Code Execution",
                description="[Spring Boot] /actuator/jolokia exposes JMX over "
                            "HTTP — MBean access is a known RCE pivot "
                            "(e.g. loading a malicious MLet/Logback config).",
                remediation="Remove Jolokia from production or lock it to admin.",
                asset_keys=[f"webapp:{base}"],
                verification={"method": "actuator_jolokia"})
        # Spring Cloud Gateway actuator (CVE-2022-22947 SpEL RCE surface).
        if "gateway" in links or await self._exists(f"{base}/actuator/gateway/routes"):
            self.state.add_finding(
                title="Spring Cloud Gateway actuator exposed (CVE-2022-22947 surface)",
                severity="HIGH", confidence="FIRM",
                category="Remote Code Execution",
                description="[Spring Boot] The gateway actuator is reachable — "
                            "the route-filter SpEL injection (CVE-2022-22947) is "
                            "RCE when the actuator is writable. Confirm version.",
                remediation="Disable the gateway actuator or upgrade Spring "
                            "Cloud Gateway past the patched release.",
                asset_keys=[f"webapp:{base}"],
                verification={"method": "actuator_gateway"})
        # Secrets inside /actuator/env. Spring nests each property as
        # {name: {"value": ..., "origin": ...}} across propertySources, so
        # flatten to {name: value} before scanning — otherwise the sensitive
        # key's value is a dict and the scalar scan skips it.
        est, env = await curl_json_with_status(f"{base}/actuator/env")
        if est == 200 and isinstance(env, dict):
            from core.tech_intel import scan_sensitive_json
            flat = {}
            for src in env.get("propertySources", []) or []:
                for key, meta in (src.get("properties", {}) or {}).items():
                    flat[key] = meta.get("value") if isinstance(meta, dict) else meta
            leaked = scan_sensitive_json(flat or env)
            if leaked:
                self.state.add_finding(
                    title="Spring Boot /actuator/env leaks secrets",
                    severity="CRITICAL", confidence="FIRM",
                    category="Credential Exposure",
                    description="[Spring Boot] Property sources in /actuator/env "
                                "contain secret-shaped values readable without auth.",
                    evidence=[f"{i['kind']} at {i['path']}" for i in leaked[:10]],
                    remediation="Restrict actuator endpoints; mask sensitive "
                                "properties (management.endpoint.env.show-values).",
                    asset_keys=[f"webapp:{base}"],
                    verification={"method": "actuator_env"})

    async def _exists(self, url: str) -> bool:
        r = await curl_with_status(url)
        return r.get("status") == 200 and not self._is_catch_all(
            r.get("status", 0), r.get("body", "") or "")

    async def _correlate_current_cves(self, base: str, matched: list,
                                      attrs: dict) -> None:
        """Pull live OSV / GHSA advisories for each matched stack's packages,
        filtered to the detected version — current CVEs, not a hard-coded set."""
        versions = dict(attrs.get("product_versions", {}) or {})
        if attrs.get("wordpress_version"):
            versions["wordpress"] = attrs["wordpress_version"]
        if attrs.get("php_version"):
            versions["php"] = attrs["php_version"]
        versions.update(self._discovered_versions)

        seen_pkgs = set()
        for profile, _c, _s in matched:
            for ecosystem, package in profile.packages:
                if package in seen_pkgs or self.should_stop(reserve=8):
                    continue
                seen_pkgs.add(package)
                version = self._version_for(package, profile, versions)
                if not version:
                    continue  # no version → skip rather than emit noise
                data = await osv_query(package, ecosystem=ecosystem,
                                       version=version)
                records = sort_advisories(parse_osv_vulns(data))
                if not records:
                    continue
                worst = worst_severity(records)
                severity = worst if worst in (
                    "CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM"
                self.state.add_finding(
                    title=f"Current advisories affecting {package} {version}: "
                          f"{len(records)}",
                    severity=severity, confidence="FIRM",
                    category="Known Vulnerability",
                    description=f"[{profile.label}] OSV/GHSA lists {len(records)} "
                                f"advisory(ies) whose affected range includes the "
                                f"detected {package} {version}. These are live, "
                                f"version-matched — confirmed applicable.",
                    evidence=[
                        f"{(r['cve'] or r['id'])} ({r['severity']}): "
                        f"{r['summary'][:80]}"
                        + (f" [fixed: {', '.join(r['fixed'][:2])}]" if r['fixed'] else "")
                        for r in records[:15]
                    ],
                    remediation=f"Upgrade {package} to a fixed release past the "
                                f"affected range.",
                    asset_keys=[f"webapp:{base}"],
                    verification={"method": "osv_version_match",
                                  "package": package, "version": version})
                self.log(f"  [{profile.name}] {len(records)} current advisories "
                         f"for {package} {version}")

    @staticmethod
    def _version_for(package: str, profile, versions: dict) -> str:
        for key in (package, package.split("/")[-1], package.split(":")[-1],
                    profile.name):
            v = versions.get(key)
            if v:
                return str(v)
        return ""

    async def _run_probe(self, base: str, profile, probe) -> None:
        url = base.rstrip("/") + probe.path
        try:
            if probe.differential:
                baseline = await curl_with_status(url, method=probe.method)
                with_hdr = await curl_with_status(
                    url, method=probe.method, headers=probe.headers)
                # Fire only if the header flipped an auth status to 200.
                if not (baseline.get("status") in (401, 403, 302)
                        and with_hdr.get("status") == 200):
                    return
                result = with_hdr
            else:
                result = await curl_with_status(
                    url, method=probe.method, headers=probe.headers,
                    data=probe.data)
        except Exception:  # noqa: BLE001 - a probe failure is not a module failure
            return

        status = result.get("status", 0)
        body = result.get("body", "") or ""
        if status not in probe.status_in:
            return
        # A 200 (or any status) that matches the site's catch-all baseline is
        # not evidence the artifact exists — gate every probe through it.
        if not probe.differential and self._is_catch_all(status, body):
            return
        if probe.body_regex and not re.search(probe.body_regex, body, re.I):
            return
        if probe.body_not_regex and re.search(probe.body_not_regex, body, re.I):
            return

        self.state.add_finding(
            title=probe.title,
            severity=probe.severity,
            confidence="FIRM",
            category=probe.category,
            description=f"[{profile.label}] {probe.description}",
            evidence=[f"{probe.method} {url} -> HTTP {status}"],
            remediation=probe.remediation,
            asset_keys=[f"webapp:{base}"],
            verification={"method": "tech_playbook_probe", "url": url},
        )
