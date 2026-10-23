"""Stage 4: Parameter discovery from archives, crawls, and optional tools."""

import asyncio

from core.noise_filters import is_noise_parameter
from modules.base import BaseModule
from tools.external import (
    arjun_scan,
    extract_parameters_from_urls,
    paramspider_scan,
    tool_available,
)
from tools.wrappers import curl

# When crawls and archives yield zero parameters (clean-URL apps like
# Next.js), injection modules all skip and the active phase loses its
# targets. Seeding probes a bounded set of live pages with inert marker
# values under common names; a page that reflects the marker is a real
# reflection point, which is exactly what XSS/SQLi/open-redirect need.
# The marker is alphanumeric noise — no payload, no special characters —
# so seeding detects reflection without testing any vulnerability.
SEED_MARKER = "zxqseed9k2"
SEED_PARAM_NAMES = (
    "q", "s", "search", "query", "keyword", "id", "page", "lang",
    "redirect", "url", "next", "return", "callback", "debug",
)


class ParameterDiscovery(BaseModule):
    id = "parameter_discovery"
    name = "Parameter Discovery"
    stage = 4
    detectability = "medium"
    depends_on = ["wayback_machine"]

    async def run(self) -> str:
        urls = self._known_urls()
        parameters = extract_parameters_from_urls(urls)
        # Provenance matters: parameters mined from the live crawl/JS/API
        # surface are testable now. ParamSpider returns archive URLs, many
        # of which no longer exist; they are leads, not injection points.
        for item in parameters:
            item["source"] = "crawl"
            item["provenance"] = "live"
        live_keys = {_url_key(item.get("url", "")) for item in parameters}
        live_keys.update(_url_key(url) for url in urls)
        live_keys.update(_url_key(self.base_url))
        live_keys.update(_url_key(url) for url in self._scan_targets())
        evidence_refs = []

        if tool_available("paramspider"):
            result = await paramspider_scan(self.domain, timeout=180)
            archived = []
            for item in result.get("parameters", []):
                item = dict(item)
                item["source"] = "paramspider"
                item["provenance"] = "archive"
                archived.append(item)
            parameters.extend(archived)
            self.log(f"  ParamSpider: {len(result.get('urls', []))} urls, "
                     f"{len(result.get('parameters', []))} parameters")
            evidence_refs.append(
                self.state.add_evidence(
                    self.id,
                    "paramspider",
                    self.domain,
                    {
                        "available": result.get("available"),
                        "url_count": len(result.get("urls", [])),
                        "parameter_count": len(result.get("parameters", [])),
                        "stderr": result.get("stderr", ""),
                    },
                )
            )

        if tool_available("arjun"):
            run_dir = self.state.state_dir / "tool-output"
            run_dir.mkdir(exist_ok=True)
            for target in self._scan_targets()[:5]:
                output_file = run_dir / f"arjun-{len(evidence_refs) + 1}.json"
                result = await arjun_scan(target, str(output_file), timeout=240)
                for item in result.get("results", []):
                    item = dict(item)
                    item["source"] = "arjun"
                    item["provenance"] = "live"
                    parameters.append(item)
                self.log(f"  arjun {target}: "
                         f"{len(result.get('results', []))} parameters")
                evidence_refs.append(
                    self.state.add_evidence(
                        self.id,
                        "arjun",
                        target,
                        {
                            "available": result.get("available"),
                            "parameter_count": len(result.get("results", [])),
                            "exit_code": result.get("exit_code"),
                            "stderr": result.get("stderr", ""),
                        },
                    )
                )

        # Drop out-of-scope and malformed URLs BEFORE dedupe: archive
        # junk (youtube embeds, third-party trackers, `localhost:/8080`
        # misbuilds) must never become sqlmap targets.
        parameters = [item for item in parameters
                      if self._in_scope(str(item.get("url", "")))]
        # Cache-busters (`?ver=` on static assets), analytics plumbing and
        # asset-versioning names are not injectable inputs; dropping them
        # here keeps sqlmap/XSS off 48 copies of `ver` and keeps the asset
        # inventory to parameters an operator would actually test. Seeded
        # reflection params are exempt — they were chosen deliberately.
        before = len(parameters)
        parameters = [
            item for item in parameters
            if item.get("seeded")
            or not is_noise_parameter(str(item.get("parameter", "")),
                                      str(item.get("url", "")))
        ]
        dropped = before - len(parameters)
        if dropped:
            self.log(f"  Dropped {dropped} non-testable parameter(s) "
                     f"(cache-busters / static-asset versioning / analytics)")

        # Archive URLs are not evidence that a path exists. Promote only
        # those whose path is also on the live crawl/API/JS surface; keep
        # the rest as TENTATIVE archive leads so they are still visible to
        # an operator without sending SQLMap/XSS at a decade-old URL.
        live_parameters = []
        archive_leads = []
        for item in parameters:
            if item.get("provenance") == "archive" \
                    and _url_key(item.get("url", "")) not in live_keys:
                archive_leads.append(item)
            else:
                live_parameters.append(item)
        if archive_leads:
            self.log(f"  Kept {len(live_parameters)} live parameter(s); "
                     f"{len(archive_leads)} archive-only lead(s) parked")
        archive_unique = _dedupe_parameters(archive_leads)
        for item in archive_unique:
            self.state.add_asset(
                "archive_parameter",
                f"archive_param:{item['url']}:{item['parameter']}",
                item["parameter"],
                confidence="TENTATIVE",
                sources=[self.id],
                attrs={**item, "live": False},
            )

        unique = _dedupe_parameters(live_parameters)
        # Seed even when the crawl found parameters. A crawl usually finds
        # archive-shaped query names, not the pages that actually reflect
        # input; skipping seeding whenever one parameter existed left XSS and
        # SQLi without a reflection surface. Merge rather than replace.
        seeded = await self._seed_reflection_params()
        if seeded:
            unique = _dedupe_parameters(list(unique) + list(seeded))
        if not unique:
            self.state.skip_module(self.id, "no parameters discovered")
            return "skipped"

        sensitive = []
        known = {node.get("key") for node in self.state.assets.get("nodes", [])
                 if node.get("key")}
        for item in unique:
            key = f"param:{item['url']}:{item['parameter']}"
            self.state.add_asset(
                "parameter",
                key,
                item["parameter"],
                confidence="FIRM",
                sources=[self.id],
                attrs=item,
            )
            page_key = f"url:{item['url']}"
            if page_key in known:
                self.state.add_edge(page_key, key, "HAS_PARAMETER")
            if _sensitive_parameter(item["parameter"]) and not item.get("seeded"):
                sensitive.append(item)

        if sensitive:
            self.state.add_finding(
                title="Sensitive Parameter Names Discovered",
                severity="LOW",
                confidence="FIRM",
                category="Parameter Discovery",
                description=(
                    "Parameter mining found names commonly associated with secrets, "
                    "redirects, authorization, or object references. Names "
                    "alone prove nothing — they are the input list for "
                    "injection and auth testing, not a vulnerability."
                ),
                evidence=[
                    f"{item['url']} -> {item['parameter']}"
                    for item in sensitive[:15]
                ],
                evidence_refs=evidence_refs,
                remediation="Review handlers for authorization, validation, and secret leakage.",
            )

        self.state.add_asset(
            "parameter_inventory",
            f"params:{self.domain}",
            self.domain,
            confidence="FIRM",
            sources=[self.id],
            attrs={
                "parameters": len(unique),
                "archive_leads": len(archive_unique),
                "sensitive": len(sensitive),
                "top": unique[:50],
            },
        )
        self.state.complete_module(self.id)
        self.log(f"Parameters: {len(unique)} discovered")
        return "done"

    def _known_urls(self) -> list[str]:
        urls = []
        for asset_type in ("url", "api_endpoint", "web_path", "js_file"):
            for asset in self.state.get_assets_by_type(asset_type):
                value = str(asset.get("value", "")).strip()
                if value.startswith(("http://", "https://")) \
                        and self._in_scope(value):
                    urls.append(value)
        return urls

    def _scan_targets(self) -> list[str]:
        targets = []
        for asset_type in ("webapp", "url"):
            for asset in self.state.get_assets_by_type(asset_type):
                value = str(asset.get("value", "")).strip()
                if value.startswith(("http://", "https://")) \
                        and value not in targets and self._in_scope(value):
                    targets.append(value)
        if not targets:
            targets.append(self.base_url)
        return targets

    def _in_scope(self, url: str) -> bool:
        """Engagement-host containment, not "any absolute URL"."""
        from core.probe_targets import in_scope_url
        return in_scope_url(url, self.base_url, self.domain)

    async def _seed_reflection_params(self) -> list[dict]:
        """Probe live pages for reflection under common parameter names.

        Bounded and inert: at most a dozen pages times a dozen names, one
        GET each, marker value is noise. Anything reflecting the marker
        becomes a `parameter` asset so the injection modules have targets
        instead of skipping the whole active phase.
        """
        cfg = self.config.get("modules", {}).get(self.id, {})
        if isinstance(cfg, dict) and cfg.get("seed_when_empty") is False:
            return []
        names = list(SEED_PARAM_NAMES)
        if isinstance(cfg, dict) and cfg.get("seed_params"):
            names = [str(p) for p in cfg["seed_params"] if p][:24]
        pages = []
        for page in [self.base_url] + self._scan_targets():
            clean = str(page or "").split("?")[0].rstrip("/") or str(page or "")
            if clean.startswith(("http://", "https://")) and clean not in pages:
                pages.append(clean)
        # Bounded by default: seeding is a supplement, not a crawl. A
        # configured 0 means "no extra bound" for an explicit full sweep.
        raw_pages = cfg.get("seed_targets", 12) if isinstance(cfg, dict) else 12
        try:
            max_pages = int(raw_pages)
        except (TypeError, ValueError):
            max_pages = 12
        if max_pages > 0:
            pages = pages[:max_pages]
        self.log(f"  No parameters from crawl — seeding reflection on "
                 f"{len(pages)} page(s) x {len(names)} names...")

        semaphore = asyncio.Semaphore(8)

        async def probe(page: str, name: str):
            from urllib.parse import urlencode, urlparse, urlunparse
            parsed = urlparse(page)
            query = urlencode({name: SEED_MARKER})
            url = urlunparse(parsed._replace(query=query))
            async with semaphore:
                try:
                    result = await curl(url, output="full",
                                        follow_redirects=False, timeout=10)
                except Exception:
                    return None
            body = result.get("body", "") or ""
            if SEED_MARKER in body:
                return {"url": page, "parameter": name,
                        "example_value": SEED_MARKER,
                        "sources": ["reflection_seed"],
                        "source": "reflection_seed",
                        "seeded": True,
                        "status": result.get("status", 0)}
            return None

        # Control name: one no real app routes. If the marker still reflects
        # under it, the page echoes the whole query string back (SPA
        # client-side hydration, debug echo), so every "reflection" on that
        # page is noise — not an injectable backend parameter. This is what
        # kept feeding q/s/search… as fake params on Next.js/React SPAs and
        # made the pentest burn 180s per param on SQLi that never applied.
        import uuid as _uuid
        control = "zq" + _uuid.uuid4().hex[:8]
        probe_names = list(names) + [control]
        probed = await asyncio.gather(
            *(probe(page, name) for page in pages for name in probe_names),
            return_exceptions=True,
        )
        results = [p for p in probed if isinstance(p, dict)]
        echo_pages = {p["url"] for p in results if p["parameter"] == control}
        seeded = [p for p in results
                  if p["parameter"] != control and p["url"] not in echo_pages]
        if echo_pages:
            self.log(f"  {len(echo_pages)} page(s) echo arbitrary query params "
                     f"(client-side hydration) — reflection seeds dropped as noise")
        self.log(f"  Reflection seeding: {len(seeded)} reflecting "
                 f"(page, param) pairs from {len(pages) * len(probe_names)} probes")
        if seeded:
            self.state.add_evidence(
                self.id,
                "reflection_seed",
                self.domain,
                {"pages": pages, "names": names, "marker": SEED_MARKER,
                 "reflecting": len(seeded),
                 "pairs": [(p["url"], p["parameter"]) for p in seeded[:50]]},
            )
        return seeded


def _url_key(url: str) -> str:
    """Compare discovery surfaces without query strings or fragments."""
    from urllib.parse import urlsplit
    try:
        parsed = urlsplit(str(url or ""))
    except ValueError:
        return ""
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")


def _dedupe_parameters(items: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for item in items:
        url = str(item.get("url", "")).strip()
        parameter = str(item.get("parameter", "")).strip()
        if not url or not parameter:
            continue
        # One parameter per host+path shape. `?q=1` and `?q=2` are the same
        # test point; keeping both doubled every downstream probe.
        key = (_url_key(url), parameter)
        if key in seen:
            continue
        seen.add(key)
        unique.append({
            "url": url,
            "parameter": parameter,
            "example_value": item.get("example_value", ""),
            "sources": item.get("sources", []),
            "source": item.get("source", ""),
            "provenance": item.get("provenance", "live"),
            "seeded": bool(item.get("seeded")),
        })
    return unique


def _sensitive_parameter(name: str) -> bool:
    lowered = str(name).lower()
    # High-signal names only. Generic web tokens (id, url, user, next,
    # return, file, path, page, q) match every normal app and fired this
    # finding everywhere; they still become parameter assets that the
    # injection modules test, which is where their value lives.
    tokens = (
        "token", "key", "secret", "password", "passwd", "auth", "admin",
        "debug", "api_key", "apikey", "credential", "private",
    )
    return any(token in lowered for token in tokens)
