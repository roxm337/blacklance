"""Stage 4: Client-Side Path Traversal (CSPT) audit (I4).

Drives the real browser with canary values injected into URL-borne inputs
(query, fragment, optionally path) and watches the XHR/fetch layer for a
request whose resolved path leaves the natural endpoint prefix.

Three states, per inject point:

- ``not_reached``  — the token never appeared in a request (observation)
- ``unchanged``    — it reached a request but stayed under the prefix (no signal)
- ``path_altered`` — the resolved path escaped on a segment boundary and
  carries the payload's effect segments (adjacent signal, candidate)

Traversal-like strings and normalization alone are NEVER findings. A
candidate is promoted to PROOF only when a configured impact probe replays
the exact altered URL over the framework transport and observes the
configured value the natural request does not return, with an absent-ref
control ruling out catch-all servers.

Read-only by design; the module opens no mutation records. Any future
canary mode (state-changing path) must go through the R8 ledger.
"""

from __future__ import annotations

import hashlib
import json
import time
from typing import Optional

from core.authorization import _body_shape
from core.auth_harness import AuthHarness
from core.urlpaths import (effect_segments, escaped, has_traversal,
                           path_segments, server_view_path, stable_prefix,
                           templatize)
from modules.base import BaseModule

PAYLOAD_FAMILIES = (
    "..%2f",
    "%2e%2e%2f",
    "..%252f",
)

XHR_TYPES = frozenset({"xhr", "fetch"})


class CSPTAudit(BaseModule):
    id = "cspt_audit"
    name = "Client-Side Path Traversal (CSPT)"
    stage = 4
    detectability = "medium"
    depends_on = ["browser_crawl"]
    active = False

    async def run(self) -> str:
        cfg = self._cfg()
        if not cfg.get("enabled"):
            self.state.skip_module(
                self.id,
                "disabled — it drives a real browser with traversal "
                "payloads; set modules.cspt_audit.enabled: true to run")
            return "skipped"
        # An injected driver (module-level monkeypatch) does not need the
        # real browser package; only the default driver does. Requiring
        # Playwright unconditionally made the unit suite fail in CI, where
        # the optional package is intentionally absent.
        if _drive_epochs is _DEFAULT_DRIVE:
            try:
                import playwright.async_api  # noqa: F401
            except Exception:
                self.state.skip_module(self.id, "playwright not installed")
                return "skipped"
        harness = AuthHarness(self.config)
        harness.mutations = self.state.mutations
        harness.adopt_discovered(self.state, log=self.log)
        try:
            identities = await harness.establish_all(self._base_url())
        except Exception:
            identities = []
        max_identities = max(1, int(cfg.get("max_identities", 2) or 2))
        contexts = [("anonymous", None)]
        for identity in identities[:max_identities]:
            headers = dict(identity.request_headers() or {})
            contexts.append((identity.name, headers))
        if not identities and not cfg.get("allow_anonymous"):
            self.state.skip_module(
                self.id, "no verified identities (allow_anonymous is false)")
            return "skipped"

        targets = self._targets(cfg)
        if not targets:
            self.state.skip_module(self.id, "no renderable targets")
            return "skipped"

        try:
            max_payloads = max(1, int(cfg.get("max_payloads", 6) or 6))
            wait_ms = max(0, min(10000, int(cfg.get("wait_ms", 1200))))
        except (TypeError, ValueError):
            max_payloads, wait_ms = 6, 1200
        try:
            deadline = float(self.config.get("module_timeout", 300) or 300)
        except (TypeError, ValueError):
            deadline = 300.0
        stop_at = time.monotonic() + max(60.0, deadline - 30.0)

        run_token = f"cz{hashlib.sha256(str(time.time()).encode()).hexdigest()[:6]}"
        sibling_paths = list(
            (cfg.get("canary_route") or {}).get("sibling_paths") or [])
        hint_segments = list(
            (cfg.get("canary_route") or {}).get("hint_segments") or
            ["admin", "internal", "secrets", "users", "export"])
        inject_points = list(cfg.get("inject_points") or ["query", "fragment"])
        inject_names = list(cfg.get("inject_names") or ["r", "path", "file", "url"])

        report = {"schema_version": 1, "run_token": run_token,
                  "targets": [], "pairs": [], "state_counts": {},
                  "untested": []}
        findings = 0
        proven = 0
        state_counts = {"not_reached": 0, "unchanged": 0, "path_altered": 0}

        for target in targets:
            if time.monotonic() >= stop_at:
                report["untested"].append(
                    {"target": target, "reason": "time-box hit"})
                break
            report["targets"].append(target)
            for context_name, headers in contexts:
                if time.monotonic() >= stop_at:
                    break
                for point in inject_points:
                    names = inject_names if point != "form" else [""]
                    for name in names[:3]:
                        payloads = self._payloads(
                            run_token, payloads_max=max_payloads,
                            siblings=sibling_paths or [
                                "/..%2f" + "/".join(hint_segments[:2])])
                        try:
                            epochs = await _drive_epochs(
                                target, point, name, run_token, payloads,
                                wait_ms, headers)
                        except Exception as exc:
                            report["untested"].append({
                                "target": target,
                                "reason": f"browser error: {str(exc)[:120]}"})
                            continue
                        pairs = self._classify_epochs(epochs, run_token,
                                                      payloads,
                                                      point=point, name=name)
                        for pair in pairs:
                            state_counts[pair["state"]] = \
                                state_counts.get(pair["state"], 0) + 1
                            pair["identity"] = context_name
                            pair["target"] = target
                            report["pairs"].append(pair)
                        altered = [p for p in pairs
                                   if p["state"] == "path_altered"]
                        for pair in altered[:2]:
                            outcome = await self._impact_probe(
                                pair, harness, context_name, cfg)
                            if outcome.get("proven"):
                                proven += 1
                                findings += 1
                                self._file_proof(pair, outcome, target)
                            elif outcome.get("candidate"):
                                findings += 1
                                self._file_candidate(pair, outcome, target)

        report["state_counts"] = state_counts
        self.state.add_evidence(self.id, "cspt_report", self._base_url(),
                                report)
        self.state.add_asset(
            "cspt_scan", f"cspt_scan:{self.domain}", self.domain,
            confidence="FIRM", sources=[self.id],
            attrs={"targets": len(targets),
                   "pairs": len(report["pairs"]),
                   "altered": state_counts.get("path_altered", 0),
                   "proven": proven,
                   "untested": len(report["untested"])})
        self.state.complete_module(self.id)
        self.log(f"CSPT: {state_counts.get('path_altered', 0)} altered path(s), "
                 f"{findings} finding(s), {proven} proven")
        return "done"

    # ── Planning ─────────────────────────────────────────────────

    def _targets(self, cfg: dict) -> list[str]:
        max_targets = max(1, int(cfg.get("max_targets", 3) or 3))
        configured = cfg.get("targets") or []
        if configured:
            return [self._absolute(str(t)) for t in configured[:max_targets]
                    if self._absolute(str(t))]
        discovered = []
        for asset_type in ("url", "web_path", "api_endpoint"):
            for node in self.state.get_assets_by_type(asset_type):
                value = str(node.get("value") or "")
                if value.startswith(("http://", "https://")):
                    discovered.append(value)
        if not discovered:
            discovered = [self._base_url()]
        seen, out = set(), []
        for url in discovered:
            if url in seen:
                continue
            seen.add(url)
            out.append(url)
            if len(out) >= max_targets:
                break
        return out

    def _payloads(self, token: str, *, payloads_max: int,
                  siblings: list[str]) -> list[str]:
        """Traversal payload strings, each carrying the run token."""
        payloads = []
        for family in PAYLOAD_FAMILIES:
            for sibling in siblings[:2]:
                clean = str(sibling).lstrip("/")
                payloads.append(f"{family}{family}{clean}")
                # Resident variant: keep the token in the query so
                # attribution survives dot-segment resolution.
                payloads.append(f"{family}{family}{clean}%3fcspt%3d{token}")
                if len(payloads) >= payloads_max:
                    return payloads
        if not payloads:
            payloads = [f"..%2f..%2fadmin%2fsecrets%3fcspt%3d{token}"]
        return payloads

    def _classify_epochs(self, epochs: list[dict], token: str,
                         payloads: list[str], *, point: str = "",
                         name: str = "") -> list[dict]:
        """Classify the request stream of one inject point (three states)."""
        # Every pair carries the inject surface it came from: without it the
        # operator cannot tell an escape injected in the query from one
        # injected in the fragment.
        surface = {"point": point, "name": name}
        baseline_sigs = set()
        natural_paths = []
        token_seen = False
        for event in epochs:
            if event.get("epoch") == "baseline":
                baseline_sigs.add((event.get("method"),
                                   server_view_path(event.get("url"))))
        for event in epochs:
            if event.get("epoch") != "natural":
                continue
            url = str(event.get("url") or "")
            if token in url:
                token_seen = True
                natural_paths.append(server_view_path(url))
        if not token_seen:
            return [{"state": "not_reached", "natural_path": "",
                     "probe_path": "", "prefix": [], "payload": "",
                     **surface}]
        prefixes = []
        for natural_path in natural_paths:
            prefix = stable_prefix(natural_path, token)
            if not prefix:
                continue
            if natural_path.endswith("/" + token) or token in natural_path:
                prefixes.append((prefix, natural_path))
        if not prefixes:
            return [{"state": "unchanged", "natural_path": natural_paths[0],
                     "probe_path": "", "prefix": [], "payload": "",
                     **surface}]
        prefix, natural_path = min(prefixes, key=lambda item: len(item[0]))
        natural_sigs = set()
        for event in epochs:
            if event.get("epoch") in ("baseline", "natural"):
                natural_sigs.add((event.get("method"),
                                  server_view_path(event.get("url"))))
        pairs = []
        seen_altered = set()
        for event in epochs:
            if event.get("epoch") != "payload":
                continue
            url = str(event.get("url") or "")
            resolved = server_view_path(url)
            signature = (event.get("method"), resolved)
            payload = str(event.get("payload") or "")
            effects = effect_segments(payload)
            altered = (
                has_traversal(payload)
                and escaped(prefix, resolved)
                and effects
                and set(effects) <= set(path_segments(resolved))
                and signature not in natural_sigs
            )
            if altered:
                key = (signature, tuple(effects))
                if key in seen_altered:
                    continue
                seen_altered.add(key)
                pairs.append({
                    "state": "path_altered",
                    "natural_path": natural_path,
                    "probe_path": resolved,
                    "probe_url": url,
                    "prefix": prefix,
                    "effect_segments": effects,
                    "payload": str(event.get("payload") or ""),
                    "status": int(event.get("status", 0) or 0),
                    "natural_url": str(event.get("natural_url") or ""),
                    **surface,
                })
        if not pairs:
            return [{"state": "unchanged", "natural_path": natural_path,
                     "probe_path": "", "prefix": prefix, "payload": "",
                     **surface}]
        return pairs

    # ── Impact verification (only PROOF path) ────────────────────

    async def _impact_probe(self, pair: dict, harness: AuthHarness,
                            identity: str, cfg: dict) -> dict:
        """Replay the altered URL and require a configured value the
        natural request does not return; absent-ref control gates catch-alls."""
        probe_cfg = cfg.get("impact_probe") or {}
        if not probe_cfg.get("enabled", True):
            # Altered path, no probe requested: adjacent signal, candidate.
            return {"candidate": True, "proven": False,
                    "reason": "impact probe disabled"}
        from core.workflows import _extract
        natural_url = str(pair.get("natural_url") or "")
        probe_url = str(pair.get("probe_url") or "")
        if not natural_url or not probe_url:
            return {"candidate": False, "proven": False}
        expect = probe_cfg.get("expect") or {}
        equals = str(probe_cfg.get("equals") or "")
        if not expect or not equals:
            # No configured expectation: impact cannot be verified.
            return {"candidate": True, "proven": False,
                    "reason": "no configured expectation"}
        altered = await self._fetch(harness, identity, probe_url)
        baseline = await self._fetch(harness, identity, natural_url)
        control = await self._fetch(
            harness, identity,
            self._absent_variant(probe_url))
        altered_body = str(altered.get("body") or "")
        baseline_body = str(baseline.get("body") or "")
        observed = _extract(expect, altered_body)
        baseline_value = _extract(expect, baseline_body)
        catch_all = _body_shape(int(control.get("status", 0) or 0),
                                str(control.get("body") or "")) == _body_shape(
            int(altered.get("status", 0) or 0), altered_body)
        if observed == equals and baseline_value != equals and not catch_all:
            evidence = self.state.add_evidence(
                self.id, "cspt_impact", self._base_url(),
                {"natural_url": natural_url, "probe_url": probe_url,
                 "resolved_path": pair.get("probe_path"),
                 "observed": observed, "expectation": equals,
                 "baseline_status": baseline.get("status", 0),
                 "control_same_shape": catch_all})
            return {"candidate": False, "proven": True,
                    "observed": observed, "evidence": evidence}
        return {"candidate": True, "proven": False,
                "observed": observed,
                "reason": "expectation not met on the altered replay"}

    async def _fetch(self, harness: AuthHarness, identity: str,
                     url: str) -> dict:
        if identity in ("anonymous", ""):
            return await harness.request_anonymous(url)
        return await harness.request(identity, url)

    @staticmethod
    def _absent_variant(url: str) -> str:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(url)
        segments = [s for s in parsed.path.split("/") if s]
        if not segments:
            return url
        last = segments[-1]
        replacement = str(int(last) + 1000000) if last.isdigit() \
            else "zz-absent-" + last[:8]
        segments[-1] = replacement
        return urlunparse(parsed._replace(path="/" + "/".join(segments)))

    # ── Findings ─────────────────────────────────────────────────

    def _fingerprint(self, pair: dict) -> str:
        from urllib.parse import urlparse
        host = urlparse(self._base_url()).hostname or ""
        base = json.dumps({
            "module": "cspt_audit", "host": host,
            "natural": templatize(pair.get("natural_path") or "",
                                  self._run_token_placeholder(pair)),
            "altered": "/".join(path_segments(pair.get("probe_path"))[:3]),
        }, sort_keys=True)
        return hashlib.sha256(base.encode()).hexdigest()[:16]

    @staticmethod
    def _run_token_placeholder(pair: dict) -> str:
        for segment in path_segments(pair.get("natural_path") or ""):
            if segment.startswith("cz"):
                return segment
        return ""

    def _file_proof(self, pair: dict, outcome: dict, target: str) -> None:
        fp = self._fingerprint(pair)
        self.state.add_finding(
            title=(f"Client-Side Path Traversal: "
                   f"{templatize(pair.get('natural_path') or '', self._run_token_placeholder(pair))}"
                   f" → {pair.get('probe_path')} [{fp[:8]}]"),
            severity="HIGH",
            confidence="CONFIRMED",
            category="Client-Side Path Traversal",
            description=(
                f"A URL-borne input reached an XHR/fetch path; a traversal "
                f"payload resolved to {pair.get('probe_path')} and the "
                f"replayed request returned the configured impact value "
                f"{outcome.get('observed')!r} that the natural request does "
                f"not return."),
            evidence=[f"natural:{pair.get('natural_url')}",
                      f"altered:{pair.get('probe_url')}",
                      outcome.get("evidence", "")],
            asset_keys=[f"url:{target}"],
            verified=True,
            verification={"method": "cspt_impact_observed",
                          "natural_path": pair.get("natural_path"),
                          "probe_path": pair.get("probe_path")},
        )

    def _file_candidate(self, pair: dict, outcome: dict, target: str) -> None:
        fp = self._fingerprint(pair)
        self.state.add_finding(
            title=(f"Client-Side Path Traversal candidate: "
                   f"{pair.get('probe_path')} [{fp[:8]}]"),
            severity="MEDIUM",
            confidence="FIRM",
            category="Client-Side Path Traversal",
            description=(
                f"A URL-borne input reached an XHR/fetch path and a payload "
                f"resolved to {pair.get('probe_path')}, leaving the natural "
                f"prefix {'/'.join(pair.get('prefix') or [])}. Impact is not "
                f"independently confirmed."),
            evidence=[f"natural:{pair.get('natural_url')}",
                      f"altered:{pair.get('probe_url')}"],
            asset_keys=[f"url:{target}"],
            verified=False,
            verification={},
        )

    # ── Plumbing ─────────────────────────────────────────────────

    def _absolute(self, value: str) -> str:
        value = (value or "").strip()
        if value.startswith(("http://", "https://")):
            return value
        base = self._base_url().rstrip("/")
        return f"{base}/{value.lstrip('/')}" if base else ""

    def _base_url(self) -> str:
        return str(self.target.get("base_url")
                   or (self.base_url if self.domain else ""))

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}


# ── Browser driver (monkeypatchable seam) ─────────────────────────

async def _drive_epochs(url: str, point: str, name: str, token: str,
                        payloads: list[str], wait_ms: int,
                        headers: Optional[dict] = None) -> list[dict]:
    """Navigate the target once per epoch and collect XHR/fetch events.

    Epochs: baseline (clean URL), natural (token in the configured input),
    then one navigation per payload. Requests are read from a RAW
    page.on("request") handler — the persisted traffic copy never carries
    the token through redaction.
    """
    from urllib.parse import urlparse, urlunparse
    from playwright.async_api import async_playwright

    events: list[dict] = []
    epoch_requests: list[dict] = []

    def _on_request(request):
        try:
            resource_type = str(getattr(request, "resource_type", "") or "")
            if resource_type not in XHR_TYPES:
                return
            epoch_requests.append({
                "method": str(getattr(request, "method", "") or ""),
                "url": str(request.url),
                "resource_type": resource_type,
            })
        except Exception:
            pass

    def _inject(base: str, epoch_point: str, value: str) -> str:
        parsed = urlparse(base)
        if epoch_point == "query":
            # Insert the value VERBATIM: payloads are already
            # percent-encoded for exactly one decode by URLSearchParams.
            # Re-encoding here would double-encode and keep the slashes
            # literal, so the browser would never resolve the dots.
            param = name or "r"
            separator = "&" if parsed.query else ""
            return urlunparse(parsed._replace(
                query=f"{parsed.query}{separator}{param}={value}"))
        if epoch_point == "fragment":
            return urlunparse(parsed._replace(fragment=value))
        return urlunparse(parsed._replace(
            path=parsed.path.rstrip("/") + "/" + value))

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            context = await browser.new_context(
                extra_http_headers=headers or {})
            page = await context.new_page()
            page.on("request", _on_request)

            async def navigate(target_url: str, epoch: str,
                               payload: str = "") -> None:
                epoch_requests.clear()
                try:
                    await page.goto(target_url,
                                    wait_until="domcontentloaded",
                                    timeout=max(wait_ms * 8, 10000))
                    await page.wait_for_timeout(wait_ms)
                except Exception:
                    pass
                for item in list(epoch_requests):
                    events.append({**item, "epoch": epoch,
                                   "payload": payload,
                                   "natural_url": natural_url})

            natural_page = _inject(url, point, token)
            natural_url = natural_page
            await navigate(url, "baseline")
            await navigate(natural_page, "natural")
            # The natural baseline for impact comparison is the XHR that
            # carried the token, not the page URL.
            natural_url = next(
                (item["url"] for item in events
                 if item.get("epoch") == "natural" and token in item.get("url", "")),
                natural_page)
            for payload in payloads:
                await navigate(_inject(url, point, payload), "payload",
                               payload)
        finally:
            await browser.close()
    return events


# Sentinel for the gate above: if this name is rebound (test seam), the
# default browser driver is not in use.
_DEFAULT_DRIVE = _drive_epochs
