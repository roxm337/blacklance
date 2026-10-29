"""Verification Oracle — deterministic PoC confirmation engine.

A vulnerability is never "confirmed" by an LLM saying so. It must pass the oracle:
- Differential response (baseline vs payload)
- Tool confirmation (sqlmap "confirmed", nuclei "matched")
- Time-based proof (statistical timing)
- Reproducibility (re-run N times, must be deterministic)
- Out-of-band callback (interactsh)

Confidence: CONFIRMED (oracle-proven, reproducible) / FIRM / TENTATIVE
"""

from __future__ import annotations

import asyncio
import json
import os
import statistics
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

from tools.wrappers import curl
from core.validators import inject_param as _inject_param


_OOB_CONFIG: dict = {}


def configure_oob(config: Optional[dict] = None):
    """Configure out-of-band callback infrastructure for oracle checks."""
    global _OOB_CONFIG
    _OOB_CONFIG = (config or {}).get("oob", {}) or {}


def make_oob_client(oob_config: Optional[dict] = None):
    """Build the configured OOB client, or None when OOB is off.

    Surfaces used to instantiate InteractshClient directly and ignored
    `oob.mode: public`, so an action could not use the same callback
    channel as the modules.
    """
    cfg = oob_config if oob_config is not None else _OOB_CONFIG
    if not isinstance(cfg, dict):
        cfg = {}
    if cfg.get("enabled") is False:
        return None
    if str(cfg.get("mode", "")).lower() == "public":
        from tools.external import PublicInteractshClient
        client = PublicInteractshClient(
            server=str(cfg.get("server_url")
                       or "oast.pro,oast.live,oast.site,oast.online,"
                          "oast.fun,oast.me"),
            poll_interval=float(cfg.get("poll_interval", 2.0) or 2.0),
            poll_timeout=float(cfg.get("poll_timeout", 30.0) or 30.0),
        )
        return client if client.enabled else None
    client = InteractshClient(config=cfg)
    return client if client.enabled else None


class Confidence(Enum):
    CONFIRMED = "CONFIRMED"
    FIRM = "FIRM"
    TENTATIVE = "TENTATIVE"


@dataclass
class Verdict:
    confidence: Confidence
    score: float  # 0.0 - 1.0
    evidence: dict = field(default_factory=dict)
    reason: str = ""


class DifferentialAnalyzer:
    """Compare baseline vs payload responses to detect injection."""

    SIGNAL_KEYS = [
        "status", "body_length", "body_hash",
        "word_count", "line_count",
    ]
    # response_time_ms deliberately excluded: normal jitter trips any
    # percent-change threshold and mints flaky FIRM verdicts. Timing
    # belongs to TimingOracle, which uses means and stdevs.

    # Identifiers, not measurements: a hash that differs at all means the
    # bytes differ, and a percent-change on two hash magnitudes is noise.
    # (The numeric branch below made "hello world" vs a longer body score
    # 2/6 instead of 3/6 whenever PYTHONHASHSEED put the two hashes within
    # 15% of each other — a seed-dependent flake in two suites.)
    IDENTITY_KEYS = {"body_hash"}

    async def baseline(self, url: str, method: str = "GET",
                       headers: Optional[dict] = None) -> dict:
        result = await curl(url, method=method, headers=headers or {},
                            output="full")
        return self._fingerprint(result)

    async def compare_urls(self, base_url: str, test_url: str,
                           method: str = "GET",
                           headers: Optional[dict] = None):
        """Verdict plus both raw bodies, fetching each URL exactly once.

        The bodies are needed because a fingerprint cannot tell a query that
        *ran* from a query the server *refused*. Both look like divergence.
        """
        base_raw = await curl(base_url, method=method,
                              headers=headers or {}, output="full")
        test_raw = await curl(test_url, method=method,
                              headers=headers or {}, output="full")
        verdict = self.compare(self._fingerprint(base_raw),
                               self._fingerprint(test_raw))
        return verdict, base_raw, test_raw

    async def test(self, url: str, method: str = "GET",
                   headers: Optional[dict] = None,
                   data: str = "") -> dict:
        result = await curl(url, method=method, headers=headers or {},
                            data=data if method == "POST" else None,
                            output="full")
        return self._fingerprint(result)

    def compare(self, baseline: dict, test_result: dict,
                sensitivity: float = 0.15) -> Verdict:
        """Return FIRM if response diverges beyond sensitivity threshold."""
        diff_count = 0
        total_checks = 0
        details = {}

        for key in self.SIGNAL_KEYS:
            b = baseline.get(key)
            t = test_result.get(key)
            if b is None or t is None:
                continue
            total_checks += 1
            if key in self.IDENTITY_KEYS:
                if b != t:
                    diff_count += 1
                    details[key] = {"baseline": str(b)[:200], "test": str(t)[:200]}
                continue
            if isinstance(b, (int, float)) and isinstance(t, (int, float)):
                if b == 0 and t == 0:
                    continue  # errored identically — no signal either way
                if b == 0 or t == 0:
                    # Transport error vs a real response is divergence, not
                    # a reason to skip: the old `b == 0: continue` dropped
                    # baseline-zero signals into false negatives.
                    diff_count += 1
                    details[key] = {"baseline": b, "test": t,
                                    "change": "zero-vs-nonzero"}
                    continue
                change = abs(t - b) / max(abs(b), 1)
                details[key] = {"baseline": b, "test": t, "change_pct": round(change, 3)}
                if change > sensitivity:
                    diff_count += 1
            elif b != t:
                diff_count += 1
                details[key] = {"baseline": str(b)[:200], "test": str(t)[:200]}

        if total_checks == 0:
            return Verdict(Confidence.TENTATIVE, 0.0, reason="no comparable signals")

        divergence = diff_count / total_checks
        if divergence >= 0.4:
            return Verdict(Confidence.FIRM, divergence,
                           evidence={"differential": details},
                           reason=f"response diverged on {diff_count}/{total_checks} signals")
        return Verdict(Confidence.TENTATIVE, divergence,
                       evidence={"differential": details},
                       reason=f"response diverged on {diff_count}/{total_checks} signals")

    def _fingerprint(self, result: dict) -> dict:
        body = result.get("body", "") or ""
        return {
            "status": result.get("status", 0),
            "body_length": len(body),
            "body_hash": hash(body[:10000]),
            "word_count": len(body.split()),
            "line_count": len(body.splitlines()),
            "headers": result.get("headers", {}),
        }


class TimingOracle:
    """Statistical timing analysis for blind/time-based injection."""

    async def measure(self, url: str, method: str = "GET",
                      headers: Optional[dict] = None,
                      samples: int = 5) -> dict:
        times = []
        for _ in range(samples):
            start = time.monotonic()
            await curl(url, method=method, headers=headers or {}, output="status")
            elapsed = (time.monotonic() - start) * 1000
            times.append(elapsed)
        return {
            "mean": statistics.mean(times) if times else 0,
            "stdev": statistics.stdev(times) if len(times) > 1 else 0,
            "min": min(times) if times else 0,
            "max": max(times) if times else 0,
            "samples": times,
        }

    def compare(self, baseline: dict, test: dict,
                threshold_ms: float = 3000,
                stdev_multiplier: float = 3) -> Verdict:
        mean_diff = test["mean"] - baseline["mean"]
        combined_stdev = (baseline["stdev"] ** 2 + test["stdev"] ** 2) ** 0.5

        if mean_diff >= threshold_ms and mean_diff > combined_stdev * stdev_multiplier:
            return Verdict(Confidence.FIRM, min(mean_diff / 10000, 1.0),
                           evidence={
                               "timing": {
                                   "baseline_mean_ms": round(baseline["mean"], 2),
                                   "test_mean_ms": round(test["mean"], 2),
                                   "diff_ms": round(mean_diff, 2),
                                   "combined_stdev": round(combined_stdev, 2),
                               }
                           },
                           reason=f"mean response +{mean_diff:.0f}ms exceeds threshold")
        if mean_diff >= threshold_ms:
            return Verdict(Confidence.TENTATIVE, min(mean_diff / 20000, 0.5),
                           evidence={"timing": {"diff_ms": round(mean_diff, 2)}},
                           reason=f"timing diff {mean_diff:.0f}ms but high variance")

        return Verdict(Confidence.TENTATIVE, 0.0,
                       evidence={"timing": {"diff_ms": round(mean_diff, 2)}},
                       reason="no significant timing difference")


class ReproducibilityChecker:
    """Re-run a probe N times; requires deterministic behavior for CONFIRMED."""

    def __init__(self, min_reps: int = 3, required_match: float = 1.0):
        self.min_reps = min_reps
        self.required_match = required_match

    async def check(self, probe_fn: Callable, **kwargs) -> Verdict:
        results = []
        for i in range(self.min_reps):
            result = await probe_fn(**kwargs)
            results.append(result)

        if not results:
            return Verdict(Confidence.TENTATIVE, 0.0, reason="no results")

        # Compare fingerprints
        fingerprints = [
            (r.get("status", 0), r.get("body", "")[:200], r.get("time_ms", 0) // 100)
            for r in results
        ]
        matches = sum(
            1 for i in range(1, len(fingerprints))
            if fingerprints[i] == fingerprints[0]
        )
        match_rate = matches / (len(fingerprints) - 1) if len(fingerprints) > 1 else 1.0

        return Verdict(
            Confidence.CONFIRMED if match_rate >= self.required_match else Confidence.FIRM,
            match_rate,
            evidence={"reproducibility": {"reps": self.min_reps, "match_rate": match_rate}},
            reason=f"reproducible {match_rate:.0%} across {self.min_reps} runs"
        )


class InteractshClient:
    """Out-of-band callback detection for blind SSRF/XXE/SQLi/RCE."""

    def __init__(self, server_url: str = "", poll_interval: float = 2.0,
                 poll_timeout: float = 30.0, callback_domain: str = "",
                 poll_url: str = "", token: str = "", config: Optional[dict] = None):
        # An explicit `config` wins over the process-wide `_OOB_CONFIG`. Without
        # it a caller can only ever read the configuration that happened to be
        # in place when some other object called `configure_oob`, which makes
        # the client impossible to test in isolation.
        cfg = config if config is not None else _OOB_CONFIG
        if not isinstance(cfg, dict):
            cfg = {}
        self.server_url = (
            server_url
            or cfg.get("server_url")
            or os.environ.get("INTERACTSH_SERVER_URL", "")
        ).rstrip("/")
        self.poll_url = (
            poll_url
            or cfg.get("poll_url")
            or os.environ.get("INTERACTSH_POLL_URL", "")
        ).rstrip("/")
        self.callback_domain = (
            callback_domain
            or cfg.get("callback_domain")
            or os.environ.get("OOB_DOMAIN", "")
        ).strip().strip(".")
        self.token = token or cfg.get("token") or os.environ.get("INTERACTSH_TOKEN", "")
        self.poll_interval = float(cfg.get("poll_interval", poll_interval))
        self.poll_timeout = float(cfg.get("poll_timeout", poll_timeout))
        if isinstance(cfg, dict) and cfg.get("enabled") is False:
            # Operator kill-switch: oob.enabled:false stops OOB egress even
            # for direct VerificationOracle() constructions, not just
            # modules going through BaseModule.oob().
            self.enabled = False
        else:
            self.enabled = bool(self.callback_domain or self.server_url or self.poll_url)

    async def register_callback(self, payload: str) -> str:
        """Register an OOB payload and return the unique callback identifier.

        CSPRNG hex, not md5(time:payload): predictable ids collide under
        parallel probes and misattribute a callback to the wrong URL.
        """
        import secrets
        corr_id = secrets.token_hex(6)
        if self.server_url:
            registered = await self._api_request(
                "POST",
                f"{self.server_url}/register",
                {"payload": payload, "correlation_id": corr_id},
            )
            if isinstance(registered, dict):
                corr_id = (
                    registered.get("correlation_id")
                    or registered.get("id")
                    or corr_id
                )
        return corr_id

    def callback_url(self, corr_id: str, path: str = "/") -> str:
        """Return the OOB URL to inject for a correlation id."""
        if self.callback_domain:
            return f"http://{corr_id}.{self.callback_domain}{path}"
        if self.server_url:
            return f"{self.server_url}/callback/{corr_id}{path}"
        return f"http://{corr_id}.oob.invalid{path}"

    async def poll(self, corr_id: str) -> list[dict]:
        """Poll for callbacks matching the correlation ID."""
        if not self.enabled or not corr_id:
            # Disabled or unregistered: instant empty, never a sleep loop.
            # Blind-confirm loops poll up to 6x; each sleeping poll
            # interval on a dead client burns the module time-box.
            return []
        endpoint = self.poll_url or (f"{self.server_url}/interactions" if self.server_url else "")
        if not endpoint:
            return []
        separator = "&" if "?" in endpoint else "?"
        data = await self._api_request("GET", f"{endpoint}{separator}corr_id={corr_id}")
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            interactions = data.get("interactions") or data.get("data") or []
            if isinstance(interactions, list):
                return interactions
        return []

    async def verify(self, payload: str, poll: bool = True) -> Verdict:
        corr_id = await self.register_callback(payload)
        return await self.verify_callback(
            corr_id, self.callback_url(corr_id), poll=poll)

    async def verify_callback(self, corr_id: str, callback_url: str = "",
                              poll: bool = True) -> Verdict:
        """Poll a callback that was already registered.

        Callers that inject ``callback_url(corr_id)`` must not call
        ``verify(payload)``: that registers a second, unrelated correlation
        id and polls it forever while the real interaction sits unread.
        """
        if not poll:
            return Verdict(Confidence.TENTATIVE, 0.0,
                           evidence={"corr_id": corr_id,
                                     "callback_url": callback_url},
                           reason="callback registered, no poll requested")
        if not self.enabled or not corr_id:
            return Verdict(Confidence.TENTATIVE, 0.0,
                           evidence={"corr_id": corr_id,
                                     "callback_url": callback_url,
                                     "interactions": []},
                           reason="OOB callback channel is not configured")

        deadline = time.time() + self.poll_timeout
        interactions = []
        while time.time() < deadline:
            interactions = await self.poll(corr_id)
            if interactions:
                return Verdict(Confidence.CONFIRMED, 1.0,
                               evidence={
                                   "oob": {
                                       "corr_id": corr_id,
                                       "callback_url": callback_url,
                                       "interactions": interactions,
                                   }
                               },
                               reason=f"OOB callback received ({len(interactions)} interactions)")
            await asyncio.sleep(self.poll_interval)

        return Verdict(Confidence.TENTATIVE, 0.0,
                       evidence={"corr_id": corr_id, "callback_url": callback_url, "interactions": []},
                       reason=f"no OOB callback within {self.poll_timeout}s")

    async def _api_request(self, method: str, url: str, payload: Optional[dict] = None):
        import urllib.error
        import urllib.request

        def request():
            body = json.dumps(payload).encode() if payload is not None else None
            req = urllib.request.Request(url, data=body, method=method)
            req.add_header("Accept", "application/json")
            if body is not None:
                req.add_header("Content-Type", "application/json")
            if self.token:
                req.add_header("Authorization", f"Bearer {self.token}")
            with urllib.request.urlopen(req, timeout=10) as resp:
                text = resp.read().decode("utf-8", errors="replace")
            return json.loads(text) if text else {}

        try:
            return await asyncio.to_thread(request)
        except (OSError, ValueError, urllib.error.URLError):
            return None


class VerificationOracle:
    """Composite oracle — runs multiple checks and assigns confidence."""

    def __init__(self):
        self.differential = DifferentialAnalyzer()
        self.timing = TimingOracle()
        self.reproducibility = ReproducibilityChecker()
        self.interactsh = InteractshClient()

    async def verify_sqli(self, url: str, param: str, payload: str,
                          method: str = "GET") -> Verdict:
        baseline_url = _inject_param(url, param, "1")
        test_url = _inject_param(url, param, payload)

        base = await self.differential.baseline(baseline_url, method=method)
        test = await self.differential.test(test_url, method=method)
        verdict = self.differential.compare(base, test)

        if verdict.confidence == Confidence.FIRM:
            repro = await self.reproducibility.check(
                lambda: self.differential.test(test_url, method=method)
            )
            if repro.confidence == Confidence.CONFIRMED:
                return Verdict(Confidence.CONFIRMED, (verdict.score + repro.score) / 2,
                               evidence={**verdict.evidence, **repro.evidence},
                               reason="differential + reproducible")

        return verdict

    async def verify_blind_sqli(self, url: str, param: str,
                                true_payload: str, false_payload: str) -> Verdict:
        true_url = _inject_param(url, param, true_payload)
        false_url = _inject_param(url, param, false_payload)

        true_time = await self.timing.measure(true_url)
        false_time = await self.timing.measure(false_url)

        return self.timing.compare(false_time, true_time)

    async def verify_xss(self, url: str, param: str, payload: str) -> Verdict:
        test_url = _inject_param(url, param, payload)
        result = await curl(test_url, output="full")
        body = result.get("body", "") or ""

        if payload in body:
            if not _reflection_is_html(result.get("headers", "")):
                return Verdict(Confidence.TENTATIVE, 0.2,
                               evidence={"reflected": {
                                   "payload": payload, "found_in_body": True,
                                   "context": "non-HTML"}},
                               reason="payload reflected into a non-HTML "
                                      "context (JSON/API): not executable on "
                                      "direct navigation")
            repro = await self.reproducibility.check(
                lambda: curl(test_url, output="full")
            )
            if repro.confidence == Confidence.CONFIRMED:
                evidence = {
                    "reflected": {"payload": payload, "found_in_body": True},
                    **repro.evidence,
                }
                return Verdict(Confidence.FIRM, 0.8, evidence=evidence,
                               reason="reproducible HTML reflection; browser execution unproven")

            return Verdict(Confidence.FIRM, 0.8,
                           evidence={"reflected": {"payload": payload, "found_in_body": True}},
                           reason="payload reflected in response")

        return Verdict(Confidence.TENTATIVE, 0.0,
                       evidence={"reflected": {"payload": payload, "found_in_body": False}},
                       reason="payload not reflected")

    def confidence_score(self, verdict: Verdict) -> int:
        mapping = {
            Confidence.CONFIRMED: 95,
            Confidence.FIRM: 75,
            Confidence.TENTATIVE: 30,
        }
        return mapping.get(verdict.confidence, 0)


def _reflection_is_html(headers: object) -> bool:
    """Is the reflection context one a browser would execute?

    A payload echoed inside application/json (or any non-HTML body) is
    inert on direct navigation — filing it FIRM is how entity-encoded
    echoes become fake CONFIRMEDs. Missing headers are treated as HTML:
    mocks and minimal clients often return a body alone, and refusing to
    grade those would blind the oracle, not sharpen it.
    """
    if not headers:
        return True
    if isinstance(headers, dict):
        content_type = str(headers.get("content-type", "")
                           or headers.get("Content-Type", ""))
    else:
        content_type = ""
        for line in str(headers).splitlines():
            if line.lower().startswith("content-type:"):
                content_type = line.split(":", 1)[1]
                break
        if not content_type:
            return True
    return "html" in content_type.lower()


def looks_unsanitized(body: str, payload: str, marker: str) -> bool:
    """Is the payload present in the response *as sent*?

    The body is never unescaped before matching: unescaping makes the
    encoding that defends against the payload look like proof of it (an
    entity-encoded `&lt;svg...&gt;` unescapes straight back into the
    payload). The dangerous pieces have to appear verbatim, or not at
    all — either the whole payload, or every executable fragment of it.
    """
    if not body:
        return False
    # Verbatim only. The old fallback ("all dangerous fragments appear
    # somewhere") fired on GitHub's commits page because `<svg`, `onload=`
    # and `document.body.append` each exist independently in the page and
    # its bundles; they were never the injected payload. A scanner that
    # concatenates unrelated fragments proves nothing. If a server rewrites
    # the payload but still executes it, the browser witness is the oracle.
    return payload in body


async def probe_reflected_xss(url: str, param: str, payloads: list,
                              fetch) -> tuple:
    """Marker gate + payload ladder for reflected XSS.

    `fetch` is `async (url) -> body str` (the caller's own client).
    Returns (payload, test_url, verdict): FIRM when a payload reflects
    verbatim, TENTATIVE otherwise. A unique marker must reflect first —
    a parameter that swallows input needs no payloads. Each payload
    carries its own execution marker so one payload's reflection can
    never confirm another's.
    """
    import secrets as _secrets
    from core.validators import inject_param as _inject

    try:
        marker_body = await fetch(_inject(url, param,
                                          f"osintxss{_secrets.token_hex(4)}"))
    except Exception:
        return "", "", Verdict(Confidence.TENTATIVE, 0.0,
                               reason="marker probe failed")
    if "osintxss" not in (marker_body or ""):
        return "", "", Verdict(Confidence.TENTATIVE, 0.0,
                               reason="parameter does not reflect input")

    for make_payload in payloads:
        exec_marker = _secrets.token_hex(4)
        payload = make_payload(exec_marker) \
            if callable(make_payload) else make_payload
        test_url = _inject(url, param, payload)
        try:
            body = await fetch(test_url)
        except Exception:
            continue
        if looks_unsanitized(body or "", payload, exec_marker):
            return payload, test_url, Verdict(
                Confidence.FIRM, 0.8,
                evidence={"reflected": {"payload": payload,
                                        "test_url": test_url}},
                reason="payload reflected verbatim with executable metacharacters")
    return "", "", Verdict(Confidence.TENTATIVE, 0.0,
                           reason="no payload reflected verbatim")
