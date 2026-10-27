"""Stage 5: inventory the LLM-backed surface, without pretending it is a bug.

An assistant endpoint is attack surface, not a vulnerability: a chat widget
is supposed to answer anonymous visitors. The module therefore fingerprints
first (response shape, provider headers, widget markers) and records
`ai_endpoint` assets. Only a completion served without credentials — the
auth boundary actually failing — becomes a finding, and only when the
operator opts into one bounded prompt.
"""

import json

from modules.base import BaseModule
from tools.wrappers import curl

AI_PATH_HINTS = (
    "chat", "assistant", "copilot", "completion", "llm", "prompt",
    "openai", "anthropic", "gemini", "bedrock", "ollama", "embedding",
    "vector", "rag", "agent", "ai/", "/ai", "gpt", "claude",
)

COMMON_PATHS = (
    "/v1/models",
    "/v1/chat/completions",
    "/api/chat",
    "/api/chat/completions",
    "/api/assistant",
)

PROVIDER_HEADERS = (
    "openai-organization", "openai-processing-ms", "openai-version",
    "anthropic-ratelimit-requests-limit", "x-amzn-bedrock",
    "x-goog-model", "cf-aig-request-id",
)

WIDGET_MARKERS = (
    "chat-widget", "intercom", "drift.com", "tidio", "crisp.chat",
    "zendesk", "livechat", "botpress", "dialogflow", "voiceflow",
    "azure-openai", "openai", "anthropic", "chatbot",
)


def candidate_urls(urls, limit: int = 25) -> list:
    seen = set()
    out = []
    for url in urls:
        raw = str(url or "").strip()
        if not raw.startswith(("http://", "https://")):
            continue
        key = raw.split("#", 1)[0]
        if not any(hint in key.lower() for hint in AI_PATH_HINTS):
            continue
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out if limit <= 0 else out[:limit]


def header_map(headers) -> dict:
    """Normalise the two shapes the transport returns: dict or raw block."""
    if isinstance(headers, dict):
        return {str(k).lower(): str(v) for k, v in headers.items()}
    out = {}
    for line in str(headers or "").splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip():
            out.setdefault(key.strip().lower(), value.strip())
    return out


def classify_fingerprint(status: int, headers, body: str) -> dict | None:
    """Name the LLM surface a response exposes, or None when it does not."""
    if not status or status >= 500:
        return None
    lowered = header_map(headers)
    for header in PROVIDER_HEADERS:
        if header in lowered:
            return {"kind": "provider_header", "confidence": "FIRM",
                    "evidence": f"provider header {header}"}
    text = (body or "").strip()
    if text.startswith("{"):
        try:
            payload = json.loads(text)
        except ValueError:
            payload = None
        if isinstance(payload, dict):
            if "choices" in payload:
                return {"kind": "openai_compatible", "confidence": "FIRM",
                        "evidence": "completion-shaped JSON (`choices`)"}
            if payload.get("object") in ("list", "error"):
                return {"kind": "openai_compatible", "confidence": "FIRM",
                        "evidence": f"OpenAI object shape (`{payload['object']}`)"}
    low = text.lower()
    hits = [marker for marker in WIDGET_MARKERS if marker in low][:3]
    if hits:
        return {"kind": "chat_widget", "confidence": "TENTATIVE",
                "evidence": "widget markers: " + ", ".join(hits)}
    return None


def first_model(body: str) -> str | None:
    try:
        payload = json.loads(body)
    except ValueError:
        return None
    data = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("id"):
                return str(item["id"])
    return None


class LLMSurface(BaseModule):
    id = "llm_surface"
    name = "LLM Surface Inventory"
    stage = 5
    detectability = "low"
    depends_on = ["tech_detection"]
    active = True

    async def run(self) -> str:
        cfg = self._cfg()
        if cfg.get("enabled", True) is False:
            self.state.skip_module(self.id, "disabled in config")
            return "skipped"

        urls = []
        for asset_type in ("api_endpoint", "url", "webapp"):
            for asset in self.state.get_assets_by_type(asset_type):
                urls.append(str(asset.get("value", "")))
        limit = int(cfg.get("max_endpoints", 0) or 0)
        candidates = candidate_urls(urls, limit)
        if cfg.get("probe_common_paths", True):
            for path in COMMON_PATHS:
                common = f"{self.base_url}{path}"
                if common not in candidates:
                    candidates.append(common)
        if limit > 0:
            candidates = candidates[:limit]
        model = None
        found = 0
        for url in candidates:
            if self.should_stop(reserve=8):
                break
            result = await self._fetch(url)
            kind = classify_fingerprint(result["status"], result["headers"],
                                        result["body"])
            if not kind:
                continue
            found += 1
            self.state.add_asset(
                "ai_endpoint",
                f"ai:{url}",
                url,
                confidence=kind["confidence"],
                sources=["llm_surface"],
                attrs={"kind": kind["kind"], "evidence": kind["evidence"],
                       "status": result["status"]},
            )
            evidence_id = self.state.add_evidence(
                self.id, "fingerprint", url,
                {"status": result["status"], "kind": kind["kind"],
                 "evidence": kind["evidence"],
                 "body_excerpt": result["body"][:500]},
            )
            self.log(f"  LLM surface ({kind['kind']}, {kind['confidence']}): "
                     f"{url}")
            if not model and "models" in url:
                model = first_model(result["body"])
                if model:
                    self.state.add_asset(
                        "ai_endpoint", f"ai:{url}", url,
                        confidence="FIRM", sources=["llm_surface"],
                        attrs={"model": model},
                    )
            if (cfg.get("probe_completion", False)
                    and kind["kind"] == "openai_compatible"
                    and "chat/completions" in url):
                await self._probe_completion(
                    url, model or cfg.get("model"), evidence_id)

        self.state.complete_module(self.id)
        self.log(f"LLM surface: {found} AI endpoint(s) inventoried")
        return "done"

    async def _probe_completion(self, url: str, model: str | None,
                                evidence_id: str) -> bool:
        """One benign completion, only to test the anonymous boundary.

        Without a model name the request would be a 400, not evidence, so
        the probe is skipped rather than guessed.
        """
        if not model:
            self.log(f"  {url}: no model id discovered, skipping completion "
                     "probe")
            return False
        try:
            result = await curl(
                url, method="POST",
                headers={"Content-Type": "application/json"},
                data=json.dumps({
                    "model": model,
                    "messages": [{"role": "user",
                                  "content": "Reply with the single word: "
                                             "ping"}],
                    "max_tokens": 1,
                }),
                output="full", timeout=20, no_session=True)
        except Exception as exc:
            self.log(f"  {url}: completion probe failed: {exc}")
            return False
        body = result.get("body", "") or ""
        status = result.get("status", 0)
        try:
            payload = json.loads(body)
            choice = payload["choices"][0]["message"]
            content = str(choice.get("content") or "").strip()
        except (ValueError, KeyError, IndexError, TypeError):
            return False
        if status != 200 or not content:
            return False
        self.state.add_finding(
            title=f"Unauthenticated LLM completion endpoint: {url}",
            severity="MEDIUM",
            confidence="CONFIRMED",
            category="Exposed AI Endpoint",
            description=(
                f"An anonymous request to {url} (no cookies, no Authorization "
                f"header) returned a model completion for `{model}`. Anyone "
                "who can reach the host can spend the target's inference "
                "budget and use the model as a proxy; prompt-injection and "
                "tool-abuse testing belong on top of this boundary failure."
            ),
            evidence=[
                f"URL: {url}",
                f"Model: {model}",
                f"HTTP {status} without credentials",
                f"Completion excerpt: {content[:200]}",
            ],
            evidence_refs=[evidence_id],
            remediation=(
                "Require authentication and per-user quotas on completion "
                "endpoints; keep model ids out of anonymous listings."
            ),
            asset_keys=[f"url:{url}"],
            verified=True,
            verification={"method": "unauthenticated_completion",
                          "url": url, "model": model,
                          "http_status": status},
        )
        self.log(f"  UNAUTHENTICATED COMPLETION on {url} ({model})")
        return True

    async def _fetch(self, url: str) -> dict:
        try:
            result = await curl(url, output="full", timeout=10,
                                no_session=True)
        except Exception:
            return {"status": 0, "body": "", "headers": {}}
        return {"status": result.get("status", 0),
                "body": result.get("body", "") or "",
                "headers": result.get("headers", {}) or {}}

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}
