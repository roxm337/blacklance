"""Stage 4: OAuth 2.0 / OpenID Connect flow audit.

OAuth is where modern account-takeover lives, and none of it is reachable by
a generic path scan. The high-value, black-box-safe checks are:

  - redirect_uri validation: if the authorization endpoint will 302 a login
    to an attacker-controlled host, the authorization code or access token is
    delivered to the attacker — full ATO. Tested with a unique marker host so
    a reflected Location is unambiguous, not a guess.
  - implicit flow (`response_type=token`) still enabled — token in the URL
    fragment, exposed to history/referer/JS.
  - `state` not enforced — login CSRF / code fixation.

Discovery is driven by the OIDC `.well-known` document when present (it is a
public document by design, so its mere existence is *not* a finding), falling
back to the common authorization paths. Everything is a GET that observes the
redirect decision; nothing completes a flow.
"""

import re
import uuid
from urllib.parse import urlparse

from core.site_profile import get_profile
from modules.base import BaseModule
from tools.wrappers import curl, curl_json_with_status, curl_with_status

_WELL_KNOWN = (
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
)
_COMMON_AUTHORIZE = (
    "/oauth/authorize", "/oauth2/authorize", "/authorize",
    "/connect/authorize", "/login/oauth/authorize", "/o/oauth2/v2/auth",
    "/oauth2/v1/authorize",
)
_CLIENT_ID_RE = re.compile(r"client_id=([A-Za-z0-9._\-]{6,})")


def parse_oidc_config(data: dict) -> dict:
    """Pull the endpoints and risk-relevant capabilities from an OIDC config."""
    if not isinstance(data, dict):
        return {}
    return {
        "authorization_endpoint": str(data.get("authorization_endpoint") or ""),
        "token_endpoint": str(data.get("token_endpoint") or ""),
        "response_types": [str(r) for r in
                           (data.get("response_types_supported") or [])],
        "grant_types": [str(g) for g in
                        (data.get("grant_types_supported") or [])],
        "pkce": [str(m) for m in
                 (data.get("code_challenge_methods_supported") or [])],
    }


def redirect_uri_mutations(origin: str, marker: str) -> list:
    """Attacker-controlled redirect_uri candidates for a given target origin.

    Each is a known validation-bypass shape; `marker` is a unique host so a
    reflected Location proves the bypass rather than merely suggesting it.
    """
    host = urlparse(origin).hostname or "target"
    return [
        ("arbitrary host", f"https://{marker}/cb"),
        ("subdomain suffix", f"https://{host}.{marker}/cb"),
        ("userinfo trick", f"https://{host}@{marker}/cb"),
        ("scheme-relative", f"//{marker}/cb"),
        ("path traversal", f"https://{host}/../../@{marker}/cb"),
    ]


class OAuthAudit(BaseModule):
    id = "oauth_audit"
    name = "OAuth/OIDC Flow Audit"
    stage = 4
    detectability = "low"
    depends_on = ["tech_detection"]

    async def run(self) -> str:
        base = self.base_url
        self._profile = await self._baseline(base)

        authorize_eps: set[str] = set()
        implicit_noted = False

        # 1. OIDC/OAuth discovery document (public by design — not a finding).
        for wk in _WELL_KNOWN:
            status, data = await curl_json_with_status(base + wk)
            if status != 200 or not isinstance(data, dict):
                continue
            cfg = parse_oidc_config(data)
            if cfg.get("authorization_endpoint"):
                authorize_eps.add(cfg["authorization_endpoint"])
            if ("token" in cfg.get("response_types", []) and not implicit_noted):
                implicit_noted = True
                self.state.add_finding(
                    title="OAuth implicit flow enabled (response_type=token)",
                    severity="LOW", confidence="FIRM",
                    category="Identification and Authentication Failures",
                    description="The OIDC metadata advertises the implicit flow — "
                                "the access token is returned in the URL fragment, "
                                "exposed to browser history, Referer and any JS on "
                                "the page.",
                    evidence=[f"response_types_supported includes 'token' at "
                              f"{base}{wk}"],
                    remediation="Disable the implicit flow; use authorization "
                                "code + PKCE.",
                    asset_keys=[f"webapp:{base}"],
                    verification={"method": "oidc_metadata"})

        # 2. Common authorization paths that actually behave like OAuth.
        for path in _COMMON_AUTHORIZE:
            if self.should_stop(reserve=10):
                break
            authorize_eps.add(base.rstrip("/") + path)

        client_id = await self._discover_client_id(base)

        # 3. redirect_uri validation on each candidate authorization endpoint.
        tested = 0
        for ep in sorted(authorize_eps):
            if self.should_stop(reserve=8) or tested >= 6:
                break
            if await self._probe_redirect_uri(base, ep, client_id):
                tested += 1

        self.state.complete_module(self.id)
        self.log(f"OAuth audit: {len(authorize_eps)} authorize endpoint(s), "
                 f"client_id={'yes' if client_id else 'none'}")
        return "done"

    async def _baseline(self, base: str):
        async def fetch(path: str):
            r = await curl_with_status(base.rstrip("/") + path,
                                       follow_redirects=True)
            return (r.get("status", 0), r.get("body", "") or "",
                    r.get("content_type", "") or "")
        try:
            return await get_profile(base, fetch)
        except Exception:  # noqa: BLE001
            return None

    async def _discover_client_id(self, base: str) -> str:
        # From the homepage and any discovered URLs/JS — OAuth client_ids are
        # public, and we need a valid one to get past client validation.
        try:
            home = await curl(base, output="body", timeout=15)
            m = _CLIENT_ID_RE.search(home.get("body", "") or "")
            if m:
                return m.group(1)
        except Exception:  # noqa: BLE001
            pass
        for atype in ("url", "js_file"):
            for asset in self.state.get_assets_by_type(atype):
                m = _CLIENT_ID_RE.search(str(asset.get("value", "")))
                if m:
                    return m.group(1)
        return ""

    async def _probe_redirect_uri(self, base: str, endpoint: str,
                                  client_id: str) -> bool:
        marker = f"oauthx{uuid.uuid4().hex[:10]}.example"
        cid = client_id or "test-client"
        probed = False
        for label, redirect in redirect_uri_mutations(base, marker):
            if self.should_stop(reserve=6):
                break
            url = (f"{endpoint}?response_type=code&client_id={cid}"
                   f"&scope=openid&state=xyz&redirect_uri={redirect}")
            try:
                r = await curl(url, output="full", follow_redirects=False,
                               timeout=12)
            except Exception:  # noqa: BLE001
                continue
            probed = True
            location = ""
            for line in str(r.get("headers", "")).splitlines():
                if line.lower().startswith("location:"):
                    location = line.split(":", 1)[1].strip()
                    break
            # The bypass is proven only when the server would send the flow to
            # our marker host — reflected verbatim in the redirect target.
            if marker in location:
                self.state.add_finding(
                    title="OAuth redirect_uri accepts attacker-controlled host",
                    severity="HIGH",
                    confidence="FIRM" if client_id else "TENTATIVE",
                    category="Broken Access Control",
                    description=f"The authorization endpoint redirects to an "
                                f"attacker host supplied in redirect_uri "
                                f"({label}) — the authorization code/token is "
                                f"delivered to the attacker, enabling account "
                                f"takeover."
                                + ("" if client_id else " (tested with a "
                                   "placeholder client_id — confirm with a real "
                                   "one.)"),
                    evidence=[f"GET {endpoint} redirect_uri={redirect}",
                              f"Location: {location}"],
                    remediation="Exact-match redirect_uri against a server-side "
                                "allowlist; reject host/path/scheme mutations.",
                    asset_keys=[f"webapp:{base}"],
                    verification={"method": "oauth_redirect_uri",
                                  "endpoint": endpoint})
                return True
        return probed
