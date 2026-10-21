"""Stage 4: CSRF posture — session-cookie attributes.

Classic CSRF needs a session carried automatically by the browser. The
highest-signal, zero-false-positive check is the session cookie's own
attributes: `SameSite=None` (or absent) makes the cookie ride cross-site
requests, which is the precondition for CSRF; missing `HttpOnly`/`Secure` are
the adjacent token-theft / transport gaps. This parses the `Set-Cookie`
headers the app issues and reports only on a real, named weakness — no
guessing about whether a given endpoint is state-changing.
"""

import re

from modules.base import BaseModule
from tools.wrappers import curl

_SESSION_COOKIE = re.compile(
    r"(?i)(session|sess|sid|auth|token|jwt|connect\.sid|csrf|xsrf|remember)")
_PROBE_PATHS = ("", "/login", "/account", "/profile", "/api/auth/login")


def cookie_csrf_issues(set_cookie_lines: list, https: bool) -> list:
    """Return [(severity, cookie_name, issue)] for session cookies with a
    CSRF/transport weakness in their attributes."""
    issues = []
    for line in set_cookie_lines or []:
        raw = line.split(":", 1)[1].strip() if ":" in line else line
        name = raw.split("=", 1)[0].strip()
        if not name or not _SESSION_COOKIE.search(name):
            continue
        attrs = raw.lower()
        samesite = re.search(r"samesite=(\w+)", attrs)
        if samesite and samesite.group(1) == "none":
            issues.append(("MEDIUM", name,
                           "SameSite=None — sent on cross-site requests (CSRF)"))
        elif not samesite:
            issues.append(("LOW", name,
                           "no SameSite attribute (CSRF hardening gap)"))
        if "httponly" not in attrs:
            issues.append(("LOW", name,
                           "no HttpOnly — readable by JS (token theft via XSS)"))
        if https and "secure" not in attrs:
            issues.append(("LOW", name,
                           "no Secure on HTTPS — sent over plaintext"))
    return issues


class CSRFAudit(BaseModule):
    id = "csrf_audit"
    name = "CSRF / Cookie Posture"
    stage = 4
    detectability = "low"
    depends_on = ["tech_detection"]

    async def run(self) -> str:
        base = self.base_url
        https = base.lower().startswith("https")
        seen_cookies: set = set()
        reported: set = set()
        for path in _PROBE_PATHS:
            if self.should_stop(reserve=8):
                break
            try:
                r = await curl(base.rstrip("/") + path, output="full", timeout=10)
            except Exception:  # noqa: BLE001
                continue
            lines = [ln for ln in str(r.get("headers", "")).splitlines()
                     if ln.lower().startswith("set-cookie:")]
            for name, sev, issue in [(i[1], i[0], i[2])
                                     for i in cookie_csrf_issues(lines, https)]:
                key = (name, issue)
                if key in reported:
                    continue
                reported.add(key)
                seen_cookies.add(name)
                self.state.add_finding(
                    title=f"Session cookie CSRF/transport weakness: {name}",
                    severity=sev, confidence="FIRM",
                    category="Broken Access Control" if "SameSite" in issue
                    else "Security Misconfiguration",
                    description=f"The session cookie '{name}' {issue}.",
                    evidence=[f"Set-Cookie: {name}=… at {base}{path or '/'} — {issue}"],
                    remediation="Set SameSite=Lax/Strict, HttpOnly, and Secure on "
                                "session cookies; add anti-CSRF tokens on "
                                "state-changing endpoints.",
                    asset_keys=[f"webapp:{base}"],
                    verification={"method": "set_cookie_attributes"})

        if not reported:
            self.state.skip_module(self.id, "no session cookies with a weakness")
            return "skipped"
        self.state.complete_module(self.id)
        self.log(f"CSRF/cookie posture: {len(reported)} issue(s) across "
                 f"{len(seen_cookies)} session cookie(s)")
        return "done"
