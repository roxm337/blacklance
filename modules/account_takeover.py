"""Stage 5: Account-takeover primitives — password-reset host poisoning.

Password-reset poisoning is one of the highest-paying bug classes: if the
reset link is built from an attacker-controllable Host / X-Forwarded-Host, the
victim's reset token is delivered to the attacker. Testing it safely is the
whole challenge — this module never completes a takeover and never spams real
users:

  1. Inert reflection (always, under --active): GET the reset page with an
     X-Forwarded-Host marker and look for the marker in an absolute URL in the
     response. No email is sent — this catches apps that echo the forwarded
     host into canonical/reset links, as a MEDIUM lead.
  2. Confirmation (only when an operator test email is configured): POST the
     reset request for *that operator-owned address* with the injected host.
     If the marker reflects, the reset mail to the operator's own inbox would
     point at the attacker — a HIGH, confirmed finding against a mailbox the
     tester controls.

OTP/2FA brute and reuse are deliberately out of scope here: they cannot be run
black-box without hammering a real auth flow.
"""

import re
import uuid

from core.site_profile import get_profile
from modules.base import BaseModule
from tools.wrappers import curl, curl_with_status

_RESET_PATHS = (
    "/forgot-password", "/forgot", "/password/reset", "/reset-password",
    "/rest/user/reset-password",
    "/account/recover", "/users/password/new", "/api/auth/forgot-password",
    "/api/password/forgot", "/api/forgot-password", "/wp-login.php?action=lostpassword",
)
_HOST_HEADERS = ("X-Forwarded-Host", "X-Forwarded-Server", "X-Host",
                 "Forwarded")
_EMAIL_FIELDS = ("email", "user", "username", "login", "emailAddress")


def _marker_in_url_context(body: str, marker: str) -> bool:
    """Is the marker host present inside an absolute URL in the body?

    Reflection in `href`/`src`/`action`/a bare `https://<marker>` is what makes
    it a reset-link poisoning signal; a marker echoed as plain text elsewhere
    is not actionable.
    """
    if marker not in (body or ""):
        return False
    return bool(re.search(
        r'(?:https?://|//|href=["\']?|src=["\']?|action=["\']?)[^"\'\s]*'
        + re.escape(marker), body, re.I))


class AccountTakeover(BaseModule):
    id = "account_takeover"
    name = "Account Takeover Primitives"
    stage = 5
    detectability = "high"
    depends_on = ["tech_detection"]
    active = True

    async def run(self) -> str:
        base = self.base_url
        self._profile = await self._baseline(base)
        cfg = self.config.get("modules", {}).get(self.id, {})
        test_email = str(cfg.get("test_email", "") or "").strip()

        endpoints = await self._reset_endpoints(base)
        if not endpoints:
            self.state.skip_module(self.id, "no password-reset endpoint found")
            return "skipped"

        confirmed = leads = 0
        for ep in endpoints[:6]:
            if self.should_stop(reserve=10):
                break
            # 1. Inert reflection — no email submitted.
            if await self._inert_reflection(base, ep):
                leads += 1
            # 2. Confirmation — only against an operator-owned mailbox.
            if test_email and await self._confirm_poisoning(base, ep, test_email):
                confirmed += 1

        self.state.complete_module(self.id)
        note = "no test_email configured — confirmation step skipped" \
            if not test_email else f"{confirmed} confirmed"
        self.log(f"Account takeover: {len(endpoints)} reset endpoint(s), "
                 f"{leads} reflection lead(s), {note}")
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

    def _is_catch_all(self, status: int, body: str) -> bool:
        if self._profile is None:
            return False
        try:
            from core.response_fingerprint import fingerprint
            return self._profile.baseline.catch_all(fingerprint(status, body, ""))
        except Exception:  # noqa: BLE001
            return False

    async def _reset_endpoints(self, base: str) -> list:
        found = []
        for path in _RESET_PATHS:
            if self.should_stop(reserve=12):
                break
            url = base.rstrip("/") + path
            try:
                r = await curl_with_status(url)
            except Exception:  # noqa: BLE001
                continue
            body = r.get("body", "") or ""
            if r.get("status") in (200, 405) and not self._is_catch_all(
                    r.get("status", 0), body):
                # A real reset page mentions resetting a password.
                if re.search(r"(reset|forgot|recover).{0,40}(password|account)",
                             body, re.I) or path.endswith("lostpassword"):
                    found.append(url)
        return found

    async def _inert_reflection(self, base: str, endpoint: str) -> bool:
        marker = f"atohost{uuid.uuid4().hex[:8]}.example"
        try:
            r = await curl(endpoint, output="full", timeout=12,
                           headers={"X-Forwarded-Host": marker})
        except Exception:  # noqa: BLE001
            return False
        body = r.get("body", "") or ""
        if _marker_in_url_context(body, marker):
            self.state.add_finding(
                title="Password-reset host reflection (poisoning lead)",
                severity="MEDIUM", confidence="TENTATIVE",
                category="Identification and Authentication Failures",
                description="The reset page reflects the X-Forwarded-Host header "
                            "into an absolute URL. If the reset email link is "
                            "built the same way, a reset token can be delivered "
                            "to an attacker host. Confirm by requesting a reset "
                            "to a mailbox you control.",
                evidence=[f"GET {endpoint} with X-Forwarded-Host: <marker> → "
                          f"marker reflected in a link"],
                remediation="Build reset URLs from a server-side configured host, "
                            "never from request headers; validate Host.",
                asset_keys=[f"webapp:{base}"],
                verification={"method": "reset_host_reflection_inert",
                              "url": endpoint})
            return True
        return False

    async def _confirm_poisoning(self, base: str, endpoint: str,
                                 email: str) -> bool:
        marker = f"atohost{uuid.uuid4().hex[:8]}.example"
        data = "&".join(f"{f}={email}" for f in _EMAIL_FIELDS[:1])
        try:
            r = await curl(endpoint, method="POST", output="full", timeout=12,
                           data=data,
                           headers={"X-Forwarded-Host": marker,
                                    "Content-Type": "application/x-www-form-urlencoded"})
        except Exception:  # noqa: BLE001
            return False
        body = r.get("body", "") or ""
        location = ""
        for line in str(r.get("headers", "")).splitlines():
            if line.lower().startswith("location:"):
                location = line.split(":", 1)[1].strip()
        if marker in location or _marker_in_url_context(body, marker):
            self.state.add_finding(
                title="Password-reset poisoning via Host header (confirmed)",
                severity="HIGH", confidence="FIRM",
                category="Identification and Authentication Failures",
                description="A password-reset request for an operator-controlled "
                            "address, sent with an attacker X-Forwarded-Host, was "
                            "reflected into the reset flow — the reset link mailed "
                            "to the account would point at the attacker host, "
                            "yielding account takeover.",
                evidence=[f"POST {endpoint} (test mailbox) with "
                          f"X-Forwarded-Host: <marker> → marker in reset target"],
                remediation="Derive reset URLs from server config; reject/validate "
                            "forwarded host headers.",
                asset_keys=[f"webapp:{base}"],
                verification={"method": "reset_host_poisoning_confirmed",
                              "url": endpoint})
            return True
        return False
