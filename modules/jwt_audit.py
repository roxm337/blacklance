"""Stage 5: JWT harvesting and weakness analysis.

The framework had JWT attacks only at the risk-gated action layer, with no
token ever fed to them. This harvests JWTs the app actually issues (session
cookies, login responses) and analyses them: sensitive data baked into the
payload (Juice Shop ships the password hash in the token), and the algorithm's
forgery surface (`alg:none`, RS256→HS256 confusion, crackable HS256). Active
forgery+replay stays with the gated `auth.jwt.*` actions; this surfaces the
token and the weakness so they can be aimed.
"""

import base64
import json
import re

from core.tech_intel import scan_sensitive_json
from modules.base import BaseModule
from tools.wrappers import curl

_JWT = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{0,}")
_LOGIN_PATHS = ("/rest/user/login", "/api/login", "/api/auth/login",
                "/login", "/api/sessions", "/auth/login")


def _b64url(seg: str):
    seg += "=" * (-len(seg) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(seg).decode("utf-8", "ignore"))
    except Exception:  # noqa: BLE001
        return None


def decode_jwt(token: str) -> tuple:
    """(header, payload) dicts, or ({}, {}) if it will not decode."""
    parts = token.split(".")
    if len(parts) < 2:
        return {}, {}
    return (_b64url(parts[0]) or {}), (_b64url(parts[1]) or {})


def extract_jwts(text: str) -> set:
    return {m.group(0) for m in _JWT.finditer(text or "")
            if m.group(0).count(".") >= 2}


class JWTAudit(BaseModule):
    id = "jwt_audit"
    name = "JWT Harvest & Analysis"
    stage = 5
    detectability = "medium"
    depends_on = ["tech_detection"]
    active = True

    async def run(self) -> str:
        base = self.base_url
        tokens = await self._harvest(base)
        if not tokens:
            self.state.skip_module(self.id, "no JWT issued by the application")
            return "skipped"

        reported_payload = False
        for token in list(tokens)[:5]:
            header, payload = decode_jwt(token)
            if not payload:
                continue
            # 1. Sensitive data baked into the token.
            leaked = scan_sensitive_json(payload)
            if leaked and not reported_payload:
                reported_payload = True
                self.state.add_finding(
                    title="JWT payload exposes sensitive data",
                    severity="HIGH", confidence="CONFIRMED",
                    category="Identification and Authentication Failures",
                    description="The application's JWT carries sensitive fields in "
                                "its (base64, not encrypted) payload — readable by "
                                "anyone who holds the token.",
                    evidence=[f"{i['kind']} at {i['path']}" for i in leaked[:8]],
                    remediation="Keep secrets/PII out of the JWT payload; store "
                                "only an opaque session reference.",
                    asset_keys=[f"webapp:{base}"],
                    verification={"method": "jwt_payload_decode"})
            # 2. Algorithm forgery surface.
            self._report_alg(base, header)

        self.state.complete_module(self.id)
        self.log(f"JWT audit: {len(tokens)} token(s) harvested and analysed")
        return "done"

    def _report_alg(self, base: str, header: dict) -> None:
        alg = str(header.get("alg", "")).lower()
        surface = None
        if alg == "none":
            surface = ("alg:none — if the server accepts unsigned tokens, any "
                       "claim can be forged (test with auth.jwt.none_alg).")
            sev = "HIGH"
        elif alg.startswith("hs"):
            surface = ("HMAC (HS*) — crackable if the secret is weak "
                       "(auth.jwt.weak_secret_crack).")
            sev = "MEDIUM"
        elif alg.startswith("rs") or alg.startswith("es"):
            surface = ("asymmetric (RS/ES) — test RS256→HS256 algorithm "
                       "confusion with the public key (auth.jwt.alg_confusion).")
            sev = "MEDIUM"
        if surface:
            self.state.add_finding(
                title=f"JWT algorithm forgery surface ({header.get('alg','?')})",
                severity=sev, confidence="TENTATIVE",
                category="Identification and Authentication Failures",
                description=f"The app signs sessions with {header.get('alg','?')}. "
                            + surface,
                evidence=[f"JWT header alg={header.get('alg','?')}"
                          + (f", kid={header['kid']}" if header.get("kid") else "")],
                remediation="Pin the verification algorithm server-side; reject "
                            "'none'; use a strong secret / correct key type.",
                asset_keys=[f"webapp:{base}"],
                verification={"method": "jwt_alg_analysis"})

    async def _harvest(self, base: str) -> set:
        tokens: set = set()
        # Homepage: cookies + inline tokens.
        try:
            home = await curl(base, output="full", timeout=12)
            tokens |= extract_jwts(str(home.get("headers", "")))
            tokens |= extract_jwts(home.get("body", ""))
        except Exception:  # noqa: BLE001
            pass
        # Login responses: a benign attempt and a classic bypass, scanned for
        # an issued token (we only read what the server returns).
        for path in _LOGIN_PATHS:
            if self.should_stop(reserve=10) or tokens:
                break
            url = base.rstrip("/") + path
            for cred in ('{"email":"test@test.test","password":"test"}',
                         '{"email":"\' OR 1=1--","password":"x"}'):
                try:
                    r = await curl(url, method="POST", output="full", timeout=10,
                                   data=cred,
                                   headers={"Content-Type": "application/json"})
                except Exception:  # noqa: BLE001
                    continue
                tokens |= extract_jwts(r.get("body", ""))
                tokens |= extract_jwts(str(r.get("headers", "")))
                if tokens:
                    break
        return tokens
