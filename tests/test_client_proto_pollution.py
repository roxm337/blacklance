"""Client-side prototype pollution: browser-proof, not reflection-guessing."""

import asyncio
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.client_proto_pollution import ClientProtoPollution, payload_urls
from state.manager import StateManager

VULNERABLE_PAGE = b"""<!doctype html><html><body><div>app</div>
<script>
function merge(t, s) {
  for (const k in s) {
    if (s[k] && typeof s[k] === 'object') {
      if (!t[k]) t[k] = {};
      merge(t[k], s[k]);
    } else { t[k] = s[k]; }
  }
}
const params = new URLSearchParams(location.search);
const src = {};
for (const [k, v] of params) {
  const m = k.match(/^__proto__\\[([^\\]\\[]+)\\]$/);
  if (m) {
    const inner = {};
    inner[m[1]] = v;
    Object.defineProperty(src, '__proto__',
      {value: inner, enumerable: true, configurable: true});
  }
}
if (Object.keys(src).length) merge({}, src);
</script></body></html>
"""


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(VULNERABLE_PAGE)

    def log_message(self, *args):
        pass


def _serve():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _module(base_url):
    st = StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))
    module = ClientProtoPollution(st, {
        "target": {"domain": "127.0.0.1", "base_url": base_url},
        "modules": {"client_proto_pollution": {"max_pages": 1,
                                               "timeout_ms": 10000,
                                               "wait_ms": 300}},
        "paths": {}, "auth": {},
    })
    return module, st


def test_payload_urls_cover_query_and_hash():
    urls = dict(payload_urls("https://acme.com/app?x=1", "pp123", "polluted"))
    assert "__proto__[pp123]=polluted" in urls["query.__proto__[key]"]
    assert "?x=1&" in urls["query.__proto__[key]"]
    assert "constructor[prototype][pp123]" in urls[
        "query.constructor[prototype][key]"]
    assert "#__proto__[pp123]=polluted" in urls["hash.__proto__[key]"]


def test_merge_helper_is_proven_in_a_browser():
    import pytest
    try:
        from playwright.async_api import async_playwright

        async def _check():
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(headless=True)
                await browser.close()

        asyncio.run(_check())
    except Exception:
        pytest.skip("chromium unavailable")

    server = _serve()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    module, st = _module(base)
    try:
        asyncio.run(module.run())
    finally:
        server.shutdown()
    findings = st.findings["findings"]
    assert len(findings) == 1, "a vulnerable merge must be found exactly once"
    finding = findings[0]
    assert finding["confidence"] == "CONFIRMED"
    assert finding["verified"] is True
    assert finding["verification"]["method"] == "browser_prototype_pollution"
    assert "Object.prototype" in finding["description"]
