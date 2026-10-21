"""Technology-aware playbook: fingerprint a stack, run only its probes."""

import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.tech_playbook as tp
from core.tech_profiles import PROFILES, get_profile, match_profiles
from modules.tech_playbook import TechPlaybook
from state.manager import StateManager


# ── fingerprinting ───────────────────────────────────────────────────

def test_major_stacks_fingerprint_specifically():
    cases = {
        "nextjs": {"header": "x-powered-by: Next.js",
                   "body": '__NEXT_DATA__ /_next/static/', "cookie": "", "hint": ""},
        "laravel": {"header": "", "body": "",
                    "cookie": "set-cookie: laravel_session=a", "hint": ""},
        "wordpress": {"header": "", "body": "/wp-content/ /wp-includes/",
                      "cookie": "", "hint": "WordPress"},
        "spring_boot": {"header": "", "body": "Whitelabel Error Page",
                        "cookie": "", "hint": ""},
        "django": {"header": "", "body": 'name="csrfmiddlewaretoken"',
                   "cookie": "", "hint": ""},
    }
    for name, blobs in cases.items():
        names = [p.name for p, _, _ in match_profiles(blobs)]
        assert name in names, (name, names)


def test_static_site_matches_nothing():
    assert match_profiles({"header": "server: nginx",
                           "body": "<html>hi</html>",
                           "cookie": "", "hint": ""}) == []


def test_every_profile_is_wellformed():
    for p in PROFILES:
        assert p.name and p.label and p.signals
        for probe in p.probes:
            assert probe.severity in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
            assert probe.path.startswith("/")


def test_nextjs_bypass_probe_is_differential_and_active():
    probe = next(pr for pr in get_profile("nextjs").probes
                 if "CVE-2025-29927" in pr.title)
    assert probe.active and probe.differential


# ── executor ─────────────────────────────────────────────────────────

def _state(tmp):
    st = StateManager(str(Path(tmp) / "example.com"))
    st.add_asset("webapp", "webapp:https://example.com", "https://example.com",
                 confidence="CONFIRMED", sources=["t"],
                 attrs={"framework": "", "cms": "", "server": "nginx",
                        "php_version": "7.4.3"})
    return st


def test_laravel_playbook_fires_env_and_feeds_cve_products(monkeypatch):
    tmp = tempfile.mkdtemp()
    st = _state(tmp)

    async def fake_curl(url, output="status", **kw):
        # Homepage: Laravel session cookie in headers → fingerprint.
        return {"status": 200,
                "headers": "HTTP/1.1 200 OK\nset-cookie: laravel_session=xyz\n",
                "body": "<html>app</html>"}

    async def fake_curl_with_status(url, method="GET", headers=None, data=None, **kw):
        if url.endswith("/.env"):
            return {"status": 200, "body": "APP_KEY=base64:zzz\nDB_PASSWORD=secret"}
        return {"status": 404, "body": "Not Found"}

    monkeypatch.setattr(tp, "curl", fake_curl)
    monkeypatch.setattr(tp, "curl_with_status", fake_curl_with_status)

    m = TechPlaybook(st, {"target": {"domain": "example.com", "active": False},
                          "modules": {}, "paths": {}})
    m.domain = "example.com"
    assert asyncio.run(m.run()) == "done"

    titles = [f["title"] for f in st.findings["findings"]]
    assert "Laravel .env exposed" in titles
    env = next(f for f in st.findings["findings"] if f["title"] == "Laravel .env exposed")
    assert env["severity"] == "CRITICAL"
    # The stack asset recorded Laravel's CPE product for CVE correlation.
    stacks = st.get_assets_by_type("tech_stack")
    assert stacks and "laravel" in stacks[0]["attrs"]["cpe_products"]


def test_nextjs_analyzer_leak_and_routes(monkeypatch):
    tmp = tempfile.mkdtemp()
    st = StateManager(str(Path(tmp) / "example.com"))
    st.add_asset("webapp", "webapp:https://example.com", "https://example.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})

    next_data = (
        '<html><script id="__NEXT_DATA__" type="application/json">'
        '{"buildId":"B1","page":"/","props":{"pageProps":'
        '{"apiToken":"livesecret123456"}}}</script>'
        '<div>/_next/static/B1/_buildManifest.js</div></html>')

    async def fake_curl(url, output="status", **kw):
        return {"status": 200, "headers": "x-powered-by: Next.js\n",
                "body": next_data}

    async def fake_cws(url, method="GET", headers=None, data=None, **kw):
        if url.endswith("_buildManifest.js"):
            return {"status": 200,
                    "body": '{"/":["a.js"],"/admin":["b.js"]}'}
        return {"status": 404, "body": ""}

    async def fake_cjws(url, **kw):
        return (404, None)

    monkeypatch.setattr(tp, "curl", fake_curl)
    monkeypatch.setattr(tp, "curl_with_status", fake_cws)
    monkeypatch.setattr(tp, "curl_json_with_status", fake_cjws)

    m = TechPlaybook(st, {"target": {"domain": "example.com", "active": False},
                          "modules": {}, "paths": {}})
    m.domain = "example.com"
    asyncio.run(m.run())

    titles = [f["title"] for f in st.findings["findings"]]
    assert "Next.js server data leak (pages router)" in titles
    # Routes from the build manifest became url assets.
    urls = [a["value"] for a in st.get_assets_by_type("url")]
    assert "https://example.com/admin" in urls


def test_current_cve_correlation_from_osv(monkeypatch):
    # A Laravel stack whose debug page reveals the version → OSV version-filtered
    # advisories become a version-matched "current advisories" finding.
    tmp = tempfile.mkdtemp()
    st = StateManager(str(Path(tmp) / "example.com"))
    st.add_asset("webapp", "webapp:https://example.com", "https://example.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})

    async def fake_curl(url, output="status", **kw):
        return {"status": 200,
                "headers": "set-cookie: laravel_session=x\n",
                "body": "<html>Illuminate\\Foundation app</html>"}

    async def fake_cws(url, method="GET", headers=None, data=None, **kw):
        # The random error-probe path returns a Laravel debug page with a version.
        if "/telescope" in url or url.endswith(".env"):
            return {"status": 404, "body": ""}
        return {"status": 500,
                "body": "Whoops Illuminate\\ laravel/framework v8.1.0 PHP 7.4 "
                        "/var/www/app/x.php"}

    async def fake_cjws(url, **kw):
        return (404, None)

    async def fake_osv(package, ecosystem="", version=""):
        assert package == "laravel/framework" and version == "8.1.0"
        return {"vulns": [
            {"id": "GHSA-zz", "aliases": ["CVE-2025-9999"],
             "summary": "Laravel RCE", "database_specific": {"severity": "CRITICAL"},
             "affected": [{"ranges": [{"events": [{"fixed": "8.4.2"}]}]}]}]}

    monkeypatch.setattr(tp, "curl", fake_curl)
    monkeypatch.setattr(tp, "curl_with_status", fake_cws)
    monkeypatch.setattr(tp, "curl_json_with_status", fake_cjws)
    monkeypatch.setattr(tp, "osv_query", fake_osv)

    m = TechPlaybook(st, {"target": {"domain": "example.com", "active": False},
                          "modules": {}, "paths": {}})
    m.domain = "example.com"
    asyncio.run(m.run())

    cve = [f for f in st.findings["findings"]
           if f["title"].startswith("Current advisories affecting laravel/framework")]
    assert len(cve) == 1
    assert cve[0]["severity"] == "CRITICAL"
    assert any("CVE-2025-9999" in e for e in cve[0]["evidence"])
    assert any("8.4.2" in e for e in cve[0]["evidence"])   # fixed-in surfaced


def test_spring_boot_analyzer_flags_jolokia_and_env_secrets(monkeypatch):
    tmp = tempfile.mkdtemp()
    st = StateManager(str(Path(tmp) / "example.com"))
    st.add_asset("webapp", "webapp:https://example.com", "https://example.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})

    async def fake_curl(url, output="status", **kw):
        return {"status": 200, "headers": "x-application-context: app\n",
                "body": "Whitelabel Error Page"}

    async def fake_cws(url, method="GET", headers=None, data=None, **kw):
        if url.endswith("/actuator/jolokia"):
            return {"status": 200, "body": '{"value":{}}'}
        return {"status": 404, "body": ""}

    async def fake_cjws(url, **kw):
        if url.endswith("/actuator"):
            return (200, {"_links": {"jolokia": {"href": "/actuator/jolokia"}}})
        if url.endswith("/actuator/env"):
            return (200, {"propertySources": [
                {"properties": {"spring.datasource.password":
                                {"value": "s3cr3tpassword"}}}]})
        return (404, None)

    async def fake_osv(package, ecosystem="", version=""):
        return {"vulns": []}

    monkeypatch.setattr(tp, "curl", fake_curl)
    monkeypatch.setattr(tp, "curl_with_status", fake_cws)
    monkeypatch.setattr(tp, "curl_json_with_status", fake_cjws)
    monkeypatch.setattr(tp, "osv_query", fake_osv)

    m = TechPlaybook(st, {"target": {"domain": "example.com", "active": False},
                          "modules": {}, "paths": {}})
    m.domain = "example.com"
    asyncio.run(m.run())
    titles = [f["title"] for f in st.findings["findings"]]
    assert "Spring Boot Jolokia (JMX) endpoint exposed" in titles
    assert "Spring Boot /actuator/env leaks secrets" in titles


def test_active_probe_skipped_in_passive_mode(monkeypatch):
    tmp = tempfile.mkdtemp()
    st = StateManager(str(Path(tmp) / "example.com"))
    st.add_asset("webapp", "webapp:https://example.com", "https://example.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})

    calls = []

    async def fake_curl(url, output="status", **kw):
        return {"status": 200, "headers": "x-powered-by: Next.js\n",
                "body": "__NEXT_DATA__ /_next/static/"}

    async def fake_cws(url, method="GET", headers=None, data=None, **kw):
        calls.append(url)
        return {"status": 404, "body": ""}

    monkeypatch.setattr(tp, "curl", fake_curl)
    monkeypatch.setattr(tp, "curl_with_status", fake_cws)

    m = TechPlaybook(st, {"target": {"domain": "example.com", "active": False},
                          "modules": {}, "paths": {}})
    m.domain = "example.com"
    asyncio.run(m.run())
    # The active image-SSRF / middleware probes must not have been requested.
    assert not any("_next/image" in u for u in calls)
    assert all("x-middleware" not in u for u in calls)
