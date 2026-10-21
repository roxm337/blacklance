"""Deep per-tech intelligence parsers."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.tech_intel import (
    extract_next_routes,
    next_data_route,
    parse_env_file,
    parse_laravel_debug,
    parse_next_data,
    scan_sensitive_json,
)


def test_scan_sensitive_json_finds_keys_and_values():
    hits = scan_sensitive_json({
        "user": {"name": "ok", "access_token": "abc123def456"},
        "config": {"AWS": "AKIAIOSFODNN7EXAMPLE"},
        "safe": {"count": 3},
    })
    kinds = {h["kind"] for h in hits}
    assert "sensitive_key" in kinds        # access_token
    assert "aws_access_key" in kinds        # AKIA value
    assert all("count" not in h["path"] for h in hits)


def test_parse_next_data_extracts_buildid_and_leaks():
    html = ('<script id="__NEXT_DATA__" type="application/json">'
            '{"buildId":"xY9","page":"/acct","props":{"pageProps":'
            '{"session":{"token":"secrettokenvalue123"}}}}</script>')
    nd = parse_next_data(html)
    assert nd["found"] and nd["build_id"] == "xY9"
    assert any(h["path"].endswith("token") for h in nd["leaked"])
    assert next_data_route("xY9", "/acct") == "/_next/data/xY9/acct.json"
    assert next_data_route("xY9", "/") == "/_next/data/xY9/index.json"


def test_parse_next_data_absent():
    assert parse_next_data("<html>no next here</html>") == {"found": False}


def test_parse_next_data_app_router_rsc_flight():
    # App Router streams server data via self.__next_f.push, not __NEXT_DATA__.
    html = (
        '<html><script src="/_next/static/Ab12Cd34/_buildManifest.js"></script>'
        r'<script>self.__next_f.push([1,"{\"user\":{\"access_token\":\"livesecret12345\"}}"])</script>'
        '</html>')
    nd = parse_next_data(html)
    assert nd["found"] and nd["router"] == "app"
    assert nd["build_id"] == "Ab12Cd34"
    assert any("access_token" in h["path"] for h in nd["leaked"])


def test_extract_next_build_id_from_chunks():
    from core.tech_intel import extract_next_build_id
    assert extract_next_build_id(
        '<script src="/_next/static/XyZ999/chunks/main.js">') == "XyZ999"


def test_extract_next_routes_skips_assets():
    js = '{"/":["a.js"],"/blog/[slug]":["b.js"],"/x.css":[],"/dashboard":["c.js"]}'
    routes = extract_next_routes(js)
    assert "/" in routes and "/blog/[slug]" in routes and "/dashboard" in routes
    assert "/x.css" not in routes


def test_parse_laravel_debug_detects_and_versions():
    html = ("<div>Whoops! Illuminate\\Foundation ... "
            "laravel/framework v8.1.0 ... PHP 7.4.3 ... "
            "/var/www/html/app/Http/Controllers/HomeController.php</div>")
    info = parse_laravel_debug(html)
    assert info["is_debug"]
    assert info["laravel_version"] == "8.1.0"
    assert info["php_version"] == "7.4.3"
    assert info["app_path"].startswith("/var/www")


def test_parse_laravel_debug_not_debug():
    assert parse_laravel_debug("<html>404 Not Found</html>") == {"is_debug": False}


def test_parse_env_file_severity():
    envs = {e["key"]: e["severity"] for e in parse_env_file(
        "APP_KEY=base64:x\nAPP_DEBUG=true\nMAIL_HOST=smtp.example\n"
        "# comment\nDB_PASSWORD=hunter2\nEMPTY=")}
    assert envs["APP_KEY"] == "CRITICAL"
    assert envs["DB_PASSWORD"] == "CRITICAL"
    assert envs["APP_DEBUG"] == "HIGH"
    assert envs["MAIL_HOST"] == "MEDIUM"
    assert "EMPTY" not in envs            # no value → skipped
