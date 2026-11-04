"""Bounded file extraction: markers, PHP wrapper decoding, redaction."""

import asyncio
import base64

from core import exfil


def _fetch(routes):
    async def fetch(url):
        for needle, (status, body) in routes.items():
            if needle in url:
                return {"status": status, "body": body}
        return {"status": 404, "body": "<html>not found</html>"}
    return fetch


def test_reads_passwd_and_dotenv_markers():
    fetch = _fetch({
        "passwd": (200, "root:x:0:0:root:/root:/bin/bash\n"),
        ".env": (200, "DB_PASSWORD=" + "s3cr3t-value-42" + "\n"),
    })
    result = asyncio.run(exfil.read_files(
        "https://t.test/?file=x", "file", fetch=fetch,
        files=["/etc/passwd", "/var/www/html/.env"]))

    assert result["count"] == 2
    hosts = [item for item in result["files"] if item["path"] == "/etc/passwd"]
    assert hosts and hosts[0]["markers"] == [r"root:.*?:0:0:"]


def test_php_filter_wrapper_value_is_base64_decoded():
    source = b"<?php define('DB_PASSWORD', 'hunter2'); ?>"
    payload = base64.b64encode(source).decode()
    fetch = _fetch({"base64-encode": (200, payload)})

    result = asyncio.run(exfil.read_files(
        "https://t.test/?file=x", "file", fetch=fetch,
        files=["/var/www/html/config.php"]))

    assert result["count"] == 1
    item = result["files"][0]
    assert item["technique"] == "php-filter"
    assert "DB_PASSWORD" in item["preview"]


def test_preview_is_bounded_and_short():
    fetch = _fetch({"passwd": (200, "root:x:0:0:" + "A" * 100000)})
    result = asyncio.run(exfil.read_files(
        "https://t.test/?file=x", "file", fetch=fetch,
        files=["/etc/passwd"], max_bytes=64))
    assert len(result["files"][0]["preview"]) <= 64


def test_html_error_pages_do_not_count_as_reads():
    fetch = _fetch({"passwd": (200, "<html>Page not found</html>")})
    result = asyncio.run(exfil.read_files(
        "https://t.test/?file=x", "file", fetch=fetch, files=["/etc/passwd"]))
    assert result["count"] == 0


def test_summary_names_files_without_content():
    result = {"files": [{"path": "/etc/passwd", "technique": "traversal"}],
              "count": 1}
    summary = exfil.summarize_extraction(result)
    assert "/etc/passwd" in summary
    assert "root:" not in summary
