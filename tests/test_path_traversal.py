"""Path traversal / LFI scan."""

import asyncio
import base64
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import modules.path_traversal as pt
from modules.path_traversal import PathTraversal, detect_file_read
from state.manager import StateManager


def test_detect_file_read_signatures():
    assert detect_file_read("root:x:0:0:root:/root:/bin/bash\n", "../etc/passwd")
    assert detect_file_read("[extensions]\nmci=...", "../win.ini")
    src = base64.b64encode(b"<?php echo 1; ?>").decode()
    assert detect_file_read(f"xx {src} yy", "php://filter/...=index.php")
    # reflected payload, no file content → not a finding
    assert detect_file_read("you searched for ../../etc/passwd", "../../etc/passwd") == ""


def _state_with_param(param):
    st = StateManager(str(Path(tempfile.mkdtemp()) / "acme.com"))
    st.add_asset("webapp", "webapp:https://acme.com", "https://acme.com",
                 confidence="CONFIRMED", sources=["t"], attrs={})
    st.add_asset("parameter", f"param:https://acme.com/dl:{param}", param,
                 confidence="FIRM", sources=["t"],
                 attrs={"url": "https://acme.com/dl", "parameter": param})
    return st


def test_confirms_lfi_on_file_param(monkeypatch):
    st = _state_with_param("file")

    async def fake_cws(url, timeout=12, **kw):
        if "passwd" in url:
            return {"status": 200, "body": "root:x:0:0:root:/root:/bin/bash",
                    "content_type": "text/plain"}
        return {"status": 200, "body": "normal page", "content_type": "text/html"}

    monkeypatch.setattr(pt, "curl_with_status", fake_cws)
    m = PathTraversal(st, {"target": {"domain": "acme.com", "active": True},
                           "modules": {}, "paths": {}})
    m.domain = "acme.com"
    assert asyncio.run(m.run()) == "done"
    titles = [f["title"] for f in st.findings["findings"]]
    assert "Path traversal / local file inclusion" in titles


def test_non_file_param_is_skipped(monkeypatch):
    st = _state_with_param("sort")   # not a file-ish name

    async def fake_cws(url, **kw):
        return {"status": 200, "body": "x", "content_type": "text/html"}

    monkeypatch.setattr(pt, "curl_with_status", fake_cws)
    m = PathTraversal(st, {"target": {"domain": "acme.com", "active": True},
                           "modules": {}, "paths": {}})
    m.domain = "acme.com"
    assert asyncio.run(m.run()) == "skipped"
