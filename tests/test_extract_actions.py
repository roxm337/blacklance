"""Impact-extraction actions: LFI reads and sqlmap metadata mode."""

import asyncio

from actions.registry import ActionContext
from actions.web import extract as web_extract


def _ctx(action_id, **params):
    url = params.pop("url", "https://t.test/?file=x")
    return ActionContext(action_id=action_id,
                         params={"url": url, **params}, target=url)


def test_lfi_read_reports_markers_not_content(monkeypatch):
    async def fake_read_files(url, param, **kwargs):
        return {"count": 1, "files": [{
            "path": "/etc/passwd", "technique": "traversal",
            "markers": [r"root:.*?:0:0:"], "bytes": 120,
            "secrets": [], "preview": "root:x:0:0:..."}]}

    monkeypatch.setattr(web_extract.exfil, "read_files", fake_read_files)
    result = asyncio.run(web_extract.lfi_read(_ctx("web.lfi.read",
                                                   param="file")))

    assert result.success is True
    assert result.data["count"] == 1
    assert "/etc/passwd" in result.evidence["impact"]


def test_lfi_read_without_a_readable_file_is_negative(monkeypatch):
    async def fake_read_files(url, param, **kwargs):
        return {"count": 0, "files": []}

    monkeypatch.setattr(web_extract.exfil, "read_files", fake_read_files)
    result = asyncio.run(web_extract.lfi_read(_ctx("web.lfi.read",
                                                   param="file")))
    assert result.success is False


def test_sqli_extract_reports_metadata(monkeypatch):
    async def fake_enumerate(url, **kwargs):
        return {"available": True, "exit_code": 0,
                "dbms": "MySQL", "banner": "8.0.34",
                "current_user": "app@localhost",
                "current_database": "shop", "is_dba": False,
                "databases": ["shop", "information_schema"],
                "tables": ["users"], "stdout": "", "stderr": ""}

    monkeypatch.setattr(web_extract, "sqlmap_enumerate", fake_enumerate)
    result = asyncio.run(web_extract.sqli_extract(
        _ctx("web.sqli.extract", url="https://t.test/item?id=1")))

    assert result.success is True
    assert result.data["current_user"] == "app@localhost"
    assert result.data["tables"] == ["users"]
    assert result.evidence["is_dba"] is False


def test_sqli_extract_without_enumeration_is_negative(monkeypatch):
    async def fake_enumerate(url, **kwargs):
        return {"available": True, "exit_code": 1, "stdout": "not injectable",
                "stderr": ""}

    monkeypatch.setattr(web_extract, "sqlmap_enumerate", fake_enumerate)
    result = asyncio.run(web_extract.sqli_extract(
        _ctx("web.sqli.extract", url="https://t.test/item?id=1")))
    assert result.success is False
    assert "not confirmed" in result.error


def test_sqli_extract_reports_missing_sqlmap(monkeypatch):
    async def fake_enumerate(url, **kwargs):
        return {"available": False, "error": "missing"}

    monkeypatch.setattr(web_extract, "sqlmap_enumerate", fake_enumerate)
    result = asyncio.run(web_extract.sqli_extract(
        _ctx("web.sqli.extract", url="https://t.test/item?id=1")))
    assert result.success is False
    assert "sqlmap" in result.error
