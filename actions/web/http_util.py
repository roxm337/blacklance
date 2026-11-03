"""Small helpers shared by the web proving actions.

Every action takes a baseline and compares against it, so the same three
things recur: pick a header set, replace one parameter's value without
appending a duplicate, and read status/body out of the `curl` dict.
"""

from urllib.parse import parse_qsl, urlencode, urlparse

from core.validators import inject_param

_UA = "Mozilla/5.0 (compatible; bhs-probe)"


def status(raw: dict) -> int:
    return int(raw.get("status") or 0)


def body(raw: dict) -> str:
    return str(raw.get("body") or "")


def session_headers(ctx) -> dict:
    headers = {"User-Agent": _UA}
    if isinstance(ctx.params.get("headers"), dict):
        headers.update(ctx.params["headers"])
    return headers


def dedupe_param(url: str, param: str, value: str) -> str:
    """Replace every existing value of `param` instead of appending one.

    `inject_param` appends, which leaves the original value first in the query
    string; on a server that reads the first occurrence the baseline value wins
    and the payload never runs, so the oracle reports a clean target.
    """
    if f"{{{param}}}" in url:
        return inject_param(url, param, value)
    parsed = urlparse(url)
    kept = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
            if k != param]
    kept.append((param, value))
    return parsed._replace(query=urlencode(kept, doseq=True)).geturl()
