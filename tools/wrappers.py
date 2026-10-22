"""Async tool wrappers for DNS, HTTP, WHOIS, port scanning, etc."""

import asyncio
import shlex
import subprocess
import json
import re
import time
import base64
import tempfile
import os
from typing import Any, Optional
from urllib.parse import quote, urlencode

from core.deadline import clamp_timeout, deadline_reached
from tools import http_engine as _http_engine_mod
from tools.http_engine import HttpEngine
from tools.external import (consume_tool_budget, docker_wrap_shell,
                            terminate_process_tree)
from tools.external import tool_available as _tool_available

# Pooled aiohttp engine. Created lazily on first request and reused for the
# whole run so connections (and TLS handshakes) are shared across modules.
_engine: Optional[HttpEngine] = None
_http_budget: Any = None

# Global cookie jar for stateful web sessions across requests
_COOKIE_JAR: str | None = None
_HTTP_SESSION_HEADERS: dict[str, str] = {}

# Headers that carry a credential. Stripped whenever a request is bound to a
# named identity or explicitly marked sessionless, so the single legacy
# session in `auth.cookies` can never authenticate every other request.
_AUTH_HEADERS = frozenset({"authorization", "cookie", "cookie_header", "x-api-key"})


def _drop_auth_headers(headers: dict) -> dict:
    """Remove every credential header, in place. Used for anonymous probes."""
    for name in [h for h in headers if h.lower() in _AUTH_HEADERS]:
        headers.pop(name, None)
    return headers

def _get_cookie_jar() -> str:
    global _COOKIE_JAR
    if _COOKIE_JAR is None or not os.path.exists(_COOKIE_JAR):
        _COOKIE_JAR = os.path.join(tempfile.gettempdir(), "osint_agent_cookies.txt")
    return _COOKIE_JAR

def reset_cookie_jar():
    """Drop all session cookies — both the engine's in-memory jars and the
    on-disk jar the curl fallback still uses."""
    global _COOKIE_JAR, _HTTP_SESSION_HEADERS
    if _COOKIE_JAR and os.path.exists(_COOKIE_JAR):
        try:
            os.remove(_COOKIE_JAR)
        except OSError:
            pass
    _COOKIE_JAR = None
    _HTTP_SESSION_HEADERS = {}
    if _engine is not None:
        _engine.forget_identities()


_SCOPE_GUARD = None


def configure_scope(config: Optional[dict] = None):
    global _SCOPE_GUARD
    try:
        from core.scope_guard import from_config
        _SCOPE_GUARD = from_config(config or {})
    except Exception:
        _SCOPE_GUARD = None


def set_scope_guard(guard):
    global _SCOPE_GUARD
    _SCOPE_GUARD = guard


def get_scope_guard():
    return _SCOPE_GUARD


def configure_http_session(config: Optional[dict] = None):
    """Configure headers/cookies applied to all wrapper HTTP requests."""
    configure_scope(config)
    global _HTTP_SESSION_HEADERS
    auth = (config or {}).get("auth", {}) or {}
    headers = {
        str(k): str(v)
        for k, v in (auth.get("headers") or {}).items()
        if k and v is not None and str(v) != ""
    }

    bearer = auth.get("bearer_token") or auth.get("token")
    if bearer and "Authorization" not in headers:
        headers["Authorization"] = f"Bearer {bearer}"

    cookie_header = auth.get("cookie") or auth.get("cookie_header")
    cookies = auth.get("cookies") or {}
    if isinstance(cookies, dict) and cookies:
        cookie_header = "; ".join(
            f"{k}={v}" for k, v in cookies.items()
            if k and v is not None and str(v) != ""
        )
    if cookie_header and "Cookie" not in headers:
        headers["Cookie"] = str(cookie_header)

    _HTTP_SESSION_HEADERS = headers


def _merge_session_headers(headers: Optional[dict] = None,
                           drop_auth: bool = False) -> dict:
    """Combine the globally configured headers with the caller's.

    `drop_auth` removes the *global* credentials. The global `Cookie` and
    `Authorization` headers come from a single legacy session, and applying
    them to a request made under a different identity would defeat the whole
    point of isolated jars — and applying them to an anonymous probe would
    turn "this record is public" into a false claim.

    The caller's own headers survive. A cookie identity keeps its session in
    a per-identity jar the engine attaches itself, but a bearer identity has
    no jar to lean on: its `Authorization` header *is* the credential.
    Stripping it along with the legacy one sent every bearer request out
    unauthenticated, so every object came back 401, no ownership could be
    attributed, and the module reported zero probes against a target whose
    baskets were readable by anyone.
    """
    merged = dict(_HTTP_SESSION_HEADERS)
    if drop_auth:
        _drop_auth_headers(merged)
    if headers:
        merged.update({str(k): v for k, v in headers.items() if v is not None})
    return merged


class RateLimiter:
    """Async rate limiter with concurrency, per-minute, and *adaptive* caps.

    A fixed rate is only half the story against a real target: once the server
    starts answering 429/503 (or sends `Retry-After`), continuing at the
    configured rate just collects blocked responses — which downstream modules
    read as "not vulnerable" — and hammers a WAF that is already shedding load.
    `note_response()` feeds those signals back in, and the limiter holds new
    requests during a cooldown. The backoff is capped so one hostile
    `Retry-After: 3600` cannot stall the whole engagement, and every wait is
    bounded by the module deadline so a limiter sleep never outlives the run
    it belongs to.
    """

    # Cap on any single backoff, and the base penalty when a 429/503 arrives
    # without a usable Retry-After. Repeated hits lengthen the cooldown up to
    # the cap.
    MAX_BACKOFF = 30.0
    BASE_PENALTY = 2.0

    def __init__(self, max_concurrent: int = 5, max_per_minute: int = 60):
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._max_per_minute = max_per_minute
        self._timestamps: list[float] = []
        self._lock = asyncio.Lock()
        self._cooldown_until = 0.0
        self._consecutive_throttles = 0

    async def _sleep_bounded(self, seconds: float) -> None:
        """Sleep, but never past the current module's deadline — the next
        request short-circuits there anyway, so a longer sleep would only
        burn into the orchestrator's hard guillotine for no benefit."""
        from core.deadline import deadline_remaining
        seconds = min(seconds, max(0.0, deadline_remaining()))
        if seconds > 0:
            await asyncio.sleep(seconds)

    async def __aenter__(self):
        await self._semaphore.acquire()
        async with self._lock:
            now = time.monotonic()
            # Adaptive backoff: the target asked us to slow down.
            if self._cooldown_until > now:
                await self._sleep_bounded(self._cooldown_until - now)
                now = time.monotonic()
            self._timestamps = [t for t in self._timestamps if now - t < 60]
            if len(self._timestamps) >= self._max_per_minute:
                wait = self._timestamps[0] + 60 - now
                if wait > 0:
                    await self._sleep_bounded(wait)
                now = time.monotonic()
                self._timestamps = [t for t in self._timestamps if now - t < 60]
            self._timestamps.append(now)
        return self

    async def __aexit__(self, *args):
        self._semaphore.release()

    def note_response(self, status: int, retry_after=None) -> None:
        """Feed a response's rate-limit signals back into the limiter.

        A `Retry-After` (seconds, or an HTTP-date) is honoured when present;
        otherwise a 429/503/509 triggers an exponential base penalty that
        grows while throttling persists and resets on the first clean
        response. All capped at MAX_BACKOFF.
        """
        if status in (429, 503, 509):
            self._consecutive_throttles += 1
            penalty = _parse_retry_after(retry_after)
            if penalty <= 0:
                penalty = min(self.BASE_PENALTY * self._consecutive_throttles,
                              self.MAX_BACKOFF)
            penalty = min(penalty, self.MAX_BACKOFF)
            self._cooldown_until = max(self._cooldown_until,
                                       time.monotonic() + penalty)
        elif 200 <= status < 400:
            self._consecutive_throttles = 0


def _parse_retry_after(value) -> float:
    """Seconds to wait from a Retry-After value: a number, or an HTTP-date.

    Returns 0.0 when absent or unparseable so the caller falls back to its
    own penalty. Never returns a negative (a past date means "now").
    """
    if value in (None, ""):
        return 0.0
    text = str(value).strip()
    try:
        return max(0.0, float(text))
    except (TypeError, ValueError):
        pass
    try:
        from email.utils import parsedate_to_datetime
        when = parsedate_to_datetime(text)
        if when is not None:
            from datetime import datetime, timezone
            delta = (when - datetime.now(timezone.utc)).total_seconds()
            return max(0.0, delta)
    except (TypeError, ValueError, OverflowError):
        pass
    return 0.0


_http_limiter = RateLimiter(max_concurrent=5, max_per_minute=60)


def configure_http_limiter(max_concurrent: int = 5, max_per_minute: int = 60):
    global _http_limiter
    _http_limiter = RateLimiter(max_concurrent, max_per_minute)


def configure_http_budget(budget: Any = None):
    """Attach one engagement budget to every shared HTTP request.

    Kept duck-typed to avoid coupling the transport layer to the orchestrator.
    Passing ``None`` restores the standalone-wrapper behavior used by modules
    and tests outside an engagement.
    """
    global _http_budget
    _http_budget = budget


def _consume_http_budget() -> None:
    if _http_budget is not None:
        _http_budget.consume_request()


def _missing(tool: str) -> bool:
    """True when the binary is absent: callers return their normal shape
    with error="missing: <tool>" instead of a false negative."""
    import shutil as _shutil
    return _shutil.which(tool) is None


async def bash(command: str, timeout: int = 120) -> dict:
    """Execute a shell command with timeout.

    Returns {stdout, stderr, exit_code, error}. A missing binary is NOT
    reported here (bash cannot know which word is the tool): shell-based
    helpers check with _missing() first and return their normal shape
    with error="missing: <tool>", so absence never looks like a
    negative result.

    Docker tool backend: commands invoking a baked binary are transparently
    re-routed into the toolchain image (repo mounted at /work); anything
    else runs locally as before.
    """
    # A tool subprocess started past the deadline would run its own full
    # timeout (sqlmap's is 900s) straight through the guillotine. Refuse to
    # launch it and report an empty result the caller already handles.
    if deadline_reached():
        return {"stdout": "", "stderr": "", "exit_code": -1,
                "error": "deadline_exceeded"}
    timeout = clamp_timeout(timeout)
    consume_tool_budget()
    command = docker_wrap_shell(command)
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name != "nt",
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout)
        return {
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
            "exit_code": proc.returncode or 0,
            "error": None,
        }
    except asyncio.TimeoutError:
        await terminate_process_tree(proc)
        return {"stdout": "", "stderr": "timeout", "exit_code": -1, "error": "timeout"}
    except Exception as e:
        return {"stdout": "", "stderr": str(e), "exit_code": -1, "error": str(e)}


def get_engine() -> HttpEngine:
    """Return the process-wide HTTP engine, creating it on first use."""
    global _engine
    if _engine is None:
        _engine = HttpEngine()
    return _engine


async def close_engine() -> None:
    """Close the engine's connection pool. Call on shutdown."""
    global _engine
    if _engine is not None:
        await _engine.close()
        _engine = None


def engine_stats() -> dict:
    """Connection-pool counters for the run summary."""
    if _engine is None:
        return {
            "requests": 0,
            "connections_opened": 0,
            "connections_reused": 0,
            "identities": [],
        }
    return _engine.stats()


async def _curl_subprocess(url: str, method: str = "GET",
                           headers: Optional[dict] = None,
                           data: Optional[str] = None,
                           http1_0: bool = False,
                           output: str = "status",
                           follow_redirects: bool = True,
                           timeout: int = 10,
                           session_headers: Optional[dict] = None) -> dict:
    """Original curl-subprocess path.

    Kept for the two cases the aiohttp engine cannot serve: forcing HTTP/1.0
    (waf_module's protocol probe) and running without aiohttp installed.

    `session_headers` carries the already-merged global headers so this path
    applies exactly the same credential-stripping rules as the engine.
    """
    cmd = ["curl", "-s", "--max-time", str(timeout), "--connect-timeout", "5"]

    cmd.extend(["-b", _get_cookie_jar(), "-c", _get_cookie_jar()])

    if follow_redirects:
        cmd.append("-L")

    if output == "status":
        cmd.extend(["-o", "/dev/null", "-w", "%{http_code}"])
    elif output == "headers":
        cmd.extend(["-D", "-", "-o", "/dev/null"])
    elif output == "body":
        cmd.extend(["-w", ""])
    elif output == "full":
        cmd.extend(["-D", "-"])

    if http1_0:
        cmd.append("--http1.0")
    if method != "GET":
        cmd.extend(["-X", method])
    merged_headers = session_headers if session_headers is not None \
        else _merge_session_headers(headers)
    if merged_headers:
        for k, v in merged_headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
    if data:
        cmd.extend(["-d", data])

    cmd.append(url)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name != "nt",
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout + 5)
        out = stdout.decode("utf-8", errors="replace").strip()
    except asyncio.TimeoutError:
        await terminate_process_tree(proc)
        return {"status": 0, "body": "", "error": "timeout"}
    except Exception as e:
        return {"status": 0, "body": "", "error": str(e)}

    if output == "status":
        try:
            return {"status": int(out), "body": ""}
        except ValueError:
            return {"status": 0, "body": out, "error": "non-numeric status"}
    elif output == "headers":
        status = 0
        for line in out.split("\n"):
            m = re.match(r"HTTP/[\d.]+ (\d+)", line)
            if m:
                status = int(m.group(1))
        return {"status": status, "body": out}
    elif output == "full":
        parts = out.split("\r\n\r\n", 1) if "\r\n\r\n" in out else out.split("\n\n", 1)
        header_part = parts[0] if parts else ""
        body_part = parts[1] if len(parts) > 1 else ""
        status = 0
        for line in header_part.split("\n"):
            m = re.match(r"HTTP/[\d.]+ (\d+)", line)
            if m:
                status = int(m.group(1))
        return {"status": status, "body": body_part, "headers": header_part}
    else:
        return {"status": 0, "body": out}


async def curl(url: str, method: str = "GET",
              headers: Optional[dict] = None,
              data: Optional[str] = None,
              http1_0: bool = False,
              output: str = "status",
              follow_redirects: bool = True,
              timeout: int = 10,
              identity: Optional[str] = None,
              no_session: bool = False,
              strip_global_auth: bool = False) -> dict:
    """HTTP request via the pooled aiohttp engine.

    Drop-in replacement for the old curl wrapper: same arguments, same return
    keys, and `identity` is the only addition. Adds `time_ms`, `url`, and
    `history`, and fixes `time_ms` which was hardcoded to 0 and silently
    degraded differential response analysis.

    `identity` selects an isolated cookie jar. Requests using different
    identities never see each other's cookies, which is the precondition for
    two-account IDOR testing.

    `no_session` drops the globally configured `Authorization` and `Cookie`
    headers. Two callers need it: the anonymous probe, which would otherwise
    send a global credential and report an authenticated read as a public
    exposure, and any request bound to a named identity, which supplies its
    own. Non-authentication headers such as User-Agent still apply.

    `strip_global_auth` is for third-party API calls (urlscan, shodan,
    hunter): the target's session credentials must never ride along to
    someone else's API. The caller's own headers (API keys) survive.
    """
    # Once the running module is out of time, make no more requests: return
    # the wrapper's own "failed probe" shape so the caller's loop drains fast
    # and reaches its finding-flush instead of being guillotined mid-scan.
    if deadline_reached():
        return {"status": 0, "body": "", "error": "deadline_exceeded",
                "time_ms": 0, "url": url, "history": []}
    guard = _SCOPE_GUARD
    if guard is not None:
        allowed, reason = guard.check(url)
        if not allowed:
            return {"status": 0, "body": "", "error": reason,
                    "time_ms": 0, "url": url, "history": []}
    timeout = clamp_timeout(timeout)

    # Reserve before either the aiohttp or subprocess transport is selected;
    # otherwise HTTP/1.0 and fallback requests would bypass the same cap.
    _consume_http_budget()

    if strip_global_auth:
        merged_headers = {str(k): v for k, v in (headers or {}).items()
                          if v is not None}
    else:
        merged_headers = _merge_session_headers(headers, drop_auth=no_session or bool(identity))
    if no_session:
        # Anonymous means anonymous, including a credential the caller passed
        # in explicitly: the caller's headers now survive `drop_auth`, so
        # without this an "is it public?" probe would authenticate itself.
        _drop_auth_headers(merged_headers)

    # HTTP/1.0 has no aiohttp equivalent, and a missing aiohttp disables the
    # engine entirely — both fall back to the original subprocess.
    if http1_0 or _http_engine_mod.aiohttp is None:
        async with _http_limiter:
            result = await _curl_subprocess(
                url, method, headers, data, http1_0, output,
                follow_redirects, timeout,
                session_headers=merged_headers,
            )
        _http_limiter.note_response(result.get("status", 0),
                                    result.get("retry_after"))
        return result

    async with _http_limiter:
        engine = get_engine()
        result = await engine.request(
            url,
            method,
            headers=merged_headers,
            data=data,
            follow_redirects=follow_redirects,
            timeout=timeout,
            output=output,
            identity=identity,
        )
    # Feed the target's rate-limit signals back to the limiter so the next
    # request through it respects any cooldown this one just earned.
    _http_limiter.note_response(result.get("status", 0),
                                result.get("retry_after"))
    return result


async def curl_with_status(url: str, **kwargs) -> dict:
    """Fetch URL and return both status code and body."""
    # The old implementation always followed redirects; preserve that here
    # because callers of this helper rely on landing on the final page.
    kwargs.setdefault("follow_redirects", True)
    result = await curl(url, output="full", **kwargs)
    return {
        "status": result.get("status", 0),
        "body": result.get("body", ""),
        "time_ms": result.get("time_ms", 0.0),
        "url": result.get("url", url),
    }


async def curl_json(url: str, **kwargs) -> Optional[dict]:
    """Fetch URL and parse as JSON."""
    result = await curl(url, output="body", **kwargs)
    body = result.get("body", "").strip()
    if not body:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


async def curl_json_with_status(url: str, **kwargs) -> tuple:
    """Fetch URL and return (status, parsed_json_or_None)."""
    result = await curl_with_status(url, **kwargs)
    status = result.get("status", 0)
    body = result.get("body", "").strip()
    try:
        data = json.loads(body) if body else None
    except json.JSONDecodeError:
        data = None
    return status, data


async def dig(record_type: str, domain: str,
              server: str = "", follow_cname: bool = False) -> dict:
    """DNS lookup. Returns list of answers."""
    if _missing("dig"):
        return {"domain": domain, "type": record_type, "answers": [],
                "raw": "", "error": "missing: dig"}
    rtype = shlex.quote(str(record_type or "A"))
    target = shlex.quote(str(domain or ""))
    if follow_cname:
        cmd = f"dig {rtype} {target}"
    else:
        cmd = f"dig +short {rtype} {target}"
    if server:
        cmd += f" @{shlex.quote(str(server))}"
    result = await bash(cmd)
    answers = []
    for line in result["stdout"].split("\n"):
        line = line.strip().strip('"').strip("'").strip('“').strip('”')
        if line and not line.startswith(";") and not line.startswith(";;"):
            answers.append(line)
    return {
        "domain": domain,
        "type": record_type,
        "answers": answers,
        "raw": result["stdout"],
    }


async def dig_all(domain: str) -> dict:
    """Fetch all DNS record types for a domain in parallel."""
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA", "PTR"]
    tasks = {rtype: dig(rtype, domain) for rtype in record_types}
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    records = {}
    for rtype, result in zip(tasks.keys(), results):
        if not isinstance(result, Exception) and result.get("answers"):
            records[rtype] = result["answers"]
    return records


async def dig_bulk(hostnames: list, record_type: str = "A",
                   concurrency: int = 20) -> dict:
    """Bulk DNS resolution for a list of hostnames. Returns {hostname: [answers]}."""
    sem = asyncio.Semaphore(concurrency)

    async def _resolve(host):
        async with sem:
            result = await dig(record_type, host)
            return host, result.get("answers", [])

    pairs = await asyncio.gather(*[_resolve(h) for h in hostnames])
    return {h: answers for h, answers in pairs}


async def whois_lookup(query: str) -> dict:
    """WHOIS lookup for domain or IP."""
    if _missing("whois"):
        return {"query": query, "fields": {}, "raw": "",
                "error": "missing: whois"}
    result = await bash(f"whois {shlex.quote(str(query or ''))}")
    text = result["stdout"]
    fields = {}
    for line in text.split("\n"):
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip().lower().replace(" ", "_")
            val = val.strip()
            if key and val and key not in fields:
                fields[key] = val
    return {
        "query": query,
        "fields": fields,
        "raw": text[:3000],
    }


async def rdap_lookup(domain: str) -> dict:
    """RDAP lookup — structured JSON alternative to WHOIS."""
    result = await bash(
        f"curl -s 'https://rdap.org/domain/{shlex.quote(str(domain or ''))}' "
        f"--max-time 10 -H 'Accept: application/json' 2>/dev/null || true"
    )
    try:
        data = json.loads(result["stdout"])
        registrar = ""
        registrant = ""
        created = ""
        expires = ""
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            vcard = entity.get("vcardArray", [[], []])
            if "registrar" in roles and vcard:
                for field in vcard[1]:
                    if field[0] == "fn":
                        registrar = field[3]
            if "registrant" in roles and vcard:
                for field in vcard[1]:
                    if field[0] == "fn":
                        registrant = field[3]
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                created = event.get("eventDate", "")
            if event.get("eventAction") == "expiration":
                expires = event.get("eventDate", "")
        return {
            "domain": domain,
            "registrar": registrar,
            "registrant": registrant,
            "created": created,
            "expires": expires,
            "status": data.get("status", []),
            "nameservers": [ns.get("ldhName", "") for ns in data.get("nameservers", [])],
            "raw": data,
        }
    except (json.JSONDecodeError, KeyError, TypeError):
        return {"domain": domain, "raw": {}}


async def crtsh(domain: str) -> list:
    """Query certificate transparency logs via crt.sh."""
    result = await bash(
        f"curl -s 'https://crt.sh/?q=%25.{shlex.quote(str(domain or ''))}&output=json' "
        f"--max-time 20"
    )
    try:
        data = json.loads(result["stdout"])
        if isinstance(data, list):
            return data
    except (json.JSONDecodeError, TypeError):
        pass
    return []


async def otx_passive_dns(domain: str) -> list:
    """Query OTX AlienVault for passive DNS/subdomain data."""
    result = await bash(
        f"curl -s 'https://otx.alienvault.com/api/v1/indicators/domain/{shlex.quote(str(domain or ''))}/passive_dns' "
        f"--max-time 15 -H 'User-Agent: Mozilla/5.0' 2>/dev/null || true"
    )
    try:
        data = json.loads(result["stdout"])
        return data.get("passive_dns", [])
    except (json.JSONDecodeError, TypeError):
        return []


async def urlscan_search(domain: str, api_key: str = "") -> list:
    """Query urlscan.io for domain-related URLs.

    Engine call (no shell): the API key never appears in a process list.
    Global target credentials are stripped — they must not ride along to
    a third-party API.
    """
    headers = {"API-Key": api_key} if api_key else None
    data = await curl_json(
        f"https://urlscan.io/api/v1/search/?q=domain:{quote(str(domain or ''))}&size=200",
        headers=headers, timeout=15, strip_global_auth=True,
    )
    if not isinstance(data, dict):
        return []
    return data.get("results", [])


async def hackertarget_hostsearch(domain: str) -> list:
    """HackerTarget host search API (free tier)."""
    result = await bash(
        f"curl -s 'https://api.hackertarget.com/hostsearch/?q={shlex.quote(str(domain or ''))}' "
        f"--max-time 15 2>/dev/null || true"
    )
    output = result.get("stdout", "").strip()
    if not output or "error" in output.lower() or "API count" in output:
        return []
    hosts = []
    for line in output.split("\n"):
        line = line.strip()
        if line and "," in line:
            parts = line.split(",")
            if len(parts) >= 1:
                hosts.append({"hostname": parts[0].strip(), "ip": parts[1].strip() if len(parts) > 1 else ""})
    return hosts


def _host_matches_domain(hostname: str, domain: str) -> bool:
    host = hostname.strip().lower().strip(".")
    root = domain.strip().lower().strip(".")
    return host == root or host.endswith(f".{root}")


def _extract_domain_hosts(text: str, domain: str) -> list:
    pattern = re.compile(
        rf"(?i)\b(?:[a-z0-9_-]+\.)+{re.escape(domain.strip().lower())}\b"
    )
    hosts = {
        match.group(0).lower().strip(".")
        for match in pattern.finditer(text or "")
        if _host_matches_domain(match.group(0), domain)
    }
    return sorted(hosts)


async def rapiddns(domain: str) -> list:
    """RapidDNS passive subdomain source. Returns hostnames only."""
    result = await curl(
        f"https://rapiddns.io/subdomain/{quote(domain)}?full=1",
        output="body",
        timeout=20, strip_global_auth=True,
    )
    return _extract_domain_hosts(result.get("body", ""), domain)


async def anubisdb(domain: str) -> list:
    """AnubisDB passive subdomain source."""
    data = await curl_json(
        f"https://jldc.me/anubis/subdomains/{quote(domain)}",
        timeout=20, strip_global_auth=True,
    )
    if not isinstance(data, list):
        return []
    hosts = {
        str(host).lower().replace("*.", "").strip(".")
        for host in data
        if _host_matches_domain(str(host).replace("*.", ""), domain)
    }
    return sorted(hosts)


async def certspotter(domain: str) -> list:
    """Cert Spotter CT source. Returns certificate DNS names."""
    query = urlencode({
        "domain": domain,
        "include_subdomains": "true",
        "expand": "dns_names",
    })
    data = await curl_json(
        f"https://api.certspotter.com/v1/issuances?{query}",
        timeout=20, strip_global_auth=True,
    )
    if not isinstance(data, list):
        return []
    hosts = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        for name in item.get("dns_names", []) or []:
            clean = str(name).lower().replace("*.", "").strip(".")
            if _host_matches_domain(clean, domain):
                hosts.add(clean)
    return sorted(hosts)


async def bgpview_asn(asn: str) -> dict:
    """BGPView ASN prefix lookup."""
    clean_asn = str(asn).upper().replace("AS", "").strip()
    if not clean_asn.isdigit():
        return {"asn": asn, "ipv4_prefixes": [], "ipv6_prefixes": [], "raw": {}}
    data = await curl_json(
        f"https://api.bgpview.io/asn/{clean_asn}/prefixes",
        timeout=20, strip_global_auth=True,
    )
    if not isinstance(data, dict):
        return {"asn": f"AS{clean_asn}", "ipv4_prefixes": [], "ipv6_prefixes": [], "raw": {}}
    payload = data.get("data", {}) if isinstance(data.get("data", {}), dict) else {}
    return {
        "asn": f"AS{clean_asn}",
        "name": payload.get("name", ""),
        "description": payload.get("description_short", ""),
        "ipv4_prefixes": payload.get("ipv4_prefixes", []) or [],
        "ipv6_prefixes": payload.get("ipv6_prefixes", []) or [],
        "raw": data,
    }


async def epss_score(cves: list[str]) -> dict:
    """FIRST EPSS scores keyed by CVE."""
    cleaned = sorted({
        str(cve).upper().strip()
        for cve in cves
        if str(cve).upper().startswith("CVE-")
    })
    if not cleaned:
        return {}
    query = urlencode({"cve": ",".join(cleaned)})
    data = await curl_json(
        f"https://api.first.org/data/v1/epss?{query}",
        timeout=20, strip_global_auth=True,
    )
    if not isinstance(data, dict):
        return {}
    scores = {}
    for item in data.get("data", []) or []:
        cve = str(item.get("cve", "")).upper()
        try:
            scores[cve] = {
                "epss": float(item.get("epss", 0.0)),
                "percentile": float(item.get("percentile", 0.0)),
                "date": item.get("date", ""),
            }
        except (TypeError, ValueError):
            continue
    return scores


async def osv_query(package: str, ecosystem: str = "", version: str = "") -> dict:
    """Query OSV for package vulnerabilities.

    When `version` is given, OSV returns only the vulnerabilities whose
    affected ranges include that version — precise, authoritative
    version-range matching for free, instead of every vuln the package ever
    had. Without it, all package vulns come back (the old behaviour).
    """
    payload = {"package": {"name": package}}
    if ecosystem:
        payload["package"]["ecosystem"] = ecosystem
    if version:
        payload["version"] = str(version)
    data = await curl_json(
        "https://api.osv.dev/v1/query",
        method="POST",
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload),
        timeout=20, strip_global_auth=True,
    )
    return data if isinstance(data, dict) else {}


async def urlhaus_host(host: str) -> dict:
    """URLHaus host reputation lookup."""
    data = await curl_json(
        "https://urlhaus-api.abuse.ch/v1/host/",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=urlencode({"host": host}),
        timeout=20, strip_global_auth=True,
    )
    return data if isinstance(data, dict) else {}


async def threatfox_ioc(ioc: str) -> dict:
    """ThreatFox IOC search."""
    data = await curl_json(
        "https://threatfox-api.abuse.ch/api/v1/",
        method="POST",
        headers={"Content-Type": "application/json"},
        data=json.dumps({"query": "search_ioc", "search_term": ioc}),
        timeout=20, strip_global_auth=True,
    )
    return data if isinstance(data, dict) else {}


async def ip_api(query: str) -> dict:
    """ip-api.com geo/ASN fallback."""
    fields = (
        "status,message,country,countryCode,regionName,city,isp,org,as,asname,"
        "reverse,query"
    )
    data = await curl_json(
        f"http://ip-api.com/json/{quote(query)}?{urlencode({'fields': fields})}",
        timeout=10, strip_global_auth=True,
    )
    return data if isinstance(data, dict) else {}


async def virustotal_domain(domain: str, api_key: str) -> dict:
    """VirusTotal domain enrichment."""
    if not api_key:
        return {}
    data = await curl_json(
        f"https://www.virustotal.com/api/v3/domains/{quote(domain)}",
        headers={"x-apikey": api_key},
        timeout=20, strip_global_auth=True,
    )
    return data if isinstance(data, dict) else {}


async def virustotal_domain_subdomains(domain: str, api_key: str, limit: int = 40) -> list:
    """VirusTotal domain subdomains."""
    if not api_key:
        return []
    query = urlencode({"limit": min(max(limit, 1), 40)})
    data = await curl_json(
        f"https://www.virustotal.com/api/v3/domains/{quote(domain)}/subdomains?{query}",
        headers={"x-apikey": api_key},
        timeout=20, strip_global_auth=True,
    )
    if not isinstance(data, dict):
        return []
    hosts = []
    for item in data.get("data", []) or []:
        host = str(item.get("id", "")).lower().strip(".")
        if _host_matches_domain(host, domain):
            hosts.append(host)
    return sorted(set(hosts))


async def virustotal_ip(ip: str, api_key: str) -> dict:
    """VirusTotal IP enrichment."""
    if not api_key:
        return {}
    data = await curl_json(
        f"https://www.virustotal.com/api/v3/ip_addresses/{quote(ip)}",
        headers={"x-apikey": api_key},
        timeout=20, strip_global_auth=True,
    )
    return data if isinstance(data, dict) else {}


async def virustotal_url(url: str, api_key: str) -> dict:
    """VirusTotal URL enrichment."""
    if not api_key:
        return {}
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    data = await curl_json(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": api_key},
        timeout=20, strip_global_auth=True,
    )
    return data if isinstance(data, dict) else {}


async def greynoise_ip(ip: str, api_key: str) -> dict:
    """GreyNoise Community IP context."""
    if not api_key:
        return {}
    data = await curl_json(
        f"https://api.greynoise.io/v3/community/{quote(ip)}",
        headers={"key": api_key, "Accept": "application/json"},
        timeout=20, strip_global_auth=True,
    )
    return data if isinstance(data, dict) else {}


async def abuseipdb_check(ip: str, api_key: str, max_age_days: int = 90) -> dict:
    """AbuseIPDB IP reputation check."""
    if not api_key:
        return {}
    query = urlencode({"ipAddress": ip, "maxAgeInDays": max_age_days})
    data = await curl_json(
        f"https://api.abuseipdb.com/api/v2/check?{query}",
        headers={"Key": api_key, "Accept": "application/json"},
        timeout=20, strip_global_auth=True,
    )
    return data if isinstance(data, dict) else {}


async def chaos_subdomains(domain: str, api_key: str) -> list:
    """ProjectDiscovery Chaos subdomains."""
    if not api_key:
        return []
    data = await curl_json(
        f"https://dns.projectdiscovery.io/dns/{quote(domain)}/subdomains",
        headers={"Authorization": api_key},
        timeout=20, strip_global_auth=True,
    )
    if not isinstance(data, dict):
        return []
    hosts = {
        f"{str(item).strip().lower()}.{domain}".strip(".")
        for item in data.get("subdomains", []) or []
        if str(item).strip()
    }
    return sorted(host for host in hosts if _host_matches_domain(host, domain))


async def hunter_domain(domain: str, api_key: str, limit: int = 50) -> dict:
    """Hunter.io domain search."""
    if not api_key:
        return {}
    query = urlencode({"domain": domain, "api_key": api_key, "limit": limit})
    data = await curl_json(
        f"https://api.hunter.io/v2/domain-search?{query}",
        timeout=20, strip_global_auth=True,
    )
    return data if isinstance(data, dict) else {}


async def ssllabs_scan(host: str, publish: bool = False, from_cache: bool = True) -> dict:
    """Qualys SSL Labs analysis status/result."""
    query = urlencode({
        "host": host,
        "publish": "on" if publish else "off",
        "fromCache": "on" if from_cache else "off",
        "all": "done",
    })
    data = await curl_json(
        f"https://api.ssllabs.com/api/v3/analyze?{query}",
        timeout=30, strip_global_auth=True,
    )
    return data if isinstance(data, dict) else {}


async def securitytrails_subdomains(domain: str, api_key: str) -> list:
    """SecurityTrails subdomain source."""
    if not api_key:
        return []
    data = await curl_json(
        f"https://api.securitytrails.com/v1/domain/{quote(domain)}/subdomains",
        headers={"APIKEY": api_key, "Accept": "application/json"},
        timeout=20, strip_global_auth=True,
    )
    if not isinstance(data, dict):
        return []
    hosts = {
        f"{str(item).strip().lower()}.{domain}".strip(".")
        for item in data.get("subdomains", []) or []
        if str(item).strip()
    }
    return sorted(host for host in hosts if _host_matches_domain(host, domain))


async def securitytrails_history_dns(domain: str, api_key: str, record_type: str = "A") -> dict:
    """SecurityTrails historical DNS records."""
    if not api_key:
        return {}
    data = await curl_json(
        f"https://api.securitytrails.com/v1/history/{quote(domain)}/dns/{quote(record_type)}",
        headers={"APIKEY": api_key, "Accept": "application/json"},
        timeout=20, strip_global_auth=True,
    )
    return data if isinstance(data, dict) else {}


async def vulners_search(query_text: str, api_key: str = "", limit: int = 20) -> dict:
    """Vulners search API."""
    payload = {"query": query_text, "size": limit}
    if api_key:
        payload["apiKey"] = api_key
    data = await curl_json(
        "https://vulners.com/api/v3/search/lucene/",
        method="POST",
        headers={"Content-Type": "application/json"},
        data=json.dumps(payload),
        timeout=20, strip_global_auth=True,
    )
    return data if isinstance(data, dict) else {}


async def nmap_scan(target: str, ports: str = "--top-ports 1000",
                    version_detect: bool = False,
                    scripts: str = "") -> dict:
    """Run nmap scan. HIGH detectability."""
    # ports/scripts legitimately contain nmap flags (the default ports IS
    # a flag), so quoting would break them: validate the alphabet
    # instead and fail closed on metacharacters.
    for value, label in ((ports, "ports"), (scripts, "scripts")):
        if re.search(r"[^\w\s,./-]", str(value or "")):
            raise ValueError(f"nmap {label} contains shell metacharacters")
    if _missing("nmap"):
        return {"hosts": [], "raw": "", "error": "missing: nmap"}
    flags = "-sV" if version_detect else ""
    script_flag = f"--script={scripts}" if scripts else ""
    result = await bash(
        f"nmap {flags} {script_flag} {ports} "
        f"{shlex.quote(str(target))} 2>/dev/null",
        timeout=600
    )
    return parse_nmap_output(result["stdout"])


def parse_nmap_output(text: str) -> dict:
    """Parse nmap output into structured data."""
    result = {
        "hosts": [],
        "raw": text[:10000],
    }
    current_host = {}
    for line in text.split("\n"):
        host_match = re.match(r"Nmap scan report for (.+)", line)
        if host_match:
            if current_host.get("hostname") or current_host.get("ports"):
                result["hosts"].append(current_host)
            current_host = {"hostname": host_match.group(1), "ports": []}
        port_match = re.match(r"(\d+)/tcp\s+(\w+)\s+(\S+)\s*(.*)", line)
        if port_match and current_host:
            current_host["ports"].append({
                "port": int(port_match.group(1)),
                "state": port_match.group(2),
                "service": port_match.group(3),
                "version": port_match.group(4).strip(),
            })
    if current_host.get("hostname") or current_host.get("ports"):
        result["hosts"].append(current_host)
    return result


async def cert_info(host: str, port: int = 443) -> dict:
    """Get TLS certificate info via openssl."""
    if _missing("openssl"):
        return {"san": [], "error": "missing: openssl"}
    endpoint = f"{shlex.quote(str(host or ''))}:{int(port or 443)}"
    server = shlex.quote(str(host or ""))
    result = await bash(
        f"echo | openssl s_client -connect {endpoint} -servername {server} 2>/dev/null "
        f"| openssl x509 -noout -subject -dates -issuer -serial -fingerprint -ext subjectAltName 2>/dev/null"
    )
    info = {}
    for line in result["stdout"].split("\n"):
        if "=" in line:
            key, _, val = line.partition("=")
            info[key.strip().lower()] = val.strip()
    # Also get SANs
    san_result = await bash(
        f"echo | openssl s_client -connect {endpoint} -servername {server} 2>/dev/null "
        f"| openssl x509 -noout -ext subjectAltName 2>/dev/null"
    )
    sans = re.findall(r"DNS:([\w.*-]+)", san_result["stdout"])
    info["san"] = sans
    return info


async def tls_protocols(host: str, port: int = 443) -> dict:
    """Check supported TLS protocols and detect weak ones."""
    if _missing("openssl"):
        return {"error": "missing: openssl"}
    protocols = {}
    endpoint = f"{shlex.quote(str(host or ''))}:{int(port or 443)}"
    server = shlex.quote(str(host or ""))
    for proto in ["ssl2", "ssl3", "tls1", "tls1_1", "tls1_2", "tls1_3"]:
        result = await bash(
            f"echo | timeout 5 openssl s_client -{proto} -connect {endpoint} "
            f"-servername {server} 2>&1 | head -3"
        )
        out = result["stdout"].lower()
        if "handshake failure" in out or "unknown option" in out or "no protocols" in out:
            protocols[proto] = False
        elif "connected" in out or "verify return" in out:
            protocols[proto] = True
        else:
            protocols[proto] = None
    return protocols


async def wayback_cdx(domain: str, limit: int = 5000,
                       output_fields: str = "timestamp,original,statuscode,mimetype") -> list:
    """Query Wayback Machine CDX API for historical URLs."""
    result = await bash(
        f"curl -s 'https://web.archive.org/cdx/search/cdx?url={shlex.quote(str(domain or ''))}/*"
        f"&output=json&limit={int(limit)}&fl={shlex.quote(str(output_fields))}&collapse=urlkey' "
        f"--max-time 45"
    )
    try:
        data = json.loads(result["stdout"])
        if isinstance(data, list) and len(data) > 1:
            fields = output_fields.split(",")
            return [dict(zip(fields, row)) for row in data[1:]]
    except (json.JSONDecodeError, IndexError, TypeError):
        pass
    return []


async def ssl_scan(host: str, port: int = 443) -> dict:
    """TLS configuration check using openssl and testssl.sh if available."""
    import shutil
    cert = await cert_info(host, port)
    protocols = await tls_protocols(host, port)

    result = {"host": host, "port": port, "certificate": cert, "protocols": protocols}

    if _tool_available("testssl.sh"):
        ts = await bash(
            f"testssl.sh --quiet --color 0 --jsonfile /dev/stdout "
            f"{shlex.quote(str(host or ''))}:{int(port or 443)} 2>/dev/null",
            timeout=120
        )
        try:
            result["testssl"] = json.loads(ts["stdout"])
        except json.JSONDecodeError:
            result["testssl_raw"] = ts["stdout"][:5000]

    return result


async def check_host(host: str, port: int = 443) -> dict:
    """Check if host is alive on given port."""
    result = await curl(
        f"https://{host}:{port}" if port == 443 else f"http://{host}:{port}"
    )
    return {
        "host": host,
        "port": port,
        "alive": result.get("status", 0) not in (0,),
        "status": result.get("status", 0),
    }


async def httpx_probe(targets: list, timeout: int = 10) -> list:
    """Probe targets with httpx for HTTP service fingerprinting."""
    import shutil
    if not _tool_available("httpx"):
        return []
    # Quote the whole block as one shell word: newlines survive inside
    # quotes, while a ' in a target can no longer break out of echo.
    targets_str = "\n".join(str(t) for t in targets)
    result = await bash(
        f"echo {shlex.quote(targets_str)} | httpx -silent -status-code -title -tech-detect "
        f"-json -timeout {int(timeout)} 2>/dev/null",
        timeout=120
    )
    probed = []
    for line in result["stdout"].strip().split("\n"):
        if not line.strip():
            continue
        try:
            probed.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return probed


async def gau_urls(domain: str, timeout: int = 60) -> list:
    """Get All URLs via gau (GetAllUrls) — scrapes Wayback, OTX, CommonCrawl."""
    import shutil
    if not _tool_available("gau"):
        return []
    result = await bash(
        f"gau --subs {shlex.quote(str(domain or ''))} --threads 5 --timeout 30 2>/dev/null",
        timeout=timeout
    )
    return [u.strip() for u in result["stdout"].split("\n") if u.strip()]


async def subfinder_scan(domain: str, timeout: int = 60) -> list:
    """Run subfinder passive subdomain enumeration."""
    import shutil
    if not _tool_available("subfinder"):
        return []
    result = await bash(
        f"subfinder -d {shlex.quote(str(domain or ''))} -silent -all 2>/dev/null",
        timeout=timeout
    )
    return [s.strip() for s in result["stdout"].split("\n")
            if s.strip() and "." in s]


async def amass_passive(domain: str, timeout: int = 120) -> list:
    """Run amass passive subdomain enumeration."""
    import shutil
    if not _tool_available("amass"):
        return []
    result = await bash(
        f"amass enum -passive -d {shlex.quote(str(domain or ''))} -nocolor 2>/dev/null",
        timeout=timeout
    )
    return [s.strip() for s in result["stdout"].split("\n")
            if s.strip() and domain in s]


async def dnsx_resolve(hostnames: list, timeout: int = 60) -> dict:
    """Bulk DNS resolution via dnsx — faster than dig for large lists."""
    import shutil
    if not _tool_available("dnsx"):
        return {}
    input_str = "\n".join(str(h) for h in hostnames)
    result = await bash(
        f"echo {shlex.quote(input_str)} | dnsx -silent -a -resp -json 2>/dev/null",
        timeout=timeout
    )
    resolved = {}
    for line in result["stdout"].strip().split("\n"):
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            host = data.get("host", "")
            ips = data.get("a", [])
            if host and ips:
                resolved[host] = ips
        except json.JSONDecodeError:
            pass
    return resolved


async def trufflehog_scan(target: str, timeout: int = 120) -> list:
    """Run trufflehog for secret scanning against a URL or filesystem path."""
    import shutil
    if not _tool_available("trufflehog"):
        return []
    quoted = shlex.quote(str(target or ""))
    result = await bash(
        f"trufflehog git --repo={quoted} --json --no-update 2>/dev/null || "
        f"trufflehog filesystem {quoted} --json 2>/dev/null",
        timeout=timeout
    )
    findings = []
    for line in result["stdout"].strip().split("\n"):
        if not line.strip():
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return findings


async def shodan_host(ip: str, api_key: str) -> dict:
    """Query Shodan host info API (engine call: the key skips ps)."""
    if not api_key:
        return {}
    data = await curl_json(
        f"https://api.shodan.io/shodan/host/{quote(str(ip or ''))}?key={quote(str(api_key))}",
        timeout=10, strip_global_auth=True,
    )
    return data if isinstance(data, dict) else {}


async def asn_lookup(ip: str) -> dict:
    """Look up ASN info for an IP using multiple sources."""
    # Primary: ipinfo.io (no key needed for basic)
    result = await bash(
        f"curl -s 'https://ipinfo.io/{shlex.quote(str(ip or ''))}/json' --max-time 10 2>/dev/null || true"
    )
    try:
        data = json.loads(result["stdout"])
        return {
            "ip": ip,
            "asn": data.get("org", "").split(" ")[0],
            "org": " ".join(data.get("org", "").split(" ")[1:]),
            "country": data.get("country", ""),
            "city": data.get("city", ""),
            "hostname": data.get("hostname", ""),
            "raw": data,
        }
    except (json.JSONDecodeError, TypeError):
        pass
    # Fallback: whois radb
    result2 = await bash(f"whois -h whois.radb.net {shlex.quote(str(ip or ''))} 2>/dev/null | grep -i origin")
    asn = ""
    for line in result2["stdout"].split("\n"):
        if "origin" in line.lower():
            asn = line.split(":")[-1].strip()
            break
    return {"ip": ip, "asn": asn}
