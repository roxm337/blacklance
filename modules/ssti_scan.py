"""Stage 5: Server-Side Template Injection — polyglot differential.

Each engine family evaluates a different expression language, so one
payload per family plus a joint polyglot, each computed to a distinct
constant. The oracle is arithmetic, not syntactic: the response must
contain the COMPUTED value (49, 49, 49...) while a control string of
the same shape stays literal. A reflection of the raw payload is
evidence of nothing — it is the evaluation that counts.
"""

from core.probe_targets import iter_probe_points
from modules.base import BaseModule
from tools.wrappers import curl


# (label, payload): every payload evaluates to 49 in its engine.
SSTI_PAYLOADS = (
    ("jinja2-twig", "{{7*7}}"),
    ("pug-jade", "#{7*7}"),
    ("freemarker-velocity", "${7*7}"),
    ("erb-slim", "<%= 7*7 %>"),
    ("tornado", "{{7*7}}"),
    ("polyglot", "{{7*7}}#{7*7}${7*7}"),
)

# Must stay literal everywhere: same digits, no engine syntax.
CONTROL_STRING = "zz74x74zz"

# Error-based ("successful errors") probes for contexts that never reflect
# the computed value — the page swallows output but still renders its own
# stack trace. Each payload names a random marker that the engine will
# quote back in its exception, which makes the signature attributable:
# "something errored" is not evidence, "the template engine errored on the
# identifier we injected" is.
ERROR_PROBES = (
    ("jinja2/tornado", "{{zz{mark}()}}",
     ("jinja2.exceptions", "UndefinedError",
      "'zz{mark}' is undefined")),
    ("twig", "{{zz{mark}()}}",
     ("Twig\\Error", "Twig_Error", "Unknown \"zz{mark}\" function",
      "Unknown \"zz{mark}\" filter")),
    ("django", "{%zz{mark}%}",
     ("Invalid block tag", "TemplateSyntaxError",
      "django.template.exceptions")),
    ("erb", "<%= zz{mark} %>",
     ("ActionView::Template::Error",
      "undefined local variable or method `zz{mark}'",
      "undefined local variable or method")),
    ("freemarker", "${zz{mark}}",
     ("FreeMarker template error", "freemarker.core",
      "InvalidReferenceException")),
    ("spring-thymeleaf", "${zz{mark}()}",
     ("SpelEvaluationException", "EL1007E", "TemplateProcessingException",
      "org.thymeleaf.exceptions")),
    ("pebble", "{{ zz{mark}() }}",
     ("PebbleException", "Pebble error", "pebble.")),
    ("smarty", "{zz{mark}}",
     ("SmartyCompilerException", "Smarty error", "Smarty_Internal")),
    ("velocity", "${zz{mark}.x}",
     ("ParseErrorException", "VelocityException", "org.apache.velocity")),
)


class SSTIScan(BaseModule):
    id = "ssti_scan"
    name = "SSTI Scan"
    stage = 5
    detectability = "medium"
    depends_on = ["parameter_discovery"]
    active = True

    async def run(self) -> str:
        points = [p for p in iter_probe_points(
            self.state, self.base_url, self.domain)
            if p.get("method", "GET") == "GET" and p["param"]]
        if not points:
            self.state.skip_module(self.id, "no parameterized URLs")
            return "skipped"

        import time as _time_guard
        try:
            _guard_deadline = float(self.config.get("module_timeout", 300) or 300)
        except (TypeError, ValueError):
            _guard_deadline = 300.0
        _stop_at = _time_guard.monotonic() + max(60.0, _guard_deadline - 30.0)
        cfg = self._cfg()
        max_points = int(cfg.get("max_points", 40) or 40)
        error_based = cfg.get("error_based", True) is not False
        error_points = int(cfg.get("error_max_points", 8) or 8)
        reported = 0
        for index, point in enumerate(points[:max_points]):
            if _time_guard.monotonic() >= _stop_at:
                break
            if await self._test_point(
                    point, error_based=error_based and index < error_points):
                reported += 1

        self.state.complete_module(self.id)
        self.log(f"SSTI: {reported} template evaluation(s) confirmed")
        return "done"

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}

    async def _fetch(self, url: str) -> dict:
        try:
            result = await curl(url, output="full", timeout=15)
        except Exception:
            return {"status": 0, "body": ""}
        return {"status": result.get("status", 0),
                "body": result.get("body", "") or ""}

    async def _test_point(self, point: dict, *, error_based: bool = True) -> bool:
        """Control stays literal, payload computes: template evaluation.

        Counts, not presence: a shop page full of prices already contains
        "49", so only MORE forty-nines than the control produced — with
        the payload literal itself absent — counts as evaluation.

        When the output is swallowed (blind), fall back to error-based
        detection: the engine's own exception names the identifier we
        injected. A reflected payload without an engine signature is
        still nothing.
        """
        from core.validators import inject_param
        url, param = point["url"], point["param"]
        control = await self._fetch(inject_param(url, param, CONTROL_STRING))
        if control["status"] not in (200, 201):
            return False
        control_body = control["body"]

        if CONTROL_STRING in control_body:
            control_count = control_body.count("49")
            for label, payload in SSTI_PAYLOADS:
                response = await self._fetch(inject_param(url, param, payload))
                if response["status"] not in (200, 201):
                    continue
                body = response["body"]
                if body.count("49") > control_count and payload not in body:
                    self.state.add_finding(
                        title=(f"Server-Side Template Injection ({label}): "
                               f"{param}"),
                        severity="HIGH",
                        confidence="CONFIRMED",
                        category="SSTI",
                        description=(
                            f"Payload `{payload}` on parameter {param} "
                            f"evaluated server-side to 49 while the control "
                            f"string stayed literal: a {label} template "
                            f"engine renders attacker input."),
                        evidence=[
                            f"URL: {url}",
                            f"Parameter: {param}",
                            f"Payload: {payload}",
                            f"Response: {body[:300]}",
                        ],
                        remediation="Never render user input as a template; "
                                    "use logic-less templates with "
                                    "autoescaping, or sandbox the engine with "
                                    "no attribute access.",
                        asset_keys=[f"url:{url}"],
                        verified=True,
                        verification={"method": "ssti_arithmetic_differential",
                                      "url": url, "param": param},
                    )
                    return True

        if not error_based:
            return False
        return await self._test_errors(url, param, control_body)

    async def _test_errors(self, url: str, param: str,
                           control_body: str) -> bool:
        """Blind oracle: the template engine's exception names our marker."""
        import secrets
        from core.validators import inject_param

        marker = f"zz{secrets.token_hex(4)}"
        for label, template, signatures in ERROR_PROBES:
            payload = template.replace("{mark}", marker)
            response = await self._fetch(inject_param(url, param, payload))
            body = response["body"]
            if not body or body == control_body:
                continue
            for signature_template in signatures:
                signature = signature_template.replace("{mark}", marker)
                if signature.lower() not in body.lower():
                    continue
                if signature.lower() in control_body.lower():
                    # The baseline already shows this error: the payload
                    # did not cause it.
                    continue
                attributed = marker in body
                self.state.add_finding(
                    title=("Server-Side Template Injection "
                           f"({label}, error-based): {param}"),
                    severity="HIGH",
                    confidence="CONFIRMED" if attributed else "FIRM",
                    category="SSTI",
                    description=(
                        f"Malformed {label} expression `{payload}` on "
                        f"parameter {param} made the server render a "
                        f"template-engine exception (`{signature}`) that the "
                        "control request did not produce"
                        + (", and the exception names the random marker we "
                           "injected — the engine parsed input we control."
                           if attributed else
                           ". The exception class is engine-specific but does "
                           "not quote the marker, so attribution is "
                           "inferred from the closed set of delimiters.")),
                    evidence=self._error_evidence(
                        url, param, payload, signature, body),
                    remediation="Never render user input as a template; use "
                                "logic-less templates with autoescaping, or "
                                "sandbox the engine with no attribute access. "
                                "Suppress template exceptions in production "
                                "responses.",
                    asset_keys=[f"url:{url}"],
                    verified=attributed,
                    verification={
                        "method": "ssti_error_signature",
                        "engine": label,
                        "signature": signature,
                        "marker_echoed": attributed,
                        "url": url,
                        "param": param,
                    },
                )
                return True
        return False

    @staticmethod
    def _error_evidence(url: str, param: str, payload: str,
                        signature: str, body: str) -> list:
        """Trim around the signature so the report shows the leak, not a page."""
        index = body.lower().find(signature.lower())
        start = max(0, index - 120)
        excerpt = body[start:start + 320]
        return [
            f"URL: {url}",
            f"Parameter: {param}",
            f"Payload: {payload}",
            f"Signature: {signature}",
            f"Response excerpt: {excerpt}",
        ]
