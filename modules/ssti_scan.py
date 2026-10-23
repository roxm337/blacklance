"""Stage 5: Server-Side Template Injection — polyglot differential.

Each engine family evaluates a different expression language, so one
payload per family plus a joint polyglot, each computed to a distinct
constant. The oracle is arithmetic, not syntactic: the response must
contain the COMPUTED value (49, 49, 49...) while a control string of
the same shape stays literal. A reflection of the raw payload is
evidence of nothing — it is the evaluation that counts.
"""

from core.probe_targets import iter_probe_points
from core.waf_evasion import (encoded_variants, is_payload_blocked,
                              payload_block_codes, raw_param_url,
                              ssti_variants)
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
        max_points = int(cfg.get("max_points", 0) or 0)
        error_based = cfg.get("error_based", True) is not False
        error_points = int(cfg.get("error_max_points", 0) or 0)
        if max_points > 0:
            points = points[:max_points]
        reported = 0
        for index, point in enumerate(points):
            if _time_guard.monotonic() >= _stop_at:
                break
            if await self._test_point(
                    point, error_based=error_based and (error_points <= 0 or index < error_points)):
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
            # Dynamic pages move their own numbers between requests. One
            # sample is not a baseline: take two and use the maximum, then
            # require both payload samples to beat it. GitHub's commits page
            # passed the old single-sample test because its price/date noise
            # happened to carry one extra "49".
            control_counts = [control_body.count("49")]
            repeat = await self._fetch(
                inject_param(url, param, CONTROL_STRING))
            if repeat["status"] in (200, 201):
                control_counts.append(repeat["body"].count("49"))
            control_count = max(control_counts)
            for label, payload in SSTI_PAYLOADS:
                response = await self._fetch(inject_param(url, param, payload))
                if (self._waf_adaptive()
                        and is_payload_blocked(response, self._block_codes())):
                    bypass = await self._bypass(
                        url, param, payload, control_count,
                        response.get("status"))
                    if bypass:
                        confirmation = await self._fetch(bypass["test_url"])
                        if self._evaluated(confirmation, control_count,
                                           payload):
                            self._file_evaluation(label, payload, url, param,
                                                  confirmation["body"], bypass)
                            return True
                    continue
                if response["status"] not in (200, 201):
                    continue
                # Two identical payload requests, both above the loudest
                # control: a single dynamic fluctuation cannot manufacture
                # the finding.
                second = await self._fetch(inject_param(url, param, payload))
                if self._evaluated(response, control_count, payload) \
                        and self._evaluated(second, control_count, payload):
                    self._file_evaluation(label, payload, url, param,
                                          second["body"])
                    return True

        if not error_based:
            return False
        return await self._test_errors(url, param, control_body)

    def _file_evaluation(self, label: str, payload: str, url: str, param: str,
                         body: str, bypass: dict | None = None) -> None:
        evidence = [
            f"URL: {url}",
            f"Parameter: {param}",
            f"Payload: {payload}",
            f"Response: {body[:300]}",
        ]
        description = (
            f"Payload `{payload}` on parameter {param} evaluated "
            f"server-side to 49 while the control string stayed literal: "
            f"a {label} template engine renders attacker input.")
        verification = {"method": "ssti_arithmetic_differential",
                        "url": url, "param": param}
        if bypass:
            evidence.append(
                f"WAF bypass: {bypass['mutation']} at {bypass['test_url']}")
            description += (
                f" The edge blocked the plain payload (HTTP "
                f"{bypass.get('blocked_status', 'block')}); the "
                f"`{bypass['mutation']}` variant reached the engine with "
                "identical semantics and produced the same computed value.")
            verification.update({"waf_bypass": bypass["mutation"],
                                 "bypass_url": bypass["test_url"]})
        self.state.add_finding(
            title=f"Server-Side Template Injection ({label}): {param}",
            severity="HIGH",
            confidence="CONFIRMED",
            category="SSTI",
            description=description,
            evidence=evidence,
            remediation="Never render user input as a template; use "
                        "logic-less templates with autoescaping, or sandbox "
                        "the engine with no attribute access.",
            asset_keys=[f"url:{url}"],
            verified=True,
            verification=verification,
        )

    async def _bypass(self, url: str, param: str, payload: str,
                      control_count: int,
                      blocked_status=None) -> dict | None:
        """Re-send a blocked probe with semantics-preserving mutations.

        A 200 alone is not a bypass: the caller's oracle (49 more than the
        control, payload absent) must fire on the mutated response.
        """
        from core.validators import inject_param

        codes = self._block_codes()
        for name, value in ssti_variants(payload):
            candidate = inject_param(url, param, value)
            result = await self._fetch(candidate)
            if is_payload_blocked(result, codes):
                continue
            if self._evaluated(result, control_count, payload):
                return {"mutation": name, "test_url": candidate,
                        "body": result["body"],
                        "blocked_status": blocked_status}
        for name, wire in encoded_variants(payload):
            candidate = raw_param_url(url, param, wire)
            result = await self._fetch(candidate)
            if is_payload_blocked(result, codes):
                continue
            if self._evaluated(result, control_count, payload):
                return {"mutation": name, "test_url": candidate,
                        "body": result["body"],
                        "blocked_status": blocked_status}
        return None

    @staticmethod
    def _evaluated(result: dict, control_count: int, payload: str) -> bool:
        if result.get("status") not in (200, 201):
            return False
        body = result.get("body", "") or ""
        return body.count("49") > control_count and payload not in body

    def _waf_adaptive(self) -> bool:
        return self._cfg().get("waf_adaptive", True) is not False

    def _block_codes(self) -> set:
        return payload_block_codes(self.config)

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
