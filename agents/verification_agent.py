"""Verification Agent — drives the deterministic oracle to confirm PoCs."""

from __future__ import annotations

from urllib.parse import urlparse, parse_qs

from agents.base_agent import BaseAgent
from agents.blackboard import AgentRole, Hypothesis
from core.verification_oracle import (
    VerificationOracle, DifferentialAnalyzer, TimingOracle,
    ReproducibilityChecker, InteractshClient,
    Confidence, Verdict,
    _inject_param,
)


class VerificationAgent(BaseAgent):
    role = AgentRole.VERIFICATION

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.oracle = VerificationOracle()

    def _extract_target_url(self, hypothesis: Hypothesis) -> tuple[str, str]:
        """Extract (url_with_params, param_name) from hypothesis or config."""
        params = hypothesis.params or {}
        url = params.get("url", "") or hypothesis.target or ""
        param = params.get("param", "")

        # If no param in hypothesis params, parse from target URL
        if not param and url and "?" in url:
            parsed = urlparse(url)
            qs_params = parse_qs(parsed.query)
            if qs_params:
                param = list(qs_params.keys())[0]
                base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                # Rebuild URL with a param placeholder for the oracle
                url = _inject_param(url, param, "test")

        # Fallback: use raw_url from config
        if not url:
            url = self.config.get("target", {}).get("raw_url", "")
            if url and "?" in url:
                parsed = urlparse(url)
                qs_params = parse_qs(parsed.query)
                if qs_params:
                    param = list(qs_params.keys())[0]
                    url = _inject_param(url, param, "test")

        return url, param

    async def verify_finding(self, hypothesis: Hypothesis) -> dict:
        """Re-run a hypothesis through a registered, risk-classified action.

        Verification used to call oracle HTTP methods directly, bypassing the
        action registry's risk ceiling, concurrency limit, timeout and audit
        event. A repeated successful action is the reproducibility signal that
        promotes a testing hypothesis to confirmed.
        """
        self.log(f"Verifying: {hypothesis.title}")

        technique = hypothesis.technique.lower()
        url, param = self._extract_target_url(hypothesis)
        from actions import ActionRegistry

        action_id = hypothesis.action_id
        if not action_id or action_id == "manual_review" \
                or ActionRegistry.get(action_id) is None:
            if "sqli" in technique:
                action_id = "web.sqli.detect"
            elif "xss" in technique:
                action_id = "web.xss.reflected"
            elif "ssrf" in technique:
                action_id = "web.ssrf.oob_detect"
            else:
                action_id = "verify.composite_oracle"

        params = dict(hypothesis.params or {})
        params.setdefault("url", url)
        if param:
            params.setdefault("param", param)
        if action_id == "verify.composite_oracle":
            params = {"url": url, **{
                key: value for key, value in params.items()
                if key in ("baseline_url", "method")
            }}

        result = await self.execute_action(action_id, params, url)
        if result.get("blocked"):
            hypothesis.status = "testing"
            return {"status": "BLOCKED", **result}

        if result.get("success"):
            # A FIRM differential is a strong lead, not proof: only a
            # CONFIRMED result earns the status, and only then does the
            # finding on record become verified. The old code promoted any
            # success — including verify.composite_oracle's FIRM — to
            # "confirmed" and left the finding itself unverified.
            confidence = str(result.get("confidence") or "").upper()
            if confidence == "CONFIRMED":
                hypothesis.status = "confirmed"
                self._persist_confirmation(hypothesis, action_id, url, param,
                                           result)
                status = "CONFIRMED"
            else:
                hypothesis.status = "testing"
                status = confidence or "FIRM"
            self.bb.send(self.role, AgentRole.SUPERVISOR,
                         "verification_result", payload={
                             "hypothesis_id": hypothesis.id,
                             "status": status,
                             "confidence": confidence,
                             "action_id": action_id,
                             "evidence": result.get("evidence", {}),
                         })
            return {"status": status, **result}

        error = str(result.get("error", ""))
        transient = any(term in error.lower()
                        for term in ("timeout", "connection", "temporar"))
        hypothesis.status = "testing" if transient else "rejected"
        return {"status": "INCONCLUSIVE" if transient else "REJECTED",
                **result}

    def _persist_confirmation(self, hypothesis: Hypothesis, action_id: str,
                              url: str, param: str, result: dict) -> bool:
        """Write successful verification back to the finding it confirms.

        Exploitation files the finding; verification is the second, stronger
        observation. Without this, the console and blackboard said
        "CONFIRMED" while the report, SARIF, and every export still carried
        the unverified pre-confirmation claim.
        """
        finding_id = hypothesis.finding_id
        if not finding_id:
            wanted = f"exploitable: {hypothesis.title}".strip().lower()
            for finding in self.state.findings.get("findings", []):
                if str(finding.get("title", "")).strip().lower() == wanted:
                    finding_id = str(finding.get("id", ""))
                    break
        if not finding_id:
            return False
        verification = {
            "method": action_id,
            "action_id": action_id,
            "url": url,
            "param": param,
            "raw_evidence": result.get("evidence", {}),
        }
        ok = self.state.confirm_finding(
            finding_id, confidence="CONFIRMED",
            verification=verification,
            evidence=[f"Confirmed by re-running {action_id} against {url}"],
        )
        if ok:
            hypothesis.finding_id = finding_id
        return ok

    async def _verify_sqli(self, url: str, param: str,
                           hypothesis: Hypothesis) -> dict:
        # Try differential first
        payload = "' OR '1'='1"
        test_url = _inject_param(url, param, payload)
        base_url = _inject_param(url, param, "1")

        base = await self.oracle.differential.baseline(base_url)
        test = await self.oracle.differential.test(test_url)
        verdict = self.oracle.differential.compare(base, test)

        if verdict.confidence.value in ("FIRM", "CONFIRMED"):
            # Reproducibility check
            repro = await self.oracle.reproducibility.check(
                lambda: self.oracle.differential.test(test_url)
            )
            final_conf = "CONFIRMED" if repro.confidence.value == "CONFIRMED" else "FIRM"

            self.bb.send(self.role, AgentRole.SUPERVISOR,
                         "verification_result", payload={
                "hypothesis_id": hypothesis.id,
                "status": final_conf,
                "evidence": {**verdict.evidence, **repro.evidence},
            })

            hypothesis.status = "confirmed" if final_conf == "CONFIRMED" else "testing"
            return {"status": final_conf, "verdict": verdict, "repro": repro, "success": final_conf == "CONFIRMED"}

        hypothesis.status = "rejected"
        return {"status": "rejected", "verdict": verdict, "success": False}

    async def _verify_xss(self, url: str, param: str,
                          hypothesis: Hypothesis) -> dict:
        payload = "<script>alert(1)</script>"
        verdict = await self.oracle.verify_xss(url, param, payload)

        if verdict.confidence.value == "CONFIRMED":
            hypothesis.status = "confirmed"
        else:
            hypothesis.status = "rejected"

        return {"status": verdict.confidence.value, "verdict": verdict,
                "success": verdict.confidence.value == "CONFIRMED"}

    async def _verify_ssrf(self, url: str, param: str,
                           hypothesis: Hypothesis) -> dict:
        interactsh = InteractshClient()
        corr_id = await interactsh.register_callback(f"verify-{hypothesis.id}")
        oob_url = interactsh.callback_url(corr_id, "/verify")
        if not interactsh.enabled or not corr_id or "oob.invalid" in oob_url:
            hypothesis.status = "rejected"
            return {"status": "rejected",
                    "verdict": None, "success": False,
                    "reason": "OOB not configured; blind SSRF untestable "
                              "without a callback channel"}

        test_url = _inject_param(url, param, oob_url)
        await __import__("tools.wrappers", fromlist=["curl"]).curl(test_url)

        verdict = await interactsh.verify(f"verify-{hypothesis.id}", poll=True)

        if verdict.confidence.value == "CONFIRMED":
            hypothesis.status = "confirmed"
        else:
            hypothesis.status = "rejected"

        return {"status": verdict.confidence.value, "verdict": verdict,
                "success": verdict.confidence.value == "CONFIRMED"}

    async def _verify_generic(self, url: str,
                              hypothesis: Hypothesis) -> dict:
        """Composite verification for general findings."""
        base = await self.oracle.differential.baseline(url)
        test = await self.oracle.differential.test(url)
        diff_v = self.oracle.differential.compare(base, test)

        repro_v = await self.oracle.reproducibility.check(
            lambda: self.oracle.differential.test(url)
        )

        if repro_v.confidence == Confidence.CONFIRMED:
            hypothesis.status = "confirmed"
            return {"status": "CONFIRMED", "differential": diff_v, "repro": repro_v, "success": True}
        elif diff_v.confidence in (Confidence.FIRM, Confidence.CONFIRMED):
            hypothesis.status = "testing"
            return {"status": "FIRM", "differential": diff_v, "success": True}
        else:
            hypothesis.status = "rejected"
            return {"status": "REJECTED", "differential": diff_v, "success": False}
