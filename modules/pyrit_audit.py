"""Stage 5: optional PyRIT AI red-team audit (I8).

PyRIT is an operator-supplied, isolated tool. This module never imports it;
it drives the adapter in ``tools/pyrit_adapter.py``, which runs a configured
interpreter or operator runner in a private temp directory and returns a
capped JSON report.

Grading:

- unsupported — PyRIT is missing, too old, or exposes an unrecognized API.
                 The module skips with the reason; it never pretends a
                 tool ran.
- observation — a bounded attack pass completed with no signal, or the
                 runner returned an error.
- candidate   — a judge score or prompt-compliance marker. Judge output is
                 never proof.
- proof       — a configured private canary appears in an assistant reply
                 or a tool-call argument. This is the only path that files a
                 verified finding.

The pass is read-only: configured prompts are sent to the target and no
target object is created, so no mutation-ledger rows are required. Reports
store provenance, per-attack hashes and counts — never transcripts or
credentials.
"""

from __future__ import annotations

import hashlib
import json
import time
from urllib.parse import urlparse

from agents import LOCAL_PROVIDERS
from core import secrets as secretrefs
from core.untrusted import instruction_hits
from modules.base import BaseModule
from tools import pyrit_adapter as pyrit


class PyritAudit(BaseModule):
    id = "pyrit_audit"
    name = "PyRIT AI Red-Team Audit"
    stage = 5
    detectability = "medium"
    depends_on = []
    active = False

    async def run(self) -> str:
        cfg = self._cfg()
        if not cfg.get("enabled"):
            self.state.skip_module(
                self.id,
                "disabled — it sends configured attack prompts to an AI "
                "target; set modules.pyrit_audit.enabled: true to run")
            return "skipped"

        runner_cfg = cfg.get("runner") or {}
        command = [str(part) for part in (runner_cfg.get("command") or [])
                   if str(part)]
        python = ""
        raw_python = str(runner_cfg.get("python") or "")
        if raw_python:
            try:
                python = secretrefs.resolve(raw_python) \
                    if secretrefs.is_reference(raw_python) else raw_python
            except secretrefs.SecretError as exc:
                self.state.skip_module(
                    self.id, f"PyRIT interpreter reference unresolved — {exc}")
                return "skipped"
        if not python and not command:
            self.state.skip_module(
                self.id,
                "PyRIT runner not configured (tools.pyrit.python or "
                "runner.command)")
            return "skipped"

        attacks = self._attacks(cfg)
        if not attacks:
            self.state.skip_module(self.id, "no PyRIT attacks configured")
            return "skipped"

        target = cfg.get("target") or {}
        endpoint = str(target.get("endpoint") or "")
        if not endpoint:
            self.state.skip_module(self.id, "no PyRIT target endpoint")
            return "skipped"
        provider = self._provider(cfg, target)
        mode = str(((self.config.get("llm") or {}).get("data_policy") or {})
                   .get("mode") or "standard").lower()
        if mode == "local_only" and provider \
                and provider not in LOCAL_PROVIDERS:
            self.state.skip_module(
                self.id,
                f"llm.data_policy.mode=local_only forbids PyRIT provider "
                f"{provider!r}")
            return "skipped"

        if command:
            probe = {"available": True, "unsupported": False,
                     "version": "operator", "reason": ""}
        else:
            probe = pyrit.detect(
                python, min_version=str(runner_cfg.get("min_version") or ""))
        if not probe.get("available"):
            self.state.skip_module(
                self.id, f"PyRIT unavailable — {probe.get('reason')}")
            return "skipped"

        canaries = [str(value) for value in (cfg.get("canaries") or [])
                    if str(value)]
        spec = {
            "target": {key: target.get(key) for key in
                       ("endpoint", "model", "provider", "api_version")
                       if target.get(key)},
            "attacks": attacks,
            "max_prompts": int(cfg.get("max_prompts", 12) or 12),
            "max_turns": int(cfg.get("max_turns", 6) or 6),
            "api_key_ref": str(target.get("api_key_ref") or ""),
        }
        try:
            timeout = max(10, int(cfg.get("timeout", 240) or 240))
        except (TypeError, ValueError):
            timeout = 240
        result = await pyrit.run(
            spec, python_path=python, timeout=timeout,
            min_version=str(runner_cfg.get("min_version") or ""),
            runner_command=command)
        if result.unsupported:
            self.state.skip_module(
                self.id, f"PyRIT unsupported — {result.error}")
            return "skipped"

        try:
            threshold = float(cfg.get("score_threshold", 0.7) or 0.7)
        except (TypeError, ValueError):
            threshold = 0.7
        classified = pyrit.classify(result, canaries,
                                    score_threshold=threshold)
        run_token = f"pr{hashlib.sha256(str(time.time()).encode()).hexdigest()[:6]}"
        report = {
            "schema_version": 1,
            "run_token": run_token,
            "target": {"endpoint": endpoint,
                       "model": str(target.get("model") or ""),
                       "provider": provider},
            "provenance": result.provenance.as_dict(),
            "state": classified.get("state") or "error",
            "error": result.error,
            "exit_code": result.exit_code,
            "canaries_configured": len(canaries),
            "hostile_hits": sum(
                instruction_hits(attack.assistant_text())
                + instruction_hits(json.dumps(attack.tool_calls, default=str))
                for attack in result.attacks),
            "usage": result.usage,
            "attacks": self._attack_summaries(result, classified),
        }
        evidence = self.state.add_evidence(
            self.id, "pyrit_report", endpoint, report)
        state = classified.get("state")
        if state == "proof":
            self._file_proof(classified, endpoint, provider, evidence)
        elif state == "candidate":
            self._file_candidate(classified, endpoint, provider)
        self.state.add_asset(
            "pyrit_scan", f"pyrit_scan:{self.domain}", self.domain,
            confidence="FIRM", sources=[self.id],
            attrs={"target": endpoint, "provider": provider,
                   "attacks": len(attacks), "state": state,
                   "canaries": len(canaries),
                   "hostile_hits": report["hostile_hits"]})
        self.state.complete_module(self.id)
        self.log(f"PyRIT audit: {len(attacks)} attack(s), state={state}")
        return "done"

    # ── Configuration ────────────────────────────────────────────

    def _attacks(self, cfg: dict) -> list[dict]:
        try:
            max_attacks = max(1, int(cfg.get("max_attacks", 3) or 3))
            max_prompts = max(1, int(cfg.get("max_prompts", 12) or 12))
        except (TypeError, ValueError):
            max_attacks, max_prompts = 3, 12
        attacks = []
        for entry in (cfg.get("attacks") or [])[:max_attacks]:
            if not isinstance(entry, dict):
                continue
            prompts = [str(prompt) for prompt in (entry.get("prompts") or [])
                       if str(prompt)][:max_prompts]
            if not prompts:
                continue
            attacks.append({
                "name": str(entry.get("name") or f"attack-{len(attacks) + 1}"),
                "strategy": str(entry.get("strategy") or "prompt_sending"),
                "prompts": prompts,
            })
        return attacks

    def _provider(self, cfg: dict, target: dict) -> str:
        provider = str(target.get("provider") or cfg.get("provider") or "")
        if not provider and target.get("model"):
            provider = str(target["model"]).split("/")[0]
        return provider.strip().lower()

    # ── Findings ─────────────────────────────────────────────────

    def _fingerprint(self, endpoint: str, attack: str) -> str:
        host = urlparse(endpoint).hostname or ""
        raw = json.dumps({"module": self.id, "host": host,
                          "endpoint": endpoint, "attack": attack},
                         sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _file_proof(self, classified: dict, endpoint: str, provider: str,
                    evidence_ref: str) -> None:
        attack = str(classified.get("attack") or "attack")
        channel = str(classified.get("channel") or "assistant")
        canary = str(classified.get("canary") or "")
        excerpt = str(classified.get("excerpt") or "")
        fp = self._fingerprint(endpoint, attack)
        self.state.add_finding(
            title=f"PyRIT canary exfiltration via {attack} [{fp[:8]}]",
            severity="HIGH",
            confidence="CONFIRMED",
            category="AI Red Team",
            description=(
                "A configured PyRIT attack caused the target to reveal a "
                f"private canary in {channel.replace('_', ' ')} output. The "
                "canary was operator-seeded and unique to this run, so its "
                "appearance demonstrates impact beyond mere prompt "
                "compliance."),
            evidence=[f"target:{endpoint}", f"attack:{attack}",
                      f"provider:{provider}", f"canary:{canary}",
                      f"excerpt:{excerpt}", evidence_ref],
            asset_keys=[f"url:{endpoint}"],
            verified=True,
            verification={"method": "pyrit_canary_observed",
                          "attack": attack, "channel": channel,
                          "canary": canary},
        )

    def _file_candidate(self, classified: dict, endpoint: str,
                        provider: str) -> None:
        attacks = [item for item in (classified.get("attacks") or [])
                   if item.get("state") == "candidate"]
        names = [str(item.get("name") or "attack") for item in attacks]
        attack = names[0] if names else "attack"
        fp = self._fingerprint(endpoint, attack)
        self.state.add_finding(
            title=(f"PyRIT compliance candidate: {attack} [{fp[:8]}]"),
            severity="MEDIUM",
            confidence="FIRM",
            category="AI Red Team",
            description=(
                "A PyRIT attack produced a judge score or compliance marker "
                "on the target. This is not proof of impact: confirm with a "
                "private canary flow or a forbidden tool action before "
                "reporting. Transcripts are not stored."),
            evidence=[f"target:{endpoint}", f"provider:{provider}",
                      f"attacks:{', '.join(names[:5])}"],
            asset_keys=[f"url:{endpoint}"],
            verified=False,
            verification={"method": "pyrit_compliance_candidate"},
        )

    # ── Plumbing ─────────────────────────────────────────────────

    @staticmethod
    def _attack_summaries(result, classified: dict) -> list[dict]:
        by_name = {str(item.get("name") or ""): item
                   for item in (classified.get("attacks") or [])}
        summaries = []
        for attack in result.attacks:
            entry = by_name.get(attack.name, {})
            transcript = json.dumps(attack.transcript, sort_keys=True,
                                    default=str)
            summaries.append({
                "name": attack.name,
                "strategy": attack.strategy,
                "state": entry.get("state", "observation"),
                "turns": attack.turns,
                "tool_calls": len(attack.tool_calls),
                "compliance": bool(entry.get("compliance")),
                "high_score": bool(entry.get("high_score")),
                "error": attack.error,
                "transcript_sha256": hashlib.sha256(
                    transcript.encode("utf-8")).hexdigest()[:32],
            })
        return summaries

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}
