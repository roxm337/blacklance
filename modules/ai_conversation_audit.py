"""Stage 5: AI conversation isolation audit (I8 remainder).

Multi-turn assistants and retrieval-augmented applications keep state the
HTTP layer does not authorize for you. This module tests three boundaries:

- thread read       — can one identity read another identity's thread?
- thread continue   — can one identity post into another identity's thread
                      and receive its accumulated context?
- retrieval         — can one identity retrieve another identity's private
                      document by asking a question?

Grading:

- observations — endpoint shape and hostile-response indicators. Target
                 replies are DATA, never instructions: instruction-like
                 text is counted, never stored or acted upon.
- candidates   — a configured prompt returns another identity's marker
                 with baseline/absent controls passing (values never
                 stored).
- proof        — a seeded canary is observed through the forbidden lane
                 while the owner read, absent control, list baseline and
                 verified cleanup all hold. Only our own R8-created thread
                 or document may reach PROOF.

Read-only except for the seeded thread/document, always recorded in the
mutation ledger before creation and cleaned up with a fresh verification
read. Captured response bodies are never persisted; only booleans, counts
and our own seed survive in the report.
"""

from __future__ import annotations

import hashlib
import json
import time
from urllib.parse import urlparse

from core.auth_harness import AuthHarness
from core.authorization import _identity_markers, finalize_canary_cleanup
from core.mutations import OwnedObject
from core.workflows import _extract
from modules.base import BaseModule

CANARY_MODES = ("thread", "continue", "retrieval")

HOSTILE_MARKERS = (
    "ignore previous", "ignore all previous", "ignore the above",
    "system prompt", "you must call", "exfiltrate", "send the token",
    "do not tell the user", "reveal your instructions",
)


class AIConversationAudit(BaseModule):
    id = "ai_conversation_audit"
    name = "AI Conversation Isolation Audit"
    stage = 5
    detectability = "medium"
    depends_on = []
    active = False

    async def run(self) -> str:
        cfg = self._cfg()
        if not cfg.get("enabled"):
            self.state.skip_module(
                self.id,
                "disabled — it creates threads/documents and drives prompts; "
                "set modules.ai_conversation_audit.enabled: true to run")
            return "skipped"

        canary_cfg = cfg.get("canary") or {}
        probes = cfg.get("probes") or []
        if not (canary_cfg.get("enabled") or probes):
            self.state.skip_module(
                self.id, "no conversation checks configured")
            return "skipped"

        harness = AuthHarness(self.config)
        harness.mutations = self.state.mutations
        harness.adopt_discovered(self.state, log=self.log)
        try:
            identities = await harness.establish_all(self._base_url())
        except Exception:
            identities = []

        try:
            max_seconds = max(20, int(cfg.get("max_seconds", 240) or 240))
        except (TypeError, ValueError):
            max_seconds = 240
        stop_at = time.monotonic() + max_seconds
        run_token = f"ai{hashlib.sha256(str(time.time()).encode()).hexdigest()[:6]}"

        report = {
            "schema_version": 1,
            "run_token": run_token,
            "canaries": [],
            "probes": [],
            "state_counts": {"observation": 0, "candidate": 0, "proof": 0},
            "hostile_responses": 0,
            "untested": [],
        }

        if canary_cfg.get("enabled") and identities:
            await self._run_canaries(harness, canary_cfg, identities,
                                     run_token, report, stop_at)
        elif canary_cfg.get("enabled"):
            report["untested"].append(
                {"surface": "canary", "reason": "no verified identities"})
        await self._run_probes(harness, identities, cfg, report, run_token,
                               stop_at)

        self.state.add_evidence(self.id, "ai_conversation_report",
                                self._base_url(), report)
        counts = report["state_counts"]
        self.state.add_asset(
            "ai_conversation_scan", f"ai_conversation_scan:{self.domain}",
            self.domain, confidence="FIRM", sources=[self.id],
            attrs={"candidates": counts["candidate"],
                   "proofs": counts["proof"],
                   "hostile_responses": report["hostile_responses"],
                   "untested": len(report["untested"])})
        self.state.complete_module(self.id)
        self.log(f"AI conversation audit: {counts['candidate']} candidate(s), "
                 f"{counts['proof']} proven")
        return "done"

    # ── Canary protocol (the only PROOF path) ────────────────────

    async def _run_canaries(self, harness, canary_cfg, identities,
                            run_token, report, stop_at) -> None:
        owner_name = str(canary_cfg.get("owner_identity") or "")
        forbidden_name = str(canary_cfg.get("forbidden_identity") or "")
        if owner_name not in harness.identities:
            report["untested"].append(
                {"surface": "canary", "reason": f"owner {owner_name!r} unknown"})
            return
        try:
            max_canaries = max(0, int(canary_cfg.get("max", 3) or 3))
        except (TypeError, ValueError):
            max_canaries = 3
        specs = [p for p in (canary_cfg.get("probes") or [])
                 if isinstance(p, dict)][:max_canaries]
        for spec in specs:
            if time.monotonic() >= stop_at or self.should_stop(reserve=25):
                report["untested"].append(
                    {"surface": "canary", "reason": "time budget"})
                break
            outcome = await self._canary_once(
                harness, canary_cfg, spec, owner_name, forbidden_name,
                run_token)
            report["hostile_responses"] += outcome.pop("hostile_hits", 0)
            if outcome.get("proven"):
                report["state_counts"]["proof"] += 1
            else:
                report["state_counts"]["observation"] += 1
            report["canaries"].append(outcome)

    async def _canary_once(self, harness, canary_cfg, spec, owner_name,
                           forbidden_name, seed) -> dict:
        mode = str(spec.get("mode") or "thread").strip().lower()
        name = str(spec.get("name") or mode)
        result = {"name": name, "mode": mode, "proven": False, "hostile_hits": 0}
        if mode not in CANARY_MODES:
            result["error"] = f"unknown mode {mode!r}"
            return result
        if owner_name not in harness.identities \
                or forbidden_name not in harness.identities \
                or forbidden_name == owner_name:
            result["error"] = "owner/forbidden identity unusable"
            return result
        if mode == "retrieval":
            return await self._retrieval_once(
                harness, canary_cfg, spec, owner_name, forbidden_name, seed,
                result)
        return await self._thread_once(
            harness, canary_cfg, spec, owner_name, forbidden_name, seed,
            result)

    async def _thread_once(self, harness, canary_cfg, spec, owner_name,
                           forbidden_name, seed, result) -> dict:
        thread = canary_cfg.get("thread") or {}
        create = thread.get("create") or {}
        post = thread.get("post") or {}
        read = thread.get("read") or {}
        if not create.get("url_template") or not post.get("url_template") \
                or not read.get("url_template"):
            result["error"] = "thread create/post/read specs missing"
            return result
        mut_id = self.state.mutations.begin(
            self.id, "object_create",
            {"url": self._abs(create.get("url_template")),
             "method": create.get("method", "POST"),
             "object": "thread"},
            identity=owner_name,
            owned_objects=[OwnedObject(type="thread", identifier="")])
        result["mut_id"] = mut_id
        created = await self._fetch_with_body(
            harness, owner_name, self._abs(create.get("url_template")),
            str(create.get("method") or "POST"),
            self._fmt(create.get("body_template") or "{}", "", seed))
        ref = _extract(create.get("extract_id") or {},
                       str(created.get("body") or ""))
        if not ref:
            self.state.mutations.mark_failed(
                mut_id, "thread create produced no bindable id")
            result["error"] = "thread create produced no bindable id"
            return result
        result["ref_bound"] = True
        posted = await self._fetch_with_body(
            harness, owner_name,
            self._abs(str(post.get("url_template")).replace("{id}", str(ref))),
            str(post.get("method") or "POST"),
            self._fmt(post.get("body_template") or '{"text":"{run}"}', ref,
                      seed))
        result["hostile_hits"] += _hostile_hits(str(posted.get("body") or ""))
        owner_read = await self._fetch(
            harness, owner_name,
            self._abs(str(read.get("url_template")).replace("{id}", str(ref))))
        owner_body = str(owner_read.get("body") or "")
        result["hostile_hits"] += _hostile_hits(owner_body)
        owner_seed = _contains(owner_body, seed)
        result["owner_seed"] = owner_seed

        list_spec = thread.get("list") or {}
        baseline_seed = False
        if list_spec.get("url_template"):
            listed = await self._fetch(
                harness, forbidden_name,
                self._abs(list_spec.get("url_template")))
            result["hostile_hits"] += _hostile_hits(
                str(listed.get("body") or ""))
            baseline_seed = _contains(str(listed.get("body") or ""), seed)
        result["baseline_seed"] = baseline_seed

        absent_uri = self._abs(
            str(read.get("url_template")).replace(
                "{id}", self._absent_ref(ref)))
        absent = await self._fetch(harness, forbidden_name, absent_uri)
        result["hostile_hits"] += _hostile_hits(
            str(absent.get("body") or ""))
        absent_seed = _contains(str(absent.get("body") or ""), seed)
        result["absent_seed"] = absent_seed

        observed_seed = False
        if result.get("mode") == "continue":
            continue_spec = thread.get("continue") or post
            sent = await self._fetch_with_body(
                harness, forbidden_name,
                self._abs(str(continue_spec.get("url_template") or "")
                          .replace("{id}", str(ref))),
                str(continue_spec.get("method") or "POST"),
                self._fmt(continue_spec.get("body_template")
                          or '{"text":"continue"}', ref, seed))
            reply_body = str(sent.get("body") or "")
            result["hostile_hits"] += _hostile_hits(reply_body)
            observed_seed = _contains(reply_body, seed)
        forbidden_read = await self._fetch(
            harness, forbidden_name,
            self._abs(str(read.get("url_template")).replace("{id}", str(ref))))
        forbidden_body = str(forbidden_read.get("body") or "")
        result["hostile_hits"] += _hostile_hits(forbidden_body)
        observed_seed = observed_seed or _contains(forbidden_body, seed)
        result["observed_seed"] = observed_seed

        owner_reread = await self._fetch(
            harness, owner_name,
            self._abs(str(read.get("url_template")).replace("{id}", str(ref))))
        result["hostile_hits"] += _hostile_hits(
            str(owner_reread.get("body") or ""))
        intact_after = owner_seed and _contains(
            str(owner_reread.get("body") or ""), seed)
        result["seed_intact"] = intact_after

        cleanup_status = await finalize_canary_cleanup(
            self.state,
            lambda identity, url, method="GET":
                self._fetch(harness, identity, url, method=method),
            self._base_url(), mut_id, str(ref), thread.get("cleanup") or {},
            owner_name)
        result["cleanup_status"] = cleanup_status
        proven = bool(observed_seed and intact_after and not absent_seed
                      and not baseline_seed
                      and cleanup_status == "verified")
        if not proven and not result.get("reason"):
            result["reason"] = "controls or cleanup not satisfied"
        result["proven"] = proven
        if proven:
            evidence = self.state.add_evidence(
                self.id, f"ai_{result['mode']}_canary", self._base_url(),
                {"name": result["name"], "mut_id": mut_id,
                 "cleanup_status": cleanup_status})
            self._file_proof(result["mode"], result["name"], evidence)
        return result

    async def _retrieval_once(self, harness, canary_cfg, spec, owner_name,
                              forbidden_name, seed, result) -> dict:
        retrieval = canary_cfg.get("retrieval") or {}
        create = retrieval.get("create") or {}
        ask = retrieval.get("ask") or {}
        if not create.get("url_template") or not ask.get("url_template"):
            result["error"] = "retrieval create/ask specs missing"
            return result
        mut_id = self.state.mutations.begin(
            self.id, "object_create",
            {"url": self._abs(create.get("url_template")),
             "method": create.get("method", "POST"),
             "object": "document"},
            identity=owner_name,
            owned_objects=[OwnedObject(type="document", identifier="")])
        result["mut_id"] = mut_id
        created = await self._fetch_with_body(
            harness, owner_name, self._abs(create.get("url_template")),
            str(create.get("method") or "POST"),
            self._fmt(create.get("body_template") or '{"text":"{run}"}', "",
                      seed))
        ref = _extract(create.get("extract_id") or {},
                       str(created.get("body") or ""))
        if not ref:
            self.state.mutations.mark_failed(
                mut_id, "document create produced no bindable id")
            result["error"] = "document create produced no bindable id"
            return result
        result["ref_bound"] = True

        owner_answer = await self._ask(harness, owner_name, ask, seed, seed)
        owner_body = str(owner_answer.get("body") or "")
        result["hostile_hits"] += _hostile_hits(owner_body)
        owner_seed = _contains(owner_body, seed)
        result["owner_seed"] = owner_seed

        absent_answer = await self._ask(
            harness, forbidden_name, ask, seed,
            self._absent_ref(seed))
        absent_body = str(absent_answer.get("body") or "")
        result["hostile_hits"] += _hostile_hits(absent_body)
        absent_seed = _contains(absent_body, seed)
        result["absent_seed"] = absent_seed

        forbidden_answer = await self._ask(
            harness, forbidden_name, ask, seed, seed)
        forbidden_body = str(forbidden_answer.get("body") or "")
        result["hostile_hits"] += _hostile_hits(forbidden_body)
        observed_seed = _contains(forbidden_body, seed)
        result["observed_seed"] = observed_seed

        owner_reread = await self._ask(harness, owner_name, ask, seed, seed)
        result["hostile_hits"] += _hostile_hits(
            str(owner_reread.get("body") or ""))
        intact_after = owner_seed and _contains(
            str(owner_reread.get("body") or ""), seed)
        result["seed_intact"] = intact_after

        cleanup_status = await finalize_canary_cleanup(
            self.state,
            lambda identity, url, method="GET":
                self._fetch(harness, identity, url, method=method),
            self._base_url(), mut_id, str(ref),
            retrieval.get("cleanup") or {}, owner_name)
        result["cleanup_status"] = cleanup_status
        proven = bool(observed_seed and intact_after and not absent_seed
                      and cleanup_status == "verified")
        if not proven and not result.get("reason"):
            result["reason"] = "controls or cleanup not satisfied"
        result["proven"] = proven
        if proven:
            evidence = self.state.add_evidence(
                self.id, "ai_retrieval_canary", self._base_url(),
                {"name": result["name"], "mut_id": mut_id,
                 "cleanup_status": cleanup_status})
            self._file_proof("retrieval", result["name"], evidence)
        return result

    # ── Candidate probes ─────────────────────────────────────────

    async def _run_probes(self, harness, identities, cfg, report, run_token,
                          stop_at) -> None:
        probes = cfg.get("probes") or []
        if not probes or not identities:
            return
        try:
            max_probes = max(1, int(cfg.get("max_probes", 6) or 6))
        except (TypeError, ValueError):
            max_probes = 6
        for spec in probes[:max_probes]:
            if not isinstance(spec, dict):
                continue
            if time.monotonic() >= stop_at or self.should_stop(reserve=20):
                report["untested"].append(
                    {"surface": "probe", "reason": "time budget"})
                break
            name = str(spec.get("name") or "probe")
            identity_name = str(spec.get("identity")
                                or identities[-1].name)
            identity = harness.identities.get(identity_name)
            ask = spec.get("ask") or {}
            if identity is None or not ask.get("url_template"):
                report["untested"].append(
                    {"surface": name, "reason": "identity/ask missing"})
                continue
            sent = await self._ask(harness, identity_name, ask, "", run_token)
            body = str(sent.get("body") or "")
            report["hostile_responses"] += _hostile_hits(body)
            others = {m for other in identities if other.name != identity_name
                      for m in self._own_markers(other)}
            matched = _identity_markers(body) & others
            baseline = spec.get("baseline_ask") or {}
            if matched and baseline.get("url_template"):
                base = await self._ask(harness, identity_name, baseline, "",
                                       run_token)
                matched -= _identity_markers(str(base.get("body") or ""))
            absent = spec.get("absent_ask") or {}
            if matched and absent.get("url_template"):
                miss = await self._ask(harness, identity_name, absent, "",
                                       run_token)
                matched -= _identity_markers(str(miss.get("body") or ""))
            entry = {"name": name, "identity": identity_name,
                     "state": "observation"}
            if matched and _extract(ask.get("extract") or {}, body):
                entry["state"] = "candidate"
                entry["attributed_markers"] = len(matched)
                entry["note"] = "values are never stored"
                report["state_counts"]["candidate"] += 1
                self._file_candidate(name, identity_name, len(matched))
            else:
                report["state_counts"]["observation"] += 1
            report["probes"].append(entry)

    # ── Findings ─────────────────────────────────────────────────

    def _fingerprint(self, mode: str, name: str) -> str:
        host = urlparse(self._base_url()).hostname or ""
        raw = json.dumps({"module": self.id, "host": host, "mode": mode,
                          "name": name}, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _file_candidate(self, name: str, identity: str,
                        markers: int) -> None:
        fp = self._fingerprint("probe", name)
        self.state.add_finding(
            title=(f"AI conversation returns another identity's data: "
                   f"{name} [{fp[:8]}]"),
            severity="MEDIUM",
            confidence="FIRM",
            category="AI Conversation Isolation",
            description=(
                f"A prompt sent as '{identity}' returned values "
                f"attributable to another identity ({markers} marker(s)). "
                f"Values are not stored; confirm with a seeded canary "
                f"before reporting."),
            evidence=[f"probe:{name}"],
            asset_keys=[f"url:{self._base_url()}"],
            verified=False, verification={})

    def _file_proof(self, mode: str, name: str, evidence_ref: str) -> None:
        titles = {
            "thread": "AI conversation thread readable across identities",
            "continue": "AI conversation can be continued across identities",
            "retrieval": ("AI retrieval returns another identity's private "
                          "document"),
        }
        fp = self._fingerprint(f"{mode}_canary", name)
        self.state.add_finding(
            title=f"{titles.get(mode, 'AI conversation isolation')}: "
                  f"{name} [{fp[:8]}]",
            severity="HIGH",
            confidence="CONFIRMED",
            category="AI Conversation Isolation",
            description=(
                f"A seeded canary ({name}) owned by one identity was "
                f"observed through the forbidden lane in mode '{mode}'. "
                f"The owner read confirmed the seed survived, controls did "
                f"not expose it, and cleanup was verified by re-read."),
            evidence=[f"canary:{name}", evidence_ref],
            asset_keys=[f"url:{self._base_url()}"],
            verified=True,
            verification={"method": f"ai_{mode}_canary", "mode": mode,
                          "name": name, "observed_seed": True,
                          "cleanup_verified": True})

    # ── Plumbing ─────────────────────────────────────────────────

    async def _ask(self, harness, identity: str, spec: dict, ref,
                   value: str) -> dict:
        return await self._fetch_with_body(
            harness, identity, self._abs(str(spec.get("url_template") or "")),
            str(spec.get("method") or "POST"),
            self._fmt(spec.get("body_template") or "{}", ref, value))

    @staticmethod
    def _fmt(template, ref, seed: str) -> str:
        return (str(template or "")
                .replace("{id}", str(ref))
                .replace("{run}", str(seed))
                .replace("{seed}", str(seed)))

    @staticmethod
    def _absent_ref(ref) -> str:
        text = str(ref)
        return str(int(text) + 1000000) if text.isdigit() \
            else f"zz-absent-{text}"

    @staticmethod
    def _own_markers(identity) -> set:
        try:
            return set(identity.own_markers() or ())
        except Exception:
            return set()

    @staticmethod
    async def _fetch(harness, identity: str, url: str,
                     method: str = "GET") -> dict:
        if identity in ("anonymous", ""):
            return await harness.request_anonymous(url, method=method)
        return await harness.request(identity, url, method=method)

    @staticmethod
    async def _fetch_with_body(harness, identity: str, url: str, method: str,
                               body: str) -> dict:
        kwargs = {"method": method,
                  "headers": {"Content-Type": "application/json"},
                  "data": body}
        if identity in ("anonymous", ""):
            return await harness.request_anonymous(url, **kwargs)
        return await harness.request(identity, url, **kwargs)

    def _abs(self, value: str) -> str:
        value = str(value or "").strip()
        if not value or value.startswith(("http://", "https://")):
            return value
        base = self._base_url().rstrip("/")
        return f"{base}/{value.lstrip('/')}" if base else value

    def _base_url(self) -> str:
        return str(self.target.get("base_url")
                   or (self.base_url if self.domain else ""))

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}


def _contains(body: str, seed: str) -> bool:
    return bool(seed and seed in str(body or ""))


def _hostile_hits(text: str) -> int:
    lowered = str(text or "").lower()
    return sum(1 for marker in HOSTILE_MARKERS if marker in lowered)
