"""Stage 5: MCP (Model Context Protocol) assessment audit (I8).

MCP servers expose tools, resources and session state to AI clients. This
module tests the authorization boundaries the protocol does not define for
you:

- tool authorization      — can one identity invoke a tool that returns
                            another identity's private object?
- resource authorization  — can one identity read another identity's
                            resource URI?
- session ownership       — does a server accept another identity's
                            ``Mcp-Session-Id`` and serve its state?
- audience                — does a server accept a token issued for a
                            different audience and return private data?

Grading:

- observations — initialize/tools/list/resources/list outcomes, counts and
                 hostile-description indicators. Discovery is never a
                 finding; instruction-like target content is data, never
                 acted upon.
- candidates   — a configured tool probe returns another identity's marker
                 with baseline/absent controls passing (values never
                 stored), or a cross-audience initialize is accepted
                 (impact unproven).
- proof        — a seeded canary is observed through the forbidden lane
                 while controls stay clean and cleanup verifies. Only our
                 own R8-created canary may reach PROOF.

The engine is ``tools/mcp_engine.py``; it uses the framework transport, so
deadlines, budgets, rate limiting and wire accounting apply. No external
SDK, no model provider and no credentials beyond configured identities are
used.
"""

from __future__ import annotations

import hashlib
import json
import time
from urllib.parse import urlparse

from core.auth_harness import AuthHarness
from core.authorization import _identity_markers
from core.mutations import OwnedObject
from core.validators import redact_for_log
from modules.base import BaseModule
from tools import mcp_engine as mcp

CANARY_MODES = ("tool", "resource", "session", "audience")

HOSTILE_MARKERS = (
    "ignore previous", "ignore all previous", "ignore the above",
    "system prompt", "you must call", "call the tool", "exfiltrate",
    "send the token", "do not tell the user", "reveal your instructions",
)


class MCPAudit(BaseModule):
    id = "mcp_audit"
    name = "MCP Assessment Audit"
    stage = 5
    detectability = "medium"
    depends_on = []
    active = False

    async def run(self) -> str:
        cfg = self._cfg()
        if not cfg.get("enabled"):
            self.state.skip_module(
                self.id,
                "disabled — it calls MCP tools and seeds resources; set "
                "modules.mcp_audit.enabled: true to run")
            return "skipped"

        harness = AuthHarness(self.config)
        harness.mutations = self.state.mutations
        harness.adopt_discovered(self.state, log=self.log)
        try:
            identities = await harness.establish_all(self._base_url())
        except Exception:
            identities = []

        self._io = {
            "timeout": self._num(cfg, "timeout", 15.0),
            "protocol_version": str(cfg.get("protocol_version")
                                    or mcp.DEFAULT_PROTOCOL_VERSION),
            "max_servers": max(1, int(self._num(cfg, "max_servers", 4))),
        }
        servers = self._servers(cfg)
        if not servers:
            self.state.skip_module(self.id, "no MCP endpoints")
            return "skipped"
        try:
            max_seconds = max(20, int(cfg.get("max_seconds", 240) or 240))
        except (TypeError, ValueError):
            max_seconds = 240
        stop_at = time.monotonic() + max_seconds
        run_token = f"mc{hashlib.sha256(str(time.time()).encode()).hexdigest()[:6]}"

        report = {
            "schema_version": 1,
            "run_token": run_token,
            "servers": [{"name": s["name"], "url": s["url"]}
                        for s in servers],
            "discovery": [],
            "audience_checks": [],
            "probes": [],
            "canaries": [],
            "state_counts": {"observation": 0, "candidate": 0, "proof": 0},
            "untested": [],
        }

        await self._discover(harness, identities, servers, cfg, report, stop_at)
        await self._audience_checks(harness, servers, cfg, report)
        await self._probe_tools(harness, identities, servers, cfg, report,
                                run_token, stop_at)
        canary_cfg = cfg.get("canary") or {}
        if canary_cfg.get("enabled") and (canary_cfg.get("seed") or {}).get("tool"):
            await self._run_canaries(harness, servers, canary_cfg, run_token,
                                     report, stop_at)

        self.state.add_evidence(self.id, "mcp_report", self._base_url(),
                                report)
        counts = report["state_counts"]
        self.state.add_asset(
            "mcp_scan", f"mcp_scan:{self.domain}", self.domain,
            confidence="FIRM", sources=[self.id],
            attrs={"servers": len(servers),
                   "candidates": counts["candidate"],
                   "proofs": counts["proof"],
                   "untested": len(report["untested"])})
        self.state.complete_module(self.id)
        self.log(f"MCP audit: {len(servers)} server(s), "
                 f"{counts['candidate']} candidate(s), "
                 f"{counts['proof']} proven")
        return "done"

    # ── Configuration ────────────────────────────────────────────

    def _servers(self, cfg: dict) -> list[dict]:
        out, seen = [], set()
        for entry in cfg.get("servers") or []:
            if isinstance(entry, str):
                entry = {"name": entry, "url": entry}
            if not isinstance(entry, dict):
                continue
            url = mcp.endpoint_url(self._base_url(),
                                   str(entry.get("url") or ""))
            if not url or url in seen:
                continue
            seen.add(url)
            name = str(entry.get("name") or url)
            out.append({"name": name, "url": url,
                        "headers": dict(entry.get("headers") or {})})
            if len(out) >= self._io["max_servers"]:
                break
        return out

    def _server(self, servers: list[dict], name: str):
        wanted = str(name or "").strip()
        if wanted:
            for server in servers:
                if server["name"] == wanted or server["url"] == wanted:
                    return server
        return servers[0] if servers else None

    def _identity(self, harness, name: str):
        if name in ("anonymous", ""):
            return None
        return harness.identities.get(name)

    def _client(self, harness, server: dict, identity_name: str, *,
                session_id: str = "", initialized: bool = False):
        identity = self._identity(harness, identity_name)
        headers = identity.request_headers() if identity is not None else {}
        headers.update(server.get("headers") or {})
        return mcp.McpClient(
            server["url"],
            identity=identity.name if identity is not None else None,
            headers=headers,
            protocol_version=self._io["protocol_version"],
            timeout=self._io["timeout"],
            session_id=session_id,
            initialized=initialized)

    async def _open(self, harness, server: dict, identity_name: str):
        client = self._client(harness, server, identity_name)
        result = await client.initialize()
        return client, result

    # ── Discovery (observations only) ────────────────────────────

    async def _discover(self, harness, identities, servers, cfg, report,
                        stop_at) -> None:
        identity_name = str(cfg.get("discover_identity") or "")
        if not identity_name and identities:
            identity_name = identities[0].name
        for server in servers:
            if time.monotonic() >= stop_at or self.should_stop(reserve=20):
                report["untested"].append(
                    {"surface": server["name"], "reason": "time budget"})
                break
            client, init = await self._open(harness, server, identity_name)
            entry = {
                "server": server["name"],
                "identity": identity_name or "anonymous",
                "initialize_status": init.status,
                "initialize_ok": init.ok,
                "tools": 0,
                "resources": 0,
                "tool_names": [],
                "resource_uris": [],
                "hostile_descriptions": 0,
            }
            if init.ok:
                listing = await client.list_tools()
                if listing.ok:
                    tools = (listing.result or {}).get("tools") or []
                    entry["tools"] = len(tools)
                    entry["tool_names"] = [
                        redact_for_log(str(t.get("name") or ""))[:80]
                        for t in tools[:20] if isinstance(t, dict)]
                    entry["hostile_descriptions"] += _hostile_hits(
                        json.dumps(tools, default=str))
                resources = await client.list_resources()
                if resources.ok:
                    items = (resources.result or {}).get("resources") or []
                    entry["resources"] = len(items)
                    entry["resource_uris"] = [
                        redact_for_log(str(r.get("uri") or ""))[:120]
                        for r in items[:20] if isinstance(r, dict)]
                    entry["hostile_descriptions"] += _hostile_hits(
                        json.dumps(items, default=str))
                report["state_counts"]["observation"] += 1
            else:
                entry["error"] = init.error_text
            await _safe_close(client)
            report["discovery"].append(entry)

    async def _audience_checks(self, harness, servers, cfg, report) -> None:
        for check in cfg.get("audience_checks") or []:
            if not isinstance(check, dict):
                continue
            server = self._server(servers, check.get("server"))
            identity_name = str(check.get("identity") or "")
            if server is None or not identity_name:
                report["untested"].append(
                    {"surface": "audience", "reason": "server/identity missing"})
                continue
            client, init = await self._open(harness, server, identity_name)
            expected = str(check.get("expected") or "rejected").lower()
            accepted = bool(init.ok)
            report["audience_checks"].append({
                "name": str(check.get("name") or identity_name),
                "identity": identity_name,
                "server": server["name"],
                "status": init.status,
                "accepted": accepted,
                "expected": expected,
            })
            await _safe_close(client)
            if accepted and expected == "rejected":
                report["state_counts"]["candidate"] += 1
                self._file_audience_candidate(server, identity_name, init.status)

    # ── Tool probes (candidates only) ────────────────────────────

    async def _probe_tools(self, harness, identities, servers, cfg, report,
                           run_token, stop_at) -> None:
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
            if time.monotonic() >= stop_at or self.should_stop(reserve=25):
                report["untested"].append(
                    {"surface": "probe", "reason": "time budget"})
                break
            name = str(spec.get("name") or "probe")
            server = self._server(servers, spec.get("server"))
            identity_name = str(spec.get("identity") or identities[-1].name)
            identity = harness.identities.get(identity_name)
            tool = str(spec.get("tool") or "")
            extract = spec.get("extract") or {}
            if server is None or identity is None or not tool or not extract:
                report["untested"].append(
                    {"surface": name, "reason": "server/identity/spec missing"})
                continue
            client, init = await self._open(harness, server, identity_name)
            entry = {"name": name, "server": server["name"],
                     "identity": identity_name, "state": "observation"}
            if init.ok:
                call = await client.call_tool(
                    tool, self._fmt(spec.get("arguments") or {},
                                    spec.get("id") or "", run_token))
                text = _result_text(call)
                others = {m for other in identities
                          if other.name != identity_name
                          for m in self._own_markers(other)}
                matched = _identity_markers(text) & others
                baseline_args = spec.get("baseline_arguments")
                if matched and baseline_args is not None:
                    base = await client.call_tool(
                        tool, self._fmt(baseline_args, "", run_token))
                    matched -= _identity_markers(_result_text(base))
                absent_args = spec.get("absent_arguments")
                if matched and absent_args is not None:
                    absent = await client.call_tool(
                        tool, self._fmt(absent_args, "", run_token))
                    matched -= _identity_markers(_result_text(absent))
                if matched and call.value(extract):
                    entry["state"] = "candidate"
                    entry["attributed_markers"] = len(matched)
                    entry["note"] = "values are never stored"
                    report["state_counts"]["candidate"] += 1
                    self._file_probe_candidate(spec, server, identity_name,
                                               len(matched))
                else:
                    entry["state"] = "observation"
                    report["state_counts"]["observation"] += 1
            else:
                entry["error"] = init.error_text
            await _safe_close(client)
            report["probes"].append(entry)

    # ── Canary protocol (the only PROOF path) ────────────────────

    async def _run_canaries(self, harness, servers, canary_cfg, run_token,
                            report, stop_at) -> None:
        owner_default = str(canary_cfg.get("owner_identity") or "")
        if owner_default not in harness.identities:
            report["untested"].append(
                {"surface": "canary",
                 "reason": f"owner {owner_default!r} unknown"})
            return
        try:
            max_canaries = max(0, int(canary_cfg.get("max", 2) or 2))
        except (TypeError, ValueError):
            max_canaries = 2
        probes = [p for p in (canary_cfg.get("probes") or [])
                  if isinstance(p, dict)][:max_canaries]
        for spec in probes:
            if time.monotonic() >= stop_at or self.should_stop(reserve=30):
                report["untested"].append(
                    {"surface": "canary", "reason": "time budget"})
                break
            outcome = await self._canary_once(
                harness, servers, canary_cfg, spec, run_token)
            if outcome.get("proven"):
                report["state_counts"]["proof"] += 1
            else:
                report["state_counts"]["observation"] += 1
            report["canaries"].append(outcome)

    async def _canary_once(self, harness, servers, canary_cfg, spec,
                           seed) -> dict:
        mode = str(spec.get("mode") or "tool").strip().lower()
        name = str(spec.get("name") or mode)
        result = {"name": name, "mode": mode, "proven": False}
        if mode not in CANARY_MODES:
            result["error"] = f"unknown mode {mode!r}"
            return result
        server = self._server(servers, spec.get("server")
                              or canary_cfg.get("server"))
        owner_name = str(spec.get("owner_identity")
                         or canary_cfg.get("owner_identity") or "")
        forbidden_name = str(spec.get("forbidden_identity")
                             or canary_cfg.get("forbidden_identity") or "")
        read = spec.get("read") or {}
        seed_spec = canary_cfg.get("seed") or {}
        cleanup = canary_cfg.get("cleanup") or {}
        if server is None or owner_name not in harness.identities:
            result["error"] = "server/owner unavailable"
            return result
        if not read or not (read.get("tool") or read.get("uri_template")):
            result["error"] = "read lane missing"
            return result
        if mode in ("tool", "resource") \
                and (not forbidden_name
                     or forbidden_name == owner_name):
            result["error"] = "forbidden identity unusable"
            return result

        mut_id = self.state.mutations.begin(
            self.id, "object_create",
            {"server": server["url"], "tool": str(seed_spec.get("tool") or "")},
            identity=owner_name,
            owned_objects=[OwnedObject(type="mcp_resource", identifier="")])
        result.update({"server": server["name"], "created_by": owner_name,
                       "read_by": forbidden_name or owner_name,
                       "mut_id": mut_id})

        owner_client, owner_init = await self._open(harness, server, owner_name)
        try:
            if not owner_init.ok:
                self.state.mutations.mark_failed(
                    mut_id, f"owner initialize failed: {owner_init.status}")
                result["error"] = f"owner initialize failed: {owner_init.status}"
                return result

            created = await owner_client.call_tool(
                str(seed_spec.get("tool") or ""),
                self._fmt(seed_spec.get("arguments") or {}, "", seed))
            ref = created.value(seed_spec.get("extract") or {})
            if not ref:
                self.state.mutations.mark_failed(
                    mut_id, "seed tool produced no bindable id")
                result["error"] = "seed tool produced no bindable id"
                return result
            result["ref_bound"] = True

            owner_read = await self._read_lane(owner_client, read, ref, seed)
            seed_intact = _contains(owner_read, seed)
            result["owner_seed"] = seed_intact

            baseline_text = await self._baseline(harness, server,
                                                 forbidden_name)
            baseline_seed = seed in baseline_text
            result["baseline_seed"] = baseline_seed

            absent_read = await self._read_lane(
                owner_client, read, self._absent_ref(ref), seed)
            absent_seed = _contains(absent_read, seed)
            result["absent_seed"] = absent_seed

            observed_seed = False
            initialize_ok = False
            if mode == "session":
                forbidden_client = self._client(
                    harness, server, forbidden_name,
                    session_id=owner_client.session_id, initialized=True)
                result["session_reused"] = bool(owner_client.session_id)
                observed = await self._read_lane(
                    forbidden_client, read, ref, seed)
                observed_seed = _contains(observed, seed)
                # Do NOT close this client: its session id belongs to the
                # owner, and closing would terminate the owner's session
                # before the integrity re-read.
                forbidden_client.session_id = ""
            else:
                forbidden_client, init = await self._open(
                    harness, server, forbidden_name)
                initialize_ok = init.ok
                if init.ok:
                    observed = await self._read_lane(
                        forbidden_client, read, ref, seed)
                    observed_seed = _contains(observed, seed)
                await _safe_close(forbidden_client)
            result["initialize_ok"] = initialize_ok
            result["observed_seed"] = observed_seed

            owner_reread = await self._read_lane(
                owner_client, read, ref, seed)
            intact_after = seed_intact and _contains(owner_reread, seed)
            result["seed_intact"] = intact_after

            cleanup_status = await self._cleanup(
                owner_client, cleanup, ref, seed, mut_id)
            result["cleanup_status"] = cleanup_status

            proven = bool(observed_seed and intact_after and not absent_seed
                          and not baseline_seed
                          and cleanup_status == "verified")
            if mode == "audience":
                proven = proven and initialize_ok
            if not proven and not result.get("reason"):
                result["reason"] = "controls or cleanup not satisfied"
            result["proven"] = proven
            if proven:
                evidence = self.state.add_evidence(
                    self.id, f"mcp_{mode}_canary", self._base_url(),
                    {"name": name, "server": server["name"],
                     "mut_id": mut_id, "cleanup_status": cleanup_status})
                self._file_proof(spec, server, evidence)
            return result
        finally:
            await _safe_close(owner_client)

    async def _read_lane(self, client, read: dict, ref, seed: str):
        if read.get("uri_template"):
            uri = self._fmt(read.get("uri_template"), ref, seed)
            return await client.read_resource(uri)
        return await client.call_tool(
            str(read.get("tool") or ""),
            self._fmt(read.get("arguments") or {}, ref, seed))

    async def _baseline(self, harness, server, identity_name: str) -> str:
        client, init = await self._open(harness, server, identity_name)
        try:
            if not init.ok:
                return ""
            tools = await client.list_tools()
            resources = await client.list_resources()
            return _result_text(tools) + "\n" + _result_text(resources)
        finally:
            await _safe_close(client)

    async def _cleanup(self, client, cleanup: dict, ref, seed: str,
                       mut_id: str) -> str:
        tool = str(cleanup.get("tool") or "")
        if not tool:
            self.state.mutations.mark_not_required(
                mut_id, "no MCP cleanup tool declared")
            return "not_required"
        removed = await client.call_tool(
            tool, self._fmt(cleanup.get("arguments") or {}, ref, seed))
        verify = cleanup.get("verify") or {}
        check = await client.call_tool(
            str(verify.get("tool") or ""),
            self._fmt(verify.get("arguments") or {}, ref, seed)) \
            if verify.get("tool") else mcp.McpResult(method="verify")
        expect = str(verify.get("expect") or "absent").lower()
        gone = not _contains(check, seed)
        if expect == "error" and check.ok:
            gone = False
        verification = {"method": "mcp_tool_read",
                        "cleanup_ok": removed.ok,
                        "verify_ok": check.ok,
                        "found_seed": not gone}
        self.state.mutations.record_rollback(
            mut_id, "verified" if gone else "failed",
            verification=verification)
        if gone:
            self.state.mutations.verify_cleanup(mut_id, verification)
            return "verified"
        self.state.mutations.mark_failed(
            mut_id, "cleanup verification still exposed the seed")
        return "failed"

    # ── Findings ─────────────────────────────────────────────────

    def _fingerprint(self, server: dict, mode: str, name: str = "") -> str:
        host = urlparse(self._base_url()).hostname or ""
        path = urlparse(server["url"]).path
        raw = json.dumps({"module": self.id, "host": host, "path": path,
                          "mode": mode, "name": name}, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _file_audience_candidate(self, server: dict, identity: str,
                                 status: int) -> None:
        fp = self._fingerprint(server, "audience_handshake", identity)
        self.state.add_finding(
            title=("MCP server accepted a token from another audience "
                   f"[{fp[:8]}]"),
            severity="LOW",
            confidence="FIRM",
            category="MCP Authorization",
            description=(
                f"The MCP endpoint {server['url']} completed initialize "
                f"(HTTP {status}) for identity '{identity}', whose token "
                f"was issued for a different audience. Acceptance alone "
                f"does not prove data access; confirm with a seeded canary."),
            evidence=[f"server:{server['name']}", f"identity:{identity}"],
            asset_keys=[f"url:{server['url']}"],
            verified=False, verification={})

    def _file_probe_candidate(self, spec: dict, server: dict,
                              identity: str, markers: int) -> None:
        name = str(spec.get("name") or "probe")
        fp = self._fingerprint(server, "tool_probe", name)
        self.state.add_finding(
            title=(f"MCP tool returns another identity's data: {name} "
                   f"[{fp[:8]}]"),
            severity="MEDIUM",
            confidence="FIRM",
            category="MCP Authorization",
            description=(
                f"Tool '{spec.get('tool')}' on {server['url']} run as "
                f"'{identity}' returned values attributable to another "
                f"identity ({markers} marker(s)). Values are not stored; "
                f"confirm with a seeded canary before reporting."),
            evidence=[f"server:{server['name']}", f"probe:{name}"],
            asset_keys=[f"url:{server['url']}"],
            verified=False, verification={})

    def _file_proof(self, spec: dict, server: dict,
                    evidence_ref: str) -> None:
        mode = str(spec.get("mode") or "tool").strip().lower()
        name = str(spec.get("name") or mode)
        fp = self._fingerprint(server, f"{mode}_canary", name)
        titles = {
            "tool": "MCP tool authorization bypass",
            "resource": "MCP resource read leaks a private canary",
            "session": "MCP session state is readable across identities",
            "audience": "MCP server serves private data to a foreign audience",
        }
        self.state.add_finding(
            title=f"{titles.get(mode, 'MCP authorization')}: {name} "
                  f"[{fp[:8]}]",
            severity="HIGH",
            confidence="CONFIRMED",
            category="MCP Authorization",
            description=(
                f"A seeded canary ({name}) created by one identity was "
                f"observed through the forbidden lane on {server['url']} "
                f"(mode '{mode}'). The owner read confirmed the seed "
                f"survived, controls did not expose it, and cleanup was "
                f"verified by re-read."),
            evidence=[f"canary:{name}", evidence_ref],
            asset_keys=[f"url:{server['url']}"],
            verified=True,
            verification={"method": f"mcp_{mode}_canary", "mode": mode,
                          "name": name, "observed_seed": True,
                          "cleanup_verified": True})

    # ── Plumbing ─────────────────────────────────────────────────

    @staticmethod
    def _fmt(value, ref, seed: str):
        def sub(text: str) -> str:
            return (text.replace("{id}", str(ref))
                    .replace("{run}", str(seed))
                    .replace("{seed}", str(seed)))
        if isinstance(value, dict):
            return {k: MCPAudit._fmt(v, ref, seed) for k, v in value.items()}
        if isinstance(value, list):
            return [MCPAudit._fmt(v, ref, seed) for v in value]
        return sub(value) if isinstance(value, str) else value

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
    def _num(cfg: dict, key: str, default: float) -> float:
        try:
            return float(cfg.get(key, default))
        except (TypeError, ValueError):
            return float(default)

    def _base_url(self) -> str:
        return str(self.target.get("base_url")
                   or (self.base_url if self.domain else ""))

    def _cfg(self) -> dict:
        cfg = self.config.get("modules", {}).get(self.id, {})
        return cfg if isinstance(cfg, dict) else {}


async def _safe_close(client) -> None:
    try:
        await client.close_session()
    except Exception:
        pass


def _result_text(result) -> str:
    if result is None:
        return ""
    parts = [result.text or ""]
    if result.result is not None:
        parts.append(json.dumps(result.result, default=str))
    return "\n".join(parts)


def _contains(result, seed: str) -> bool:
    return bool(result is not None and seed and result.contains(str(seed)))


def _hostile_hits(text: str) -> int:
    lowered = str(text or "").lower()
    return sum(1 for marker in HOSTILE_MARKERS if marker in lowered)
