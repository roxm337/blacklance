"""Stage 5: WebSocket authorization audit (I7).

WebSocket endpoints expose the same object-level authorization surface as
HTTP, but the sockets are usually tested only for "does it connect". This
module separates three questions and keeps them strictly graded:

- origin       — does the server accept a handshake from a foreign Origin?
- message authz — can one identity read another identity's object by
                  sending a message over the socket?
- subscriptions — can one identity subscribe to another identity's channel?
- revocation   — does a logged-out session still read over an open socket?

Grading:

- observations — handshake accepted/rejected, origin behaviour, discovered
                 message shapes. Handshake acceptance alone is NEVER a
                 finding.
- candidates   — a configured message probe returns another identity's
                 marker with baseline/absent controls passing (values are
                 never stored), or an authenticated foreign-origin
                 handshake is accepted (impact unproven).
- proof        — a seeded canary is observed by the forbidden identity:
                 message read, subscription delivery, foreign-origin read
                 by the owner's own session, or a revoked session still
                 reading. The seed is created through R8, the owner re-read
                 confirms it survived, and cleanup must verify by re-read.

Captured sockets/messages come from I1 traffic (``core.traffic``); replay
uses ``tools.websocket_engine`` with fresh identity material. The module
never speaks WebSocket directly.
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
from tools import websocket_engine as ws

DEFAULT_ORIGIN_PROBE = "https://evil.example"
CANARY_MODES = ("message", "subscription", "origin", "revocation")


class WebSocketAudit(BaseModule):
    id = "websocket_audit"
    name = "WebSocket Authorization Audit"
    stage = 5
    detectability = "medium"
    depends_on = ["browser_crawl"]
    active = False

    async def run(self) -> str:
        cfg = self._cfg()
        if not cfg.get("enabled"):
            self.state.skip_module(
                self.id,
                "disabled — it opens sockets and seeds records; set "
                "modules.websocket_audit.enabled: true to run")
            return "skipped"

        harness = AuthHarness(self.config)
        harness.mutations = self.state.mutations
        harness.adopt_discovered(self.state, log=self.log)
        try:
            identities = await harness.establish_all(self._base_url())
        except Exception:
            identities = []

        sockets = self._discover_sockets(cfg)
        if not sockets:
            self.state.skip_module(self.id, "no websocket endpoints")
            return "skipped"

        self._io = {
            "connect_timeout": self._num(cfg, "connect_timeout", 10.0),
            "read_timeout": self._num(cfg, "read_timeout", 2.0),
            "window": self._num(cfg, "window", 6.0),
            "max_frames": max(1, int(self._num(cfg, "max_frames", 50))),
            "verify_tls": bool(cfg.get("verify_tls", True)),
        }
        try:
            max_seconds = max(20, int(cfg.get("max_seconds", 180) or 180))
        except (TypeError, ValueError):
            max_seconds = 180
        stop_at = time.monotonic() + max_seconds
        run_token = f"ws{hashlib.sha256(str(time.time()).encode()).hexdigest()[:6]}"

        report = {
            "schema_version": 1,
            "run_token": run_token,
            "sockets": sockets,
            "handshakes": [],
            "probes": [],
            "canaries": [],
            "state_counts": {"observation": 0, "candidate": 0, "proof": 0},
            "untested": [],
        }

        await self._handshake_phase(identities, sockets, cfg, report, stop_at)
        await self._probe_messages(harness, identities, sockets, cfg, report,
                                   run_token, stop_at)
        canary_cfg = cfg.get("canary") or {}
        if canary_cfg.get("enabled") \
                and (canary_cfg.get("record") or {}).get("url_template"):
            await self._run_canaries(harness, sockets, canary_cfg, run_token,
                                     report, stop_at)

        self.state.add_evidence(self.id, "websocket_report",
                                self._base_url(), report)
        counts = report["state_counts"]
        self.state.add_asset(
            "websocket_scan", f"websocket_scan:{self.domain}", self.domain,
            confidence="FIRM", sources=[self.id],
            attrs={"sockets": len(sockets),
                   "candidates": counts["candidate"],
                   "proofs": counts["proof"],
                   "untested": len(report["untested"])})
        self.state.complete_module(self.id)
        self.log(f"WebSocket audit: {len(sockets)} socket(s), "
                 f"{counts['candidate']} candidate(s), "
                 f"{counts['proof']} proven")
        return "done"

    # ── Discovery ────────────────────────────────────────────────

    def _discover_sockets(self, cfg: dict) -> list[dict]:
        try:
            max_sockets = max(1, int(cfg.get("max_sockets", 4) or 4))
        except (TypeError, ValueError):
            max_sockets = 4
        out: list[dict] = []
        seen: set[str] = set()

        def add(raw_url, source, *, messages=None, extra=None) -> None:
            url = ws.ws_url(self._base_url(), str(raw_url or ""))
            if not url or url in seen:
                return
            seen.add(url)
            entry = {"url": url, "source": source,
                     "messages": list(messages or []),
                     "subprotocols": [], "headers": {}}
            entry.update(extra or {})
            out.append(entry)

        for entry in cfg.get("sockets") or []:
            if isinstance(entry, str):
                entry = {"url": entry}
            if not isinstance(entry, dict):
                continue
            add(entry.get("url"), "configured", extra={
                "subprotocols": [str(s) for s in
                                 entry.get("subprotocols") or []],
                "headers": dict(entry.get("headers") or {}),
            })

        capture = cfg.get("capture") or {}
        if capture.get("enabled", True):
            from core.traffic import TrafficStore
            store = TrafficStore(self.state.state_dir / "traffic.jsonl",
                                 verify_existing=False)
            try:
                events = store.load()
            except Exception:
                events = []
            try:
                max_messages = max(1, int(capture.get("max_messages", 10) or 10))
            except (TypeError, ValueError):
                max_messages = 10
            for entry in ws.captured_sockets(events, max_sockets=max_sockets,
                                             max_messages=max_messages):
                add(entry.get("url"), "capture",
                    messages=entry.get("messages") or [],
                    extra={"page_url": entry.get("page_url") or "",
                           "identity": entry.get("identity") or {}})
        return out[:max_sockets]

    # ── Handshake origin checks (observation + precondition candidate) ──

    async def _handshake_phase(self, identities, sockets, cfg, report,
                               stop_at) -> None:
        origin_cfg = cfg.get("origin_probe", DEFAULT_ORIGIN_PROBE)
        origin = DEFAULT_ORIGIN_PROBE if origin_cfg is None \
            else str(origin_cfg).strip()
        subject = identities[-1] if identities else None
        headers = ws.build_headers(subject)
        for socket in sockets:
            if time.monotonic() >= stop_at or self.should_stop(reserve=15):
                report["untested"].append(
                    {"surface": socket["url"], "reason": "time budget"})
                break
            normal = await ws.probe_handshake(
                socket["url"], headers=headers, subprotocols=socket.get("subprotocols") or (),
                timeout=self._io["connect_timeout"],
                verify_tls=self._io["verify_tls"])
            entry = {
                "socket": socket["url"],
                "identity": getattr(subject, "name", "anonymous"),
                "normal": {"status": normal.status,
                           "accepted": normal.accepted,
                           "error": normal.error},
            }
            if origin:
                foreign = await ws.probe_handshake(
                    socket["url"], headers=headers, origin=origin,
                    subprotocols=socket.get("subprotocols") or (),
                    timeout=self._io["connect_timeout"],
                    verify_tls=self._io["verify_tls"])
                entry["foreign_origin"] = {
                    "origin": origin, "status": foreign.status,
                    "accepted": foreign.accepted, "error": foreign.error}
                if foreign.accepted and subject is not None:
                    report["state_counts"]["candidate"] += 1
                    self._file_origin_candidate(socket["url"], origin,
                                                subject.name)
            report["handshakes"].append(entry)
            report["state_counts"]["observation"] += 1

    # ── Message probes (candidates only) ─────────────────────────

    async def _probe_messages(self, harness, identities, sockets, cfg, report,
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
            if time.monotonic() >= stop_at or self.should_stop(reserve=20):
                report["untested"].append(
                    {"surface": "probe", "reason": "time budget"})
                break
            name = str(spec.get("name") or "probe")
            identity_name = str(spec.get("identity") or identities[-1].name)
            identity = harness.identities.get(identity_name)
            socket = self._pick_socket(sockets, spec)
            template = str(spec.get("send_template") or "")
            extract = spec.get("extract") or {}
            if identity is None or socket is None or not template or not extract:
                report["untested"].append(
                    {"surface": name, "reason": "identity/socket/spec missing"})
                continue
            send = self._format(template, spec.get("id") or "", run_token,
                                run_token)
            result = await self._session(harness, socket, identity_name,
                                         [send], extract)
            text = "\n".join(result.received_text())
            others = {m for other in identities if other.name != identity_name
                      for m in self._own_markers(other)}
            matched = _identity_markers(text) & others
            baseline_send = str(spec.get("baseline_send") or "")
            if matched and baseline_send:
                base = await self._session(
                    harness, socket, identity_name,
                    [self._format(baseline_send, "", run_token, run_token)],
                    extract)
                matched -= _identity_markers(
                    "\n".join(base.received_text()))
            absent_send = str(spec.get("absent_send") or "")
            if matched and absent_send:
                absent = await self._session(
                    harness, socket, identity_name,
                    [self._format(absent_send, "", run_token, run_token)],
                    extract)
                matched -= _identity_markers(
                    "\n".join(absent.received_text()))
            value = result.first_value(extract)
            if matched and value:
                report["state_counts"]["candidate"] += 1
                report["probes"].append({
                    "name": name, "socket": socket["url"],
                    "identity": identity_name, "state": "candidate",
                    "attributed_markers": len(matched),
                    "note": "values are never stored",
                })
                self._file_candidate_probe(spec, socket["url"], identity_name,
                                           len(matched))
            else:
                report["state_counts"]["observation"] += 1

    # ── Canary protocol (the only PROOF path) ────────────────────

    async def _run_canaries(self, harness, sockets, canary_cfg, run_token,
                            report, stop_at) -> None:
        owner_name = str(canary_cfg.get("owner_identity") or "")
        if not owner_name or owner_name not in harness.identities:
            report["untested"].append(
                {"surface": "canary", "reason": f"owner {owner_name!r} unknown"})
            return
        try:
            max_canaries = max(0, int(canary_cfg.get("max", 2) or 2))
        except (TypeError, ValueError):
            max_canaries = 2
        probes = [p for p in (canary_cfg.get("probes") or [])
                  if isinstance(p, dict)]
        # Logging a session out is destructive for later probes; run it last.
        probes.sort(key=lambda p: 1 if str(p.get("mode") or "message")
                    == "revocation" else 0)
        probes = probes[:max_canaries]
        for spec in probes:
            if time.monotonic() >= stop_at or self.should_stop(reserve=25):
                report["untested"].append(
                    {"surface": "canary", "reason": "time budget"})
                break
            outcome = await self._canary_once(
                harness, sockets, canary_cfg, spec, owner_name, run_token)
            if outcome.get("proven"):
                report["state_counts"]["proof"] += 1
            elif outcome.get("error"):
                report["state_counts"]["observation"] += 1
            report["canaries"].append(outcome)

    async def _canary_once(self, harness, sockets, canary_cfg, spec, owner_name,
                           seed) -> dict:
        mode = str(spec.get("mode") or "message").strip().lower()
        name = str(spec.get("name") or mode)
        result = {"name": name, "mode": mode, "proven": False}
        if mode not in CANARY_MODES:
            result["error"] = f"unknown mode {mode!r}"
            return result
        socket = self._pick_socket(sockets, spec)
        if socket is None:
            result["error"] = "no socket"
            return result
        send_template = str(spec.get("send_template") or "")
        extract = spec.get("extract") \
            or (canary_cfg.get("read") or {}).get("extract") or {}
        if not send_template or not extract:
            result["error"] = "send_template/extract missing"
            return result

        forbidden_name = str(canary_cfg.get("forbidden_identity") or "")
        target_owner = owner_name
        if mode == "revocation":
            target_owner = str(spec.get("identity") or forbidden_name
                               or owner_name)
        if target_owner not in harness.identities:
            result["error"] = f"identity {target_owner!r} unknown"
            return result

        record = canary_cfg.get("record") or {}
        read = canary_cfg.get("read") or {}
        cleanup = canary_cfg.get("cleanup") or {}
        create_target = str(record.get("url_template") or "")
        mut_id = self.state.mutations.begin(
            self.id, "object_create",
            {"url_template": create_target,
             "method": record.get("method", "POST")},
            identity=target_owner,
            owned_objects=[OwnedObject(type="resource", identifier="")])
        body = str(record.get("body_template") or "{}").replace("{run}", seed)
        created = await self._fetch_with_body(
            harness, target_owner, self._abs(create_target),
            str(record.get("method") or "POST"), body)
        ref = _extract(record.get("extract_id") or {},
                       str(created.get("body") or ""))
        result.update({"created_by": target_owner, "mut_id": mut_id,
                       "socket": socket["url"]})
        if not ref:
            self.state.mutations.mark_failed(
                mut_id, "canary create produced no bindable id")
            result["error"] = "canary create produced no bindable id"
            return result

        message = self._format(send_template, ref, seed, seed)
        absent_message = self._format(
            send_template, self._absent_ref(ref), seed, seed)
        direct_template = str(read.get("direct_url_template") or "")
        direct_url = self._abs(direct_template.replace("{id}", str(ref))) \
            if direct_template else ""
        read_extract = read.get("extract") or extract
        seed_intact = False
        if direct_url:
            owner_direct = await self._fetch(harness, target_owner, direct_url)
            seed_intact = _extract(
                read_extract, str(owner_direct.get("body") or "")) == seed

        observed_seed = False
        absent_seed = False
        baseline_seed = False
        public_seed = False
        pre_logout_seed = False
        post_logout_http_denied = False

        if mode in ("message", "subscription"):
            reader = forbidden_name or "anonymous"
            if reader == target_owner:
                self.state.mutations.mark_failed(
                    mut_id, "forbidden identity equals the owner")
                result["error"] = "forbidden identity equals the owner"
                return result
            owner_ws = await self._session(
                harness, socket, owner_name, [message], extract, seed=seed)
            seed_intact = seed_intact \
                or owner_ws.first_value(extract) == seed
            observed = await self._session(
                harness, socket, reader, [message], extract, seed=seed)
            observed_seed = observed.first_value(extract) == seed
            absent = await self._session(
                harness, socket, reader, [absent_message], extract, seed=seed)
            absent_seed = absent.first_value(extract) == seed
            baseline = await self._session(
                harness, socket, reader, [], extract, seed=seed)
            baseline_seed = baseline.first_value(extract) == seed
            forbidden_direct_seed = False
            if direct_url:
                forbidden_direct = await self._fetch(
                    harness, reader, direct_url)
                forbidden_direct_seed = _extract(
                    read_extract,
                    str(forbidden_direct.get("body") or "")) == seed
            result["http_direct_seed"] = forbidden_direct_seed
            if forbidden_direct_seed:
                result["reason"] = (
                    "the HTTP direct read already returns the seed; this is "
                    "an IDOR lane, not a WebSocket authorization proof")
        elif mode == "origin":
            origin_cfg = canary_cfg.get("origin_probe",
                                        DEFAULT_ORIGIN_PROBE)
            origin = DEFAULT_ORIGIN_PROBE if origin_cfg is None \
                else str(origin_cfg).strip()
            if not origin:
                self.state.mutations.mark_failed(
                    mut_id, "origin probe disabled")
                result["error"] = "origin probe disabled"
                return result
            normal = await self._session(
                harness, socket, owner_name, [message], extract, seed=seed)
            seed_intact = seed_intact or normal.first_value(extract) == seed
            foreign = await self._session(
                harness, socket, owner_name, [message], extract, seed=seed,
                origin=origin)
            observed_seed = foreign.first_value(extract) == seed
            foreign_absent = await self._session(
                harness, socket, owner_name, [absent_message], extract,
                seed=seed, origin=origin)
            absent_seed = foreign_absent.first_value(extract) == seed
            anonymous = await self._session(
                harness, socket, "anonymous", [message], extract, seed=seed)
            public_seed = anonymous.first_value(extract) == seed
            result["origin"] = origin
            if public_seed:
                result["reason"] = (
                    "anonymous reads the seed without any session; the "
                    "canary is public, so origin acceptance proves nothing")
        elif mode == "revocation":
            identity = harness.identities[target_owner]
            client = await self._open(harness, socket, target_owner)
            try:
                if not client.accepted:
                    result["error"] = "handshake rejected"
                    self.state.mutations.mark_failed(
                        mut_id, "handshake rejected for revocation probe")
                    return result
                await client.send(message)
                pre = await client.read_until(
                    stop_on={"contains": seed},
                    window=self._io["window"])
                pre_logout_seed = self._value_in(pre, extract) == seed
                seed_intact = pre_logout_seed
                try:
                    logged_out = await identity.logout(self._base_url())
                except Exception:
                    logged_out = False
                if direct_url:
                    after = await self._fetch(harness, target_owner,
                                              direct_url)
                    post_logout_http_denied = int(
                        after.get("status", 0) or 0) in (401, 403, 404, 410)
                await client.send(message)
                post = await client.read_until(
                    stop_on={"contains": seed},
                    window=self._io["window"])
                observed_seed = self._value_in(post, extract) == seed
                result.update({
                    "logged_out": bool(logged_out),
                    "pre_logout_seed": pre_logout_seed,
                    "post_logout_http_denied": post_logout_http_denied,
                })
                if not post_logout_http_denied:
                    result["reason"] = (
                        "logout did not revoke HTTP access, so WebSocket "
                        "behaviour cannot be attributed to revocation")
            finally:
                await client.close()
                try:
                    await identity.establish(self._base_url())
                except Exception:
                    pass

        cleanup_status = await finalize_canary_cleanup(
            self.state,
            lambda identity, url, method="GET":
                self._fetch(harness, identity, url, method=method),
            self._base_url(), mut_id, str(ref), cleanup, target_owner)
        result["cleanup_status"] = cleanup_status

        if mode in ("message", "subscription"):
            proven = bool(observed_seed and seed_intact and not absent_seed
                          and not baseline_seed
                          and not result.get("http_direct_seed")
                          and cleanup_status == "verified")
        elif mode == "origin":
            proven = bool(observed_seed and seed_intact and not absent_seed
                          and not public_seed
                          and cleanup_status == "verified")
        else:
            proven = bool(observed_seed and pre_logout_seed
                          and post_logout_http_denied
                          and cleanup_status == "verified")
        if not proven and not result.get("reason"):
            result["reason"] = "controls or cleanup not satisfied"
        result.update({"observed_seed": observed_seed,
                       "absent_seed": absent_seed,
                       "baseline_seed": baseline_seed,
                       "seed_intact": seed_intact,
                       "proven": proven})
        if proven:
            evidence = self.state.add_evidence(
                self.id, f"websocket_{mode}_canary", self._base_url(),
                {"name": name, "socket": socket["url"], "mut_id": mut_id,
                 "cleanup_status": cleanup_status})
            self._file_proof(spec, socket["url"], evidence)
        return result

    # ── Findings ─────────────────────────────────────────────────

    def _fingerprint(self, socket_url: str, mode: str, name: str = "") -> str:
        host = urlparse(self._base_url()).hostname or ""
        path = urlparse(socket_url).path
        raw = json.dumps({"module": self.id, "host": host, "path": path,
                          "mode": mode, "name": name}, sort_keys=True)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _file_origin_candidate(self, socket_url: str, origin: str,
                               identity: str) -> None:
        fp = self._fingerprint(socket_url, "origin_handshake", origin)
        self.state.add_finding(
            title=(f"WebSocket accepted a foreign-origin handshake for an "
                   f"authenticated session [{fp[:8]}]"),
            severity="LOW",
            confidence="FIRM",
            category="WebSocket Authorization",
            description=(
                f"The socket at {socket_url} accepted the handshake with "
                f"Origin {origin} while presenting the session of "
                f"'{identity}'. Acceptance alone does not prove data "
                f"exposure; confirm with a seeded canary read."),
            evidence=[f"socket:{socket_url}", f"origin:{origin}",
                      f"identity:{identity}"],
            asset_keys=[f"url:{socket_url}"],
            verified=False,
            verification={},
        )

    def _file_candidate_probe(self, spec: dict, socket_url: str,
                              identity: str, markers: int) -> None:
        name = str(spec.get("name") or "probe")
        fp = self._fingerprint(socket_url, "message_probe", name)
        self.state.add_finding(
            title=(f"WebSocket message exposes another identity's data: "
                   f"{name} [{fp[:8]}]"),
            severity="MEDIUM",
            confidence="FIRM",
            category="WebSocket Authorization",
            description=(
                f"A message sent as '{identity}' on {socket_url} returned "
                f"values attributable to another identity ({markers} "
                f"marker(s)). Values are not stored; confirm with a seeded "
                f"canary before reporting."),
            evidence=[f"socket:{socket_url}", f"probe:{name}"],
            asset_keys=[f"url:{socket_url}"],
            verified=False,
            verification={},
        )

    def _file_proof(self, spec: dict, socket_url: str,
                    evidence_ref: str) -> None:
        mode = str(spec.get("mode") or "message").strip().lower()
        name = str(spec.get("name") or mode)
        fp = self._fingerprint(socket_url, f"{mode}_canary", name)
        titles = {
            "message": "WebSocket message authorization bypass",
            "subscription": "WebSocket subscription leaks a private object",
            "origin": "Cross-origin WebSocket read of a private canary",
            "revocation": "Revoked session still reads over an open WebSocket",
        }
        self.state.add_finding(
            title=f"{titles.get(mode, 'WebSocket authorization')}: "
                  f"{name} [{fp[:8]}]",
            severity="HIGH",
            confidence="CONFIRMED",
            category="WebSocket Authorization",
            description=(
                f"A seeded canary ({name}) owned by one identity was "
                f"observed through the WebSocket at {socket_url} in mode "
                f"'{mode}'. The seed was created, the owner read confirmed "
                f"it survived, control reads did not return it, and cleanup "
                f"was verified by re-read."),
            evidence=[f"canary:{name}", evidence_ref],
            asset_keys=[f"url:{socket_url}"],
            verified=True,
            verification={"method": f"ws_{mode}_canary", "mode": mode,
                          "name": name, "observed_seed": True,
                          "cleanup_verified": True},
        )

    # ── Plumbing ─────────────────────────────────────────────────

    async def _session(self, harness, socket: dict, identity_name: str,
                       sends: list, extract: dict, *, seed: str = "",
                       origin: str = ""):
        identity = harness.identities.get(identity_name)
        stop_on = {"contains": seed} if seed else None
        return await ws.run_session(
            socket["url"],
            headers=ws.build_headers(identity, origin=origin,
                                     extra=socket.get("headers") or {}),
            origin=origin,
            subprotocols=socket.get("subprotocols") or (),
            send=[str(s) for s in sends],
            stop_on=stop_on,
            connect_timeout=self._io["connect_timeout"],
            read_timeout=self._io["read_timeout"],
            window=self._io["window"],
            max_frames=self._io["max_frames"],
            verify_tls=self._io["verify_tls"])

    async def _open(self, harness, socket: dict, identity_name: str,
                    *, origin: str = ""):
        identity = harness.identities.get(identity_name)
        client = ws.SocketClient(
            socket["url"],
            headers=ws.build_headers(identity, origin=origin,
                                     extra=socket.get("headers") or {}),
            origin=origin,
            subprotocols=socket.get("subprotocols") or (),
            connect_timeout=self._io["connect_timeout"],
            read_timeout=self._io["read_timeout"],
            max_frames=self._io["max_frames"],
            verify_tls=self._io["verify_tls"])
        await client.connect()
        return client

    @staticmethod
    def _value_in(texts: list, extract: dict):
        for text in texts or []:
            value = _extract(extract or {}, str(text))
            if value is not None:
                return value
        return None

    @staticmethod
    def _format(template: str, ref, seed: str, run_token: str) -> str:
        return (str(template or "")
                .replace("{id}", str(ref))
                .replace("{run}", str(run_token))
                .replace("{seed}", str(seed)))

    @staticmethod
    def _absent_ref(ref) -> str:
        text = str(ref)
        return str(int(text) + 1000000) if text.isdigit() \
            else f"zz-absent-{text}"

    @staticmethod
    def _pick_socket(sockets: list, spec: dict):
        wanted = str(spec.get("socket_url") or spec.get("socket") or "")
        if wanted:
            target = wanted.rstrip("/")
            for socket in sockets:
                if socket["url"].rstrip("/") == target \
                        or socket["url"].rstrip("/").endswith(target):
                    return socket
        return sockets[0] if sockets else None

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
