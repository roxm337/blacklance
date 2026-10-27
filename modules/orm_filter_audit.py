"""Stage 5: ORM / filter leak audit (I5).

An ORM/filter leak is a READ where a filter, search, structured-where,
projection or ordering parameter changes *authorization outcomes*: the
caller obtains a record, field or relationship they cannot obtain through
the direct read. It is an access-control defect expressed through query
semantics, not an injection defect.

Grading is strict:

- observations  — the surface accepts the parameter, or an ORM error /
                  ordering signal appears; never a security claim.
- candidates    — real records attributable to another identity appear
                  through the filter, with baseline and absent-value
                  controls passing. Values are never stored, only leaf
                  paths and marker counts. Real records NEVER exceed
                  candidate (no real-secret extraction).
- proof         — the module's OWN seeded record (R8 create, verified
                  cleanup) is retrievable by the forbidden identity via
                  the filter while its direct read is denied. Timing-only
                  signals never promote; they are recorded as information.

Read-only while probing; the only writes are canary records, always
recorded in the mutation ledger before creation and cleaned up with a
fresh verification read.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from core.auth_harness import AuthHarness
from core.authorization import finalize_canary_cleanup
from core.mutations import OwnedObject
from core.workflows import _extract
from modules.base import BaseModule

INCLUSION_RE = re.compile(
    r"^(filter|where|q|search|query|keyword|term|find)(\[[^\]]+\])?$",
    re.IGNORECASE)
FIELD_RE = re.compile(
    r"^(include|fields|select|expand|with|embed|populate|preload)"
    r"(\[[^\]]+\])?$", re.IGNORECASE)
SORT_RE = re.compile(r"^(sort|order|order_by|orderby|sort_by)$", re.IGNORECASE)

DEFAULT_FILTER_NAMES = (
    "q", "search", "owner_id", "user_id", "account_id",
    "filter[owner_id]", "filter[user_id]", "include", "fields",
)

ORM_ERROR_MARKERS = (
    "cannot resolve keyword", "invalidrequesterror",
    "activerecord::statementinvalid", "unknown arg",
    "unknown column", "sqlalchemy.exc", "django.db",
)


def param_vector(name: str) -> str:
    """inclusion | field | ordering | '' for a parameter name."""
    name = str(name or "").strip()
    if INCLUSION_RE.match(name):
        return "inclusion"
    if FIELD_RE.match(name):
        return "field"
    if SORT_RE.match(name):
        return "ordering"
    return ""


def rows_of(body: str) -> list:
    """Top-level rows from a list or a common envelope shape."""
    text = (body or "").strip()
    if not text or text[0] not in "[{":
        return []
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        for key in ("data", "results", "items", "records", "rows",
                    "hydra:member"):
            value = payload.get(key)
            if isinstance(value, list):
                return [r for r in value if isinstance(r, dict)]
    return []


def with_param(url: str, param: str, value: str) -> str:
    """Set one query parameter, preserving the others and the fragment."""
    parsed = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
             if k != param]
    pairs.append((param, value))
    return urlunparse(parsed._replace(query=urlencode(pairs)))


class ORMFilterAudit(BaseModule):
    id = "orm_filter_audit"
    name = "ORM / Filter Leak Audit"
    stage = 5
    detectability = "medium"
    depends_on = ["parameter_discovery", "rest_api_audit"]
    active = False

    async def run(self) -> str:
        cfg = self._cfg()
        if not cfg.get("enabled"):
            self.state.skip_module(
                self.id,
                "disabled — it seeds records and manipulates filter "
                "parameters; set modules.orm_filter_audit.enabled: true "
                "to run")
            return "skipped"

        harness = AuthHarness(self.config)
        harness.mutations = self.state.mutations
        harness.adopt_discovered(self.state, log=self.log)
        try:
            identities = await harness.establish_all(self._base_url())
        except Exception:
            identities = []
        canary_cfg = cfg.get("canary") or {}
        if not identities and not cfg.get("allow_anonymous"):
            self.state.skip_module(
                self.id, "no verified identities (allow_anonymous is false)")
            return "skipped"

        surfaces = self._discover_surfaces(cfg)
        if not surfaces:
            self.state.skip_module(self.id, "no filter/search surfaces")
            return "skipped"

        try:
            max_seconds = max(30, int(cfg.get("max_seconds", 300) or 300))
        except (TypeError, ValueError):
            max_seconds = 300
        stop_at = time.monotonic() + max_seconds
        run_token = f"of{hashlib.sha256(str(time.time()).encode()).hexdigest()[:6]}"

        report = {"schema_version": 1, "run_token": run_token,
                  "surfaces": surfaces,
                  "probes": [], "canaries": [], "observations": [],
                  "state_counts": {"observation": 0, "candidate": 0, "proof": 0},
                  "untested": []}

        await self._probe_surfaces(harness, identities, surfaces, cfg,
                                   report, stop_at)
        if canary_cfg.get("enabled"):
            if (canary_cfg.get("record") or {}).get("url_template"):
                await self._run_canaries(harness, canary_cfg, run_token, report)
            else:
                report["untested"].append({
                    "surface": "canary",
                    "reason": "canary.enabled is true but canary.record."
                              "url_template is not set — no proof path exists"})

        self.state.add_evidence(self.id, "orm_filter_report",
                                self._base_url(), report)
        counts = report["state_counts"]
        self.state.add_asset(
            "orm_filter_scan", f"orm_filter_scan:{self.domain}", self.domain,
            confidence="FIRM", sources=[self.id],
            attrs={"surfaces": len(surfaces),
                   "candidates": counts["candidate"],
                   "proofs": counts["proof"],
                   "untested": len(report["untested"])})
        self.state.complete_module(self.id)
        self.log(f"ORM filter audit: {len(surfaces)} surface(s), "
                 f"{counts['candidate']} candidate(s), {counts['proof']} proven")
        return "done"

    # ── Discovery ────────────────────────────────────────────────

    def _discover_surfaces(self, cfg: dict) -> list[dict]:
        max_surfaces = max(1, int(cfg.get("max_surfaces", 8) or 8))
        surfaces: list[dict] = []
        seen: set[tuple] = set()

        def add(url: str, param: str, source: str) -> None:
            vector = param_vector(param)
            if not vector or vector == "ordering":
                return  # ordering is an oracle, not a finding surface
            key = (url, param)
            if key in seen:
                return
            seen.add(key)
            surfaces.append({"url": url, "param": param, "vector": vector,
                             "source": source, "method": "GET"})

        for entry in cfg.get("surfaces") or []:
            url = str(entry.get("url") or "")
            for param in entry.get("filter_params") or []:
                add(url, str(param), "configured")
        if cfg.get("traffic_surfaces", True):
            for url, param in self._traffic_params():
                add(url, param, "traffic")
        if cfg.get("augment_collections", True):
            names = list(cfg.get("filter_names") or DEFAULT_FILTER_NAMES)
            for url in self._collection_urls():
                for name in names:
                    add(url, name, "collection")
        if (cfg.get("source_rules") or {}).get("enabled"):
            for url, param in self._source_rule_params(cfg):
                add(url, param, "source_rules")
        return surfaces[:max_surfaces]

    def _traffic_params(self) -> list[tuple]:
        from core.traffic import TrafficStore
        store = TrafficStore(self.state.state_dir / "traffic.jsonl")
        try:
            events = store.load()
        except Exception:
            return []
        found = []
        for event in events:
            if event.get("kind") == "response" \
                    or str(event.get("method", "GET")).upper() not in (
                        "GET", "HEAD", "DELETE"):
                continue
            parsed = urlparse(str(event.get("url") or ""))
            for name, _value in parse_qsl(parsed.query):
                if param_vector(name):
                    found.append((f"{parsed.scheme}://{parsed.netloc}"
                                  f"{parsed.path}", name))
        return found[:50]

    def _collection_urls(self) -> list[str]:
        out, seen = [], set()
        for asset_type in ("api_endpoint", "url", "webapp"):
            for node in self.state.get_assets_by_type(asset_type):
                value = str(node.get("value") or "")
                if not value.startswith(("http://", "https://")):
                    continue
                path = urlparse(value).path
                if path and not re.search(r"/\d+(/|$)", path):
                    if value not in seen:
                        seen.add(value)
                        out.append(value)
                if len(out) >= 20:
                    return out
        if self._base_url() not in seen:
            out.append(self._base_url())
        return out

    def _source_rule_params(self, cfg: dict) -> list[tuple]:
        try:
            from tools.orm_source_rules import load_rules
            root = str((cfg.get("source_rules") or {}).get("root") or "")
            rules = load_rules(root) if root else []
        except Exception:
            return []
        params = []
        for rule in rules[:50]:
            for name in (rule.get("filterable") or [])[:10]:
                params.append(name)
            for name in (rule.get("searchable") or [])[:10]:
                params.append(name)
            for name in (rule.get("relationships") or [])[:10]:
                params.append(f"include[{name}]" if name else name)
        out = []
        for url in self._collection_urls()[:5]:
            for param in params:
                out.append((url, str(param)))
        return out[:50]

    # ── Candidate probing (never exceeds candidate) ──────────────

    async def _probe_surfaces(self, harness, identities, surfaces, cfg,
                              report, stop_at) -> None:
        values = [str(v) for v in (cfg.get("vector_values") or []) if str(v)]
        if not values:
            report["untested"].append({
                "surface": "candidate probing",
                "reason": "vector_values is empty — no filter value was sent"})
            return
        if not identities:
            report["untested"].append({
                "surface": "candidate probing",
                "reason": "no verified identities to attribute rows to"})
            return
        try:
            max_payloads = max(1, int(cfg.get("max_payloads", 12) or 12))
        except (TypeError, ValueError):
            max_payloads = 12
        forbidden = identities[-1]
        others = {m for identity in identities
                  if identity.name != forbidden.name
                  for m in identity.own_markers()}
        absent = f"zz-absent-{report['run_token']}"
        payload_calls = 0
        for surface in surfaces:
            if time.monotonic() >= stop_at or self.should_stop(reserve=25):
                report["untested"].append(
                    {"surface": surface["url"], "reason": "time-box hit"})
                break
            base_rows = rows_of(str((await self._fetch(
                harness, forbidden.name, surface["url"])).get("body") or ""))
            base_markers = {m for row in base_rows
                            for m in _markers(row)}
            candidates = 0
            tried = 0
            for value in values:
                if payload_calls >= max_payloads:
                    # A surface probed against part of the value list is not a
                    # negative result; say which values never went out.
                    report["untested"].append({
                        "surface": surface["url"],
                        "reason": f"max_payloads reached after {tried} of "
                                  f"{len(values)} value(s)"})
                    return
                payload_calls += 1
                tried += 1
                probe_url = with_param(surface["url"], surface["param"], value)
                probe_rows = rows_of(str((await self._fetch(
                    harness, forbidden.name, probe_url)).get("body") or ""))
                if not probe_rows:
                    continue
                control_rows = rows_of(str((await self._fetch(
                    harness, forbidden.name,
                    with_param(surface["url"], surface["param"],
                               absent))).get("body") or ""))
                control_markers = {m for row in control_rows
                                   for m in _markers(row)}
                matched_other = sorted(
                    ({m for row in probe_rows for m in _markers(row)}
                     & others) - base_markers - control_markers)
                if not matched_other:
                    continue
                candidates += 1
                report["state_counts"]["candidate"] += 1
                report["probes"].append({
                    "surface": surface["url"], "param": surface["param"],
                    "identity": forbidden.name, "state": "candidate",
                    "row_delta": len(probe_rows),
                    "attributed_markers": len(matched_other),
                    "note": "real records only — values are never stored",
                })
                self._file_candidate(surface, len(matched_other))
            if not candidates:
                # The surface was driven and stayed clean: the only honest
                # negative this pass can offer for it.
                report["state_counts"]["observation"] += 1
                report["observations"].append({
                    "surface": surface["url"], "param": surface["param"],
                    "vector": surface["vector"], "source": surface["source"],
                    "identity": forbidden.name, "values_tried": tried,
                    "state": "no_signal",
                })

    @staticmethod
    async def _fetch(harness, identity: str, url: str) -> dict:
        if identity in ("anonymous", ""):
            return await harness.request_anonymous(url)
        return await harness.request(identity, url)

    # ── Canary protocol (the only PROOF path) ────────────────────

    async def _run_canaries(self, harness, canary_cfg: dict, run_token: str,
                            report: dict) -> None:
        owner = str(canary_cfg.get("owner_identity") or "")
        forbidden = str(canary_cfg.get("forbidden_identity") or "anonymous")
        if not owner or owner == forbidden:
            report["untested"].append(
                {"surface": "canary", "reason": "owner identity not usable"})
            return
        if owner not in harness.identities:
            report["untested"].append(
                {"surface": "canary", "reason": f"owner {owner!r} unknown"})
            return
        max_canaries = max(0, int(canary_cfg.get("max", 2) or 2))
        record = canary_cfg.get("record") or {}
        read = canary_cfg.get("read") or {}
        direct_template = str(read.get("direct_url_template") or "")
        create_target = str(record.get("url_template") or "")
        extract_id = record.get("extract_id") or {}
        seed = run_token
        for spec in (canary_cfg.get("probes") or [])[:max_canaries]:
            outcome = await self._canary_once(
                harness, owner, forbidden, spec, record, read, direct_template,
                create_target, extract_id, seed, canary_cfg)
            if outcome.get("proven"):
                report["state_counts"]["proof"] += 1
            report["canaries"].append(outcome)

    async def _canary_once(self, harness, owner: str, forbidden: str,
                           spec: dict, record: dict, read: dict,
                           direct_template: str, create_target: str,
                           extract_id: dict, seed: str,
                           canary_cfg: dict) -> dict:
        mut_id = self.state.mutations.begin(
            self.id, "object_create",
            {"url_template": create_target,
             "method": record.get("method", "POST")},
            identity=owner,
            owned_objects=[OwnedObject(type="resource", identifier="")])
        body = str(record.get("body_template") or "{}").replace("{run}", seed)
        created = await self._fetch_with_body(
            harness, owner, self._abs(create_target),
            str(record.get("method") or "POST"), body)
        ref = _extract(extract_id, str(created.get("body") or ""))
        name = str(spec.get("name") or spec.get("param") or "canary")
        result = {"name": name, "created_by": owner, "read_by": forbidden,
                  "mut_id": mut_id, "proven": False}
        if not ref:
            self.state.mutations.mark_failed(
                mut_id, "created object could not be bound")
            result["error"] = "created object could not be bound"
            return result
        direct_url = self._abs(direct_template.replace("{id}", str(ref)))
        # Owner baseline: the seed must be readable directly by its owner.
        owner_direct = await self._fetch(harness, owner, direct_url)
        owner_value = _extract(read.get("extract") or {},
                               str(owner_direct.get("body") or ""))
        seed_intact = owner_value == seed
        # Forbidden direct read must be DENIED — otherwise this is IDOR,
        # not a filter leak, and the module must not claim a proof.
        forbidden_direct = await self._fetch(harness, forbidden, direct_url)
        direct_status = int(forbidden_direct.get("status", 0) or 0)
        direct_denied = direct_status in (401, 403, 404, 410)
        if not direct_denied or not seed_intact:
            self.state.mutations.mark_failed(
                mut_id, "prerequisite failed: direct-read lane, not a filter leak")
            result.update({"direct_read_status": direct_status,
                           "seed_intact": seed_intact,
                           "reason": "prerequisite failed "
                                     f"(direct read {direct_status})"})
            return result
        probe_url_template = self._abs(str(spec.get("url_template") or ""))
        param = str(spec.get("param") or "q")
        extract = spec.get("extract") or read.get("extract") or {}
        value_for_probe = seed if spec.get("bind") == "seed" else str(
            spec.get("value") or seed)
        baseline_url = probe_url_template
        baseline = await self._fetch(harness, forbidden, baseline_url)
        baseline_hit = _extract(extract, str(baseline.get("body") or "")) == seed
        absent_url = with_param(probe_url_template, param,
                                f"zz-absent-{seed}")
        absent = await self._fetch(harness, forbidden, absent_url)
        absent_hit = _extract(extract, str(absent.get("body") or "")) == seed
        leak_url = with_param(probe_url_template, param, value_for_probe)
        leaked = await self._fetch(harness, forbidden, leak_url)
        observed = _extract(extract, str(leaked.get("body") or ""))
        owner_positive = await self._fetch(harness, owner, leak_url)
        owner_hit = _extract(extract, str(owner_positive.get("body") or "")) == seed
        leaked_hit = observed == seed
        cleanup_status = await finalize_canary_cleanup(
            self.state,
            lambda identity, url, method="GET":
                self._fetch(harness, identity, url, method=method),
            self._base_url(), mut_id, ref,
            canary_cfg.get("cleanup") or {}, owner)
        proven = bool(leaked_hit and not baseline_hit and not absent_hit
                      and seed_intact and cleanup_status == "verified")
        result.update({
            "observed": observed if leaked_hit else None,
            "direct_read_status": direct_status,
            "seed_intact": seed_intact,
            "baseline_contains": baseline_hit,
            "absent_contains": absent_hit,
            "owner_positive": owner_hit,
            "proven": proven,
            "cleanup_status": cleanup_status,
            "param": param,
        })
        if proven:
            evidence = self.state.add_evidence(
                self.id, "orm_filter_canary", self._base_url(),
                {"name": name, "param": param,
                 "mut_id": mut_id, "cleanup_status": cleanup_status})
            self._file_proof(spec, param, evidence)
        return result

    @staticmethod
    async def _fetch_with_body(harness, identity: str, url: str, method: str,
                               body: str) -> dict:
        kwargs = {"method": method,
                  "headers": {"Content-Type": "application/json"},
                  "data": body}
        if identity in ("anonymous", ""):
            return await harness.request_anonymous(url, **kwargs)
        return await harness.request(identity, url, **kwargs)

    # ── Findings ─────────────────────────────────────────────────

    def _fingerprint(self, url: str, param: str, vector: str = "") -> str:
        host = urlparse(self._base_url()).hostname or ""
        path = urlparse(url).path
        base = json.dumps({"module": "orm_filter_audit", "host": host,
                           "path": path, "param": param, "vector": vector},
                          sort_keys=True)
        return hashlib.sha256(base.encode()).hexdigest()[:16]

    def _file_candidate(self, surface: dict, markers: int) -> None:
        fp = self._fingerprint(surface["url"], surface["param"],
                               surface["vector"])
        self.state.add_finding(
            title=(f"ORM filter leak candidate: {surface['vector']} "
                   f"'{surface['param']}' on {surface['url']} [{fp[:8]}]"),
            severity="MEDIUM",
            confidence="FIRM",
            category="ORM Filter Leak",
            description=(
                f"Filter parameter '{surface['param']}' returned rows "
                f"attributable to another identity ({markers} marker(s)) "
                f"that neither the direct read nor the baseline collection "
                f"exposes. Values are not stored; confirm with a seeded "
                f"canary before reporting."),
            evidence=[f"surface:{surface['url']}",
                      f"param:{surface['param']}",
                      f"vector:{surface['vector']}"],
            asset_keys=[f"url:{surface['url']}"],
            verified=False,
            verification={},
        )

    def _file_proof(self, spec: dict, param: str, evidence_ref: str) -> None:
        url = str(spec.get("url_template") or "")
        fp = self._fingerprint(url, param, "inclusion")
        self.state.add_finding(
            title=(f"ORM filter leak: '{param}' on {url} [{fp[:8]}]"),
            severity="HIGH",
            confidence="CONFIRMED",
            category="ORM Filter Leak",
            description=(
                f"A seeded record owned by one identity was retrievable by "
                f"another identity through filter parameter '{param}' while "
                f"its direct read was denied (401/403/404). Cleanup of the "
                f"seeded record was verified by re-read."),
            evidence=[f"canary:{spec.get('name') or param}", evidence_ref],
            asset_keys=[f"url:{url}"],
            verified=True,
            verification={"method": "filter_canary_observed",
                          "param": param, "observed_seed": True},
        )

    # ── Plumbing ─────────────────────────────────────────────────

    async def _fetch(self, harness, identity: str, url: str,
                     method: str = "GET") -> dict:
        if identity in ("anonymous", ""):
            return await harness.request_anonymous(url, method=method)
        return await harness.request(identity, url, method=method)

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


def _markers(row: dict) -> set[str]:
    from core.authorization import _identity_markers
    return _identity_markers(json.dumps(row, default=str))
