"""Authorization matrix engine (I3).

One shared engine for the IDOR, BFLA and GraphQL audits: every probe is a
*cell* in the identity × tenant × operation × object × field matrix. Cells
are classified by differential reads across identity pairs — a cross-identity
read is only a leak when it passes three gates: not denied/absent, not
indistinguishable from a missing-object control, and attributed to the
victim's own markers (whole-object) or a field-level diff under an
ownership-hinted key.

Nothing here self-promotes to a verified finding: PROOF comes only from
configured canary probes (a seeded object a forbidden identity must not
read/act on, re-checked by the owner afterwards), and every canary
creation is recorded in the R8 mutation ledger with verified cleanup.

The pure helpers below were moved from ``modules/idor_differ`` and are
re-exported there for compatibility; behavior is unchanged.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field as dc_field
from typing import Any, Optional

_OWNER_KEY_HINTS = (
    "email", "e_mail", "username", "user_name", "login", "handle",
    "full_name", "fullname", "first_name", "last_name", "display_name",
    "phone", "ssn", "address", "owner", "owner_id", "user_id", "account_id",
    "customer_email", "billing_email", "contact_email",
)
_OWNER_HINTS_FLAT = {h.replace("_", "") for h in _OWNER_KEY_HINTS}


def _maybe_json(text: str):
    stripped = (text or "").strip()
    if not stripped or stripped[0] not in "[{":
        return None
    try:
        return json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
        return None


def _looks_like_owner_key(low: str) -> bool:
    """Does this response key plausibly name whose record this is?"""
    if low.replace("_", "") in _OWNER_HINTS_FLAT:
        return True
    return any(hint in low for hint in ("email", "name", "owner", "account"))


def _walk_identifiers(node: Any, key_hint: str = ""):
    """Yield (key, value) pairs whose key looks ownership-related."""
    if isinstance(node, dict):
        for key, value in node.items():
            low = str(key).lower().replace("-", "_")
            if _looks_like_owner_key(low) and isinstance(value, (str, int, float)):
                if str(value).strip():
                    yield key, value
            yield from _walk_identifiers(value, low)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_identifiers(item, key_hint)


def _identity_markers(body: str) -> set:
    """Values in a response that plausibly identify whose data it is."""
    loose: set = set()
    for email in set(re.findall(r"[\w.+-]+@[\w-]+\.[\w.]{2,}", body or "")):
        loose.add(email.lower())

    strict: set = set()
    payload = _maybe_json(body)
    for key, value in _walk_identifiers(payload):
        raw = str(value).strip().lower()
        if not raw:
            continue
        flat = str(key).lower().replace("-", "_").replace("_", "")
        if flat in _OWNER_HINTS_FLAT:
            strict.add(raw)
        else:
            loose.add(raw)

    generic = {"", "null", "none", "true", "false", "0", "1", "admin", "user",
               "active", "pending", "usd", "eur", "gbp", "test", "demo"}
    result = {m for m in loose if len(m) > 3 and m not in generic}
    for m in strict:
        if m.isdigit():
            result.add(m)
        elif m not in generic and len(m) > 3:
            result.add(m)
    return result


def _leaf_paths(node: Any, prefix: str = "") -> list[str]:
    """Recursive JSON leaf paths: {"a": {"b": 1}} -> ["a.b"]."""
    if isinstance(node, dict):
        paths = []
        for key, value in node.items():
            paths.extend(_leaf_paths(value, f"{prefix}{key}."))
        return paths
    if isinstance(node, list):
        paths = []
        for index, item in enumerate(node):
            paths.extend(_leaf_paths(item, f"{prefix}{index}."))
        return paths
    return [prefix.rstrip(".")]


def _value_at(node: Any, path: str):
    current = node
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() \
                and int(part) < len(current):
            current = current[int(part)]
        else:
            return None
    return current


def _field_diff(owner_body: str, cross_body: str) -> list[str]:
    """Leaf paths that differ between two JSON bodies.

    Never whole-object inequality: only differing leaf values are reported,
    so timestamp/id noise can be filtered by the caller.
    """
    owner = _maybe_json(owner_body)
    cross = _maybe_json(cross_body)
    if not isinstance(owner, dict) or not isinstance(cross, dict):
        return [] if owner_body == cross_body else ["<root>"]
    owner_paths = set(_leaf_paths(owner))
    cross_paths = set(_leaf_paths(cross))
    diffs = []
    for path in sorted(owner_paths | cross_paths):
        if path not in owner_paths or path not in cross_paths:
            diffs.append(path)
            continue
        if json.dumps(_value_at(owner, path), sort_keys=True,
                      default=str) != json.dumps(_value_at(cross, path),
                                                 sort_keys=True, default=str):
            diffs.append(path)
    return diffs


def _body_shape(status: int, body: str) -> str:
    """Short structural signature for cell comparisons."""
    digest = hashlib.sha256((body or "").encode("utf-8")).hexdigest()[:12]
    payload = _maybe_json(body)
    keys = ",".join(sorted(payload.keys()))[:80] \
        if isinstance(payload, dict) else ""
    return f"{status}|{keys}|{digest}"


@dataclass
class MatrixCell:
    subject: str                    # identity name | "anonymous" | "stale:<n>"
    tenant: str
    operation: str                  # read | write | execute | query | mutation
    object: dict                    # {"template": ..., "ref": ...}
    field: str = ""
    status: int = 0
    outcome: str = "error"          # allowed | denied | absent | ambiguous |
                                    # leak | field_leak | error
    attribution: dict = dc_field(default_factory=dict)
    owner_baseline: Optional[dict] = None
    diff_fields: list = dc_field(default_factory=list)
    evidence_sha256: str = ""

    def to_dict(self) -> dict:
        return {
            "subject": self.subject,
            "tenant": self.tenant,
            "operation": self.operation,
            "object": self.object,
            "field": self.field,
            "status": self.status,
            "outcome": self.outcome,
            "attribution": self.attribution,
            "owner_baseline": self.owner_baseline,
            "diff_fields": self.diff_fields,
            "evidence_sha256": self.evidence_sha256,
        }


@dataclass
class MatrixReport:
    cells: list[MatrixCell] = dc_field(default_factory=list)
    checks: dict = dc_field(default_factory=dict)
    canaries: list = dc_field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "schema_version": 1,
            "cells": [c.to_dict() for c in self.cells],
            "checks": self.checks,
            "canaries": self.canaries,
        }

    def violations(self) -> list[MatrixCell]:
        return [c for c in self.cells
                if c.outcome in ("leak", "field_leak")]


class AuthorizationMatrix:
    """Differential authz checks over configured identity pairs."""

    def __init__(self, harness, base_url: str, cfg: dict, state, log=None):
        self.harness = harness
        self.base_url = base_url.rstrip("/")
        self.cfg = cfg or {}
        self.state = state
        self.log = log or (lambda *a, **k: None)
        self.report = MatrixReport()
        self._run_token = f"osint-canary-{_short_id()}"

    # ── primitives ───────────────────────────────────────────────

    async def _request(self, subject: str, url: str, method: str = "GET",
                       **kwargs) -> dict:
        if subject in ("anonymous", ""):
            return await self.harness.request_anonymous(
                url, method=method, **kwargs)
        return await self.harness.request(subject, url, method=method,
                                          **kwargs)

    def _session_failed(self, result: dict) -> bool:
        """A response that proves nothing because the session is dead."""
        status = int(result.get("status", 0) or 0)
        if status in (401, 403):
            return True
        body = (result.get("body", "") or "").lower()
        return "login" in body and "<form" in body

    def _absent_ref(self, ref: str) -> str:
        if ref.isdigit():
            return str(int(ref) + 1000000)
        return ("z" * len(ref))[:64]

    def _classify(self, result: dict, control: dict,
                  owner_baseline: dict, victim_markers: set,
                  control_markers: set) -> dict:
        """The three-gate classification used by every cell."""
        status = int(result.get("status", 0) or 0)
        body = result.get("body", "") or ""
        if status in (401, 403):
            return {"outcome": "denied", "status": status}
        if status in (404, 410) or status == 0:
            return {"outcome": "absent", "status": status}
        if self._session_failed(result):
            return {"outcome": "ambiguous", "status": status}
        if status >= 500:
            return {"outcome": "error", "status": status}
        if control and _body_shape(status, body) == _body_shape(
                control.get("status", 0), control.get("body", "") or ""):
            return {"outcome": "ambiguous", "status": status}
        markers = _identity_markers(body)
        attributed = markers - control_markers
        if attributed and victim_markers and attributed & victim_markers:
            return {"outcome": "leak", "status": status,
                    "attribution": {"markers": sorted(attributed)}}
        diffs = _field_diff(owner_baseline.get("body", ""), body)
        owner_fields = [p for p in diffs
                        if _looks_like_owner_key(p.split(".")[-1].lower())]
        if diffs and owner_fields:
            return {"outcome": "field_leak", "status": status,
                    "diff_fields": owner_fields,
                    "attribution": {"markers": sorted(markers)}}
        return {"outcome": "allowed", "status": status,
                "attribution": {"markers": sorted(markers)}}

    async def _cell(self, subject, victim, template: str,
                    ref: str, operation: str = "read") -> MatrixCell:
        subject_name = subject.name if hasattr(subject, "name") \
            else str(subject)
        victim_name = victim.name if hasattr(victim, "name") \
            else str(victim)
        url = self._url_for(template, ref)
        victim_markers = set(victim.own_markers() if hasattr(victim, "own_markers") else ())
        result = await self._request(subject_name, url)
        owner_baseline = None
        if subject_name != victim_name:
            own = await self._request(victim_name, url)
            owner_baseline = {"status": own.get("status", 0),
                              "body": own.get("body", "") or "",
                              "shape": _body_shape(own.get("status", 0),
                                                   own.get("body", "") or "")}
            # Self-attribution: the victim's own record names them, so the
            # markers in their own baseline are the victim's markers even
            # when no token claims or configured owner_markers exist.
            victim_markers |= _identity_markers(own.get("body", "") or "")
        control = None
        control_markers: set = set()
        if subject_name != victim_name and ref:
            control = await self._request(
                subject_name, self._url_for(template, self._absent_ref(ref)))
            control_markers = _identity_markers(
                control.get("body", "") or "") if control else set()
        classification = self._classify(result, control, owner_baseline or {},
                                        victim_markers, control_markers)
        cell = MatrixCell(
            subject=subject_name,
            tenant=self.base_url, operation=operation,
            object={"template": template, "ref": ref},
            status=classification.get("status", 0),
            outcome=classification.get("outcome", "error"),
            attribution=classification.get("attribution", {}),
            owner_baseline=owner_baseline,
            diff_fields=classification.get("diff_fields", []),
        )
        cell.evidence_sha256 = hashlib.sha256(
            json.dumps(cell.to_dict(), sort_keys=True,
                       default=str).encode("utf-8")).hexdigest()[:16]
        return cell

    def _url_for(self, template: str, ref: str) -> str:
        concrete = str(template).replace("{id}", str(ref))
        if concrete.startswith(("http://", "https://")):
            return concrete
        return self.base_url + concrete

    # ── checks ───────────────────────────────────────────────────

    async def run_ownership(self, objects: list[dict],
                            identity_pairs: list[tuple]) -> None:
        """objects: [{"template": "/api/x/{id}", "ref": "200", "owner": Identity}]"""
        max_cells = max(1, int(self.cfg.get("max_cells", 200) or 200))
        for attacker, victim in identity_pairs[:max_cells]:
            for obj in objects[:max_cells]:
                if len(self.report.cells) >= max_cells:
                    return
                cell = await self._cell(attacker, victim,
                                        obj["template"], obj["ref"])
                cell.attribution["owner"] = getattr(
                    obj.get("owner"), "name", "") or victim.name
                self.report.cells.append(cell)

    async def run_sharing(self, sharing: list[dict],
                          identities: dict) -> None:
        results = []
        for spec in sharing:
            template = str(spec.get("read_probe") or spec.get("url_template")
                           or "")
            refs = list(spec.get("ids") or [])
            if not template or not refs:
                continue
            for ref in refs:
                bodies = {}
                for name, identity in identities.items():
                    url = self.base_url + template.replace("{id}", str(ref))
                    result = await self._request(name, url)
                    bodies[name] = _body_shape(result.get("status", 0),
                                               result.get("body", "") or "")
                ok = len(set(bodies.values())) == 1 \
                    and all(not s.startswith(("401|", "403|", "0|"))
                            for s in bodies.values())
                results.append({"template": template, "ref": ref,
                                "shapes": bodies, "ok": ok})
        self.report.checks["sharing"] = {
            "specs": len(results),
            "ok": sum(1 for r in results if r["ok"]),
            "regressions": [r for r in results if not r["ok"]],
        }

    async def run_freshness(self, identity) -> None:
        """Re-establish the session and compare against the first read."""
        url = self.base_url + "/"
        before = await self._request(identity.name, url)
        try:
            ok = await identity.establish(self.base_url)
        except Exception as exc:
            self.report.checks["freshness"] = {
                "drift": [], "error": str(exc)}
            return
        after = await self._request(identity.name, url)
        drift = []
        if self._session_failed(before) != self._session_failed(after):
            drift.append("session-state drift after re-establishment")
        if not ok:
            drift.append("fresh session could not be verified")
        self.report.checks["freshness"] = {"drift": drift, "verified": ok}

    async def run_revocation(self, identity, logout_spec: dict = None) -> None:
        """Sacrificial-session revocation: logout S1, prove denied, then
        re-establish S2 and prove allowed. Never touches primary creds."""
        spec = logout_spec or {}
        logout_url = spec.get("url")
        if not logout_url and hasattr(identity, "logout_url"):
            logout_url = identity.logout_url
        if not logout_url:
            self.report.checks["revocation"] = {
                "identity": identity.name, "status": "untested",
                "reason": "no logout_url configured"}
            return
        try:
            await identity.establish(self.base_url)
        except Exception:
            pass
        try:
            logged_out = await identity.logout(self.base_url)
        except Exception:
            logged_out = False
        probe = await self._request(identity.name,
                                    self.base_url + (spec.get("probe") or "/"))
        denied_after = self._session_failed(probe) \
            or int(probe.get("status", 0) or 0) in (401, 403, 404)
        reestablished = False
        try:
            reestablished = bool(await identity.establish(self.base_url))
        except Exception:
            reestablished = False
        self.report.checks["revocation"] = {
            "identity": identity.name,
            "status": "proven" if (logged_out and denied_after
                                   and reestablished) else "inconclusive",
            "after_logout": "denied" if denied_after else "not-denied",
            "reestablished": "allowed" if reestablished else "failed",
        }

    # ── canaries ─────────────────────────────────────────────────

    async def run_canaries(self, specs: list[dict]) -> list[dict]:
        """Configured canary probes — the ONLY path to verified PROOF.

        Each canary: owner creates a seeded object (R8-recorded), the
        forbidden identity attempts the read/action, the owner re-reads to
        confirm the seed survived (rules out transient errors), then the
        object is cleaned up and the cleanup verified.
        """
        from core.mutations import OwnedObject
        from core.workflows import _extract

        max_canaries = max(0, int(self.cfg.get("canaries", {}).get("max", 3)
                                  or 3))
        results = []
        for spec in (specs or [])[:max_canaries]:
            owner = str(spec.get("owner_identity") or "")
            forbidden = str(spec.get("forbidden_identity") or "anonymous")
            create = spec.get("create") or {}
            seed = str(spec.get("seed") or self._run_token)
            body = str(create.get("body_template") or "{}").replace(
                "{run}", seed)
            mut_id = self.state.mutations.begin(
                "authorization_matrix", "object_create",
                {"url_template": create.get("url_template"),
                 "method": create.get("method", "POST")},
                identity=owner,
                owned_objects=[OwnedObject(type="resource", identifier="")])
            created = await self._request(
                owner, self.base_url + str(create.get("url_template") or ""),
                method=str(create.get("method") or "POST"),
                headers={"Content-Type": "application/json"},
                data=body)
            created_body = str(created.get("body") or "")
            ref = _extract(create.get("extract_id") or {}, created_body)
            probe = spec.get("read_probe") or {}
            if not ref or not probe.get("url_template"):
                self.state.mutations.mark_failed(
                    mut_id, "canary create produced no bindable id")
                results.append({"name": spec.get("name"), "proven": False,
                                "error": "no bindable id"})
                continue
            url = self.base_url + str(probe.get("url_template")).replace(
                "{id}", ref)
            observed = await self._request(forbidden, url)
            value = _extract(probe.get("extract") or {},
                             str(observed.get("body") or ""))
            expected = spec.get("expected", "denied")
            denied = self._session_failed(observed) \
                or int(observed.get("status", 0) or 0) in (401, 403, 404)
            # A leak is the forbidden identity OBSERVING the seed. A denied
            # or absent read is healthy and proves nothing.
            leaked = bool(value == seed)
            # Owner re-read: the object must still exist and carry the seed.
            owner_read = await self._request(owner, url)
            owner_value = _extract(probe.get("extract") or {},
                                   str(owner_read.get("body") or ""))
            intact = owner_value == seed
            record = {
                "name": spec.get("name"),
                "created_by": owner,
                "read_by": forbidden,
                "observed": value,
                "expected": expected,
                "proven": bool(leaked and intact),
                "denied": denied,
                "seed_intact": intact,
                "mut_id": mut_id,
            }
            await self._cleanup_canary(mut_id, ref, spec.get("cleanup") or {},
                                       owner, forbidden)
            record["cleanup_status"] = self.state.mutations.current(
                mut_id)["cleanup"]["status"]
            results.append(record)
        self.report.canaries = results
        return results

    async def _cleanup_canary(self, mut_id: str, ref: str, cleanup: dict,
                              owner: str, forbidden: str) -> None:
        await finalize_canary_cleanup(
            self.state, self._request, self.base_url,
            mut_id, ref, cleanup, owner)

    # ── grading ──────────────────────────────────────────────────

    def finding_rows(self, module_id: str) -> list[dict]:
        """(tier, title, severity, confidence, verified) rows. CANDIDATE
        for leaks; PROOF only for proven canaries."""
        rows = []
        leaks = self.report.violations()
        for cell in leaks:
            rows.append({
                "tier": "candidate",
                "title": (f"Authorization matrix leak: {cell.subject} read "
                          f"{cell.object.get('template')} "
                          f"[{cell.evidence_sha256[:8]}]"),
                "severity": "HIGH",
                "confidence": "FIRM",
                "verified": False,
                "cell": cell,
            })
        for canary in self.report.canaries:
            if canary.get("proven"):
                rows.append({
                    "tier": "proof",
                    "title": (f"Authorization canary proven: "
                              f"{canary['name']} ({canary['read_by']} "
                              f"observed the seeded object)"),
                    "severity": "CRITICAL",
                    "confidence": "CONFIRMED",
                    "verified": True,
                    "verification": {
                        "method": "canary_read_attributed",
                        "name": canary["name"],
                        "observed": canary.get("observed"),
                        "seed_intact": canary.get("seed_intact"),
                    },
                    "canary": canary,
                })
        return rows


def _short_id() -> str:
    import uuid
    return uuid.uuid4().hex[:8]


async def finalize_canary_cleanup(state, request, base_url: str,
                                   mut_id: str, ref: str, cleanup: dict,
                                   owner: str) -> str:
    """Delete a canary record and record the honestly-verified cleanup.

    ``request(identity, url, method=...)`` is the caller's transport.
    Returns the terminal cleanup status: verified | failed | not_required.
    """
    template = str((cleanup or {}).get("url_template") or "")
    if not template:
        state.mutations.mark_not_required(mut_id, "no canary cleanup spec")
        return "not_required"
    url = base_url.rstrip("/") + template.replace("{id}", str(ref))
    result = await request(owner, url,
                           method=str(cleanup.get("method") or "DELETE"))
    verify = cleanup.get("verify") or {}
    check = await request(owner, url)
    check_status = int(check.get("status", 0) or 0)
    expect = list(verify.get("expect_status") or [404, 410])
    gone = check_status in expect or check_status >= 400
    verification = {"method": str(verify.get("method") or "http_get"),
                    "cleanup_status": result.get("status", 0),
                    "check_status": check_status}
    state.mutations.record_rollback(
        mut_id, "verified" if gone else "failed",
        verification=verification)
    if gone:
        state.mutations.verify_cleanup(mut_id, verification)
        return "verified"
    state.mutations.mark_failed(
        mut_id, f"canary cleanup verify read returned {check_status}")
    return "failed"
