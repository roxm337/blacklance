"""Observation history. Absence is untested unless a negative retest is supplied."""

import json
from datetime import datetime, timezone
from pathlib import Path

from core.fingerprints import fingerprint, finding_url
from core.persistence import atomic_json

VERSION = 2


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def empty() -> dict:
    return {"version": VERSION, "findings": {}}


def load(path, *, strict: bool = False) -> dict:
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError, json.JSONDecodeError):
        if strict and Path(path).exists():
            raise ValueError(f"Cannot read history without losing its baseline: {path}")
        return empty()
    if not isinstance(data, dict) or not isinstance(data.get("findings"), dict):
        if strict:
            raise ValueError(f"Invalid history baseline: {path}")
        return empty()
    if (data.get("version", 1) not in (1, VERSION)
            or any(not isinstance(entry, dict) for entry in data["findings"].values())
            or not isinstance(data.get("assets", {}), dict)
            or any(not isinstance(entry, dict) for entry in data.get("assets", {}).values())):
        raise ValueError(f"Unsupported or invalid history baseline: {path}")
    assets = data.get("assets")
    return {"version": data.get("version", VERSION),
            "findings": data["findings"],
            "assets": assets if isinstance(assets, dict) else {}}


def save(path, history: dict) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    atomic_json(target, history)


def annotate(findings: list, history: dict, now: str | None = None, *,
             run_id: str | None = None, retested: set[str] | None = None,
             observation_ids: dict[str, str] | None = None) -> tuple:
    """Return (annotated findings, updated history, diff).

    Pure: the caller decides when to persist. Each finding gains a
    `history` block; occurrences count distinct observations, not exports or
    duplicate records. Callers with persisted item timestamps can supply stable
    per-item observation_ids instead of counting unrelated run activity.
    """
    stamp = now or _now()
    observation = run_id or stamp
    updated = {"version": VERSION,
               "findings": {k: dict(v) for k, v in
                            (history.get("findings") or {}).items()},
               "assets": {k: dict(v) for k, v in
                          (history.get("assets") or {}).items()}}
    diff = {"new": [], "recurring": [], "resolved": [], "untested": []}
    seen = set()
    annotated = []
    for finding in findings:
        url = finding_url(finding)
        fp = fingerprint(finding, url)
        if fp in seen:
            continue
        seen.add(fp)
        previous = updated["findings"].get(fp)
        item_observation = (observation_ids or {}).get(fp, observation)
        same_run = bool(previous and previous.get("last_run_id") == item_observation)
        if same_run:
            status = previous.get("history_status", "recurring")
            first_seen = previous["first_seen"]
            occurrences = previous["occurrences"]
        elif previous:
            status = "recurring"
            first_seen = previous.get("first_seen") or stamp
            occurrences = int(previous.get("occurrences") or 1) + 1
        else:
            status = "new"
            first_seen = stamp
            occurrences = 1
        entry = {
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "category": finding.get("category"),
            "url": url,
            "first_seen": first_seen,
            "last_seen": previous["last_seen"] if same_run else stamp,
            "occurrences": occurrences,
            "module_id": finding.get("module_id", ""),
            "last_run_id": item_observation,
            "history_status": status,
        }
        updated["findings"][fp] = entry
        diff[status].append({"fingerprint": fp, **entry})
        annotated.append({**finding,
                          "history": {"status": status,
                                      "first_seen": first_seen,
                                      "occurrences": occurrences}})
    for fp, entry in updated["findings"].items():
        if fp in seen:
            entry["last_status"] = "active"
            continue
        if entry.get("last_status") == "resolved":
            continue
        if fp in (retested or set()):
            diff["resolved"].append({"fingerprint": fp, **entry})
            entry["last_status"] = "resolved"
        else:
            diff["untested"].append({"fingerprint": fp, **entry})
            entry["last_status"] = "untested"
    return annotated, updated, diff


def annotate_assets(assets: list, history: dict,
                    now: str | None = None, *, run_id: str | None = None,
                    retested: set[str] | None = None,
                    observation_ids: dict[str, str] | None = None) -> tuple:
    """Track asset keys across runs, the same way findings are tracked.

    New surface is useful even when no finding exists. Missing surface stays
    untested unless the caller supplies its key in an explicit negative retest.
    Re-exporting the same run_id does not add another occurrence.
    """
    stamp = now or _now()
    observation = run_id or stamp
    updated = {"version": history.get("version", VERSION),
               "findings": {k: dict(v) for k, v in
                            (history.get("findings") or {}).items()},
               "assets": {k: dict(v) for k, v in
                          (history.get("assets") or {}).items()}}
    diff = {"new": [], "recurring": [], "resolved": [], "untested": []}
    seen = set()
    for asset in assets:
        key = str(asset.get("key") or "").strip()
        if not key or key in seen:
            continue
        seen.add(key)
        previous = updated["assets"].get(key)
        item_observation = (observation_ids or {}).get(key, observation)
        same_run = bool(previous and previous.get("last_run_id") == item_observation)
        if same_run:
            status = previous.get("history_status", "recurring")
            first_seen = previous["first_seen"]
            occurrences = previous["occurrences"]
        elif previous:
            status = "recurring"
            first_seen = previous.get("first_seen") or stamp
            occurrences = int(previous.get("occurrences") or 1) + 1
        else:
            status = "new"
            first_seen = stamp
            occurrences = 1
        entry = {
            "type": asset.get("type", ""),
            "value": asset.get("value", ""),
            "first_seen": first_seen,
            "last_seen": previous["last_seen"] if same_run else stamp,
            "occurrences": occurrences,
            "last_run_id": item_observation,
            "history_status": status,
        }
        updated["assets"][key] = entry
        diff[status].append({"key": key, **entry})
    for key, entry in updated["assets"].items():
        if key in seen:
            entry["last_status"] = "active"
            continue
        if entry.get("last_status") == "resolved":
            continue
        if key in (retested or set()):
            diff["resolved"].append({"key": key, **entry})
            entry["last_status"] = "resolved"
        else:
            diff["untested"].append({"key": key, **entry})
            entry["last_status"] = "untested"
    return updated, diff


def regression(bundle: dict, diff: dict, asset_diff: dict | None = None) -> dict:
    doc = {
        "target": (bundle.get("metadata") or {}).get("target"),
        "generated_at": (bundle.get("metadata") or {}).get("generated_at"),
        "counts": {key: len(value) for key, value in diff.items()},
        "new": diff["new"],
        "recurring": diff["recurring"],
        "resolved": diff["resolved"],
        "untested": diff.get("untested", []),
        "resolution_policy": "explicit negative retest required; absence is untested",
    }
    if asset_diff is not None:
        doc["assets"] = {
            "counts": {key: len(value) for key, value in asset_diff.items()},
            "new": asset_diff["new"],
            "recurring": asset_diff["recurring"],
            "resolved": asset_diff["resolved"],
            "untested": asset_diff.get("untested", []),
        }
    return doc
