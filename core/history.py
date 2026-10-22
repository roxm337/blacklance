"""Cross-run finding history: what is new, recurring, or resolved.

State is per-target, so the previous run's findings are the baseline. A
finding absent from this run is resolved *relative to the last scan*, not
"fixed" — the report says which.
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from core.fingerprints import fingerprint, finding_url

VERSION = 1


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def empty() -> dict:
    return {"version": VERSION, "findings": {}}


def load(path) -> dict:
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError, json.JSONDecodeError):
        return empty()
    if not isinstance(data, dict) or not isinstance(data.get("findings"), dict):
        return empty()
    assets = data.get("assets")
    return {"version": data.get("version", VERSION),
            "findings": data["findings"],
            "assets": assets if isinstance(assets, dict) else {}}


def save(path, history: dict) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(history, indent=2, default=str))


def annotate(findings: list, history: dict, now: str | None = None) -> tuple:
    """Return (annotated findings, updated history, diff).

    Pure: the caller decides when to persist. Each finding gains a
    `history` block; occurrences count runs, not duplicate records.
    """
    stamp = now or _now()
    updated = {"version": VERSION,
               "findings": {k: dict(v) for k, v in
                            (history.get("findings") or {}).items()},
               "assets": {k: dict(v) for k, v in
                          (history.get("assets") or {}).items()}}
    diff = {"new": [], "recurring": [], "resolved": []}
    seen = set()
    annotated = []
    for finding in findings:
        url = finding_url(finding)
        fp = fingerprint(finding, url)
        seen.add(fp)
        previous = updated["findings"].get(fp)
        if previous:
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
            "last_seen": stamp,
            "occurrences": occurrences,
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
        # Report a disappearance once; later runs must not re-alert on the
        # same already-resolved entry.
        if entry.get("last_status") != "resolved":
            diff["resolved"].append({"fingerprint": fp, **entry})
        entry["last_status"] = "resolved"
    return annotated, updated, diff


def annotate_assets(assets: list, history: dict,
                    now: str | None = None) -> tuple:
    """Track asset keys across runs, the same way findings are tracked.

    A new subdomain or endpoint is worth an alert even when nothing is wrong
    with it yet: it is new attack surface, and the next run will only scan it
    if the operator notices. Resolved assets are reported once for the same
    reason findings are — a disappearing endpoint means the surface changed,
    not that it was fixed.
    """
    stamp = now or _now()
    updated = {"version": history.get("version", VERSION),
               "findings": {k: dict(v) for k, v in
                            (history.get("findings") or {}).items()},
               "assets": {k: dict(v) for k, v in
                          (history.get("assets") or {}).items()}}
    diff = {"new": [], "recurring": [], "resolved": []}
    seen = set()
    for asset in assets:
        key = str(asset.get("key") or "").strip()
        if not key:
            continue
        seen.add(key)
        previous = updated["assets"].get(key)
        if previous:
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
            "last_seen": stamp,
            "occurrences": occurrences,
        }
        updated["assets"][key] = entry
        diff[status].append({"key": key, **entry})
    for key, entry in updated["assets"].items():
        if key in seen:
            entry["last_status"] = "active"
            continue
        if entry.get("last_status") != "resolved":
            diff["resolved"].append({"key": key, **entry})
        entry["last_status"] = "resolved"
    return updated, diff


def regression(bundle: dict, diff: dict, asset_diff: dict | None = None) -> dict:
    doc = {
        "target": (bundle.get("metadata") or {}).get("target"),
        "generated_at": (bundle.get("metadata") or {}).get("generated_at"),
        "counts": {key: len(value) for key, value in diff.items()},
        "new": diff["new"],
        "recurring": diff["recurring"],
        "resolved": diff["resolved"],
    }
    if asset_diff is not None:
        doc["assets"] = {
            "counts": {key: len(value) for key, value in asset_diff.items()},
            "new": asset_diff["new"],
            "recurring": asset_diff["recurring"],
            "resolved": asset_diff["resolved"],
        }
    return doc
