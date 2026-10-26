"""Evidence manifests and external anchors (R10).

Local hashes detect accidental corruption and local tampering, but they are
not signatures: an attacker who replaces the evidence, the manifest and the
anchor together leaves a self-consistent store. The anchor exists so the
operator can copy one small file to an external system; only then does the
record gain an out-of-store reference point.

The anchor file says this explicitly. Nothing here claims signing or
protection against whole-store replacement.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from core.persistence import atomic_json

MANIFEST_NAME = "evidence-manifest.json"
ANCHOR_NAME = "evidence-anchor.json"
ANCHOR_NOTE = (
    "This anchor contains a local manifest hash. A local hash is not a "
    "signature and does not protect against whole-store replacement. Copy "
    "this file to an external system to anchor the record."
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _root(state) -> Path:
    return Path(state.output_dir).resolve()


def _candidate_paths(state, extra_paths: Iterable) -> list[Path]:
    root = _root(state)
    evidence_dir = Path(getattr(state, "evidence_dir",
                                root / "evidence")).resolve()
    paths: list[Path] = []
    if evidence_dir.exists():
        paths.extend(path for path in evidence_dir.rglob("*")
                     if path.is_file())
    snapshot = root / "state" / "snapshot.json"
    if snapshot.is_file():
        paths.append(snapshot)
    for item in extra_paths or []:
        try:
            path = Path(item).resolve()
        except (TypeError, ValueError):
            continue
        if path.is_file():
            paths.append(path)
    unique = {path for path in paths
              if path.name not in (MANIFEST_NAME, ANCHOR_NAME)}
    return sorted(unique)


def build_manifest(state, extra_paths: Iterable = ()) -> dict:
    """Hash evidence, the state snapshot and any extra report artifacts."""
    root = _root(state)
    files = []
    for path in _candidate_paths(state, extra_paths):
        try:
            relative = str(path.relative_to(root))
        except ValueError:
            continue
        files.append({
            "path": relative,
            "sha256": _sha256(path),
            "size_bytes": path.stat().st_size,
        })
    manifest = {
        "schema_version": 1,
        "generated_at": _now(),
        "file_count": len(files),
        "total_bytes": sum(entry["size_bytes"] for entry in files),
        "files": files,
    }
    canonical = json.dumps(manifest, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
    manifest["manifest_sha256"] = hashlib.sha256(canonical).hexdigest()
    return manifest


def write_manifest(state, extra_paths: Iterable = ()) -> dict:
    """Write the manifest and its external-anchor file; return both paths."""
    manifest = build_manifest(state, extra_paths)
    root = _root(state)
    manifest_path = root / MANIFEST_NAME
    anchor_path = root / ANCHOR_NAME
    atomic_json(manifest_path, manifest)
    anchor = {
        "schema_version": 1,
        "manifest": MANIFEST_NAME,
        "manifest_sha256": manifest["manifest_sha256"],
        "generated_at": manifest["generated_at"],
        "note": ANCHOR_NOTE,
    }
    atomic_json(anchor_path, anchor)
    return {"path": str(manifest_path), "anchor": str(anchor_path),
            "manifest": manifest}


def verify_manifest(state, manifest_path: str | Path = "",
                    anchor_path: str | Path = "") -> dict:
    """Recompute every hash and verify the manifest and anchor linkage."""
    root = _root(state)
    manifest_file = Path(manifest_path) if manifest_path \
        else root / MANIFEST_NAME
    anchor_file = Path(anchor_path) if anchor_path else root / ANCHOR_NAME
    try:
        manifest = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"ok": False, "reason": "manifest missing or unreadable"}
    files = manifest.get("files") if isinstance(manifest, dict) else None
    if not isinstance(files, list):
        return {"ok": False, "reason": "manifest has no file list"}

    changed, missing = [], []
    for entry in files:
        if not isinstance(entry, dict):
            changed.append("<invalid entry>")
            continue
        relative = str(entry.get("path") or "")
        path = (root / relative).resolve()
        if not path.is_relative_to(root):
            changed.append(relative or "<empty path>")
            continue
        if not path.is_file():
            missing.append(relative)
            continue
        if _sha256(path) != entry.get("sha256") \
                or path.stat().st_size != entry.get("size_bytes"):
            changed.append(relative)

    stored = str(manifest.get("manifest_sha256") or "")
    canonical = json.dumps(
        {key: value for key, value in manifest.items()
         if key != "manifest_sha256"},
        sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest_ok = stored == hashlib.sha256(canonical).hexdigest()

    anchor_ok = None
    if anchor_file.is_file():
        try:
            anchor = json.loads(anchor_file.read_text(encoding="utf-8"))
            anchor_ok = str(anchor.get("manifest_sha256") or "") == stored
        except (OSError, ValueError):
            anchor_ok = False

    return {
        "ok": bool(manifest_ok and not changed and not missing
                   and anchor_ok is not False),
        "files_checked": len(files),
        "changed": changed,
        "missing": missing,
        "manifest_ok": manifest_ok,
        "anchor_ok": anchor_ok,
    }
