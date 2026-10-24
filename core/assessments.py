"""Origin-bound assessment storage. This selects data, never target scope."""

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
import uuid
from urllib.parse import urlsplit

from core.persistence import atomic_json, file_lock


def target_url(target: str) -> str:
    raw = str(target or "").strip()
    if not raw:
        raise ValueError("A target is required")
    if "://" not in raw:
        parts = urlsplit("//" + raw)
        raw = ("http://" if parts.port is not None else "https://") + raw
    return raw.rstrip("/")


def canonical_origin(target: str) -> str:
    parts = urlsplit(target_url(target))
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise ValueError("Assessment storage requires an HTTP(S) origin")
    host = parts.hostname.rstrip(".")
    try:
        host = ipaddress.ip_address(host).compressed
    except ValueError:
        host = host.encode("idna").decode("ascii").lower()
    if ":" in host:
        host = f"[{host}]"
    scheme = parts.scheme.lower()
    port = parts.port if parts.port is not None else (443 if scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("Invalid assessment origin port")
    suffix = "" if port == (443 if scheme == "https" else 80) else f":{port}"
    return f"{scheme}://{host}{suffix}"


def new_assessment_id() -> str:
    return uuid.uuid4().hex


def _assessment_id(value: str) -> str:
    if not re.fullmatch(r"[a-f0-9]{32}", str(value or "")):
        raise ValueError("Assessment ID must be 32 lowercase hexadecimal characters")
    return value


@dataclass(frozen=True)
class Assessment:
    directory: Path
    metadata: dict

    @property
    def id(self):
        return self.metadata["assessment_id"]


class AssessmentStore:
    def __init__(self, output_dir, target: str):
        self.root = Path(output_dir).resolve()
        self.origin = canonical_origin(target)
        parts = urlsplit(self.origin)
        label = re.sub(r"[^a-z0-9.-]", "-", parts.hostname.lower())[:48]
        digest = hashlib.sha256(self.origin.encode()).hexdigest()[:20]
        self.service_dir = self.root / "services" / f"{parts.scheme}-{label}-{digest}"

    def directory(self, assessment_id: str) -> Path:
        path = self.service_dir / "assessments" / _assessment_id(assessment_id)
        if not path.resolve().is_relative_to(self.root):
            raise ValueError("Assessment storage path escapes the output directory")
        return path

    def open(self, assessment_id: str) -> Assessment:
        path = self.directory(assessment_id)
        try:
            meta = json.loads((path / "assessment.json").read_text())
        except (OSError, ValueError) as exc:
            raise ValueError("Selected assessment is missing or has invalid metadata") from exc
        if (not isinstance(meta, dict) or meta.get("schema_version") != 1
                or meta.get("origin") != self.origin
                or meta.get("assessment_id") != assessment_id
                or not isinstance(meta.get("created_at"), str)
                or meta.get("kind") not in ("fresh", "retest", "legacy_import")
                or (meta.get("parent_assessment_id") is not None
                    and not re.fullmatch(r"[a-f0-9]{32}", str(meta["parent_assessment_id"])))):
            raise ValueError("Selected assessment does not match this origin and ID")
        from core.persistence import valid_snapshot
        try:
            snapshot = json.loads((path / "state" / "snapshot.json").read_text())
        except (OSError, ValueError) as exc:
            raise ValueError("Selected assessment has no valid committed state snapshot") from exc
        if (not valid_snapshot(snapshot) or snapshot["module"].get("assessment") != meta
                or snapshot["module"].get("investigation_id") != assessment_id):
            raise ValueError("Assessment identity does not match its committed snapshot")
        return Assessment(path, meta)

    def list(self) -> list[Assessment]:
        if not self.service_dir.exists():
            return []
        entries = []
        for path in (self.service_dir / "assessments").glob("*/assessment.json"):
            # Invalid entries are not candidates for automatic selection.
            try:
                entries.append(self.open(path.parent.name))
            except ValueError:
                continue
        return sorted(entries, key=lambda item: (item.metadata.get("created_at", ""), item.id),
                      reverse=True)

    def create(self, *, assessment_id=None, parent_id=None) -> Assessment:
        from state.manager import StateManager
        parent = self.open(parent_id) if parent_id else None
        identifier = _assessment_id(assessment_id or new_assessment_id())
        path = self.directory(identifier)
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
        meta = {"schema_version": 1, "origin": self.origin, "assessment_id": identifier,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "kind": "retest" if parent else "fresh", "parent_assessment_id": parent_id}
        state = StateManager(str(path))
        state.module["assessment"] = meta
        state.module["investigation_id"] = identifier
        state._dirty = True
        state.save()
        if parent:
            from core.history import load, save
            # A baseline is history, not current findings, evidence or completion.
            source_history = parent.directory / "findings_history.json"
            if source_history.exists():
                save(path / "findings_history.json", load(source_history, strict=True))
            else:
                from core.history import annotate, annotate_assets, empty
                previous = StateManager(str(parent.directory))
                _, baseline, _ = annotate(previous.findings["findings"], empty(), run_id=parent.id)
                baseline, _ = annotate_assets(previous.assets["nodes"], baseline, run_id=parent.id)
                save(path / "findings_history.json", baseline)
        # Publish only after state and the optional baseline are ready.
        atomic_json(path / "assessment.json", meta)
        return Assessment(path, meta)

    def select(self, mode="fresh", *, assessment_id=None, parent_id=None) -> Assessment:
        if mode == "resume":
            if parent_id:
                raise ValueError("Resume does not accept a baseline assessment")
            return self.open(_assessment_id(assessment_id))
        if mode == "retest":
            if not parent_id:
                raise ValueError("Retest requires --from-assessment")
            return self.create(assessment_id=assessment_id, parent_id=parent_id)
        if mode != "fresh" or parent_id:
            raise ValueError("Invalid assessment mode or baseline selection")
        return self.create(assessment_id=assessment_id)

    def import_legacy(self, source, *, assessment_id=None) -> Assessment:
        """Copy an explicitly selected, inactive legacy result tree; never move it."""
        from state.manager import StateManager
        source = Path(source).resolve()
        state_dir = source / "state"
        if (source / "assessment.json").exists():
            raise ValueError("This is already an assessment; use resume or retest")
        if not state_dir.is_dir() or not any(
                (state_dir / name).is_file() for name in ("snapshot.json", "assets.json", "findings.json")):
            raise ValueError("Legacy import requires an existing investigation state directory")
        if any(path.is_symlink() for path in source.rglob("*")):
            raise ValueError("Legacy import refuses symlinks; source files were not changed")
        identifier = _assessment_id(assessment_id or new_assessment_id())
        destination = self.directory(identifier)
        if destination.resolve().is_relative_to(source):
            raise ValueError("Import destination must not be inside its source")
        if destination.exists():
            raise ValueError("Assessment destination already exists")
        # Read-only validation: even constructing StateManager can create folders.
        snapshot = state_dir / "snapshot.json"
        if snapshot.exists():
            from core.persistence import valid_snapshot
            document = json.loads(snapshot.read_text())
            if not valid_snapshot(document):
                raise ValueError("Invalid legacy snapshot")
            module = document["module"]
        else:
            documents = {name: json.loads(path.read_text())
                         for name in ("assets", "findings", "module", "evidence")
                         if (path := state_dir / f"{name}.json").exists()}
            if any(not isinstance(value, dict) for value in documents.values()):
                raise ValueError("Invalid legacy investigation JSON")
            module = documents.get("module", {})
        if module.get("assessment"):
            raise ValueError("Legacy source already has assessment identity")
        shutil.copytree(source, destination)
        destination.chmod(0o700)
        copied = StateManager(str(destination))
        meta = {"schema_version": 1, "origin": self.origin, "assessment_id": identifier,
                "created_at": datetime.now(timezone.utc).isoformat(), "kind": "legacy_import",
                "parent_assessment_id": None, "origin_binding": "operator_declared"}
        copied.module["assessment"] = meta
        copied.module["investigation_id"] = identifier
        copied._dirty = True
        copied.save()
        budget_path = destination / "state" / "budget.json"
        if budget_path.exists():
            budget = json.loads(budget_path.read_text())
            if not isinstance(budget, dict) or not isinstance(budget.get("state"), dict):
                raise ValueError("Invalid legacy budget checkpoint")
            budget["assessment"] = meta
            atomic_json(budget_path, budget)
        atomic_json(destination / "assessment.json", meta)
        return Assessment(destination, meta)


class AssessmentLease:
    """Only one executor may change an assessment's budget/audit/state at a time."""

    def __init__(self, directory):
        self._context = file_lock(Path(directory) / "execution.lock", blocking=False)
        try:
            self._context.__enter__()
        except OSError as exc:
            self._context = None
            raise ValueError("Selected assessment is already running or its execution lease is inaccessible") from exc

    def close(self):
        context, self._context = self._context, None
        if context is not None:
            context.__exit__(None, None, None)

    def __del__(self):
        self.close()
