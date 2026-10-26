"""Optional source-rule importer (I5).

Offline-only: reads operator-supplied framework sources (Django/DRF,
SQLAlchemy, Rails) and extracts *names* of filterable/searchable fields
and relationships. Rules only ever name probes; they are never evidence
of vulnerability, and no file content or secret value is retained.

Never used on the default runtime path — the module imports this lazily
and only when ``source_rules.enabled`` is set.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

MAX_FILE_BYTES = 512 * 1024
MAX_FILES = 500

DJANGO_FIELD = re.compile(r"^\s{4}(\w+)\s*=\s*models\.(\w+)\(", re.MULTILINE)
DJANGO_FILTERSET = re.compile(
    r"(filterset_fields|search_fields|ordering_fields)\s*=\s*[\[(]([^\]\)]*)[\])]",
    re.DOTALL)
DJANGO_FILTER_CALL = re.compile(r"\.filter\(\s*(\w+)\s*[=__]")
SQLA_COLUMN = re.compile(r"^\s{4}(\w+)\s*=\s*(?:Column|mapped_column)\(", re.MULTILINE)
SQLA_RELATION = re.compile(r"relationship\(\s*[\"'](\w+)")
SQLA_FILTER_BY = re.compile(r"filter_by\(\s*(\w+)\s*=")
RAILS_RANSACK = re.compile(
    r"ransackable_(attributes|associations)[^\n]*\n\s*%w[\[(]([^\]\)]*)[\])]")
RAILS_ASSOC = re.compile(r"^\s*(has_many|belongs_to|has_one)\s+:(\w+)",
                         re.MULTILINE)
RAILS_PERMIT = re.compile(r"\.permit\(\s*([^)]*)\)")

_HIDDEN_HINTS = ("password", "secret", "token", "ssn", "salary", "private",
                 "internal", "email", "phone", "credit")


def _parse_words(blob: str) -> list[str]:
    return [w.strip(" '\"\n\t") for w in re.split(r"[,\s]+", blob or "")
            if w.strip(" '\"\n\t")]


def _read_text(path: Path) -> Optional[str]:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        raw = path.read_bytes()
        if b"\x00" in raw[:4096]:
            return None
        return raw.decode("utf-8", errors="ignore")
    except OSError:
        return None


def parse_django(path: Path, text: str) -> list[dict]:
    fields = [m.group(1) for m in DJANGO_FIELD.finditer(text)]
    filterable, searchable, orderable = [], [], []
    for match in DJANGO_FILTERSET.finditer(text):
        key, blob = match.group(1), _parse_words(match.group(2))
        if key == "filterset_fields":
            filterable.extend(blob)
        elif key == "search_fields":
            searchable.extend(blob)
        else:
            orderable.extend(blob)
    filterable.extend(m.group(1) for m in DJANGO_FILTER_CALL.finditer(text))
    if not (fields or filterable or searchable):
        return []
    return [{"framework": "django", "model": path.stem,
             "fields": fields, "filterable": filterable,
             "searchable": searchable, "orderable": orderable,
             "relationships": [], "source": str(path)}]


def parse_sqlalchemy(path: Path, text: str) -> list[dict]:
    fields = [m.group(1) for m in SQLA_COLUMN.finditer(text)]
    rels = [m.group(1) for m in SQLA_RELATION.finditer(text)]
    filterable = [m.group(1) for m in SQLA_FILTER_BY.finditer(text)]
    if not (fields or rels):
        return []
    return [{"framework": "sqlalchemy", "model": path.stem,
             "fields": fields, "filterable": sorted(set(filterable)),
             "searchable": [], "orderable": [],
             "relationships": sorted(set(rels)), "source": str(path)}]


def parse_rails(path: Path, text: str) -> list[dict]:
    filterable, rels = [], []
    for match in RAILS_RANSACK.finditer(text):
        kind, blob = match.group(1), _parse_words(match.group(2))
        if kind == "attributes":
            filterable.extend(blob)
        else:
            rels.extend(blob)
    rels.extend(m.group(2) for m in RAILS_ASSOC.finditer(text))
    permitted = []
    for match in RAILS_PERMIT.finditer(text):
        permitted.extend(_parse_words(match.group(1)))
    if not (filterable or rels or permitted):
        return []
    return [{"framework": "rails", "model": path.stem,
             "fields": permitted, "filterable": sorted(set(filterable)),
             "searchable": [], "orderable": [],
             "relationships": sorted(set(rels)), "source": str(path)}]


def load_rules(root: str) -> list[dict]:
    """Parse operator-supplied sources under ``root`` (offline only)."""
    raw_root = str(root or "").strip()
    if not raw_root:
        return []
    base = Path(raw_root).expanduser()
    if not base.is_dir():
        return []
    rules: list[dict] = []
    count = 0
    for path in sorted(base.rglob("*")):
        if count >= MAX_FILES:
            break
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix not in (".py", ".rb"):
            continue
        text = _read_text(path)
        if not text:
            continue
        count += 1
        try:
            if suffix == ".py":
                rules.extend(parse_django(path, text))
                rules.extend(parse_sqlalchemy(path, text))
            else:
                rules.extend(parse_rails(path, text))
        except Exception:
            continue
    return rules


def sensitive_fields(rule: dict) -> list[str]:
    """Names that should only ever be probed through field projections."""
    return [name for name in (rule.get("fields") or [])
            if any(hint in str(name).lower() for hint in _HIDDEN_HINTS)]
