"""I5 source-rule importer tests: offline parsing, name extraction only."""

from __future__ import annotations

import tempfile
from pathlib import Path

from tools.orm_source_rules import load_rules, sensitive_fields

FIXTURES = Path(__file__).parent / "fixtures" / "orm_rules"


def test_parses_django_model_and_filterset():
    rules = load_rules(str(FIXTURES))
    django = [r for r in rules if r["framework"] == "django"]
    assert django
    rule = django[0]
    assert "name" in rule["fields"]
    assert "owner" in rule["filterable"]
    assert "private_note" in rule["searchable"]


def test_parses_sqlalchemy_columns_and_relationships():
    rules = load_rules(str(FIXTURES))
    sqla = [r for r in rules if r["framework"] == "sqlalchemy"]
    models = {r["model"] for r in sqla}
    assert "sqlalchemy_models" in models or sqla
    all_fields = {f for r in sqla for f in r["fields"]}
    assert "api_token" in all_fields
    assert any("Account" in r["relationships"] for r in sqla)


def test_parses_rails_ransack_and_permit():
    rules = load_rules(str(FIXTURES))
    rails = [r for r in rules if r["framework"] == "rails"]
    assert rails
    rule = rails[0]
    assert "owner_id" in rule["filterable"]
    assert "notes" in rule["relationships"]


def test_sensitive_fields_hint_matching():
    rule = {"fields": ["name", "api_token", "email", "ssn"]}
    assert set(sensitive_fields(rule)) == {"api_token", "email", "ssn"}


def test_missing_root_returns_empty():
    assert load_rules("") == []
    assert load_rules(str(FIXTURES / "does-not-exist")) == []


def test_large_and_binary_files_skipped():
    root = Path(tempfile.mkdtemp())
    (root / "big.py").write_bytes(b"x = 1\n" * 200000)  # > 512 KiB
    (root / "blob.py").write_bytes(b"\x00\x01\x02" * 100)
    (root / "ok.py").write_text("class A:\n    name = models.CharField()\n")
    rules = load_rules(str(root))
    assert all("big.py" not in r["source"] for r in rules)
    assert all("blob.py" not in r["source"] for r in rules)
