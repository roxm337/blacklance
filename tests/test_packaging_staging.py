"""A stale build directory must not silently reintroduce excluded files."""

from pathlib import Path
import runpy

import pytest
import setuptools
from setuptools import Distribution


def _builder(tmp_path, monkeypatch):
    captured = {}
    monkeypatch.setattr(setuptools, "setup", lambda **kwargs: captured.update(kwargs))
    root = Path(__file__).resolve().parents[1]
    runpy.run_path(str(root / "setup.py"))
    monkeypatch.chdir(root)
    dist = Distribution({"packages": ["core"], "script_name": "setup.py"})
    builder = captured["cmdclass"]["build_py"](dist)
    builder.build_lib = str(tmp_path / "staging")
    builder.ensure_finalized()
    return builder


def test_clean_staging_builds_with_resources(tmp_path, monkeypatch):
    builder = _builder(tmp_path, monkeypatch)
    builder.run()
    stage = Path(builder.build_lib)
    assert (stage / "core" / "persistence.py").is_file()
    assert (stage / "osint_agent_resources" / "config.example.yaml").is_file()


@pytest.mark.parametrize("stale", ["tests/old.py", ".DS_Store", ".env"])
def test_dirty_staging_is_rejected_without_deleting_files(tmp_path, monkeypatch, stale):
    builder = _builder(tmp_path, monkeypatch)
    path = Path(builder.build_lib) / stale
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("fixture")
    with pytest.raises(RuntimeError, match="fresh build directory"):
        builder.run()
    assert path.read_text() == "fixture"
