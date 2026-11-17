"""Installation entry points must reject versions below the security floors."""

from pathlib import Path
import runpy

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
import pytest
import setuptools


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def metadata(monkeypatch):
    captured = {}
    monkeypatch.setattr(setuptools, "setup", lambda **kwargs: captured.update(kwargs))
    monkeypatch.chdir(ROOT)
    runpy.run_path(str(ROOT / "setup.py"))
    return captured


@pytest.mark.parametrize("name,patched,vulnerable", [
    ("litellm", "1.95.0", "1.94.0"),
    ("aiohttp", "3.14.4", "3.14.3"),
    ("dnspython", "2.9.2", "2.9.1"),
    ("lxml", "6.1.0", "6.0.2"),
])
def test_security_floors_in_requirements_and_package_metadata(
        metadata, name, patched, vulnerable):
    requirements = [
        line.split("#", 1)[0].strip()
        for line in (ROOT / "requirements.txt").read_text().splitlines()
    ]
    package = metadata["install_requires"] + metadata["extras_require"]["full"]
    for declarations in (requirements, package):
        matches = [Requirement(line) for line in declarations
                   if line and Requirement(line).name == name]
        assert len(matches) == 1
        specifier = matches[0].specifier
        assert patched in specifier
        assert vulnerable not in specifier


def test_python_requirement_supports_patched_dnspython(metadata):
    supported = SpecifierSet(metadata["python_requires"])
    assert "3.10" not in supported
    assert "3.11" in supported
    assert "Programming Language :: Python :: 3.10" not in metadata["classifiers"]
