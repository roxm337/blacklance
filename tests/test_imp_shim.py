"""Tests for docker/imp_shim.py (cement 2.x on Python 3.12+).

The shim is baked into the toolchain image so droopescan imports; these
tests pin its find_module/load_module contract without needing the image.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _load_shim():
    path = (Path(__file__).resolve().parent.parent
            / "docker" / "imp_shim.py")
    spec = importlib.util.spec_from_file_location("imp_shim_under_test",
                                                  path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_reload_is_importlib_reload():
    shim = _load_shim()
    assert shim.reload is importlib.reload


def test_find_and_load_module_roundtrip(tmp_path):
    shim = _load_shim()
    (tmp_path / "plug.py").write_text("VALUE = 41\n")
    f, pathname, desc = shim.find_module("plug", [str(tmp_path)])
    assert pathname.endswith("plug.py")
    assert desc[0].endswith(".py")
    module = shim.load_module("plug", f, pathname, desc)
    assert module.VALUE == 41


def test_find_and_load_package(tmp_path):
    shim = _load_shim()
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("FROM_PKG = 'yes'\n")
    f, pathname, _desc = shim.find_module("pkg", [str(tmp_path)])
    module = shim.load_module("pkg", f, pathname, _desc)
    assert module.FROM_PKG == "yes"


def test_find_module_missing_raises(tmp_path):
    shim = _load_shim()
    with pytest.raises(ImportError):
        shim.find_module("no_such_plugin_xyz", [str(tmp_path)])
