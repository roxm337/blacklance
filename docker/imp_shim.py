"""imp compatibility shim for Python 3.12+.

CPython removed the stdlib `imp` module in 3.12; cement 2.x (which
droopescan is built on) still does `from imp import reload` and
`imp.find_module`/`imp.load_module` for plugins. This shim re-exports
the importlib equivalents so the scanner imports without patching
third-party site-packages. Only the surface cement 2.x touches is
implemented: reload, find_module, load_module.

Note find_spec(name, path) does NOT search a path list (its second
argument is the anchor package for relative imports), so find_module
scans the directories itself, like the original imp did.
"""
import importlib
import importlib.machinery
import importlib.util
import os

reload = importlib.reload

_PY_SOURCE = importlib.machinery.SOURCE_SUFFIXES[0]


def _search_path(name, path):
    """Pathname of the source module or package, or None."""
    for entry in path or []:
        candidate = os.path.join(entry, name + _PY_SOURCE)
        if os.path.isfile(candidate):
            return candidate, None
        init = os.path.join(entry, name, "__init__.py")
        if os.path.isfile(init):
            return init, os.path.join(entry, name)
    return None, None


def find_module(name, path=None):
    """imp.find_module subset: locate a source module, return the
    (file, pathname, description) triple load_module expects."""
    pathname, pkgdir = _search_path(name.split(".")[-1], path)
    if pathname is None:
        raise ImportError("No module named %r" % (name,))
    return open(pathname, "rb"), pathname, (_PY_SOURCE, "rb", 1)


def load_module(name, file, pathname, description):
    """imp.load_module subset: load (or return cached) module from file."""
    import sys
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, pathname)
    if spec is None or spec.loader is None:
        raise ImportError("No module named %r" % (name,))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        try:
            file.close()
        except Exception:
            pass
    return module
