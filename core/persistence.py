"""Small, dependency-free persistence primitives for local investigation data."""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile


def valid_snapshot(data) -> bool:
    """Validate the persisted envelope before readers use any of its stores."""
    if (not isinstance(data, dict) or data.get("schema_version") != 1
            or type(data.get("revision")) is not int or data["revision"] < 1
            or any(not isinstance(data.get(key), dict)
                   for key in ("assets", "findings", "module", "evidence"))):
        return False
    for store, field in (("assets", "nodes"), ("assets", "edges"),
                         ("findings", "findings"), ("evidence", "items")):
        values = data[store].get(field)
        if not isinstance(values, list) or any(not isinstance(v, dict) for v in values):
            return False
    return (isinstance(data["module"].get("stats"), dict)
            and isinstance(data["module"].get("completed"), list))


def atomic_json(path: Path, data: dict) -> None:
    """Replace a JSON file using a private, uniquely named, flushed temporary file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2, default=str)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


@contextmanager
def file_lock(path: Path, *, blocking: bool = True):
    """Serialize cooperating processes. The lock file is permanent, not a lease."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(fd, "r+b") as stream:
        if os.name == "nt":
            import msvcrt
            if not stream.read(1):
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        try:
            yield
        finally:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
