"""Machine-readable scope, enforced before every HTTP request.

A scope file is the difference between a scanner and a liability: recon
finds hosts the program never authorised, and "it came up in the crawl" is
not permission. The guard is fail-closed once a file is configured —
unknown hosts are refused unless `allow_external` is explicit, and deny
always wins.
"""

import json
from pathlib import Path
from urllib.parse import urlparse


def host_matches(pattern: str, host: str) -> bool:
    """`example.com` covers its subdomains; `*.example.com` does not cover
    the apex (so a wildcard scope cannot silently include the root site)."""
    rule = str(pattern or "").strip().lower().rstrip(".")
    name = str(host or "").strip().lower().rstrip(".")
    if not rule or not name:
        return False
    if rule.startswith("*."):
        base = rule[2:]
        return bool(base) and name != base and name.endswith("." + base)
    return name == rule or name.endswith("." + rule)


class ScopeGuard:
    def __init__(self, allow=(), deny=(), allow_external: bool = True):
        self.allow = [str(item) for item in allow]
        self.deny = [str(item) for item in deny]
        self.allow_external = bool(allow_external)

    def check(self, url: str) -> tuple:
        parsed = urlparse(str(url or ""))
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            return False, "blocked_by_scope: only http(s) is allowed"
        host = (parsed.hostname or "").strip().lower().rstrip(".")
        if not host:
            return False, "blocked_by_scope: no host"
        if any(host_matches(rule, host) for rule in self.deny):
            return False, "blocked_by_scope: host is explicitly denied"
        if any(host_matches(rule, host) for rule in self.allow):
            return True, "in scope"
        if self.allow_external:
            return True, "external hosts allowed"
        return False, "blocked_by_scope: host is not in the allow list"


def load_scope(path: str, allow_external=None) -> ScopeGuard:
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise ValueError("scope file must be a JSON object")
    allow = data.get("allow") or []
    deny = data.get("deny") or []
    if not isinstance(allow, list) or not isinstance(deny, list):
        raise ValueError("scope allow/deny must be lists")
    external = data.get("allow_external")
    if allow_external is not None:
        external = allow_external
    if external is None:
        external = True
    return ScopeGuard(allow, deny, external)


def from_config(config) -> ScopeGuard | None:
    """No file, no enforcement (backwards compatible). A broken file is
    fail-closed: it refuses everything rather than scanning unbounded."""
    if "scope" not in (config or {}):
        return None
    cfg = (config or {}).get("scope", {}) or {}
    if cfg.get("enabled") is False:
        return None
    path = (cfg.get("file")
            or (config or {}).get("paths", {}).get("scope_file")
            or "scope.json")
    target = Path(path)
    if not target.exists():
        return None
    try:
        return load_scope(str(target), cfg.get("allow_external"))
    except (OSError, ValueError, json.JSONDecodeError):
        return ScopeGuard(allow=[], deny=[], allow_external=False)
