"""Tests for core/config_doctor.py and the --check-config flag.

A stale config never crashes — every key has a code default — so without
this the operator runs Tier-2 tools on defaults they cannot see. The
doctor lists what the file does not say; --check-config prints coverage
without running anything.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.config_doctor import KNOWN_KEYS, coverage, doctor


def test_empty_config_warns_on_every_known_key():
    warnings = doctor({})

    assert len(warnings) == len(KNOWN_KEYS)
    assert any(w.startswith("tools.backend") for w in warnings)
    assert any("kiterunner" in w for w in warnings)


def test_covered_keys_stay_silent():
    config: dict = {}
    for dotted, default, _why in KNOWN_KEYS:
        node = config
        parts = dotted.split(".")
        for part in parts[:-1]:
            child = node.setdefault(part, {})
            node = child if isinstance(child, dict) else node.setdefault(
                part + "_", {})
        node[parts[-1]] = default

    assert doctor(config) == []


def test_partial_config_warns_only_on_gaps():
    warnings = doctor({"tools": {"backend": "docker"}})

    assert not any(w.startswith("tools.backend") for w in warnings)
    assert any(w.startswith("tools.image") for w in warnings)


def test_non_dict_hops_count_as_absent():
    assert any(w.startswith("modules.content_discovery.kiterunner.enabled")
               for w in doctor({"modules": {"content_discovery": None}}))


def test_coverage_reports_effective_values():
    rows = {dotted: (present, value)
            for dotted, present, value, _why in coverage({"tools": {}})}

    assert rows["tools.backend"] == (False, "local")
    assert rows["semgrep.enabled"] == (False, True)


def test_check_config_runs_nothing(monkeypatch, capsys):
    """--check-config prints coverage and returns before any module runs."""
    import asyncio
    import orchestrator
    from orchestrator import Orchestrator
    from unittest.mock import AsyncMock, patch

    argv = ["orchestrator.py", "-t", "example.com", "-o", "/tmp/x",
            "--check-config"]
    monkeypatch.setattr(sys, "argv", argv)
    with patch.object(Orchestrator, "run_all", new=AsyncMock()) as run_all, \
         patch.object(Orchestrator, "run_module", new=AsyncMock()) as run_mod:
        asyncio.run(orchestrator.main())

    run_all.assert_not_called()
    run_mod.assert_not_called()
    out = capsys.readouterr().out
    assert "Config coverage" in out
    assert "tools.backend" in out


def test_shipped_config_has_no_silent_default_blocks():
    """config.yaml must carry every run-shaping block explicitly — a missing
    block runs on invisible code defaults (kiterunner politeness, budgets,
    module timeout, IDOR identities)."""
    import yaml

    with open(Path(__file__).resolve().parent.parent / "config.yaml") as handle:
        config = yaml.safe_load(handle)

    kr = config["modules"]["content_discovery"]["kiterunner"]
    assert kr["delay_ms"] == 100
    assert kr["connections"] == 3
    assert config["budget_limits"]["max_concurrent_actions"] == 5
    assert config["module_timeout"] == 300
    assert config["auth"]["identities"] == {}


def test_retired_namespaces_warn():
    from core.config_doctor import retired_warnings
    warnings = retired_warnings({
        "xss": {"max_points": 1},
        "modules": {"idor": {"endpoints": []}},
    })
    assert any(w.startswith("xss:") and "modules.xss_scan" in w
               for w in warnings)
    assert any(w.startswith("modules.idor:") and "idor_differ" in w
               for w in warnings)
    assert retired_warnings({"modules": {"xss_scan": {}}}) == []


def test_unknown_module_keys_warn_but_extra_keys_pass():
    from core.config_doctor import unknown_warnings
    warnings = unknown_warnings({"modules": {
        "xss_scan": {"write_methods": ["PUT"], "max_points": 5},
        "misconfig_probes": {"extra_backup_bases": ["a.bak"]},
    }})
    assert any("write_methods" in w for w in warnings)
    assert not any("extra_backup_bases" in w for w in warnings)
    assert not any("max_points" in w for w in warnings)


def test_doctor_flags_both_directions_on_typo_config():
    config = {"modules": {"xss_scan": {"write_methods": ["PUT"]}}}
    warnings = doctor(config)
    assert any("write_methods" in w and "unknown key" in w for w in warnings)


def test_shipped_configs_warn_only_on_informative_defaults():
    """config.yaml and config.example.yaml must be warning-free except the
    two keys whose defaults are dynamic/legacy by design (nuclei
    max_seconds, full_cve). Anything else means a shipped default drifted
    from the engine again."""
    import yaml

    allowed = {"modules.nuclei_scan.max_seconds",
               "modules.nuclei_scan.full_cve"}
    root = Path(__file__).resolve().parent.parent
    for name in ("config.yaml", "config.example.yaml"):
        with open(root / name) as handle:
            warnings = doctor(yaml.safe_load(handle))
        unexpected = [w for w in warnings
                      if w.split(" ")[0] not in allowed]
        assert unexpected == [], (name, unexpected)
