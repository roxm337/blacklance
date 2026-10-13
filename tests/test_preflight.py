"""Tests for core/preflight.py and skip/block warning logs.

A degraded run must be impossible to miss: docker backend down, missing
identities, armed risk ceilings, and every skipped/blocked module get
reported up front and in the closing summary — the silent-degradation
class that once cost a live engagement its tool coverage.
"""
import logging
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tools.external as external
from core.preflight import coverage_lines, preflight
from state.manager import StateManager

_LLM_KEY_ENV = ("DEEPSEEK_API_KEY", "OSINT_AGENT_LLM_API_KEY",
                "LITELLM_API_KEY", "OPENAI_API_KEY",
                "OSINT_AGENT_LLM_MODEL", "LITELLM_MODEL")
# configure_tool_backend lets the environment win over config, and the
# repo .env sets OSINT_TOOLS_BACKEND=docker: scrub it so backend tests
# assert on config, not on whichever shell runs them.
_BACKEND_ENV = ("OSINT_TOOLS_BACKEND", "OSINT_TOOLS_IMAGE")


@pytest.fixture
def _backend_snapshot():
    mode, image, ok = (external._BACKEND["mode"],
                       external._BACKEND["image"], external._DOCKER_OK)
    yield
    external._BACKEND["mode"] = mode
    external._BACKEND["image"] = image
    external._DOCKER_OK = ok


@pytest.fixture
def _no_llm_keys(monkeypatch):
    for var in _LLM_KEY_ENV + _BACKEND_ENV:
        monkeypatch.delenv(var, raising=False)


def test_local_backend_has_no_docker_warning(_backend_snapshot, _no_llm_keys):
    report = preflight({"tools": {"backend": "local"}})
    assert not [w for w in report["warnings"] if "docker" in w.lower()]
    assert any("local" in n for n in report["notices"])


def test_docker_backend_down_warns(monkeypatch, _backend_snapshot,
                                   _no_llm_keys):
    monkeypatch.setattr(external, "_docker_ready", lambda: False)
    report = preflight({"tools": {"backend": "docker",
                                  "image": "osint-tools:latest"}})
    assert any("daemon" in w for w in report["warnings"])
    assert any("will skip" in w for w in report["warnings"])


def test_docker_backend_ready_is_a_notice(monkeypatch, _backend_snapshot,
                                            _no_llm_keys):
    monkeypatch.setattr(external, "_docker_ready", lambda: True)
    report = preflight({"tools": {"backend": "docker"}})
    assert not report["warnings"]
    assert any("reachable" in n for n in report["notices"])


def test_llm_ready_and_missing_key(_backend_snapshot, _no_llm_keys):
    ready = preflight({"llm": {"model": "openai/gpt-4o", "api_key": "sk-t"}})
    assert any("LLM ready" in n for n in ready["notices"])
    missing = preflight({"llm": {"model": "openai/gpt-4o"}})
    assert any("fallbacks" in n for n in missing["notices"])


def test_budgets_identities_and_arming(_backend_snapshot, _no_llm_keys):
    config = {"budget_limits": {"max_llm_calls": 50, "max_requests": 0,
                                "max_wall_clock_seconds": 600},
              "module_timeout": 120,
              "auth": {"identities": {"a": {}, "b": {}}}}
    report = preflight(config, {"execute": True, "max_risk": "HIGH"})
    assert any("50 LLM calls" in n and "600s" in n for n in report["notices"])
    assert any("120s" in n for n in report["notices"])
    assert any("2 test identities" in n for n in report["notices"])
    assert any("ARMED" in w and "HIGH" in w for w in report["warnings"])

    naked = preflight({}, {"execute": False, "max_risk": "LOW"})
    assert any("no test identities" in n for n in naked["notices"])
    assert not [w for w in naked["warnings"] if "ARMED" in w]


def _stub_state():
    return SimpleNamespace(
        llm_calls_used=7,
        module={
            "completed": ["a", "b"],
            "skipped": [{"module_id": "nuclei_scan",
                         "reason": "nuclei not installed"}],
            "blocked": [{"module_id": "x", "reason": "boom"}],
            "runs": [
                {"module_id": "y", "status": "timeout",
                 "error": "exceeded 300s module deadline"},
                {"module_id": "z", "status": "error", "error": "kaboom"},
                {"module_id": "a", "status": "done"},
            ],
            "waf": {"detected": True, "vendor": "cloudflare", "blocks": [1]},
        },
    )


def test_coverage_lines_lists_everything():
    lines = coverage_lines(_stub_state())
    text = "\n".join(lines)
    assert "2/4 completed, 1 skipped, 1 blocked" in text
    assert "skipped nuclei_scan: nuclei not installed" in text
    assert "blocked x: boom" in text
    assert "timeout y" in text
    assert "error z: kaboom" in text
    assert "cloudflare" in text
    assert "LLM calls used: 7" in text


def test_coverage_lines_quiet_when_clean():
    state = SimpleNamespace(llm_calls_used=0,
                            module={"completed": ["a"], "skipped": [],
                                    "blocked": [], "runs": [],
                                    "waf": {"detected": False}})
    lines = coverage_lines(state)
    assert lines == ["Modules: 1/1 completed, 0 skipped, 0 blocked"]


def test_skip_and_block_log_warnings(tmp_path, caplog):
    state = StateManager(str(tmp_path / "run"))
    with caplog.at_level(logging.WARNING, logger="osint-agent"):
        state.skip_module("nuclei_scan", "nuclei not installed")
        state.block_module("x", "boom")
        state.skip_module("nuclei_scan", "nuclei not installed")  # no dup log
    warnings = [r.message for r in caplog.records
                if r.levelno == logging.WARNING]
    assert any("nuclei_scan" in m and "skipped" in m for m in warnings)
    assert any("blocked" in m for m in warnings)
    assert sum("nuclei_scan" in m for m in warnings) == 1
