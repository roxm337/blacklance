"""Test hermeticity: operator environment must not leak into tests.

The repo .env sets OSINT_TOOLS_BACKEND=docker plus live LLM keys — CI
never sees them (gitignored), but local runs do once agents/__init__
load_dotenv() fires at collection. Without this, tests that assume
missing tools/keys silently execute REAL tools (daemon up) or REAL
LLM calls (keys present): green with the daemon down, hanging or
spending money with it up. Scrubbed here for every test; tests that
need these values set their own via monkeypatch.
"""
import pytest

_SCRUBBED = (
    "OSINT_TOOLS_BACKEND",
    "OSINT_TOOLS_IMAGE",
    "DEEPSEEK_API_KEY",
    "OSINT_AGENT_LLM_API_KEY",
    "LITELLM_API_KEY",
    "OPENAI_API_KEY",
    "OSINT_AGENT_LLM_MODEL",
    "LITELLM_MODEL",
)


@pytest.fixture(autouse=True)
def _scrub_operator_env(monkeypatch):
    for var in _SCRUBBED:
        monkeypatch.delenv(var, raising=False)
