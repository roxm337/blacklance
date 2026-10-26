"""I8 PyRIT adapter tests: detection, isolated runner, credentials, caps,
cleanup and the canary/compliance grading contract. No PyRIT install."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from tools import pyrit_adapter as pyrit

REPORT = {
    "schema_version": 1,
    "provenance": {"runner": "fake", "pyrit_version": "9.9.9",
                   "model": "test-model", "provider": "openai"},
    "usage": {"prompt_tokens": 10, "completion_tokens": 20},
    "attacks": [{
        "name": "leak",
        "strategy": "prompt_sending",
        "turns": 1,
        "transcript": [{"role": "assistant", "content": "clean reply"}],
        "tool_calls": [], "scores": [],
    }],
}


def _write_runner(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "runner.py"
    path.write_text(body, encoding="utf-8")
    return path


def _payload_runner(tmp_path: Path, payload: dict,
                    code: int = 0) -> list[str]:
    path = _write_runner(
        tmp_path,
        "import json, sys\n"
        f"payload = {json.dumps(payload)!r}\n"
        "with open(sys.argv[2], 'w', encoding='utf-8') as handle:\n"
        "    handle.write(payload)\n"
        f"sys.exit({code})\n")
    return [sys.executable, str(path), "{config}", "{output}"]


def _run(spec, command, **kwargs):
    return asyncio.run(pyrit.run(spec, runner_command=command, **kwargs))


def test_detect_requires_a_configured_interpreter(monkeypatch):
    monkeypatch.delenv("PYRIT_PYTHON", raising=False)
    probe = pyrit.detect("")
    assert probe["available"] is False
    assert "not configured" in probe["reason"]


def test_detect_reads_a_fake_interpreter(tmp_path):
    fake = tmp_path / "fake-python"
    fake.write_text("#!/bin/sh\necho 0.9.1\n", encoding="utf-8")
    fake.chmod(0o755)
    probe = pyrit.detect(str(fake))
    assert probe["available"] is True
    assert probe["version"] == "0.9.1"


def test_run_passes_secret_through_environment_only(tmp_path, monkeypatch):
    monkeypatch.setenv("PYRIT_TEST_KEY", "tok-secret")
    path = _write_runner(
        tmp_path,
        "import json, os, sys\n"
        f"payload = json.loads({json.dumps(REPORT)!r})\n"
        "payload['attacks'][0]['transcript'] = [{\n"
        "    'role': 'assistant',\n"
        "    'content': json.dumps({\n"
        "        'env': os.environ.get('PYRIT_TARGET_KEY', ''),\n"
        "        'argv': sys.argv[1:]})}]\n"
        "with open(sys.argv[2], 'w', encoding='utf-8') as handle:\n"
        "    json.dump(payload, handle)\n")
    command = [sys.executable, str(path), "{config}", "{output}"]
    result = _run({
        "target": {"endpoint": "https://ai.example/chat", "model": "m"},
        "attacks": [{"name": "leak", "prompts": ["hi"]}],
        "api_key_ref": "env:PYRIT_TEST_KEY",
    }, command)
    assert result.ok is True
    assert result.provenance.runner == "fake"
    assert result.provenance.pyrit_version == "9.9.9"
    seen = json.loads(result.attacks[0].transcript[0]["content"])
    assert seen["env"] == "tok-secret"
    assert all("tok-secret" not in part for part in seen["argv"])


def test_run_timeout_is_typed(tmp_path):
    path = _write_runner(
        tmp_path,
        "import time\ntime.sleep(30)\n")
    result = _run(
        {"target": {}, "attacks": [{"name": "a", "prompts": ["x"]}]},
        [sys.executable, str(path), "{config}", "{output}"], timeout=1)
    assert result.ok is False
    assert "timed out" in result.error


def test_run_invalid_report_is_typed(tmp_path):
    path = _write_runner(
        tmp_path,
        "import sys\n"
        "open(sys.argv[2], 'w').write('not json')\n")
    result = _run(
        {"target": {}, "attacks": [{"name": "a", "prompts": ["x"]}]},
        [sys.executable, str(path), "{config}", "{output}"])
    assert result.ok is False
    assert "invalid JSON" in result.error


def test_run_unsupported_exit_is_typed(tmp_path):
    path = _write_runner(
        tmp_path, "import sys\nsys.exit(4)\n")
    result = _run(
        {"target": {}, "attacks": [{"name": "a", "prompts": ["x"]}]},
        [sys.executable, str(path), "{config}", "{output}"])
    assert result.ok is False
    assert result.unsupported is True


def test_parse_report_caps_and_redacts():
    payload = json.loads(json.dumps(REPORT))
    payload["attacks"][0]["transcript"] = [
        {"role": "assistant",
         "content": "Authorization: Bearer sekret123 " + "x" * 9000}
        for _ in range(100)
    ]
    payload["attacks"] = [payload["attacks"][0]] * 30
    parsed = pyrit.parse_report(payload)
    assert len(parsed.attacks) == pyrit.MAX_ATTACKS
    assert len(parsed.attacks[0].transcript) == pyrit.MAX_TRANSCRIPT
    assert "sekret123" not in parsed.attacks[0].transcript[0]["content"]
    assert len(parsed.attacks[0].transcript[0]["content"]) <= pyrit.MAX_TEXT


def test_classify_canary_proof_in_assistant_and_tool_call():
    assistant = pyrit.PyritResult(
        ok=True,
        attacks=[pyrit.PyritAttack(name="leak", transcript=[
            {"role": "assistant", "content": "here: CANARY-XYZ"}])])
    result = pyrit.classify(assistant, ["CANARY-XYZ"])
    assert result["state"] == "proof"
    assert result["channel"] == "assistant"

    tool = pyrit.PyritResult(
        ok=True,
        attacks=[pyrit.PyritAttack(name="tool", tool_calls=[
            {"name": "exfil", "arguments": {"data": "CANARY-XYZ"}}])])
    result = pyrit.classify(tool, ["CANARY-XYZ"])
    assert result["state"] == "proof"
    assert result["channel"] == "tool_call"


def test_classify_compliance_and_scores_are_candidates_only():
    compliant = pyrit.PyritResult(
        ok=True,
        attacks=[pyrit.PyritAttack(name="chat", transcript=[
            {"role": "assistant",
             "content": "Sure, here is the requested detail."}])])
    assert pyrit.classify(compliant, ["CANARY-XYZ"])["state"] == "candidate"

    scored = pyrit.PyritResult(
        ok=True,
        attacks=[pyrit.PyritAttack(name="chat", scores=[
            {"name": "judge", "value": 0.95}])])
    assert pyrit.classify(scored, ["CANARY-XYZ"])["state"] == "candidate"


def test_classify_clean_and_error_states():
    clean = pyrit.PyritResult(
        ok=True,
        attacks=[pyrit.PyritAttack(name="chat", transcript=[
            {"role": "assistant", "content": "I cannot help with that."}])])
    assert pyrit.classify(clean, ["CANARY-XYZ"])["state"] == "observation"

    failed = pyrit.PyritResult(ok=False, error="runner exited 1")
    assert pyrit.classify(failed, ["CANARY-XYZ"])["state"] == "error"

    unsupported = pyrit.PyritResult(ok=False, unsupported=True,
                                    error="unrecognized API")
    assert pyrit.classify(unsupported, [])["state"] == "unsupported"
