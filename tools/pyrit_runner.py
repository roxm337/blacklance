"""Reference PyRIT runner for one bounded prompt-sending pass.

This file is invoked by ``tools.pyrit_adapter`` with a config path and an
output path. It is intentionally thin and version-gated: it targets the
PyRIT API surface with ``OpenAIChatTarget`` + ``PromptSendingOrchestrator``
and exits 4 when the installed PyRIT exposes a different one. Operators on
a newer release should point ``modules.pyrit_audit.runner.command`` at their
own runner that emits the same JSON contract.

Exit codes: 0 report written; 3 PyRIT unavailable; 4 unsupported API.

The target credential arrives via ``PYRIT_TARGET_KEY`` only; it is never in
argv or the config file.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import sys


def _target_kwargs(cls, target: dict) -> dict:
    try:
        parameters = inspect.signature(cls.__init__).parameters
    except (TypeError, ValueError):
        return {}
    wanted = {
        "model_name": target.get("model"),
        "deployment_name": target.get("model"),
        "endpoint": target.get("endpoint"),
        "api_key": os.environ.get("PYRIT_TARGET_KEY", ""),
        "api_version": target.get("api_version"),
    }
    return {key: value for key, value in wanted.items()
            if value and key in parameters}


async def _memory(orchestrator):
    if hasattr(orchestrator, "get_memory_async"):
        return await orchestrator.get_memory_async()
    if hasattr(orchestrator, "get_memory"):
        value = orchestrator.get_memory()
        return await value if inspect.isawaitable(value) else value
    raise RuntimeError("orchestrator memory API not recognized")


def _transcript(memory) -> list[dict]:
    entries = []
    for response in memory or []:
        pieces = (getattr(response, "request_pieces", None)
                  or getattr(response, "request_responses", None) or [])
        for piece in pieces:
            content = getattr(piece, "converted_value", None)
            if content is None:
                content = getattr(piece, "original_value", "")
            entries.append({"role": str(getattr(piece, "role", "") or ""),
                            "content": str(content)})
    return entries


async def _send(orchestrator, prompts: list[str]) -> None:
    send = orchestrator.send_prompts_async
    parameters = inspect.signature(send).parameters
    if "prompt_list" in parameters:
        await send(prompt_list=prompts)
    elif "prompts" in parameters:
        await send(prompts=prompts)
    else:
        await send(prompts)


async def main() -> int:
    if len(sys.argv) < 3:
        print("usage: pyrit_runner.py CONFIG OUTPUT", file=sys.stderr)
        return 4
    try:
        with open(sys.argv[1], encoding="utf-8") as handle:
            config = json.load(handle)
    except (OSError, ValueError) as exc:
        print(f"cannot read runner config: {exc}", file=sys.stderr)
        return 4

    try:
        import pyrit
    except Exception as exc:  # pragma: no cover - live-tool path
        print(f"pyrit import failed: {exc}", file=sys.stderr)
        return 3

    version = str(getattr(pyrit, "__version__", "unknown"))
    try:  # pragma: no cover - live-tool path
        from pyrit.orchestrator import PromptSendingOrchestrator
        from pyrit.prompt_target import OpenAIChatTarget
    except Exception as exc:
        print(f"unsupported PyRIT API: {exc}", file=sys.stderr)
        return 4

    target_config = config.get("target") or {}
    report = {
        "schema_version": 1,
        "provenance": {
            "runner": "pyrit-reference/1",
            "pyrit_version": version,
            "model": str(target_config.get("model") or ""),
            "provider": str(target_config.get("provider") or ""),
        },
        "attacks": [],
        "usage": {},
    }
    max_prompts = max(1, min(24, int(config.get("max_prompts", 12) or 12)))
    for attack in (config.get("attacks") or [])[:20]:
        prompts = [str(prompt) for prompt in (attack.get("prompts") or [])
                   if str(prompt)][:max_prompts]
        entry = {
            "name": str(attack.get("name") or "attack"),
            "strategy": str(attack.get("strategy") or "prompt_sending"),
            "turns": len(prompts),
            "transcript": [],
            "tool_calls": [],
            "scores": [],
            "error": "",
        }
        try:  # pragma: no cover - live-tool path
            target = OpenAIChatTarget(
                **_target_kwargs(OpenAIChatTarget, target_config))
            orchestrator = PromptSendingOrchestrator(prompt_target=target)
            await _send(orchestrator, prompts)
            entry["transcript"] = _transcript(await _memory(orchestrator))
        except Exception as exc:
            entry["error"] = f"{type(exc).__name__}: {exc}"
        report["attacks"].append(entry)

    try:
        with open(sys.argv[2], "w", encoding="utf-8") as handle:
            json.dump(report, handle, sort_keys=True)
    except OSError as exc:
        print(f"cannot write runner report: {exc}", file=sys.stderr)
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
