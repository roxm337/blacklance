"""Startup readiness checks — warn loudly instead of degrading silently.

A run whose tool backend is unreachable still "completes" with every
tool-gated module skipped. That silent degradation once cost a live
engagement its entire nuclei/sqlmap/ffuf coverage: the daemon was down,
each module recorded "not installed" in module.json, and the final
summary printed COMPLETE anyway. Preflight runs before the first module
and says, up front, what will not run and why.
"""
from __future__ import annotations


def preflight(config: dict, context: dict | None = None) -> dict:
    """Return {"warnings": [...], "notices": [...]} for this run.

    config is the app config; context carries CLI-level facts config
    cannot see: {"mode", "execute", "max_risk", "agent"}. Pure except for
    the docker reachability probe (one `docker image inspect`).
    """
    from tools.external import (
        configure_tool_backend, tool_backend, _docker_ready, _BACKEND,
    )

    context = context or {}
    warnings: list[str] = []
    notices: list[str] = []

    mode = configure_tool_backend(config)
    if mode == "docker":
        if _docker_ready():
            notices.append(
                f"tool backend: docker ({_BACKEND['image']}) — "
                "daemon and image reachable"
            )
        else:
            warnings.append(
                "tools.backend=docker but the daemon or image "
                f"({_BACKEND['image']}) is unreachable — start Docker "
                "Desktop or rebuild the image. Every docker-gated module "
                "(nuclei, sqlmap, ffuf, katana, …) will skip. Set "
                "tools.backend=local to run host binaries instead."
            )
    else:
        notices.append("tool backend: local — modules use host binaries; "
                       "missing ones skip per module")

    # LLM posture is advisory: every agent has a deterministic fallback,
    # but the operator should know which mode the run is in.
    from agents import get_llm_config
    llm = get_llm_config(config or {})
    if llm.get("api_key"):
        notices.append(f"LLM ready: {llm['model']}")
    else:
        notices.append(f"LLM key missing for {llm['model']} — "
                       "agents run deterministic fallbacks")

    # Budgets: only caps that actually constrain, so an all-default
    # config stays quiet and a capped run states its limits.
    limits = (config or {}).get("budget_limits", {}) or {}
    caps = []
    if int(limits.get("max_requests", 0) or 0):
        caps.append(f"{limits['max_requests']} requests")
    if int(limits.get("max_llm_calls", 0) or 0):
        caps.append(f"{limits['max_llm_calls']} LLM calls")
    if int(limits.get("max_wall_clock_seconds", 0) or 0):
        caps.append(f"{limits['max_wall_clock_seconds']}s wall clock")
    if int(limits.get("max_external_commands", 0) or 0):
        caps.append(f"{limits['max_external_commands']} external commands")
    if int(context.get("max_actions", 0) or 0):
        caps.append(f"{context['max_actions']} actions")
    notices.append("budgets: " + (", ".join(caps) if caps else "unlimited")
                   + f"; module deadline {config.get('module_timeout', 300)}s")
    if limits.get("resume"):
        notices.append("budget resume enabled — restored counters apply before execution")

    # Authenticated coverage needs test identities; without them the auth
    # modules skip (recorded per module, repeated here so it is seen).
    from core import secrets as secretrefs
    identities = ((config or {}).get("auth", {}) or {}).get("identities", {})
    if isinstance(identities, dict):
        identities = [{"name": key, **value}
                      for key, value in identities.items()
                      if isinstance(value, dict)]
    if not isinstance(identities, list):
        identities = []
    count = len(identities)
    if count:
        notices.append(f"{count} test identities configured — "
                       "authenticated modules can run")
    else:
        notices.append("no test identities — authenticated modules "
                       "(business_logic, IDOR sessions) will skip")
    require_refs = bool(((config or {}).get("auth", {}) or {}).get(
        "require_secret_refs", False))
    for entry in identities:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "?")
        for field, value in secretrefs.credential_fields(entry):
            try:
                secretrefs.resolve_tree(value)
            except secretrefs.SecretError as exc:
                warnings.append(
                    f"identity {name}: {field} reference unresolved — {exc}")
        try:
            lifecycle = secretrefs.credential_state(
                entry.get("expires_at") or entry.get("expires"),
                bool(entry.get("revoked", False)))
        except secretrefs.SecretError as exc:
            warnings.append(f"identity {name}: {exc}")
            lifecycle = None
        if lifecycle:
            if lifecycle["revoked"]:
                warnings.append(
                    f"identity {name}: credential revoked — it will not be used")
            elif lifecycle["expired"]:
                warnings.append(
                    f"identity {name}: credential expired at "
                    f"{lifecycle['expires_at']} — it will not be used")
        if require_refs:
            literals = secretrefs.literal_secret_fields(entry)
            if literals:
                warnings.append(
                    f"identity {name}: plaintext credential field(s) "
                    f"{', '.join(literals)} while auth.require_secret_refs "
                    "is true — use env:NAME or file:/path")

    # Arming proving actions above LOW is the one decision that can hurt
    # someone: say it where it cannot be missed.
    ceiling = context.get("max_risk", "DESTRUCTIVE")
    if context.get("execute") or context.get("agent"):
        if ceiling not in ("SAFE", "LOW"):
            warnings.append(
                f"proving actions ARMED at risk ceiling {ceiling} — "
                "run only against targets you are authorised to test"
            )
        else:
            notices.append(f"proving actions armed (risk ceiling {ceiling})")

    run_mode = context.get("mode", "auto")
    if run_mode == "llm":
        notices.append("run mode: llm — the model picks modules, "
                       "deterministic order is the fallback")
    elif run_mode == "module":
        notices.append("run mode: single module")
    elif context.get("agent"):
        notices.append("run mode: agent engagement "
                       "(plan → exploit → verify → report)")

    return {"warnings": warnings, "notices": notices}


def coverage_lines(state) -> list[str]:
    """End-of-run coverage: what ran, what skipped, what broke, and why.

    Takes the StateManager (duck-typed: only .module and .llm_calls_used
    are read) so a hollow run can never again print COMPLETE without its
    gaps listed underneath.
    """
    lines: list[str] = []
    module = state.module
    completed = module.get("completed", [])
    skipped = module.get("skipped", [])
    blocked = module.get("blocked", [])
    runs = module.get("runs", [])
    timeouts = [r for r in runs if r.get("status") == "timeout"]
    errors = [r for r in runs if r.get("status") == "error"]
    total = len(completed) + len(skipped) + len(blocked)

    lines.append(f"Modules: {len(completed)}/{total} completed, "
                 f"{len(skipped)} skipped, {len(blocked)} blocked")
    for entry in skipped:
        reason = entry.get("reason", "") or "no reason recorded"
        lines.append(f"  — skipped {entry.get('module_id')}: {reason}")
    for entry in blocked:
        reason = entry.get("reason", "") or "no reason recorded"
        lines.append(f"  ✗ blocked {entry.get('module_id')}: {reason}")
    for run in timeouts:
        lines.append(f"  ⏱ timeout {run.get('module_id')}: "
                     f"{run.get('error', 'exceeded module deadline')}")
    for run in errors:
        lines.append(f"  ✗ error {run.get('module_id')}: "
                     f"{run.get('error', '')[:200]}")

    waf = module.get("waf", {})
    if waf.get("detected"):
        lines.append(f"WAF detected: vendor={waf.get('vendor', 'unknown')}, "
                     f"blocks={len(waf.get('blocks', []))}")

    mutations = getattr(state, "mutations", None)
    if mutations is not None:
        try:
            outstanding = mutations.outstanding()
        except Exception:
            outstanding = []
        if outstanding:
            lines.append(f"Outstanding cleanup: {len(outstanding)} mutation(s) "
                         f"not yet verified (see state/mutations.jsonl)")
            for record in outstanding[:5]:
                lines.append(
                    f"  ⚠ {record.get('module_id')} on "
                    f"{record.get('identity') or 'unknown identity'}: "
                    f"{record.get('mutation_kind')} cleanup outstanding")

    llm_used = getattr(state, "llm_calls_used", 0)
    if llm_used:
        lines.append(f"LLM calls used: {llm_used}")
    return lines
