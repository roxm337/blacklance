"""I1 lab gate: capture → replay → cleanup against a live lab instance.

Runs the browser-traffic workflow loop against a lab (default Juice Shop
at http://localhost:3000): a configured identity logs in, the browser
crawl captures the XHR/fetch traffic with identity provenance, the
capture is persisted redacted, the workflow is replayed with a FRESH
login, and the mutation ledger proves owned objects were cleaned up.

Skip, don't fail, when the lab is unreachable: this is a quality gate,
not a unit test.

Usage:
    OSINT_LAB_URL=http://localhost:3000 .venv/bin/python -m pytest \\
        benchmarks/workflow_lab.py -v

Exit/pytest contract:
    - lab unreachable  -> skipped
    - assertions pass  -> passed
    - assertions fail  -> failed
"""

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

LAB_URL = os.environ.get("OSINT_LAB_URL", "http://localhost:3000")

pytestmark = pytest.mark.lab


def _reachable(base_url: str) -> bool:
    import urllib.request
    try:
        with urllib.request.urlopen(base_url, timeout=10) as response:
            return response.status < 500
    except Exception:
        return False


def _load_config(base_url: str, identity: dict) -> dict:
    return {
        "target": {"domain": base_url.split("//")[1].split(":")[0],
                   "base_url": base_url},
        "crawl": {"browser": {"enabled": True, "max_targets": 3,
                              "depth": 0, "wait_ms": 500,
                              "capture_traffic": True}},
        "auth": {"identities": [identity]},
        "budget_limits": {"max_requests": 500},
        "module_timeout": 120,
    }


async def _run_capture(tmp_path: str, base_url: str, identity: dict):
    """Crawl one page as the configured identity with capture enabled."""
    from modules.browser_crawl import BrowserCrawl
    from state.manager import StateManager

    state = StateManager(f"{tmp_path}/run/lab")
    config = _load_config(base_url, identity)
    module = BrowserCrawl(state, config)
    from core.budget_manager import BudgetManager
    module.budget = BudgetManager(config)
    result = await module.run()
    return result, state


def _resolve_identity(base_url: str) -> dict:
    """Identity from OSINT_LAB_IDENTITY JSON, or built from
    OSINT_LAB_EMAIL/OSINT_LAB_PASSWORD with the Juice Shop login shape."""
    raw = os.environ.get("OSINT_LAB_IDENTITY", "")
    if raw:
        return json.loads(raw)
    email = os.environ.get("OSINT_LAB_EMAIL", "")
    password = os.environ.get("OSINT_LAB_PASSWORD", "")
    if not email or not password:
        pytest.skip("set OSINT_LAB_IDENTITY or "
                    "OSINT_LAB_EMAIL/OSINT_LAB_PASSWORD")
    return {
        "name": "lab_user",
        "email": email,
        "password": password,
        "verify_url": "/rest/basket/1",
        "success_marker": '"UserId":1',
        "login": {
            "url": "/rest/user/login",
            "method": "POST",
            "json": True,
            "data": {"email": email, "password": password},
            "success_marker": "authentication",
        },
    }


def test_capture_replay_cleanup_roundtrip(tmp_path):
    """Acceptance: capture → redacted persistence → fresh-token replay →
    verified cleanup. Requires a running lab and a configured identity."""
    base_url = LAB_URL
    if not _reachable(base_url):
        pytest.skip(f"lab unreachable at {base_url}")

    identity = _resolve_identity(base_url)

    result, state = asyncio.run(_run_capture(str(tmp_path), base_url, identity))

    # 1. The capture persisted, redacted.
    store_path = state.state_dir / "traffic.jsonl"
    assert store_path.exists(), "traffic capture was not persisted"
    raw = store_path.read_text(encoding="utf-8")
    # The credential value itself never appears, and any captured JSON
    # "password" key is redacted (UI text may legitimately say "Password").
    assert identity["password"] not in raw, "credential value persisted"
    assert '"password":' not in raw or '"password": "<redacted>"' in raw, \
        "password key captured without redaction"
    assert "Authorization" not in raw.split("\n")[0]

    # 2. Identity provenance is attached to captured events.
    events = []
    for line in raw.splitlines():
        if line.strip():
            events.append(json.loads(line))
    request_events = [e for e in events if e.get("kind") in ("xhr", "fetch")]
    assert request_events, "no XHR/fetch traffic captured"
    assert any(e.get("identity", {}).get("name") == identity["name"]
               for e in request_events), "identity provenance missing"

    # 3. The capture builds a workflow and replays with a fresh login.
    from core.mutations import MutationLedger
    from core.workflows import WorkflowStep, build_workflow, replay_workflow
    from core.auth_harness import AuthHarness

    workflow = build_workflow(events, source=str(store_path))
    assert workflow.steps, "no replayable steps built from capture"

    # Append a state-changing step that the mutation ledger must record and
    # verify cleaned up: create a basket item, then delete and re-check it.
    create_url = f"{base_url.rstrip('/')}/api/BasketItems"
    workflow.add(WorkflowStep(
        index=0,
        url=create_url,
        method="POST",
        identity_ref=identity["name"],
        headers={"Content-Type": "application/json"},
        body='{"ProductId": 2, "quantity": 1}',
        binds_from=[{"step": 0,
                     "extract": {"type": "jsonpath", "path": "data.id"},
                     "to": "item_id"}],
        mutation={
            "kind": "object_create",
            "owned_objects": [{"type": "resource",
                               "identifier": "{item_id}"}],
            "cleanup": {
                "method": "DELETE",
                "url_template": f"{create_url}/{{item_id}}",
                "verify": {"method": "http_get",
                           "expect_status": [404, 410]},
            },
        },
    ))

    harness = AuthHarness(_load_config(base_url, identity))
    mutations = MutationLedger(state.state_dir / "mutations.jsonl")
    report = asyncio.run(replay_workflow(
        workflow, harness, base_url=base_url, mutations=mutations))
    assert report.steps, "replay produced no step outcomes"
    assert not report.error, f"replay aborted: {report.error}"

    # 4. The declared mutation was cleaned up and the ledger verifies it —
    # never assumed, always re-checked.
    create_index = str(len(workflow.steps) - 1)
    assert report.cleanup_status.get(create_index, {}).get("status") == "verified", (
        f"basket item cleanup not verified: {report.cleanup_status}")
    record = mutations.current(
        report.cleanup_status[create_index]["mut_id"])
    assert record["cleanup"]["status"] == "verified"
    assert mutations.outstanding() == [], (
        "mutation(s) left outstanding after replay")
