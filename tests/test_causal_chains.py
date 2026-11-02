"""Tests for causal chain execution (R9) in core/chain_executor.py.

The gap this fills: the executor planned every edge independently and ran them
in suspicion-rank order. That is a set of probes, not a chain — a forge step
that needs the token a detect step produced would run first, with no token, and
report the target clean. The R9 gate names what a real causal run must do:
typed preconditions, output bindings, credential references and dependency
ordering; a failed prerequisite prevents dependent execution, while independent
branches remain possible.

What these tests pin:
  * a detected/forged credential on one leg arms the next leg that needs it
    (output binding + credential reference + dependency ordering);
  * when the producing leg does not prove, the consuming leg is reported as a
    failed precondition and never runs (failed prerequisite blocks dependents);
  * a dead leg in one chain does not block a second, independent chain;
  * none of this touches the default path — causal is opt-in, and a
    credential-needing edge with no producer is unarmable, not deferred, when
    it is off.
"""

import asyncio
import tempfile
from dataclasses import dataclass

import pytest

from actions.registry import ActionMeta, ActionRegistry, ActionResult, RiskLevel
from core.attack_graph import AttackEdge, AttackNode
from core.chain_executor import ChainExecutor
from state.manager import StateManager


@dataclass
class FakeChain:
    """Minimal ordered-path stand-in for an attack-graph chain."""
    nodes: dict
    edges: list
    score: float = 0.9

    @property
    def summary(self):
        return "fake causal chain"


def _node(node_id, node_type="url", **attrs):
    return AttackNode(id=node_id, label=attrs.get("label", node_id),
                      node_type=node_type, confidence="FIRM", attrs=attrs)


def _register(action_id, risk="LOW", success=True, confidence="CONFIRMED",
              evidence=None, data=None, requires=("url",), produces="Finding",
              record=None):
    """Register a fake action; optionally record each call's params."""
    async def fn(ctx):
        if record is not None:
            record.append(dict(ctx.params))
        return ActionResult(
            success=success, confidence=confidence,
            evidence=evidence if evidence is not None else {"impact": "marker"},
            data=data, error="" if success else "did not confirm")

    ActionRegistry.register(
        ActionMeta(id=action_id, risk=RiskLevel(risk), detectability="low",
                   description="fake", category="test",
                   requires=list(requires), produces=produces),
        fn,
    )


@pytest.fixture(autouse=True)
def _clean_registry():
    saved = dict(ActionRegistry._actions)
    yield
    ActionRegistry._actions.clear()
    ActionRegistry._actions.update(saved)


def _state():
    return StateManager(tempfile.mkdtemp())


def _run(coro):
    return asyncio.run(coro)


def _detect_forge_chain():
    """url --[exploit:detect]--> token-bearing vuln --[authenticate:forge]--> goal."""
    nodes = {
        "u": _node("u", "url", url="https://t.test/api?id=1"),
        "v": _node("v", "vuln", url="https://t.test/api?id=1", category="jwt"),
        "g": _node("g", "goal", url="https://t.test/api?id=1"),
    }
    edges = [
        AttackEdge(source_id="u", target_id="v", edge_type="exploit",
                   action_id="test.jwt.detect", likelihood=0.6, impact=0.5),
        # `escalate` is a real graph edge type with no generic edge-type
        # fallback, so the declared forge is the only candidate — the chain
        # step is tested, not a substituted probe.
        AttackEdge(source_id="v", target_id="g", edge_type="escalate",
                   action_id="test.jwt.forge", likelihood=0.6, impact=0.9),
    ]
    return FakeChain(nodes, edges)


# ── output binding + credential reference + dependency ordering ──────────

def test_upstream_token_arms_the_downstream_forge():
    """detect hands back a token; forge, which requires one, runs with it."""
    _register("test.jwt.detect", produces="JWTInfo",
              data={"token": "ey.detected.jwt"},
              evidence={"impact": "token located"})
    forge_calls = []
    _register("test.jwt.forge", produces="VulnCandidate",
              requires=("url", "token"), record=forge_calls,
              evidence={"impact": "forged token accepted"})

    state = _state()
    ex = ChainExecutor(state, {}, causal=True)
    report = _run(ex.execute([_detect_forge_chain()]))

    assert len(forge_calls) == 1, "forge never ran, so the token did not bind"
    assert forge_calls[0].get("token") == "ey.detected.jwt", \
        "forge ran without the token the detect leg produced"
    # Both legs proved: the detect observation plus the forged candidate.
    assert len(report.ran) == 2
    assert not report.skipped


# ── failed prerequisite prevents dependent execution ────────────────────

def test_failed_prerequisite_blocks_the_dependent_leg():
    """When detect does not prove, forge is a failed precondition, not a run."""
    _register("test.jwt.detect", produces="JWTInfo", success=False)
    forge_calls = []
    _register("test.jwt.forge", produces="VulnCandidate",
              requires=("url", "token"), record=forge_calls)

    state = _state()
    ex = ChainExecutor(state, {}, causal=True)
    report = _run(ex.execute([_detect_forge_chain()]))

    assert forge_calls == [], "forge ran without a proven prerequisite"
    blocked = [o for o in report.skipped
               if "precondition unproven" in o.detail]
    assert len(blocked) == 1, "the dependent leg was not reported as blocked"
    assert "token" in blocked[0].detail
    assert state.findings["findings"] == [], "a blocked chain minted a finding"


# ── independent branches remain possible ────────────────────────────────

def test_dead_leg_in_one_chain_does_not_block_another():
    """A second, independent chain still runs after the first chain stalls."""
    _register("test.jwt.detect", produces="JWTInfo", success=False)
    _register("test.jwt.forge", produces="VulnCandidate",
              requires=("url", "token"))
    other_calls = []
    _register("test.standalone", produces="Finding", record=other_calls,
              evidence={"impact": "independent proof"})

    independent = FakeChain(
        {"a": _node("a", "url", url="https://t.test/x?q=1"),
         "z": _node("z", "goal", url="https://t.test/x?q=1")},
        [AttackEdge(source_id="a", target_id="z", edge_type="exploit",
                    action_id="test.standalone", likelihood=0.6, impact=0.8)],
    )

    state = _state()
    ex = ChainExecutor(state, {}, causal=True)
    report = _run(ex.execute([_detect_forge_chain(), independent]))

    assert len(other_calls) == 1, "an unrelated chain was blocked by a dead leg"
    assert any(o.action_id == "test.standalone" for o in report.ran)


# ── a credential does not leak across independent chains ─────────────────

def test_token_from_one_chain_does_not_arm_another_chains_forge():
    """Bindings are per chain: chain B's forge must not reuse chain A's token."""
    _register("test.jwt.detect", produces="JWTInfo",
              data={"token": "ey.chainA.jwt"}, evidence={"impact": "tok"})
    forge_calls = []
    _register("test.jwt.forge", produces="VulnCandidate",
              requires=("url", "token"), record=forge_calls)

    # Chain A: detect + forge (forge arms from A's token).
    chain_a = _detect_forge_chain()
    # Chain B: a lone forge with no detect leg — must stay a failed precondition.
    chain_b = FakeChain(
        {"v2": _node("v2", "vuln", url="https://t.test/b?id=2", category="jwt"),
         "g2": _node("g2", "goal", url="https://t.test/b?id=2")},
        [AttackEdge(source_id="v2", target_id="g2", edge_type="escalate",
                    action_id="test.jwt.forge", likelihood=0.6, impact=0.9)],
    )

    state = _state()
    ex = ChainExecutor(state, {}, causal=True)
    report = _run(ex.execute([chain_a, chain_b]))

    assert len(forge_calls) == 1, "chain B's forge reused chain A's token"
    assert forge_calls[0]["url"].endswith("/api?id=1")
    assert any("precondition unproven" in o.detail for o in report.skipped)


# ── opt-in gating: default path is unchanged ─────────────────────────────

def test_credential_needing_edge_never_runs_when_causal_is_off():
    """Without causal, a forge needing a token it cannot get must not run.

    The edge may fall through to the generic arm for its type (`escalate` now
    has one: `auth.bypass.probe`), but the declared action itself must never
    execute with a made-up token, and the run must not claim the forge
    happened.
    """
    _register("test.jwt.detect", produces="JWTInfo",
              data={"token": "ey.detected.jwt"})
    forge_calls = []
    _register("test.jwt.forge", produces="VulnCandidate",
              requires=("url", "token"), record=forge_calls)

    state = _state()
    ex = ChainExecutor(state, {})  # causal defaults off
    assert ex.causal is False
    report = _run(ex.execute([_detect_forge_chain()]))

    assert forge_calls == [], "forge ran with no token on the flat path"
    assert not any(o.action_id == "test.jwt.forge" for o in report.ran)


def test_config_flag_enables_causal():
    cfg = {"chains": {"causal": {"enabled": True}}}
    ex = ChainExecutor(_state(), cfg)
    assert ex.causal is True


# ── gap #3: access-state propagation to the adoption path ────────────────

def _bypass_chain():
    """url --[escalate:bypass]--> goal, where bypass forges an admin session."""
    nodes = {
        "u": _node("u", "url", url="https://t.test/admin"),
        "g": _node("g", "goal", url="https://t.test/admin"),
    }
    edges = [AttackEdge(source_id="u", target_id="g", edge_type="escalate",
                        action_id="test.auth.bypass", likelihood=0.6, impact=0.95)]
    return FakeChain(nodes, edges)


def test_proven_access_leg_records_an_adoptable_identity():
    """A CONFIRMED escalate leg that returns a session token is persisted as an
    `identity_credential` — the shape AuthHarness.adopt_discovered consumes —
    so later authenticated modules can re-probe AS that identity."""
    _register("test.auth.bypass", produces="VulnCandidate",
              data={"forged_token": "ey.admin.session"},
              evidence={"impact": "admin panel reached"})

    state = _state()
    ex = ChainExecutor(state, {}, causal=True)
    _run(ex.execute([_bypass_chain()]))

    creds = state.get_assets_by_type("identity_credential")
    assert len(creds) == 1, "a proven access leg did not record an identity"
    attrs = creds[0]["attrs"]
    assert attrs["token"] == "ey.admin.session"
    assert attrs["acquired_via"] == "escalate"
    assert "ey.admin.session" not in attrs["token_preview"], "token not redacted"

    # The real adoption path turns it into a live identity with no extra glue.
    from core.auth_harness import AuthHarness
    harness = AuthHarness({})
    adopted = harness.adopt_discovered(state)
    assert adopted == 1
    assert any(i.bearer_token == "ey.admin.session"
               for i in harness.identities.values())


# ── R9 branch outcomes: DAG execution over shared nodes ──────────────────

def test_branch_shared_prefix_runs_once_and_propagates_bindings():
    """Two chains share the detect prefix; in DAG mode it runs once and the
    token it proves arms both downstream branches."""
    detect_calls = []
    _register("test.jwt.detect", produces="JWTInfo",
              data={"token": "ey.shared"}, evidence={"impact": "tok"},
              record=detect_calls)
    forge_a, forge_b = [], []
    _register("test.forge.a", produces="VulnCandidate",
              requires=("url", "token"), record=forge_a,
              evidence={"impact": "a"})
    _register("test.forge.b", produces="VulnCandidate",
              requires=("url", "token"), record=forge_b,
              evidence={"impact": "b"})

    nodes = {
        "u": _node("u", "url", url="https://t.test/api?id=1"),
        "v": _node("v", "vuln", url="https://t.test/api?id=1", category="jwt"),
        "ga": _node("ga", "goal", url="https://t.test/api?id=1"),
        "gb": _node("gb", "goal", url="https://t.test/api?id=1"),
    }
    detect = AttackEdge("u", "v", "exploit", action_id="test.jwt.detect",
                        likelihood=0.6, impact=0.5)
    fa = AttackEdge("v", "ga", "escalate", action_id="test.forge.a",
                    likelihood=0.6, impact=0.9)
    fb = AttackEdge("v", "gb", "escalate", action_id="test.forge.b",
                    likelihood=0.6, impact=0.9)
    chain1 = FakeChain(nodes, [detect, fa])
    chain2 = FakeChain(nodes, [detect, fb])

    state = _state()
    ex = ChainExecutor(state, {"chains": {"causal": {"branch": True}}})
    assert ex.branch is True and ex.causal is True
    _run(ex.execute([chain1, chain2]))

    assert len(detect_calls) == 1, "shared prefix ran more than once"
    assert len(forge_a) == 1 and forge_a[0].get("token") == "ey.shared"
    assert len(forge_b) == 1 and forge_b[0].get("token") == "ey.shared"


def test_branch_failure_blocks_only_descendants():
    """A failed leg on one branch blocks that branch's descendant, while the
    sibling branch runs to its own goal."""
    _register("test.jwt.detect", produces="JWTInfo",
              data={"token": "ey.shared"}, evidence={"impact": "t"})
    _register("test.forge.a", produces="VulnCandidate",
              requires=("url", "token"), success=False)   # dead branch
    _register("test.forge.b", produces="VulnCandidate",
              requires=("url", "token"), evidence={"impact": "b"})  # lives
    deep_calls = []
    _register("test.deep", produces="Finding", record=deep_calls,
              evidence={"impact": "deep"})

    nodes = {
        "u": _node("u", "url", url="https://t.test/x?id=1"),
        "v": _node("v", "vuln", url="https://t.test/x?id=1", category="jwt"),
        "m": _node("m", "vuln", url="https://t.test/x?id=1", category="jwt"),
        "ga": _node("ga", "goal", url="https://t.test/x?id=1"),
        "n": _node("n", "vuln", url="https://t.test/x?id=1", category="jwt"),
        "gb": _node("gb", "goal", url="https://t.test/x?id=1"),
    }
    detect = AttackEdge("u", "v", "exploit", action_id="test.jwt.detect",
                        likelihood=0.6, impact=0.5)
    va = AttackEdge("v", "m", "escalate", action_id="test.forge.a",
                    likelihood=0.6, impact=0.9)              # fails
    mga = AttackEdge("m", "ga", "exploit", action_id="test.deep",
                     likelihood=0.6, impact=0.9)             # must be blocked
    vb = AttackEdge("v", "n", "escalate", action_id="test.forge.b",
                    likelihood=0.6, impact=0.9)              # proves
    ngb = AttackEdge("n", "gb", "exploit", action_id="test.deep",
                     likelihood=0.6, impact=0.9)             # must run
    chain_dead = FakeChain(nodes, [detect, va, mga])
    chain_live = FakeChain(nodes, [detect, vb, ngb])

    state = _state()
    ex = ChainExecutor(state, {"chains": {"causal": {"branch": True}}})
    report = _run(ex.execute([chain_dead, chain_live]))

    # The deep action ran once — only on the live branch (n -> gb).
    assert len(deep_calls) == 1
    assert deep_calls[0]["url"].endswith("/x?id=1")
    # The dead branch's descendant was blocked as an unreached prerequisite.
    assert any("never reached" in o.detail and "'m'" in o.detail
               for o in report.skipped), "dead branch descendant was not blocked"


def test_detection_alone_does_not_record_an_identity():
    """A token *detected* on an exploit leg is not an *acquired* session: with
    no access leg behind it, it must not mint an adoptable identity."""
    _register("test.jwt.detect", produces="JWTInfo",
              data={"token": "ey.victim.jwt"}, evidence={"impact": "seen"})
    _register("test.jwt.forge", produces="VulnCandidate",
              requires=("url", "token"))

    nodes = {
        "u": _node("u", "url", url="https://t.test/api?id=1"),
        "v": _node("v", "vuln", url="https://t.test/api?id=1", category="jwt"),
    }
    detect = AttackEdge(source_id="u", target_id="v", edge_type="exploit",
                        action_id="test.jwt.detect", likelihood=0.6, impact=0.5)
    state = _state()
    ex = ChainExecutor(state, {}, causal=True)
    _run(ex.execute([FakeChain(nodes, [detect])]))

    assert state.get_assets_by_type("identity_credential") == [], \
        "a merely-detected token was recorded as an acquired identity"


def test_threaded_token_is_adoptable_once_the_access_leg_proves():
    """The canonical detect→forge chain: the forge leg consumes the detected
    token and proves escalation, so the engagement HAS moved. The session must
    be adoptable even though the detector, not the forge, produced the token
    (first-writer-wins leaves `sources` on the detector)."""
    _register("test.jwt.detect", produces="JWTInfo",
              data={"token": "ey.victim.jwt"}, evidence={"impact": "seen"})
    forge_calls = []
    _register("test.jwt.forge", produces="VulnCandidate",
              requires=("url", "token"), record=forge_calls,
              evidence={"impact": "escalated"})

    state = _state()
    ex = ChainExecutor(state, {}, causal=True)
    _run(ex.execute([_detect_forge_chain()]))

    assert len(forge_calls) == 1, "binding still had to arm the forge"
    creds = state.get_assets_by_type("identity_credential")
    assert len(creds) == 1, "the proven access leg did not record an identity"
    assert creds[0]["attrs"]["token"] == "ey.victim.jwt"
    assert creds[0]["attrs"]["technique"] == "test.jwt.forge"
    assert creds[0]["attrs"]["acquired_via"] == "escalate"


# ── binding extraction: real detector shapes, never a preview ────────────

def _result(data=None, evidence=None):
    return ActionResult(success=True, confidence="CONFIRMED",
                        data=data, evidence=evidence)


def test_binding_uses_the_full_token_not_the_display_preview():
    """`auth.jwt.detect` returns only a redacted `token` in `data`; the full
    value travels on the ActionResult binding channel. Binding the preview
    would arm the next leg with a value no server accepts."""
    from core.chain_bindings import extract_outputs
    full = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJl"
    result = _result(data={"tokens": [{"token": full[:80] + "..."}]})
    result.bindings = {"token": full}
    assert extract_outputs("auth.jwt.detect", result)["token"] == full


def test_data_bindings_are_accepted_for_hand_built_results():
    from core.chain_bindings import extract_outputs
    result = _result(data={"bindings": {"token": "ey.full.token"}})
    assert extract_outputs("test.detect", result)["token"] == "ey.full.token"


def test_truncated_preview_is_never_bound():
    """With no explicit contract, a `...` preview must yield no binding at all
    — not a guessed one."""
    from core.chain_bindings import extract_outputs
    result = _result(data={"tokens": [{"token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2lnbmF0dXJl"[:80] + "..."}]})
    assert extract_outputs("auth.jwt.detect", result) == {}


def test_explicit_bindings_beat_legacy_heuristics():
    """A crack result carries `token` (a signing input, not a token) and
    declares its real reusable output under `bindings`."""
    from core.chain_bindings import extract_outputs
    result = _result(data={
        "secret": "hunter2",
        "token": "header.payload",           # not replayable
        "bindings": {"credential": "hunter2"},
    })
    out = extract_outputs("auth.jwt.weak_secret_crack", result)
    assert out == {"credential": "hunter2"}
