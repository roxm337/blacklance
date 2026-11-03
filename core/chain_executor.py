"""Execute the exploit chains the attack graph finds, and prove them.

The gap this closes: the graph built edges tagged `exploit`, `pivot` and
`extract`, and `AttackEdge` has an `action_id` field documented as "action that
proves this edge" — which was never set, by anything, ever. `run_pentest()`
then printed the chains it found and returned. Fifteen actions were registered,
including `auth.jwt.none_alg`, `auth.jwt.weak_secret_crack` and
`web.ssrf.cloud_metadata`, and none of them were ever invoked on any target
outside an LLM agent session.

So the tool detected well and exploited never. Every finding it produced was a
claim, because nothing went and checked.

This module is the part that goes and checks. For each edge in a chain it picks
the action that can prove that edge, runs it under a risk ceiling and a request
budget, and promotes a successful result to a finding marked verified with the
evidence the action actually returned. An action that returns
`ActionResult.confidence = CONFIRMED` with real captured evidence is a very
different report from a heuristic that guessed.

Safety is by construction, not by convention:

  * Nothing above the selected risk ceiling runs. The current default is
    DESTRUCTIVE; callers can choose a lower ceiling for their engagement.
  * The budget is checked before each action, not after.
  * A chain is a proposal, not a mandate: a failed edge does not silently
    promote its neighbours, and a chain with no runnable edge is reported as
    skipped rather than silently dropped.
  * Every action is recorded in the audit log with its outcome, so a scan that
    fired payloads is reconstructable afterwards.

What "exploitation" means here is proving impact on a target the operator is
authorized to test: send the one request that demonstrates the flaw, capture
the response that demonstrates access, and report it. That is also what a
triager wants, because a proven finding with a captured artifact is payable
while a plausible one is not.
"""

import json
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import parse_qsl, urlparse

from actions.registry import ActionRegistry, RiskLevel
from core.attack_graph import AttackEdge
from core.chain_bindings import (
    BINDABLE_PARAMS,
    BindingContext,
    apply_bindings,
    extract_outputs,
)
from core.validators import inject_param, redact_secret

# A fast oracle can only say "not proven", never "proven safe". When the
# cheap arm fails and the operator has opted in, these heavier, noisier tools
# get one shot at the same target. Kept out of the default routing table
# because they are HIGH risk and slow; the risk ceiling still gates them.
HIGH_RISK_ALTERNATES: dict[str, tuple[str, ...]] = {
    "web.sqli.detect": ("web.sqli.sqlmap",),
    "web.sqli.blind_detect": ("web.sqli.sqlmap",),
    "web.xss.reflected": ("web.xss.dalfox",),
}

RISK_ORDER = [RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH,
              RiskLevel.DESTRUCTIVE]

# Edge types whose semantics are "gain or move access", as opposed to merely
# observing. Only a proven leg on one of these that hands back a reusable
# session has actually moved the engagement to a new identity — detecting a
# token in a response (an `exploit`/`extract` leg) has not. Gap #3 records an
# adoptable identity only for these.
_ACCESS_EDGES = frozenset({"authenticate", "escalate", "pivot"})


def risk_allows(action_risk: str, ceiling: RiskLevel) -> bool:
    """Is this action under the operator's ceiling?"""
    try:
        level = RiskLevel(str(action_risk).upper())
    except ValueError:
        # An unparseable risk is not permission to run it.
        return False
    return RISK_ORDER.index(level) <= RISK_ORDER.index(ceiling)


def _reason_rank(reason: str) -> int:
    """Run vuln-driven edges before generic probes.

    An edge carrying a declared action or a vuln-category match names a
    specific suspected flaw; an "edge type" fallback is a surface with a
    generic probe. When the budget only covers some of them, the
    specific suspicion must spend first.
    """
    text = str(reason or "")
    if text.startswith("declared on edge"):
        return 0
    if text.startswith("vuln category"):
        return 1
    return 2


# Which action can prove which graph transition. The table lives in
# `core.action_routing` because the attack planner needs the same answers:
# keeping two copies is how a module detected a class the executor could not
# name an action for. Re-exported here for callers that already import them
# from this module.
#
# Note `extract` is no longer empty: the causal binding layer can carry a
# credential out of an SSRF metadata read or a file-disclosure leg, and the
# old empty list meant the thread had a producer type and no producer. The
# actions named there return a real secret, not a reachability re-fetch —
# `verify.reproducible` is still deliberately absent, because a stable 200 is
# not a vulnerability.
from core.action_routing import (  # noqa: E402  (kept next to its use)
    EDGE_ACTIONS,
    action_for_category,
)


@dataclass
class PlannedEdge:
    """One edge, the action chosen to prove it, and the target to point it at."""
    edge: AttackEdge
    action_id: str
    risk: str
    url: str
    reason: str = ""
    params: dict = field(default_factory=dict)


@dataclass
class _SyntheticChain:
    """A one-edge chain view over a shared node map, for DAG-mode planning.

    `_causal_steps`, `_select_action` and `_build_params` all read a chain's
    `.nodes` to arm an edge. In branch mode the nodes come from the merged DAG,
    not a single path, so this wraps that node map with the single edge being
    classified.
    """
    nodes: dict
    edges: list
    summary: str = ""


@dataclass
class CausalStep:
    """One edge of a causal chain, classified for in-order execution.

    `armed` runs as planned. `deferred` is armable except for a bindable
    param (a token/credential) it expects an upstream leg to produce, so it is
    held until that binding exists — or blocked as a failed precondition if it
    never does. `unarmable` names an edge no registered action can prove, kept
    visible so coverage is not overstated.
    """
    edge: AttackEdge
    status: str                      # armed | deferred | unarmable
    action_id: str = ""
    reason: str = ""
    risk: str = ""
    planned: Optional[PlannedEdge] = None
    params: dict = field(default_factory=dict)
    needs: set = field(default_factory=set)
    detail: str = ""


@dataclass
class EdgeOutcome:
    """What happened when we went and proved one edge."""
    edge: AttackEdge
    action_id: str
    status: str                      # ran | skipped | blocked_risk | no_action
    finding_id: str = ""
    confidence: str = ""
    impact: str = ""
    detail: str = ""
    evidence: dict = field(default_factory=dict)


@dataclass
class ExecutionReport:
    ran: list[EdgeOutcome] = field(default_factory=list)
    blocked: list[EdgeOutcome] = field(default_factory=list)
    skipped: list[EdgeOutcome] = field(default_factory=list)
    unarmable: list[EdgeOutcome] = field(default_factory=list)

    @property
    def proven(self) -> int:
        return sum(1 for o in self.ran if o.finding_id and o.confidence == "CONFIRMED")

    def summary(self) -> str:
        parts = [f"{self.proven} proven", f"{len(self.blocked)} blocked by risk",
                 f"{len(self.skipped)} skipped"]
        if self.unarmable:
            parts.append(f"{len(self.unarmable)} unarmable")
        return ", ".join(parts)


class ChainExecutor:
    """Runs chain edges for real, under a risk ceiling and a budget."""

    def __init__(self, state, config: Optional[dict] = None,
                 budget=None, audit=None, operations=None,
                 max_risk: RiskLevel = RiskLevel.DESTRUCTIVE,
                 max_actions: int = 0,
                 module_id: str = "chain_executor",
                 causal: Optional[bool] = None):
        self.state = state
        self.config = config or {}
        self.budget = budget
        self.audit = audit
        self.operations = operations
        self.max_risk = max_risk
        self.max_actions = max(0, int(max_actions))
        self.module_id = module_id or "chain_executor"
        self._used = 0
        # Causal execution (R9) runs each chain in path order, threading the
        # credentials one leg produces into the next and blocking an edge whose
        # prerequisite never proved. Off by default — the flat probe path is
        # what the existing suite pins — and opt-in via `chains.causal.enabled`
        # or an explicit constructor flag.
        _causal_cfg = (self.config.get("chains") or {}).get("causal", {}) or {}
        if causal is None:
            causal = bool(_causal_cfg.get("enabled", False))
        self.causal = bool(causal)
        # Branch mode (R9 "branch outcomes"): instead of running each chain as
        # an isolated linear path, treat the whole chain set as one DAG over
        # shared nodes. A node reached by any proven parent runs its outgoing
        # edges once; a credential proven on a shared prefix propagates to
        # every branch below it; a failed prerequisite blocks only that node's
        # descendants, leaving sibling branches free. Opt-in via
        # `chains.causal.branch`; implies causal.
        self.branch = bool(_causal_cfg.get("branch", False))
        if self.branch:
            self.causal = True
        # Reproducibility gate (R9 verification): an action that confirms a
        # candidate is re-run once, and promotion requires the second run to
        # confirm at the same confidence or better. Opt-in — it doubles the
        # requests of every proving action — but when on, a flapping target
        # cannot be filed as a vulnerability on the strength of one 200.
        self.verify = bool((self.config.get("chains") or {}).get("verify", False))
        # Escalation to a HIGH-risk tool after the cheap oracle fails. Off by
        # default: sqlmap/dalfox are slow and loud, and "the fast check said
        # no" is not a reason to fire them without the operator asking.
        self.allow_high_risk = bool(
            (self.config.get("chains") or {}).get("allow_high_risk", False))
        # Edges we recognised but could not arm, so the operator can see that
        # coverage was limited instead of assuming the run was exhaustive.
        self.unarmable: list[EdgeOutcome] = []

    # ── planning ──────────────────────────────────────────────────

    def plan(self, chain) -> list[PlannedEdge]:
        """Choose, for each edge in a chain, the action that can prove it.

        An action is only planned if we can satisfy every parameter it declares
        in `ActionMeta.requires`. Checking that here rather than at call time is
        the point: a missing param raised as a KeyError inside the action looks
        exactly like "target not vulnerable" in the report, which is how a
        broken executor talks you into a false negative.
        """
        planned = []
        for edge in chain.edges:
            candidates = self._select_action(edge, chain)
            if not candidates:
                if edge.action_id and not ActionRegistry.get(edge.action_id):
                    self.unarmable.append(EdgeOutcome(
                        edge=edge, action_id=edge.action_id,
                        status="no_action",
                        detail=(f"declared action '{edge.action_id}' is not "
                                "registered in this build")))
                    continue
                if edge.edge_type in EDGE_ACTIONS:
                    # A known edge type with no proving action (extract):
                    # say so out loud instead of dropping it silently or,
                    # worse, spending budget re-proving reachability.
                    self.unarmable.append(EdgeOutcome(
                        edge=edge, action_id="", status="no_action",
                        detail=f"no proving action registered for "
                               f"'{edge.edge_type}' edges"))
                continue

            # Pick the first candidate we can actually arm, not merely the first
            # one that exists. verify.differential needs two URLs, so on a plain
            # URL it is unusable and must not be chosen over a real probe.
            chosen = None
            first_failure = None
            for action_id, reason in candidates:
                entry = ActionRegistry.get(action_id)
                if not entry:
                    continue
                meta, _ = entry
                params, missing = self._build_params(edge, chain, meta)
                if not missing and params.get("url"):
                    chosen = (action_id, reason, meta, params)
                    break
                if first_failure is None:
                    first_failure = (action_id, reason, missing or ["url"])

            if chosen is None:
                # Remember the edges we could not arm, so the operator learns
                # that coverage was limited rather than assuming a clean run.
                action_id, reason, missing = first_failure
                self.unarmable.append(EdgeOutcome(
                    edge=edge, action_id=action_id, status="no_action",
                    detail=reason + " — cannot supply " + ", ".join(missing)))
                continue

            action_id, reason, meta, params = chosen
            risk = getattr(meta.risk, "value", meta.risk)
            planned.append(PlannedEdge(
                edge=edge, action_id=action_id, risk=str(risk),
                url=params["url"], reason=reason, params=params))
        return planned

    # ── causal planning & execution (R9) ───────────────────────────

    def _causal_steps(self, chain) -> list["CausalStep"]:
        """Classify a chain's edges, in path order, for causal execution.

        Same candidate selection and arming as `plan()`, but it keeps the
        edge order (a chain reads source-to-goal, not by suspicion rank) and
        adds a third verdict: an edge missing only a *bindable* param — a
        token or credential an earlier leg is expected to produce — is
        `deferred` rather than dropped as unarmable. Deferral is what lets a
        detect→forge pair work: forge is unarmable on its own and armable
        once detect hands back the token.
        """
        steps: list[CausalStep] = []
        for edge in chain.edges:
            candidates = self._select_action(edge, chain)
            if not candidates:
                if edge.action_id and not ActionRegistry.get(edge.action_id):
                    steps.append(CausalStep(
                        edge=edge, status="unarmable", action_id=edge.action_id,
                        detail=(f"declared action '{edge.action_id}' is not "
                                "registered in this build")))
                elif edge.edge_type in EDGE_ACTIONS:
                    steps.append(CausalStep(
                        edge=edge, status="unarmable",
                        detail=f"no proving action registered for "
                               f"'{edge.edge_type}' edges"))
                # Structural edges (affected_by, api_discovery) prove nothing
                # and need no action: they carry reachability, not a probe.
                continue

            chosen = None
            deferred = None
            first_failure = None
            for action_id, reason in candidates:
                entry = ActionRegistry.get(action_id)
                if not entry:
                    continue
                meta, _ = entry
                params, missing = self._build_params(edge, chain, meta)
                if not missing and params.get("url"):
                    chosen = (action_id, reason, meta, params)
                    break
                # Armable but for a credential the graph cannot carry: hold it
                # for a binding from an upstream leg. `url` must already be
                # known — a deferred edge still needs a target to aim at. Stop
                # here rather than falling through: this is the highest-priority
                # candidate (a declared chain action outranks a generic probe),
                # so substituting an unrelated edge-type probe would run a
                # different test than the chain intended.
                missing_set = set(missing)
                bindable = {m for m in missing_set if m in BINDABLE_PARAMS}
                if (params.get("url") and missing_set
                        and missing_set == bindable):
                    deferred = (action_id, reason, meta, params, bindable)
                    break
                if first_failure is None:
                    first_failure = (action_id, reason, missing or ["url"])

            if chosen is not None:
                action_id, reason, meta, params = chosen
                risk = str(getattr(meta.risk, "value", meta.risk))
                steps.append(CausalStep(
                    edge=edge, status="armed", action_id=action_id,
                    reason=reason, risk=risk,
                    planned=PlannedEdge(
                        edge=edge, action_id=action_id, risk=risk,
                        url=params["url"], reason=reason, params=params)))
            elif deferred is not None:
                action_id, reason, meta, params, needs = deferred
                risk = str(getattr(meta.risk, "value", meta.risk))
                steps.append(CausalStep(
                    edge=edge, status="deferred", action_id=action_id,
                    reason=reason, risk=risk, params=params, needs=needs))
            else:
                action_id, reason, missing = first_failure
                steps.append(CausalStep(
                    edge=edge, status="unarmable", action_id=action_id,
                    detail=reason + " — cannot supply " + ", ".join(missing)))
        return steps

    async def _execute_chain_causal(self, chain, report: ExecutionReport) -> None:
        """Run one chain in path order, threading bindings between legs.

        The binding context is per chain: a credential one leg obtains arms
        only this chain's later legs, never an unrelated path. A `deferred`
        edge whose binding never materialises is reported as a failed
        precondition — not run — which is the half of the R9 gate that keeps
        the executor from firing a probe it cannot actually aim.
        """
        ctx = BindingContext()
        for step in self._causal_steps(chain):
            if step.status == "unarmable":
                self.unarmable.append(EdgeOutcome(
                    edge=step.edge, action_id=step.action_id,
                    status="no_action", detail=step.detail))
                continue

            if self.max_actions and self._used >= self.max_actions:
                report.skipped.append(EdgeOutcome(
                    edge=step.edge, action_id=step.action_id,
                    status="skipped", detail="action budget exhausted"))
                continue

            if step.status == "deferred":
                filled, unmet = apply_bindings(step.params, step.needs, ctx)
                if unmet:
                    report.skipped.append(EdgeOutcome(
                        edge=step.edge, action_id=step.action_id,
                        status="skipped",
                        detail=("precondition unproven: needs "
                                + ", ".join(sorted(unmet))
                                + " from an upstream leg that did not run "
                                "or did not prove")))
                    continue
                planned = PlannedEdge(
                    edge=step.edge, action_id=step.action_id, risk=step.risk,
                    url=filled["url"], reason=step.reason, params=filled)
            else:
                planned = step.planned

            outcome = await self._run_one(planned, binding_ctx=ctx)
            if outcome.status == "ran":
                report.ran.append(outcome)
                # Access-state propagation (gap #3): a proven leg on an
                # access-gaining edge has moved the engagement to a new
                # identity. Record it as an `identity_credential` so the
                # existing `adopt_discovered` path lets later authenticated
                # modules re-probe the surface AS that identity — web-native
                # horizontal/vertical privilege movement, not a single-request
                # dead end.
                #
                # The credential may have been produced by this leg *or* by an
                # upstream detect leg and threaded in; gating on "this action
                # produced it" made the canonical detect→forge chain record
                # nothing, because first-writer-wins leaves the source on the
                # detector. What matters is that the access leg proved and a
                # usable token exists at that point.
                if (outcome.confidence == "CONFIRMED"
                        and planned.edge.edge_type in _ACCESS_EDGES):
                    token = self._usable_token(ctx.get("token"),
                                               planned.params.get("token"))
                    if token:
                        self._record_acquired_identity(planned, token)
            elif outcome.status == "blocked_risk":
                report.blocked.append(outcome)
            else:
                report.skipped.append(outcome)

    @staticmethod
    def _usable_token(*candidates) -> str:
        """First candidate usable for authenticated replay, else "".

        Rejects empty strings, cookie-jar keys (not a header value) and
        redacted previews (`...`) — a preview cannot be replayed, and storing
        it as an identity makes every later authenticated probe fail while the
        report claims an identity was adopted.
        """
        for candidate in candidates:
            token = str(candidate or "").strip()
            if token and not token.startswith("cookie:") \
                    and not token.endswith(("...", "…")):
                return token
        return ""

    def _record_acquired_identity(self, planned: PlannedEdge, token: str) -> None:
        """Persist a session a causal leg obtained or used as an identity.

        Matches the `identity_credential` shape `auth_audit`/`auth_bypass`
        write, so no new consumer is needed: `AuthHarness.adopt_discovered`
        already turns these into live identities, and ~15 authenticated
        modules call it. The token is stored whole because authenticated
        replay must send it, and redacted (`token_preview`) everywhere it is
        displayed — the same discipline the detectors already follow.
        """
        token = self._usable_token(token)
        if not token:
            return
        technique = planned.action_id
        self.state.add_asset(
            "identity_credential",
            f"identity:{technique}:{planned.url}",
            technique,
            confidence="CONFIRMED",
            sources=[self.module_id],
            attrs={
                "endpoint": planned.url,
                "technique": technique,
                "role": "",
                "acquired_via": planned.edge.edge_type,
                "token": token,
                "token_preview": redact_secret(token),
            },
        )

    # ── DAG / branch execution (R9 branch outcomes) ────────────────

    @staticmethod
    def _merge_nodes(chains) -> dict:
        """Union of every chain's nodes, keyed by id, for DAG planning.

        Chains that share a prefix name the same node ids, so the union is the
        DAG's vertex set. First definition of an id wins; duplicates across
        chains are the same node by construction.
        """
        merged: dict = {}
        for chain in chains:
            nodes = getattr(chain, "nodes", None)
            items = (nodes.values() if isinstance(nodes, dict)
                     else (nodes or []))
            for node in items:
                nid = getattr(node, "id", None)
                if nid and nid not in merged:
                    merged[nid] = node
        return merged

    async def _execute_dag(self, chains, report: ExecutionReport) -> None:
        """Execute the whole chain set as one DAG over shared nodes.

        Reachability, not path membership, decides what runs: a root (a node no
        edge targets) starts reached; any edge whose source is reached runs
        once; a leg that proves marks its target reached and hands its
        credential context down the branch. A leg that fails — or an edge whose
        source is never reached — leaves its target unreached, so only that
        node's descendants are blocked while sibling branches proceed. This is
        the "branch outcomes / independent branches" half of R9.
        """
        node_map = self._merge_nodes(chains)
        edges: list[AttackEdge] = []
        seen: set = set()
        targets: set = set()
        for chain in chains:
            for edge in getattr(chain, "edges", []) or []:
                key = (edge.source_id, edge.target_id, edge.edge_type,
                       edge.action_id)
                if key in seen:
                    continue
                seen.add(key)
                edges.append(edge)
                targets.add(edge.target_id)

        node_ctx: dict[str, BindingContext] = {}
        reached: set = set()
        for nid in node_map:
            if nid not in targets:
                reached.add(nid)
                node_ctx[nid] = BindingContext()
        # A node present only as an edge endpoint (never declared in any
        # chain.nodes) is still a valid root if nothing targets it.
        for edge in edges:
            if edge.source_id not in targets and edge.source_id not in reached:
                reached.add(edge.source_id)
                node_ctx[edge.source_id] = BindingContext()

        processed: set = set()
        progress = True
        while progress:
            progress = False
            for edge in edges:
                key = (edge.source_id, edge.target_id, edge.edge_type,
                       edge.action_id)
                if key in processed or edge.source_id not in reached:
                    continue
                processed.add(key)
                progress = True
                await self._run_dag_edge(
                    edge, node_map,
                    node_ctx.get(edge.source_id) or BindingContext(),
                    node_ctx, reached, report)

        # Anything still unprocessed had a source that no proven leg reached.
        for edge in edges:
            key = (edge.source_id, edge.target_id, edge.edge_type,
                   edge.action_id)
            if key not in processed:
                report.skipped.append(EdgeOutcome(
                    edge=edge, action_id=edge.action_id or "",
                    status="skipped",
                    detail=("precondition unproven: source node "
                            f"'{edge.source_id}' was never reached by a "
                            "proven leg")))

    async def _run_dag_edge(self, edge: AttackEdge, node_map: dict,
                            source_ctx: BindingContext,
                            node_ctx: dict, reached: set,
                            report: ExecutionReport) -> None:
        """Run (or pass through) one DAG edge, propagating reachability + ctx."""

        def _reach(target_id: str, ctx: BindingContext) -> None:
            if target_id in node_ctx:
                for btype, value in ctx.values.items():
                    node_ctx[target_id].put(btype, value,
                                            ctx.sources.get(btype, ""))
            else:
                node_ctx[target_id] = ctx
            reached.add(target_id)

        steps = self._causal_steps(_SyntheticChain(node_map, [edge]))
        if not steps:
            # Structural edge (affected_by, api_discovery): no probe, pure
            # reachability — the target is reachable because the source is.
            _reach(edge.target_id, source_ctx.clone())
            return

        step = steps[0]
        if step.status == "unarmable":
            self.unarmable.append(EdgeOutcome(
                edge=step.edge, action_id=step.action_id,
                status="no_action", detail=step.detail))
            return

        if self.max_actions and self._used >= self.max_actions:
            report.skipped.append(EdgeOutcome(
                edge=step.edge, action_id=step.action_id,
                status="skipped", detail="action budget exhausted"))
            return

        branch_ctx = source_ctx.clone()
        if step.status == "deferred":
            filled, unmet = apply_bindings(step.params, step.needs, branch_ctx)
            if unmet:
                report.skipped.append(EdgeOutcome(
                    edge=step.edge, action_id=step.action_id,
                    status="skipped",
                    detail=("precondition unproven: needs "
                            + ", ".join(sorted(unmet))
                            + " from an upstream leg that did not run "
                            "or did not prove")))
                return
            planned = PlannedEdge(
                edge=step.edge, action_id=step.action_id, risk=step.risk,
                url=filled["url"], reason=step.reason, params=filled)
        else:
            planned = step.planned

        outcome = await self._run_one(planned, binding_ctx=branch_ctx)
        if outcome.status == "ran":
            report.ran.append(outcome)
            if outcome.confidence == "CONFIRMED":
                # Same rule as the linear path: the access leg moved the
                # engagement, whether it minted the credential or consumed one
                # the shared prefix produced.
                if planned.edge.edge_type in _ACCESS_EDGES:
                    token = self._usable_token(branch_ctx.get("token"),
                                               planned.params.get("token"))
                    if token:
                        self._record_acquired_identity(planned, token)
                # Only a proven transition propagates reachability down branch.
                _reach(edge.target_id, branch_ctx)
        elif outcome.status == "blocked_risk":
            report.blocked.append(outcome)
        else:
            report.skipped.append(outcome)

    def _build_params(self, edge: AttackEdge, chain, meta):
        """Work out the arguments an action needs, from what the graph knows.

        Returns (params, missing) where `missing` names the required parameters
        we could not fill in. The graph is thin: a `parameter` node knows its
        own name and the URL it belongs to, a `url` node only knows its URL, and
        a `vuln` node knows the category and nothing about where to send
        anything. So most edges can supply url+param and little else.
        """
        params: dict[str, Any] = {}
        nodes = [n for n in (self._node(edge.source_id, chain),
                             self._node(edge.target_id, chain))
                 if n is not None]

        url = ""
        param = ""
        for node in nodes:
            attrs = node.attrs or {}
            if not url:
                for key in ("url", "value", "endpoint"):
                    candidate = str(attrs.get(key, "")).strip()
                    if candidate.startswith(("http://", "https://")):
                        url = candidate
                        break
                if not url and str(node.label or "").startswith(
                        ("http://", "https://")):
                    url = str(node.label).strip()
            if not param:
                if str(node.node_type) == "parameter":
                    # A parameter asset's label IS the parameter name.
                    param = str(node.label or "").strip()
                elif attrs.get("param"):
                    param = str(attrs["param"]).strip()
                elif attrs.get("name") and str(attrs.get("name")):
                    param = str(attrs["name"]).strip()

        if url and not param:
            # A URL like https://h/s?a=1 tells us the parameter name.
            query = urlparse(url).query
            if query:
                first = parse_qsl(query)
                param = first[0][0] if first else ""

        # Mirror `AttackGraph._surface`: an object reference names its id in
        # the path segment, not the query string. The two must agree — if the
        # graph proposes a probe the executor cannot arm, the report says
        # "planned" and means "unarmable", which is worse than saying neither.
        if url and not param:
            template = ""
            for node in nodes:
                template = str((node.attrs or {}).get("template") or "")
                if template:
                    break
            if "{id}" in template:
                param = "id"

        if url:
            params["url"] = url
        if param:
            params["param"] = param
        token = ""
        for node in nodes:
            token = str((node.attrs or {}).get("token", "")).strip()
            if token:
                break
        if token:
            params["token"] = token

        # Two-URL oracles: baseline is the same request with a benign value,
        # test is the one carrying the payload. `inject_param` tolerates a
        # parameter that is not yet present, so this is safe to build.
        if "baseline_url" in getattr(meta, "requires", []) and url and param:
            params["baseline_url"] = inject_param(url, param, "1")
            params.setdefault("test_url", inject_param(url, param, "'"))
        if "urls" in getattr(meta, "requires", []) and url:
            params["urls"] = [url]

        missing = [r for r in getattr(meta, "requires", []) if not params.get(r)]
        return params, missing

    @staticmethod
    def _node(node_id, chain):
        """Find a node in a chain, whether it stores nodes as a list or a map.

        `AttackPath.nodes` is a `list[AttackNode]`, so `.get()` on it raises
        `AttributeError` rather than returning None. That made every chain
        built by `find_chains` fail at `_select_action`, which is the first
        thing execution does — so no chain could ever be armed, and the error
        surfaced as a crash instead of a skipped probe.

        Both shapes are accepted because this function is also used with
        hand-built stand-ins in tests, and a helper that only works for one of
        them is how the disagreement stayed invisible.
        """
        nodes = getattr(chain, "nodes", None)
        if nodes is None:
            return None
        if isinstance(nodes, dict):
            return nodes.get(node_id)
        for node in nodes:
            if getattr(node, "id", None) == node_id:
                return node
        return None

    def _select_action(self, edge: AttackEdge, chain) -> list:
        """Candidate actions to prove this edge, best first.

        Returns a list of (action_id, reason) so the caller can fall through to
        the next candidate if the preferred one cannot be armed with the data
        the graph actually has.
        """
        candidates = []
        if edge.action_id:
            if ActionRegistry.get(edge.action_id):
                candidates.append((edge.action_id, "declared on edge"))
            # An unregistered declared action no longer kills the edge: fall
            # through to the candidate lists so the surface is still tested
            # instead of reported as unarmable.

        target = self._node(edge.target_id, chain)
        category = ""
        if target is not None:
            category = str((target.attrs or {}).get("category", "")).lower()

        if category:
            # Normalizes hyphens/underscores, so "broken-access-control" and
            # "Broken Access Control" route alike.
            action_id = action_for_category(category)
            if action_id and ActionRegistry.get(action_id):
                candidates.append((action_id, f"vuln category '{category}'"))

        for action_id in EDGE_ACTIONS.get(edge.edge_type, []):
            if ActionRegistry.get(action_id):
                candidates.append((action_id, f"edge type '{edge.edge_type}'"))

        # Deduplicate, keeping the earliest (strongest) reason for each action.
        seen = set()
        unique = []
        for action_id, reason in candidates:
            if action_id not in seen:
                seen.add(action_id)
                unique.append((action_id, reason))
        return unique

    # ── execution ─────────────────────────────────────────────────

    async def execute(self, chains, max_chains: int = 0) -> ExecutionReport:
        report = ExecutionReport()
        pending = list(chains) if max_chains <= 0 else list(chains)[:max_chains]
        if self.budget is not None and not self.budget.check():
            # Budget already exhausted: report every chain as skipped WITHOUT
            # pruning. The old code pruned first and then raised out of here,
            # deleting prior findings with no replacements and skipping
            # state.save(); prune-then-skip-all would lose them just as
            # silently. Untouched prior claims survive for the operator.
            for chain in pending:
                edges = list(getattr(chain, "edges", []) or [])
                if edges:
                    report.skipped.append(EdgeOutcome(
                        edge=edges[0], action_id="",
                        status="skipped", detail="budget exhausted"))
            return report
        # Execution runs outside any module run, so without this the proven
        # findings were tagged with an empty module id — orphaned from every
        # module view — and every re-run stacked a fresh copy next to the
        # stale ones. Prune our own previous claims, tag the new ones.
        previous_current = self.state.module.get("current")
        self.state.prune_module_findings(self.module_id)
        self.state.module["current"] = self.module_id
        try:
            if self.branch:
                # One DAG over all chains: shared prefixes run once, bindings
                # propagate down each branch, and a failed prerequisite blocks
                # only its descendants.
                await self._execute_dag(pending, report)
            else:
                for chain in pending:
                    if self.causal:
                        # Each chain is an ordered path; run it in order,
                        # threading bindings and honouring preconditions.
                        # Chains stay independent of one another, so a dead leg
                        # here never blocks the next chain.
                        await self._execute_chain_causal(chain, report)
                        continue
                    # Vuln-driven edges (declared action, category match) run
                    # before generic probes: without this ordering one probe
                    # family (open redirects on every surface) spends the
                    # whole budget while the SQLi that matters never runs.
                    planned_edges = sorted(
                        self.plan(chain),
                        key=lambda item: _reason_rank(item.reason))
                    for planned in planned_edges:
                        if self.max_actions and self._used >= self.max_actions:
                            report.skipped.append(EdgeOutcome(
                                edge=planned.edge, action_id=planned.action_id,
                                status="skipped",
                                detail="action budget exhausted"))
                            continue
                        outcome = await self._run_one(planned)
                        if outcome.status == "ran":
                            report.ran.append(outcome)
                        elif outcome.status == "blocked_risk":
                            report.blocked.append(outcome)
                        else:
                            report.skipped.append(outcome)
        finally:
            self.state.module["current"] = previous_current
        report.unarmable = list(self.unarmable)
        return report

    async def _run_one(self, planned: PlannedEdge,
                       binding_ctx: Optional[BindingContext] = None) -> EdgeOutcome:
        if not risk_allows(planned.risk, self.max_risk):
            if self.operations is not None:
                self.operations.refuse(
                    {"kind": "action", "id": planned.action_id}, "risk_blocked",
                    f"{planned.action_id} is {planned.risk}, above the "
                    f"{self.max_risk.value} ceiling", target=planned.url)
            return EdgeOutcome(
                edge=planned.edge, action_id=planned.action_id,
                status="blocked_risk",
                detail=(f"{planned.action_id} is {planned.risk}, above the "
                        f"{self.max_risk.value} ceiling"),
            )

        if self.budget is not None and not self.budget.check():
            if self.operations is not None:
                self.operations.refuse(
                    {"kind": "action", "id": planned.action_id},
                    "budget_exhausted", "budget exhausted", target=planned.url)
            return EdgeOutcome(
                edge=planned.edge, action_id=planned.action_id,
                status="skipped", detail="budget exhausted",
            )

        from actions.registry import ActionContext

        ctx = ActionContext(
            action_id=planned.action_id,
            params=dict(planned.params),
            target=planned.url,
        )
        entry = ActionRegistry.get(planned.action_id)
        ctx.meta = entry[0] if entry else None
        if self.audit is not None:
            ctx.audit = self.audit
        if self.operations is not None:
            ctx.operations = self.operations

        if self.budget is not None:
            try:
                consume = getattr(self.budget, "consume_action", None)
                if consume:
                    consume()
                else:
                    self.budget.record_action()
            except Exception as exc:
                if self.operations is not None:
                    self.operations.refuse(
                        {"kind": "action", "id": planned.action_id},
                        "action_budget_exhausted", str(exc) or "action budget exhausted",
                        target=planned.url)
                return EdgeOutcome(
                    edge=planned.edge, action_id=planned.action_id,
                    status="skipped", detail=str(exc) or "action budget exhausted",
                )

        try:
            result = await ActionRegistry.execute(planned.action_id, ctx)
        except Exception as exc:
            # An action that blows up is a bug in the action, not evidence that
            # the target is safe. Record it and keep going.
            return EdgeOutcome(
                edge=planned.edge, action_id=planned.action_id,
                status="skipped", detail=f"action raised: {exc}",
            )

        self._used += 1

        if not getattr(result, "success", False):
            escalated = await self._escalate(planned, result)
            if escalated is None:
                return EdgeOutcome(
                    edge=planned.edge, action_id=planned.action_id,
                    status="skipped",
                    detail=(getattr(result, "error", "")
                            or "action did not confirm"),
                    confidence=getattr(result, "confidence", ""),
                )
            planned, result = escalated

        # Reproducibility gate: a candidate that confirms once and not twice
        # is a flapping target, not a finding. Re-run the same action with the
        # same params and require the second verdict to hold. Off by default.
        if self.verify and not await self._reconfirms(planned, result):
            return EdgeOutcome(
                edge=planned.edge, action_id=planned.action_id,
                status="skipped",
                detail=("not reproducible: the proving action did not confirm "
                        "again on a clean re-run"),
                confidence=getattr(result, "confidence", ""),
            )

        # A successful leg may hand the next one a credential the thin graph
        # could never carry — a forged JWT, a session, a cloud key. Capture it
        # here, where the raw result is in scope, so a downstream `deferred`
        # edge can arm against it. Only populated in causal mode (binding_ctx
        # is None otherwise), so the flat path is byte-for-byte unchanged.
        if binding_ctx is not None:
            for btype, value in extract_outputs(planned.action_id, result).items():
                binding_ctx.put(btype, value, source=planned.action_id)

        if ctx.meta is not None and ctx.meta.result_kind == "observation":
            self.state.add_asset(
                "observation", f"observation:{planned.action_id}:{planned.url}",
                planned.action_id, confidence=result.confidence,
                sources=[planned.action_id], attrs={"url": planned.url})
            return EdgeOutcome(edge=planned.edge, action_id=planned.action_id,
                               status="ran", confidence=result.confidence,
                               detail="observation recorded; no vulnerability proven")
        return self._promote(planned, result)

    async def _escalate(self, planned: PlannedEdge, first):
        """Retry a definitive failure with a HIGH-risk tool, when allowed.

        Returns (new_planned, result) on success, else None. The finding is
        attributed to the action that actually proved it, so a sqlmap
        confirmation is never filed under `web.sqli.detect`.
        """
        if not self.allow_high_risk:
            return None
        if getattr(first, "confidence", "") == "BLOCKED":
            return None
        for alt_id in HIGH_RISK_ALTERNATES.get(planned.action_id, ()):
            entry = ActionRegistry.get(alt_id)
            if entry is None:
                continue
            meta = entry[0]
            if not risk_allows(meta.risk.value, self.max_risk):
                continue
            if self.budget is not None and not self.budget.check():
                return None
            params = self._alternate_params(alt_id, planned)
            if params is None:
                continue
            if self.budget is not None:
                try:
                    consume = getattr(self.budget, "consume_action", None)
                    if consume:
                        consume()
                    else:
                        self.budget.record_action()
                except Exception:
                    return None
            from actions.registry import ActionContext
            ctx = ActionContext(action_id=alt_id, params=params,
                                target=planned.url, meta=meta)
            if self.audit is not None:
                ctx.audit = self.audit
            if self.operations is not None:
                ctx.operations = self.operations
            try:
                result = await ActionRegistry.execute(alt_id, ctx)
            except Exception:
                continue
            self._used += 1
            if getattr(result, "success", False):
                return (PlannedEdge(
                    edge=planned.edge, action_id=alt_id,
                    risk=meta.risk.value, url=planned.url,
                    reason=f"{planned.reason}; escalated after a clean fast-oracle miss",
                    params=params), result)
        return None

    @staticmethod
    def _alternate_params(action_id: str, planned: PlannedEdge):
        """Parameters the escalation tool needs, from what the edge carries."""
        if action_id == "web.xss.dalfox":
            url = str(planned.url or planned.params.get("url") or "")
            return {"urls": [url]} if url else None
        if action_id == "web.sqli.sqlmap":
            url = str(planned.params.get("url") or planned.url or "")
            return {"url": url} if url else None
        params = dict(planned.params)
        return params or None

    async def _reconfirms(self, planned: PlannedEdge, first) -> bool:
        """Does the same action confirm again, at the same confidence?

        A one-shot success can be a cache, a rate-limit burst, a WAF glitch or
        a random 200; promoting it is how a clean target acquires a finding.
        Candidate-producing actions are re-run once with byte-identical params
        and must reproduce their own verdict. Actions that only observe are
        not re-run — a stable 200 proves reachability, which is not a claim
        that needs confirming.
        """
        from actions.registry import ActionContext

        entry = ActionRegistry.get(planned.action_id)
        meta = entry[0] if entry else None
        if meta is None or meta.produces not in {"Finding", "VulnCandidate"}:
            return True
        if self.budget is not None and not self.budget.check():
            # Verification is a request too. No budget means no second look;
            # keep the finding rather than dropping it for lack of funds.
            return True

        ctx = ActionContext(
            action_id=planned.action_id,
            params=dict(planned.params),
            target=planned.url,
        )
        ctx.meta = meta
        if self.audit is not None:
            ctx.audit = self.audit
        if self.operations is not None:
            ctx.operations = self.operations
        if self.budget is not None:
            try:
                consume = getattr(self.budget, "consume_action", None)
                if consume:
                    consume()
                else:
                    self.budget.record_action()
            except Exception:
                return True
        try:
            second = await ActionRegistry.execute(planned.action_id, ctx)
        except Exception:
            return False
        self._used += 1
        if not getattr(second, "success", False):
            return False
        rank = {"TENTATIVE": 0, "FIRM": 1, "CONFIRMED": 2}
        return (rank.get(str(getattr(second, "confidence", "")).upper(), 0)
                >= rank.get(str(getattr(first, "confidence", "")).upper(), 0))

    def _promote(self, planned: PlannedEdge, result) -> EdgeOutcome:
        """Turn a successful action into a verified finding.

        This is the whole point. A confirmed action result with captured
        evidence becomes a finding the operator can paste into a report, with
        `verified=True` because something actually ran and returned data.
        """
        confidence = getattr(result, "confidence", "TENTATIVE") or "TENTATIVE"
        evidence = dict(getattr(result, "evidence", {}) or {})
        impact = evidence.get("impact") or evidence.get("summary") or ""
        data = getattr(result, "data", None)
        # Success without data is a lead, not proof: a buggy action
        # returning success + empty evidence must not mint verified
        # findings. Downgrade, don't drop — the action did run.
        has_proof = bool(evidence) or bool(data)
        if not has_proof:
            confidence = "TENTATIVE"

        evidence_lines = [
            f"Action: {planned.action_id} ({planned.reason})",
            f"Target: {planned.url}",
        ]
        for key, value in list(evidence.items())[:12]:
            evidence_lines.append(f"{key}: {_stringify(value)}")
        if data is not None:
            evidence_lines.append(f"data: {_stringify(data)}")

        finding_id = self.state.add_finding(
            title=f"{'Proven' if has_proof and confidence == 'CONFIRMED' else 'Candidate'}: {planned.action_id} on {planned.url}",
            severity=_severity_for(planned.edge, evidence, confidence),
            confidence=confidence,
            category=_category_for(planned.action_id),
            description=(
                f"Executed {planned.action_id} against {planned.url} "
                f"(selected because {planned.reason}). The action returned a "
                f"successful result at {confidence} confidence. This was run, "
                "not inferred: the evidence below came back from the target. "
                + (f"Impact observed: {impact}" if impact else "")
            ),
            evidence=evidence_lines[:20],
            remediation=_remediation_for(planned.action_id),
            asset_keys=[],
            verified=has_proof and confidence == "CONFIRMED",
            # The proof, not just the claim. A verified finding that does not
            # record which url, which parameter and what the action actually
            # returned is not reportable: the title is the only place the
            # target appeared, and `url`/`param` were being dropped on the
            # floor, so a triager had nothing to reproduce from.
            verification={
                "action_id": planned.action_id,
                "selected_because": planned.reason,
                "url": planned.url,
                "param": planned.params.get("param", ""),
                "params": {k: v for k, v in planned.params.items()
                           if k in ("url", "param", "baseline_url", "test_url")},
                "risk": planned.risk,
                "raw_evidence": evidence,
            },
        )
        return EdgeOutcome(
            edge=planned.edge, action_id=planned.action_id, status="ran",
            finding_id=finding_id, confidence=confidence, impact=impact,
            evidence=evidence,
        )


_SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _severity_for(edge: AttackEdge, evidence: dict,
                  confidence: str = "TENTATIVE") -> str:
    """Impact edge, from the graph's own impact score — not from sniffing
    the evidence text for words like "admin". Substring severity was
    inflation by vocabulary: any finding mentioning a token became HIGH.

    Proof couples back in at the edges: a CONFIRMED execution is at
    least MEDIUM (something ran, whatever the graph guessed), and a
    CONFIRMED result on a top-impact edge (RCE-grade goals) files
    CRITICAL. The old unconditional HIGH cap held every proven finding
    down and decoupled severity from proof strength entirely.
    """
    if edge.impact >= 0.85:
        filed = "HIGH"
    elif edge.impact >= 0.6:
        filed = "MEDIUM"
    else:
        filed = "LOW"
    if str(confidence).upper() == "CONFIRMED":
        if edge.impact >= 0.95:
            return "CRITICAL"
        if _SEVERITY_ORDER[filed] < _SEVERITY_ORDER["MEDIUM"]:
            return "MEDIUM"
    return filed


def _category_for(action_id: str) -> str:
    if "sqli" in action_id or "sqlmap" in action_id:
        return "SQL Injection"
    if "xss" in action_id:
        return "Cross-Site Scripting"
    if "ssrf" in action_id:
        return "SSRF"
    if "ssti" in action_id:
        return "SSTI"
    if "lfi" in action_id:
        return "Path Traversal"
    if "nosql" in action_id:
        return "NoSQL Injection"
    if "xxe" in action_id:
        return "XXE"
    if "crlf" in action_id:
        return "CRLF Injection"
    if "bypass" in action_id:
        return "Authorization Bypass"
    if "jwt" in action_id or "auth" in action_id:
        return "Authentication Bypass"
    if "redirect" in action_id:
        return "Open Redirect"
    if "graphql" in action_id:
        return "API Security"
    if "tls" in action_id:
        return "TLS Configuration"
    if "bucket" in action_id:
        return "Cloud Exposure"
    if "header" in action_id:
        return "Hardening Deficiency"
    return "Exploitation"


def _remediation_for(action_id: str) -> str:
    return {
        "web.sqli.detect": "Use parameterised queries; the payload was reflected in the response.",
        "web.sqli.blind_detect": "Use parameterised queries; blind injection is confirmed by a differential response.",
        "web.ssrf.oob_detect": "Restrict outbound requests to an allowlist; the server fetched an address we control.",
        "web.ssrf.cloud_metadata": "Block link-local metadata addresses at the egress proxy and require IMDSv2.",
        "auth.jwt.detect": "Pin the algorithm, validate the issuer and audience, and reject `none`.",
        "web.xss.reflected": "Contextually encode output; the payload executed in the response.",
        "web.ssti.detect": "Do not render user input through the template engine; use constant templates and pass values as data.",
        "web.lfi.detect": "Resolve user paths against a fixed allowlist; never concatenate input into a filesystem path.",
        "web.nosql.detect": "Cast parameters to scalars and reject object/operator shapes before building the query.",
        "web.xxe.detect": "Disable external entity resolution and DTDs in the XML parser.",
        "web.crlf.detect": "Encode CR/LF in any value written to a response header, and reject them in request parameters.",
        "auth.bypass.probe": "Authorize every request server-side from the session, not from client-supplied headers or paths.",
        "auth.jwt.none_alg": "Pin the accepted algorithm and reject `none`.",
        "web.redirect.probe": "Allowlist redirect destinations and reject absolute off-site values.",
        "api.graphql.introspect": "Disable introspection outside development, or restrict it to authenticated operators.",
        "network.tls.cert": "Renew the certificate, present one matching the hostname, and disable TLS 1.0/1.1.",
        "cloud.bucket.list": "Block public access on the bucket and remove anonymous list/read ACLs.",
        "recon.security_headers": "Send HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy and Permissions-Policy.",
    }.get(action_id, "Review the confirmed behaviour and remediate the root cause.")


def _stringify(value: Any, limit: int = 400) -> str:
    try:
        text = json.dumps(value, default=str)
    except (TypeError, ValueError):
        text = str(value)
    return text if len(text) <= limit else text[:limit] + "…"
