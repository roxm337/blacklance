"""Typed preconditions and output bindings for causal chain execution (R9).

The attack graph builds ordered paths — `asset --exploit--> vuln
--authenticate--> goal` — but the executor historically planned every edge
independently and reordered them by suspicion rank. That is a *set of probes*,
not a *chain*: a forge step that needs the token a detect step produced would
run first, with no token, and report the target clean.

This module supplies the three things the R9 gate names — typed preconditions,
output bindings and credential references — as pure data and pure functions. No
I/O, no registry calls: it is cheap to test and safe to call per edge, and it
changes nothing about the default (non-causal) executor path.

A *binding* is a typed value an action produced that a later action in the same
chain can consume. The only transport the thin graph could never carry is
exactly the interesting one: a credential or session token that does not exist
until an upstream action has actually run.

Nothing here judges success or mints findings. It only answers two questions:
"what does this action still need before it can run?" (preconditions) and "what
did this proven action leave behind for the next one?" (outputs). The executor
owns running, the risk ceiling and the budget.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Action parameters a binding can fill. These are the inputs whose value only
# comes into existence mid-chain — a session cookie, a JWT to forge or crack, a
# credential recovered from an upstream leg. Everything else (url, param) the
# graph already carries, so it is never deferred to a binding.
BINDABLE_PARAMS: tuple[str, ...] = ("token", "cookie", "credential", "session")

# Keys, in result.data or result.evidence, that carry a reusable secret. An
# action that forges or cracks a token may hand back the value the next auth
# probe needs; an action that only *detects* one reports the full token under
# `raw_token` and a redacted preview under `token`. Ordered by specificity so
# a forged token wins over a merely detected one.
_TOKEN_KEYS: tuple[str, ...] = (
    "forged_token", "cracked_token", "session_token", "access_token",
    "raw_token", "token", "jwt", "session", "cookie",
)
_CREDENTIAL_KEYS: tuple[str, ...] = (
    "credential", "credentials", "aws_credentials", "secret", "secret_key",
    "api_key",
)


def _is_truncated(value: str) -> bool:
    """True for a display preview (`eyJ...abc`) rather than a usable secret.

    Actions habitually truncate secrets before returning them so reports do not
    carry a replayable credential. Binding a preview is worse than binding
    nothing: it arms the next leg against a value no server will accept, and
    the inevitable rejection is then filed as proof the target is safe.
    """
    text = str(value or "")
    return text.endswith("...") or text.endswith("…")


@dataclass
class BindingContext:
    """Typed values produced so far within one chain's execution.

    Scoped to a single chain on purpose: a credential leaked on one path must
    not silently arm an edge on an unrelated path. Independent chains each get
    their own context, which is what keeps "independent branches remain
    possible" true even after a prerequisite fails elsewhere.
    """

    values: dict[str, Any] = field(default_factory=dict)
    # Which edge/action produced each binding, for the audit trail: a bound
    # credential in a finding must be traceable to the leg that obtained it.
    sources: dict[str, str] = field(default_factory=dict)

    def has(self, binding_type: str) -> bool:
        return bool(self.values.get(binding_type))

    def get(self, binding_type: str) -> Any:
        return self.values.get(binding_type)

    def put(self, binding_type: str, value: Any, source: str = "") -> None:
        if value in (None, "", [], {}):
            return
        # First writer wins: an upstream leg that already produced a usable
        # token should not be clobbered by a weaker downstream observation of
        # the same type. The chain reads top-to-bottom.
        if binding_type not in self.values:
            self.values[binding_type] = value
            if source:
                self.sources[binding_type] = source

    def provenance(self) -> dict[str, str]:
        return dict(self.sources)

    def clone(self) -> "BindingContext":
        """A detached copy, for a branch that inherits its parent's bindings.

        A child branch must start from what the shared prefix proved, yet a
        credential the child goes on to obtain must not flow back up or across
        to a sibling. Copying the dicts (first-writer-wins still applies) keeps
        each branch's later discoveries local to that branch.
        """
        return BindingContext(values=dict(self.values),
                              sources=dict(self.sources))


def _first_present(bag: Any, keys: tuple[str, ...]) -> Any:
    """First non-empty value for any of `keys`, searching one level of nesting.

    Actions are inconsistent about depth: one returns `{"token": "..."}`, the
    next `{"jwt": {"forged_token": "..."}}`, a third `{"tokens": [{"token":
    "..."}]}`. The binding layer must read all three or it silently drops the
    credential the whole chain depends on.
    """
    if not isinstance(bag, dict):
        return None
    # Direct hits first. A truncated preview is not a value: skip it and keep
    # looking, so one redacted field cannot mask a usable sibling.
    for key in keys:
        value = bag.get(key)
        if isinstance(value, str) and value.strip():
            if _is_truncated(value):
                continue
            return value.strip()
    # A list of token records (jwt detect shape): take the first string field.
    for list_key in ("tokens", "credentials"):
        items = bag.get(list_key)
        if isinstance(items, list):
            for item in items:
                if isinstance(item, str) and item.strip() and not _is_truncated(item):
                    return item.strip()
                if isinstance(item, dict):
                    nested = _first_present(item, keys)
                    if nested:
                        return nested
    # One level of nested dicts (e.g. evidence={"jwt": {...}}).
    for value in bag.values():
        if isinstance(value, dict):
            nested = _first_present(value, keys)
            if nested:
                return nested
    return None


def extract_outputs(action_id: str, result: Any) -> dict[str, Any]:
    """Typed bindings a proven action leaves for the next leg of its chain.

    Deterministic and conservative: it prefers the explicit
    `ActionResult.bindings` channel, falls back to well-known credential keys in
    `result.data`/`result.evidence`, and returns nothing when the action proved
    impact without handing back a reusable secret. A binding that is a guess is
    worse than no binding, because it arms a downstream probe against the wrong
    value and files the clean result as proof the target is safe.
    """
    out: dict[str, Any] = {}
    data = getattr(result, "data", None)
    evidence = getattr(result, "evidence", None)

    # Preferred contract: an action that knows it produced a reusable secret
    # declares it explicitly. `ActionResult.bindings` is the canonical channel
    # because it is never serialized into a finding or report; a `bindings`
    # dict inside data/evidence is still accepted for hand-built results.
    # Explicit beats inference — the heuristics below cannot tell a full token
    # from a redacted preview, or a signing input from a token, and getting
    # that wrong silently aims the next leg at a value that cannot work.
    declared = getattr(result, "bindings", None)
    if not isinstance(declared, dict) or not declared:
        # An empty channel means "nothing declared", not "must not bind": the
        # legacy heuristics below are the only source for hand-built results.
        declared = None
        for bag in (data, evidence):
            candidate = bag.get("bindings") if isinstance(bag, dict) else None
            if isinstance(candidate, dict) and candidate:
                declared = candidate
                break
    if declared is not None:
        for btype in BINDABLE_PARAMS:
            value = declared.get(btype)
            if (isinstance(value, str) and value.strip()
                    and not _is_truncated(value)):
                out[btype] = value.strip()
        return out

    for bag in (data, evidence):
        token = _first_present(bag, _TOKEN_KEYS)
        if token and "token" not in out:
            out["token"] = token
        credential = _first_present(bag, _CREDENTIAL_KEYS)
        if credential and "credential" not in out:
            out["credential"] = credential

    return out


def required_bindings(meta: Any, params: dict) -> set[str]:
    """Binding types this action needs that the graph did not already supply.

    A typed precondition is "this action declares it requires a token, and no
    token is on the params yet". If the graph already carried the value (a node
    attr), there is no precondition to satisfy and no dependency on an upstream
    leg. Only the genuinely-missing bindable requirements become preconditions.
    """
    needs: set[str] = set()
    requires = getattr(meta, "requires", None) or []
    for req in requires:
        if req in BINDABLE_PARAMS and not params.get(req):
            needs.add(req)
    return needs


def apply_bindings(params: dict, needs: set[str], ctx: BindingContext) -> tuple[dict, set[str]]:
    """Fill a planned action's missing bindable params from the context.

    Returns `(params, unmet)` where `unmet` names the preconditions still not
    satisfied after binding — those are exactly the edges whose prerequisite
    never ran or never proved, and the executor blocks them as "precondition
    unproven" instead of running a probe it cannot aim.
    """
    filled = dict(params)
    unmet: set[str] = set()
    for binding_type in needs:
        if ctx.has(binding_type):
            filled[binding_type] = ctx.get(binding_type)
        else:
            unmet.add(binding_type)
    return filled, unmet
