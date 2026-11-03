"""GraphQL actions — schema introspection as a registered, repeatable proof.

`actions/api` was an imported namespace with no actions in it, so a GraphQL
finding had nothing to arm: the enumeration module proved introspection once,
filed it, and no later leg or agent could re-prove the endpoint. This is the
smallest honest capability for that namespace — a benign POST, no mutation,
no guessing.

The proof is schema-shaped, not status-shaped: a random JSON endpoint that
echoes a request body is not GraphQL. The baseline asks for `__typename`,
which only a GraphQL executor answers with a `data`/`errors` envelope, and the
introspection result must contain `data.__schema` with a non-empty `types`
list — twice.
"""

import json

from actions.registry import action, ActionContext, ActionResult
from tools.wrappers import curl

_INTROSPECTION_QUERY = (
    "query IntrospectionProbe { __schema { queryType { name } "
    "mutationType { name } types { name kind } } }"
)
_BASELINE_QUERY = "query Probe { __typename }"


def _payload(query: str) -> str:
    return json.dumps({"query": query})


def _status(raw: dict) -> int:
    return int(raw.get("status") or 0)


def _json(raw: dict):
    try:
        return json.loads(str(raw.get("body") or ""))
    except (TypeError, ValueError):
        return None


def _is_graphql_envelope(parsed) -> bool:
    return isinstance(parsed, dict) and (
        "data" in parsed or "errors" in parsed)


def _schema_types(parsed) -> list:
    if not isinstance(parsed, dict):
        return []
    data = parsed.get("data")
    if not isinstance(data, dict):
        return []
    schema = data.get("__schema")
    if not isinstance(schema, dict):
        return []
    types = schema.get("types")
    return types if isinstance(types, list) else []


@action(
    id="api.graphql.introspect",
    risk="LOW",
    detectability="low",
    requires=["url"],
    produces="VulnCandidate",
    idempotent=True,
    description=(
        "Prove GraphQL introspection on an endpoint: a __typename baseline "
        "must return a GraphQL envelope, and a full __schema query must "
        "return a non-empty type list twice. Exposes the API schema."
    ),
    category="api",
)
async def graphql_introspect(ctx: ActionContext) -> ActionResult:
    url = str(ctx.params.get("url") or ctx.target or "").strip()
    if not url:
        return ActionResult(False, error="url is required")
    headers = {"Content-Type": "application/json",
               "User-Agent": "Mozilla/5.0 (compatible; bhs-probe)"}
    if isinstance(ctx.params.get("headers"), dict):
        headers.update(ctx.params["headers"])

    baseline = await curl(url, method="POST", headers=headers,
                          data=_payload(_BASELINE_QUERY), output="full")
    baseline_parsed = _json(baseline)
    if not (200 <= _status(baseline) < 300
            and _is_graphql_envelope(baseline_parsed)):
        return ActionResult(
            False, confidence="TENTATIVE",
            error=(f"endpoint does not answer a GraphQL __typename query "
                   f"(HTTP {_status(baseline)})"))

    probe = await curl(url, method="POST", headers=headers,
                       data=_payload(_INTROSPECTION_QUERY), output="full")
    types = _schema_types(_json(probe))
    if not types:
        return ActionResult(
            False, confidence="TENTATIVE",
            error="introspection disabled: no __schema types in the response")

    # Re-fetch: a schema dump can be a cached sample, and a one-shot 200 is
    # not proof the endpoint still exposes it.
    again = await curl(url, method="POST", headers=headers,
                       data=_payload(_INTROSPECTION_QUERY), output="full")
    again_types = _schema_types(_json(again))
    if len(again_types) != len(types):
        return ActionResult(
            False, confidence="FIRM",
            error=(f"type count changed between runs "
                   f"({len(types)} -> {len(again_types)})"))

    names = [str(t.get("name")) for t in again_types
             if isinstance(t, dict) and t.get("name")]
    user_types = [n for n in names if not n.startswith("__")]
    return ActionResult(
        True, confidence="CONFIRMED",
        data={
            "endpoint": url,
            "type_count": len(again_types),
            "user_type_count": len(user_types),
            "types": user_types[:50],
            "mutations": bool((_json(again) or {}).get("data", {})
                              .get("__schema", {})
                              .get("mutationType")),
        },
        evidence={"introspection": True, "endpoint": url,
                  "type_count": len(again_types),
                  "types": user_types[:20]},
    )
