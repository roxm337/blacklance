"""`api.graphql.introspect` — schema-shaped proof, not a 200-shaped guess.

The action must (a) refuse a JSON endpoint that does not answer a GraphQL
executor, (b) refuse an endpoint that answers but disables introspection, and
(c) require the schema to be stable across two fetches. A single schema dump
can be a cached artefact; the second call is what separates a live schema
exposure from a snapshot.

Also pins the namespace: `actions/api` was imported but registered nothing, so
`actions.registry.list_by_category("api")` was empty.
"""

import asyncio
import json

import pytest

from actions.api import graphql as gql
from actions.registry import ActionContext, ActionRegistry


def _ok(body):
    return {"status": 200, "body": json.dumps(body), "headers": "", "time_ms": 1}


def _schema(types, mutations=False):
    return {"data": {"__schema": {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"} if mutations else None,
        "types": [{"name": name, "kind": "OBJECT"} for name in types],
    }}}


def _ctx():
    return ActionContext(action_id="api.graphql.introspect",
                         params={"url": "https://t.test/graphql"},
                         target="https://t.test/graphql")


@pytest.fixture
def calls(monkeypatch):
    """Replace the transport; return the list of requests it saw."""
    seen = []
    replies = []

    async def fake_curl(url, method="GET", headers=None, data=None, **kwargs):
        seen.append({"url": url, "method": method, "data": data,
                     "headers": headers})
        return replies.pop(0)

    monkeypatch.setattr(gql, "curl", fake_curl)
    return seen, replies


def test_action_is_registered_under_the_api_namespace():
    names = [m.id for m in ActionRegistry.list_by_category("api")]
    assert "api.graphql.introspect" in names


def test_confirms_only_on_a_stable_schema(calls):
    seen, replies = calls
    replies.extend([
        _ok({"data": {"__typename": "Query"}}),
        _ok(_schema(["User", "__Schema", "Query"])),
        _ok(_schema(["User", "__Schema", "Query"])),
    ])

    result = asyncio.run(gql.graphql_introspect(_ctx()))

    assert result.success is True
    assert result.confidence == "CONFIRMED"
    assert result.data["type_count"] == 3
    assert result.data["user_type_count"] == 2  # __Schema is filtered
    assert result.data["types"] == ["User", "Query"]
    assert len(seen) == 3
    assert all(c["method"] == "POST" for c in seen)
    assert seen[0]["data"] and "__typename" in seen[0]["data"]


def test_non_graphql_json_endpoint_is_not_confirmed(calls):
    _, replies = calls
    replies.append(_ok({"ok": True, "items": []}))

    result = asyncio.run(gql.graphql_introspect(_ctx()))

    assert result.success is False
    assert "GraphQL" in result.error


def test_disabled_introspection_is_reported_as_such(calls):
    _, replies = calls
    replies.extend([
        _ok({"data": {"__typename": "Query"}}),
        _ok({"errors": [{"message": "introspection is disabled"}]}),
    ])

    result = asyncio.run(gql.graphql_introspect(_ctx()))

    assert result.success is False
    assert "introspection disabled" in result.error


def test_unstable_type_list_is_refused(calls):
    _, replies = calls
    replies.extend([
        _ok({"data": {"__typename": "Query"}}),
        _ok(_schema(["User", "Post"])),
        _ok(_schema(["User"])),
    ])

    result = asyncio.run(gql.graphql_introspect(_ctx()))

    assert result.success is False
    assert result.confidence == "FIRM"
    assert "type count changed" in result.error


def test_missing_url_is_a_validation_error(calls):
    result = asyncio.run(gql.graphql_introspect(
        ActionContext(action_id="api.graphql.introspect", params={},
                      target="")))
    assert result.success is False
    assert result.error == "url is required"
