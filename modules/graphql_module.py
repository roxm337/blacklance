"""Stage 4: GraphQL Enumeration — introspection, field suggestion, batch queries."""

import json
from core.auth_harness import AuthHarness
from modules.base import BaseModule
from tools.wrappers import curl_with_status, curl


INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
""".strip()

# Field suggestion probe — triggers "Did you mean..." hints
FIELD_SUGGESTION_QUERY = '{ __typename invalidFieldNameXYZ }'

BATCH_TEST_QUERIES = [
    '[{"query": "{ __typename }"},{"query": "{ __typename }"}]',
    '[{"query": "query q1 { __typename }"},{"query": "query q2 { __typename }"}]',
]


class GraphQLAudit(BaseModule):
    id = "graphql_audit"
    name = "GraphQL Enumeration"
    stage = 4
    detectability = "low"
    depends_on = ["tech_detection"]

    async def run(self) -> str:
        base_url = self.base_url
        self.log("Probing for GraphQL endpoints...")

        graphql_paths = self.config.get("wordlists", {}).get("graphql_paths", [
            "/graphql", "/graphiql", "/api/graphql", "/gql", "/query",
            "/playground", "/__graphql", "/v1/graphql", "/graphql/v1",
        ])

        active_endpoints = []

        for path in graphql_paths:
            url = f"{base_url}{path}"
            r = await curl_with_status(url)
            status = r.get("status", 0)
            body = r.get("body", "")

            if status not in (200, 400, 405):
                continue

            # GraphQL endpoints often return 400 with JSON error on GET
            is_graphql = (
                "graphql" in body.lower()
                or '"errors"' in body
                or '"data"' in body
                or "must provide query string" in body.lower()
                or "syntax error" in body.lower()
                or "unexpected token" in body.lower()
            )

            if not is_graphql and status == 200:
                # Try POST with minimal query to confirm
                r2 = await curl(
                    url, method="POST",
                    headers={"Content-Type": "application/json"},
                    data='{"query":"{ __typename }"}',
                    output="body"
                )
                body2 = r2.get("body", "")
                is_graphql = '"data"' in body2 or '"errors"' in body2

            if is_graphql:
                active_endpoints.append(url)
                self.state.add_asset(
                    "api_endpoint",
                    f"graphql:{url}",
                    url,
                    confidence="CONFIRMED",
                    sources=["graphql probe"],
                    attrs={"type": "graphql", "path": path},
                )
                self.log(f"  GraphQL endpoint found: {url}")

        if not active_endpoints:
            self.state.skip_module(self.id, "no GraphQL endpoints found")
            return "skipped"

        # Audit each endpoint
        for endpoint in active_endpoints:
            await self._audit_endpoint(endpoint)
            await self._matrix_pass(endpoint)

        self.state.complete_module(self.id)
        self.log(f"GraphQL: {len(active_endpoints)} endpoints audited")
        return "done"

    async def _matrix_pass(self, endpoint: str) -> None:
        """I3: field-level authorization probes across verified identities.

        Opt-in via ``modules.graphql_audit.matrix.enabled``. Each configured
        field probe runs as every verified identity; scalar leaf values
        differing per identity are recorded as matrix cells. Read-only by
        default — mutations require an explicit canary spec.
        """
        matrix_cfg = (self.config.get("modules", {}).get(self.id, {})
                      .get("matrix") or {}) if isinstance(
            self.config.get("modules", {}), dict) else {}
        if not matrix_cfg.get("enabled"):
            return
        from core.authorization import AuthorizationMatrix, _leaf_paths, \
            _value_at
        harness = AuthHarness(self.config)
        harness.mutations = self.state.mutations
        harness.adopt_discovered(self.state, log=self.log)
        try:
            identities = await harness.establish_all(self.base_url)
        except Exception:
            identities = []
        if len(identities) < 2:
            return
        max_queries = max(1, int(matrix_cfg.get("max_queries", 10) or 10))
        probes = (matrix_cfg.get("field_probes") or [])[:max_queries]
        for probe in probes:
            query = str(probe.get("query") or "")
            if not query:
                continue
            bodies = {}
            for identity in identities:
                result = await harness.request(
                    identity.name, endpoint, method="POST",
                    headers={"Content-Type": "application/json"},
                    data=f'{{"query": {json.dumps(query)}}}')
                bodies[identity.name] = str(result.get("body") or "")
            import json as _json
            parsed = {}
            for name, body in bodies.items():
                try:
                    parsed[name] = _json.loads(body).get("data") or {}
                except (ValueError, TypeError):
                    parsed[name] = {}
            leaves = set()
            for doc in parsed.values():
                leaves |= set(_leaf_paths(doc))
            for path in sorted(leaves)[:max_queries]:
                values = {name: _value_at(doc, path)
                          for name, doc in parsed.items()}
                unique = {repr(v) for v in values.values()}
                if len(unique) > 1:
                    self.state.add_evidence(
                        self.id, "matrix_report", endpoint,
                        {"field_probe": query, "path": path,
                         "per_identity": {
                             name: str(v) for name, v in values.items()}})
                    self.state.add_finding(
                        title=f"GraphQL field leak: {path} ({endpoint})",
                        severity="HIGH",
                        confidence="FIRM",
                        category="Authorization Matrix",
                        description=(
                            f"Field {path!r} differs across identities for "
                            f"probe {query!r}: {values}"),
                        evidence=[f"probe:{query}", f"field:{path}"],
                        asset_keys=[f"url:{endpoint}"],
                        verified=False,
                        verification={},
                    )
        canary_specs = (matrix_cfg.get("canaries") or {}).get("specs") or []
        if canary_specs:
            matrix = AuthorizationMatrix(harness, self.base_url,
                                         matrix_cfg, self.state, log=self.log)
            await matrix.run_canaries(canary_specs)
            for row in matrix.finding_rows(self.id):
                if row["tier"] == "proof":
                    self.state.add_finding(
                        title=row["title"],
                        severity=row["severity"],
                        confidence=row["confidence"],
                        category="Authorization Matrix",
                        description=f"GraphQL canary {row['canary']['name']} "
                                    f"proven: {row['canary']}",
                        evidence=[f"canary:{row['canary']['name']}"],
                        asset_keys=[f"url:{endpoint}"],
                        verified=True,
                        verification=row["verification"],
                    )

    async def _audit_endpoint(self, endpoint: str):
        # 1. Introspection
        self.log(f"  Testing introspection: {endpoint}...")
        r = await curl(
            endpoint,
            method="POST",
            headers={"Content-Type": "application/json"},
            data=json.dumps({"query": INTROSPECTION_QUERY}),
            output="body",
        )
        body = r.get("body", "")
        try:
            data = json.loads(body)
            introspection_enabled = bool(
                data.get("data", {}).get("__schema")
            )
        except (json.JSONDecodeError, AttributeError):
            introspection_enabled = False

        if introspection_enabled:
            schema = data.get("data", {}).get("__schema", {})
            types = schema.get("types", [])
            user_types = [t for t in types
                         if t.get("kind") in ("OBJECT", "INPUT_OBJECT")
                         and not t.get("name", "").startswith("__")]

            type_names = [t["name"] for t in user_types[:30]]

            evidence_id = self.state.add_evidence(
                self.id, "graphql", endpoint,
                {"introspection": True, "type_count": len(user_types),
                 "types": type_names, "schema_summary": str(schema)[:3000]},
            )

            self.state.add_finding(
                title=f"GraphQL Introspection Enabled: {endpoint}",
                severity="MEDIUM",
                confidence="CONFIRMED",
                category="API Security",
                description=(
                    f"GraphQL introspection is enabled at {endpoint}. "
                    f"Discovered {len(user_types)} schema types including: "
                    f"{', '.join(type_names[:10])}. "
                    f"Attackers can map the entire API schema."
                ),
                evidence=[
                    f"Endpoint: {endpoint}",
                    f"Types: {type_names[:15]}",
                    f"Has mutations: {schema.get('mutationType') is not None}",
                ],
                evidence_refs=[evidence_id],
                remediation="Disable introspection in production. Use query depth limits and complexity analysis.",
                verified=True,
                verification={"method": "introspection_schema_returned",
                              "url": endpoint},
            )

            # Look for sensitive types in schema. A type NAME is not a
            # vulnerability — every schema has a User — so names alone are
            # LOW inventory, and the module earns anything hotter by
            # reading a field without authentication (see below).
            sensitive_type_keywords = [
                "user", "password", "token", "secret", "admin", "credential",
                "auth", "payment", "card", "ssn", "private", "internal"
            ]
            sensitive_types = [
                t for t in type_names
                if any(kw in t.lower() for kw in sensitive_type_keywords)
            ]
            if sensitive_types:
                self.state.add_finding(
                    title="GraphQL Sensitive Type Names in Schema (Review Queue)",
                    severity="LOW",
                    confidence="FIRM",
                    category="API Security",
                    description=(f"Schema at {endpoint} names sensitive types: "
                                 f"{sensitive_types[:10]}. Names alone prove "
                                 f"nothing — the unauthenticated field-read "
                                 f"probes below decide whether data leaks."),
                    evidence=[f"Sensitive types: {sensitive_types[:10]}"],
                    evidence_refs=[evidence_id],
                    remediation="Audit sensitive types for proper authorization and field-level restrictions.",
                )
                await self._probe_sensitive_reads(endpoint, sensitive_types[:5],
                                                  evidence_id)
        else:
            # 2. Field suggestion attack (introspection disabled)
            r2 = await curl(
                endpoint,
                method="POST",
                headers={"Content-Type": "application/json"},
                data=json.dumps({"query": FIELD_SUGGESTION_QUERY}),
                output="body",
            )
            suggestion_body = r2.get("body", "")
            if "did you mean" in suggestion_body.lower():
                self.state.add_finding(
                    title=f"GraphQL Field Suggestion Leak: {endpoint}",
                    severity="LOW",
                    confidence="CONFIRMED",
                    category="API Security",
                    description="GraphQL returns field suggestions ('Did you mean...') even with "
                                "introspection disabled. Schema can be enumerated via wordlist attack.",
                    evidence=[
                        f"Endpoint: {endpoint}",
                        f"Suggestion response: {suggestion_body[:300]}",
                    ],
                    remediation="Disable field suggestions in production GraphQL configuration.",
                    verified=True,
                    verification={"method": "field_suggestion_returned",
                                  "url": endpoint},
                )

        # 3. Batch query test
        self.log(f"  Testing batch queries: {endpoint}...")
        for batch_query in BATCH_TEST_QUERIES:
            r3 = await curl(
                endpoint,
                method="POST",
                headers={"Content-Type": "application/json"},
                data=batch_query,
                output="body",
            )
            b3 = r3.get("body", "")
            try:
                b3_data = json.loads(b3)
                if isinstance(b3_data, list) and len(b3_data) > 1:
                    self.state.add_finding(
                        title=f"GraphQL Batch Queries Enabled: {endpoint}",
                        severity="LOW",
                        confidence="FIRM",
                        category="API Security",
                        description="GraphQL endpoint accepts batched queries. "
                                    "Batching alone is not rate-limit abuse: "
                                    "no flood was sent and no authenticated "
                                    "mutation was driven. Harden before it "
                                    "becomes a multiplexing oracle.",
                        evidence=[f"Batch response: {str(b3_data)[:300]}"],
                        remediation="Limit batch query size or disable batching in production.",
                        verified=True,
                        verification={"method": "batch_query_accepted",
                                      "url": endpoint},
                    )
                    break
            except (json.JSONDecodeError, TypeError):
                pass

        # 4. CSRF via GET query
        r4 = await curl(
            f"{endpoint}?query=%7B__typename%7D",
            output="body",
        )
        b4 = r4.get("body", "")
        if '"data"' in b4 or "__typename" in b4:
            self.state.add_finding(
                title=f"GraphQL Query via GET (CSRF Risk): {endpoint}",
                severity="LOW",
                confidence="FIRM",
                category="API Security",
                description="GraphQL endpoint answers queries via GET. That "
                            "is a CSRF shape, not a CSRF proof: no "
                            "authenticated mutation was driven, so this is "
                            "hardening, not an exploited state change.",
                evidence=[f"GET query response: {b4[:200]}"],
                remediation="Only accept POST requests for GraphQL mutations; "
                            "disable query execution via GET.",
                verified=True,
                verification={"method": "get_query_accepted",
                              "url": endpoint},
            )

    async def _probe_sensitive_reads(self, endpoint: str,
                                     type_names: list, evidence_id: str) -> None:
        """Try reading one scalar field off sensitive types, unauthenticated.

        Read-only and bounded: a handful of conventional shapes
        ({user{id}}, {users{id}}, {me{id}}) with scalar fallbacks. A
        non-null data payload without errors is an exposure finding with
        the exact query as evidence; errors and nulls mean the inventory
        stays LOW.
        """
        shapes = []
        for name in type_names:
            lowered = str(name).lower()
            shapes.append(lowered)
            if not lowered.endswith("s"):
                shapes.append(lowered + "s")
            if "user" in lowered or "account" in lowered:
                shapes.append("me")
        seen_shapes = list(dict.fromkeys(shapes))[:6]
        tried = 0
        for shape in seen_shapes:
            for field in ("id", "email", "name"):
                if tried >= 12:
                    return
                tried += 1
                query = "{ %s { %s } }" % (shape, field)
                try:
                    response = await curl(
                        endpoint, method="POST",
                        headers={"Content-Type": "application/json"},
                        data=json.dumps({"query": query}),
                        output="body", timeout=15,
                    )
                except Exception:
                    continue
                body = response.get("body", "") or ""
                try:
                    data = json.loads(body).get("data", {}) if body else {}
                except (json.JSONDecodeError, AttributeError):
                    continue
                if not isinstance(data, dict):
                    continue
                value = data.get(shape)
                if value is None or "errors" in str(body).lower()[:200]:
                    continue
                if isinstance(value, list) and not value:
                    continue
                self.state.add_finding(
                    title=f"GraphQL Unauthenticated Field Read: {shape}.{field}",
                    severity="MEDIUM",
                    confidence="CONFIRMED",
                    category="API Security",
                    description=(
                        f"GraphQL endpoint at {endpoint} returns `{shape}.{field}` "
                        f"without authentication. Query: {query}"),
                    evidence=[f"Endpoint: {endpoint}", f"Query: {query}",
                              f"Response: {str(value)[:200]}"],
                    evidence_refs=[evidence_id],
                    remediation="Enforce field-level authorization on sensitive "
                                "types; require authentication for non-public fields.",
                    asset_keys=[f"url:{endpoint}"],
                    verified=True,
                    verification={"method": "unauthenticated_graphql_read",
                                  "url": endpoint},
                )
                return
