"""Asset graph helpers for the GUI."""

from __future__ import annotations

from collections import defaultdict
from html import escape
from math import cos, pi, sin


AGGREGATE_TYPES = {"subdomain", "webapp", "bucket", "dns_record", "social_media"}


def count_relations(assets: dict) -> int:
    """Drawable relation count: edges whose both endpoints exist as nodes.

    Matches what the graph can actually render, so the "relations" metric
    never disagrees with the drawn edges (legacy states carried dangling
    finding-target edges that inflated the raw count).
    """
    keys = {node.get("key") for node in assets.get("nodes", []) if node.get("key")}
    return sum(
        1 for edge in assets.get("edges", [])
        if edge.get("source") in keys and edge.get("target") in keys
    )


def build_graph(assets: dict) -> dict:
    nodes = assets.get("nodes", [])
    # Keep only drawable edges (both endpoints are real nodes). Older
    # states carry AFFECTED_BY edges whose target is a finding ID, which
    # is never a node: they were dropped downstream anyway, but they
    # inflated the "relations" counts shown next to the graph.
    by_key = {node.get("key"): node for node in nodes if node.get("key")}
    edges = [
        edge for edge in assets.get("edges", [])
        if edge.get("source") in by_key and edge.get("target") in by_key
    ]

    inferred = []
    for node in nodes:
        key = node.get("key", "")
        attrs = node.get("attrs", {})
        if node.get("type") == "subdomain":
            domain = ".".join(str(node.get("value", "")).split(".")[-2:])
            domain_key = f"domain:{domain}"
            if domain_key in by_key:
                inferred.append({
                    "source": domain_key,
                    "target": key,
                    "type": "HAS_SUBDOMAIN",
                    "attrs": {"inferred": True},
                })
            ip = attrs.get("ip")
            if ip and f"ip:{ip}" in by_key:
                inferred.append({
                    "source": key,
                    "target": f"ip:{ip}",
                    "type": "RESOLVES_TO",
                    "attrs": {"inferred": True},
                })
        elif node.get("type") == "webapp":
            host = str(node.get("value", "")).split("//")[-1].split("/", 1)[0]
            host_key = f"domain:{host}"
            sub_key = f"sub:{host}"
            if sub_key in by_key:
                inferred.append({
                    "source": sub_key,
                    "target": key,
                    "type": "HOSTS_WEBAPP",
                    "attrs": {"inferred": True},
                })
            elif host_key in by_key:
                inferred.append({
                    "source": host_key,
                    "target": key,
                    "type": "HOSTS_WEBAPP",
                    "attrs": {"inferred": True},
                })

    seen = {(e.get("source"), e.get("target"), e.get("type")) for e in edges}
    for edge in inferred:
        identity = (edge.get("source"), edge.get("target"), edge.get("type"))
        if identity not in seen:
            edges.append(edge)
            seen.add(identity)

    return {"nodes": nodes, "edges": edges}


def build_display_graph(assets: dict, aggregate: bool = True,
                        aggregate_threshold: int = 10,
                        findings: list | None = None) -> dict:
    graph = build_graph(assets)
    nodes = graph["nodes"]
    edges = graph["edges"]
    if findings:
        _annotate_finding_counts(nodes, findings)
    if not aggregate:
        return graph

    counts = defaultdict(int)
    for node in nodes:
        counts[node.get("type", "unknown")] += 1

    collapsed_types = {
        asset_type for asset_type, count in counts.items()
        if count >= aggregate_threshold
        or (count > 1 and asset_type in AGGREGATE_TYPES)
    }

    display_nodes = []
    key_map = {}
    for asset_type in sorted(collapsed_types):
        group_key = f"group:{asset_type}"
        members = [node for node in nodes if node.get("type", "unknown") == asset_type]
        finding_count = sum(
            int((node.get("attrs") or {}).get("finding_count", 0) or 0)
            for node in members
        )
        severity_order = {"": 0, "INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
        worst_finding = max(
            (str((node.get("attrs") or {}).get("worst_finding", "")).upper()
             for node in members),
            key=lambda severity: severity_order.get(severity, 0),
            default="",
        )
        group_attrs = {
            "count": counts[asset_type],
            "group_type": asset_type,
            "finding_count": finding_count,
        }
        if worst_finding:
            group_attrs["worst_finding"] = worst_finding
        display_nodes.append({
            "type": f"{asset_type}_group",
            "key": group_key,
            "value": f"{asset_type} ({counts[asset_type]})",
            "confidence": "GROUP",
            "attrs": group_attrs,
            "sources": sorted({
                str(source)
                for node in members
                for source in node.get("sources", []) or []
                if source
            }),
        })

    for node in nodes:
        asset_type = node.get("type", "unknown")
        if asset_type in collapsed_types:
            key_map[node.get("key")] = f"group:{asset_type}"
        else:
            key_map[node.get("key")] = node.get("key")
            display_nodes.append(node)

    display_edges = []
    seen = set()
    for edge in edges:
        source = key_map.get(edge.get("source"))
        target = key_map.get(edge.get("target"))
        if not source or not target or source == target:
            continue
        relation = edge.get("type", "RELATES_TO")
        identity = (source, target, relation)
        if identity in seen:
            continue
        seen.add(identity)
        display_edges.append({
            "source": source,
            "target": target,
            "type": relation,
            "attrs": edge.get("attrs", {}),
        })

    return {
        "nodes": display_nodes,
        "edges": display_edges,
        "meta": {
            "raw_nodes": len(nodes),
            "raw_edges": len(edges),
            "collapsed_types": sorted(collapsed_types),
        },
    }


def filter_display_graph(
    graph: dict,
    query: str = "",
    asset_type: str = "",
    relation: str = "",
    provenance: str = "all",
) -> dict:
    """Return an analyst-focused subgraph while preserving one-hop context.

    Text/type matches are the focus entities. Their immediate neighbours stay
    visible so a search never removes the relationships that explain a match.
    Relation and provenance filters are applied first and therefore define
    which contextual links are allowed into the result.
    """
    nodes = list(graph.get("nodes") or [])
    edges = list(graph.get("edges") or [])
    node_by_key = {
        str(node.get("key")): node for node in nodes if node.get("key")
    }
    relation_key = str(relation or "").strip().upper()
    provenance_key = str(provenance or "all").strip().lower()

    def edge_allowed(edge: dict) -> bool:
        if relation_key and str(edge.get("type", "")).upper() != relation_key:
            return False
        attrs = edge.get("attrs") or {}
        edge_provenance = (
            "proposed" if attrs.get("proposed")
            else "inferred" if attrs.get("inferred")
            else "observed"
        )
        return provenance_key in ("", "all", edge_provenance)

    allowed_edges = [edge for edge in edges if edge_allowed(edge)]
    query_key = str(query or "").strip().casefold()
    type_key = str(asset_type or "").strip().casefold()

    def node_matches(node: dict) -> bool:
        node_type = str(node.get("type", "")).casefold()
        if type_key and node_type != type_key:
            return False
        if not query_key:
            return True
        searchable = " ".join((
            str(node.get("key", "")),
            str(node.get("value", "")),
            str(node.get("type", "")),
            str(node.get("confidence", "")),
            " ".join(str(source) for source in node.get("sources", []) or []),
            str(node.get("attrs") or {}),
        )).casefold()
        return query_key in searchable

    has_node_filter = bool(query_key or type_key)
    focus_keys = {
        str(node.get("key")) for node in nodes
        if node.get("key") and node_matches(node)
    }
    if has_node_filter:
        visible_keys = set(focus_keys)
        for edge in allowed_edges:
            source = str(edge.get("source", ""))
            target = str(edge.get("target", ""))
            if source in focus_keys or target in focus_keys:
                visible_keys.update((source, target))
    elif relation_key or provenance_key not in ("", "all"):
        visible_keys = {
            str(endpoint)
            for edge in allowed_edges
            for endpoint in (edge.get("source"), edge.get("target"))
            if endpoint
        }
    else:
        visible_keys = set(node_by_key)

    visible_nodes = []
    for key in visible_keys:
        node = node_by_key.get(key)
        if node is None:
            continue
        if key in focus_keys and has_node_filter:
            node = dict(node)
            node["attrs"] = dict(node.get("attrs") or {})
            node["attrs"]["focus_match"] = True
        visible_nodes.append(node)
    order = {str(node.get("key")): index for index, node in enumerate(nodes)}
    visible_nodes.sort(key=lambda node: order.get(str(node.get("key")), 10**9))
    visible_edges = [
        edge for edge in allowed_edges
        if str(edge.get("source", "")) in visible_keys
        and str(edge.get("target", "")) in visible_keys
    ]
    return {
        "nodes": visible_nodes,
        "edges": visible_edges,
        "meta": {
            **dict(graph.get("meta") or {}),
            "focus_nodes": len(focus_keys) if has_node_filter else len(visible_nodes),
            "filtered": bool(has_node_filter or relation_key or provenance_key not in ("", "all")),
        },
    }


def analyze_display_graph(graph: dict) -> dict:
    """Calculate compact intelligence indicators for the analyst brief."""
    nodes = list(graph.get("nodes") or [])
    edges = list(graph.get("edges") or [])
    node_by_key = {
        str(node.get("key")): node for node in nodes if node.get("key")
    }
    adjacency = {key: set() for key in node_by_key}
    relation_counts: dict[str, int] = defaultdict(int)
    provenance_counts = {"observed": 0, "inferred": 0, "proposed": 0}
    for edge in edges:
        source = str(edge.get("source", ""))
        target = str(edge.get("target", ""))
        if source in adjacency and target in adjacency:
            adjacency[source].add(target)
            adjacency[target].add(source)
        relation_counts[str(edge.get("type") or "RELATES_TO")] += 1
        attrs = edge.get("attrs") or {}
        provenance = (
            "proposed" if attrs.get("proposed")
            else "inferred" if attrs.get("inferred")
            else "observed"
        )
        provenance_counts[provenance] += 1

    unseen = set(adjacency)
    components = 0
    while unseen:
        components += 1
        stack = [unseen.pop()]
        while stack:
            current = stack.pop()
            neighbours = adjacency[current] & unseen
            unseen.difference_update(neighbours)
            stack.extend(neighbours)

    type_counts: dict[str, int] = defaultdict(int)
    source_names = set()
    affected = 0
    high_risk = 0
    for node in nodes:
        type_counts[str(node.get("type") or "unknown")] += 1
        source_names.update(str(source) for source in node.get("sources", []) or [] if source)
        attrs = node.get("attrs") or {}
        if int(attrs.get("finding_count", 0) or 0) > 0:
            affected += 1
        if str(attrs.get("worst_finding", "")).upper() in ("HIGH", "CRITICAL"):
            high_risk += 1

    pivot_keys = sorted(
        adjacency,
        key=lambda key: (-len(adjacency[key]), key),
    )[:5]
    pivots = [
        {
            "key": key,
            "label": str(node_by_key[key].get("value") or key),
            "type": str(node_by_key[key].get("type") or "unknown"),
            "degree": len(adjacency[key]),
        }
        for key in pivot_keys if adjacency[key]
    ]
    node_count = len(nodes)
    density = (len(edges) / (node_count * (node_count - 1))) if node_count > 1 else 0.0
    return {
        "nodes": node_count,
        "edges": len(edges),
        "components": components,
        "isolated": sum(1 for neighbours in adjacency.values() if not neighbours),
        "density": density,
        "types": dict(sorted(type_counts.items(), key=lambda item: (-item[1], item[0]))),
        "relations": dict(sorted(relation_counts.items(), key=lambda item: (-item[1], item[0]))),
        "provenance": provenance_counts,
        "source_count": len(source_names),
        "affected": affected,
        "high_risk": high_risk,
        "pivots": pivots,
    }


def _annotate_finding_counts(nodes: list, findings: list) -> None:
    """Mark nodes their findings affect: count + worst severity in attrs.

    The graph answers "where does it hurt" at a glance instead of making
    the operator cross-reference the triage table row by row.
    """
    _order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    by_asset: dict[str, list] = {}
    for finding in findings or []:
        for asset_key in finding.get("asset_keys", []) or []:
            by_asset.setdefault(asset_key, []).append(finding)
    for node in nodes:
        hits = by_asset.get(node.get("key", ""), [])
        if not hits:
            continue
        worst = max((str(f.get("severity", "INFO")).upper() for f in hits),
                    key=lambda severity: _order.get(severity, 0))
        node.setdefault("attrs", {})["finding_count"] = len(hits)
        node["attrs"]["worst_finding"] = worst


def to_gravis_graph(display_graph: dict, show_labels: bool = False,
                    show_edges: bool = True) -> dict:
    """Convert display graph to gravis JSON Graph Format."""
    nodes = {}
    for node in display_graph.get("nodes", []):
        node_id = str(node.get("key", ""))
        if not node_id:
            continue
        asset_type = node.get("type", "asset")
        is_group = node.get("confidence") == "GROUP"
        color = _type_color(asset_type)
        count = int(node.get("attrs", {}).get("count", 1) or 1)
        size = 38 + min(42, count * 2) if is_group else 24 + min(18, len(node.get("sources", [])) * 2)
        label = _label(node, show_labels or is_group or asset_type == "domain")
        border_color = "#e2e8f0"
        border_size = 2
        finding_count = int(node.get("attrs", {}).get("finding_count", 0) or 0)
        worst = str(node.get("attrs", {}).get("worst_finding", "") or "")
        if finding_count and worst in ("HIGH", "CRITICAL"):
            # Affected and severe: red ring + slightly larger, so the eye
            # lands on damage first and inventory second.
            border_color = "#ef4444"
            size += 8
        if node.get("attrs", {}).get("focus_match"):
            border_color = "#fbbf24"
            border_size = 4
            size += 10
        nodes[node_id] = {
            "label": label,
            "metadata": {
                "color": color,
                "size": size,
                "border_color": border_color,
                "border_size": border_size,
                "hover": _node_hover(node),
                "click": _node_click(node),
            },
        }

    edges = []
    if show_edges:
        for edge in display_graph.get("edges", []):
            source = str(edge.get("source", ""))
            target = str(edge.get("target", ""))
            if source not in nodes or target not in nodes:
                continue
            attrs = edge.get("attrs", {}) or {}
            inferred = attrs.get("inferred", False)
            proposed = attrs.get("proposed", False)
            if proposed:
                color, opacity, size = "#fbbf24", 0.95, 1.7
                hover = f"proposed probe: {attrs.get('action_id') or edge.get('type', '')}"
            elif inferred:
                color, opacity, size = "#94a3b8", 0.44, 1.0
                hover = escape(edge.get("type", "RELATES_TO"))
            else:
                color, opacity, size = "#35c7b1", 0.76, 1.4
                hover = escape(edge.get("type", "RELATES_TO"))
            edges.append({
                "source": source,
                "target": target,
                "label": edge.get("type", ""),
                "metadata": {
                    "color": color,
                    "opacity": opacity,
                    "size": size,
                    "hover": hover,
                },
            })

    return {
        "graph": {
            "directed": True,
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "background_color": "#0b111a",
                "node_label_size": 11,
                "edge_label_size": 8,
                "edge_opacity": 0.55,
            },
        }
    }


def render_gravis_html(display_graph: dict, show_labels: bool = False,
                       show_edges: bool = True, height: int = 720) -> str:
    """Render a Gravis D3 HTML document for embedding in Qt WebEngine."""
    graph = to_gravis_graph(display_graph, show_labels=show_labels, show_edges=show_edges)
    return _render_gravis_document(graph, height)


def build_attack_display(attack_graph: dict) -> dict:
    """Map an attack-graph artifact to the display shape the gravis pipeline renders.

    Attack nodes/edges keep their `proposed` marker in `attrs` so the edge
    styling can tell a hypothesis from an observed relation, which is the
    whole point of the tab.
    """
    nodes = []
    for node in attack_graph.get("nodes", []):
        nodes.append({
            "type": str(node.get("type", "asset")),
            "key": str(node.get("id", "")),
            "value": str(node.get("label") or node.get("id") or ""),
            "confidence": str(node.get("confidence", "")),
            "attrs": dict(node.get("attrs") or {}),
            "sources": [],
        })
    edges = []
    for edge in attack_graph.get("edges", []):
        attrs = dict(edge.get("attrs") or {})
        for key in ("action_id", "likelihood", "impact"):
            if edge.get(key) not in (None, ""):
                attrs.setdefault(key, edge.get(key))
        edges.append({
            "source": str(edge.get("source", "")),
            "target": str(edge.get("target", "")),
            "type": str(edge.get("type", "")),
            "attrs": attrs,
        })
    return {"nodes": nodes, "edges": edges}


def render_attack_html(attack_graph: dict, show_labels: bool = False,
                       height: int = 720) -> str:
    """Render `attack_graph.json` (nodes + edges + probe_plan) as dark-theme D3."""
    display = build_attack_display(attack_graph)
    graph = to_gravis_graph(display, show_labels=show_labels, show_edges=True)
    return _render_gravis_document(graph, height)


def _render_gravis_document(graph: dict, height: int) -> str:
    import warnings

    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="pkg_resources is deprecated.*")
        import gravis as gv

    fig = gv.d3(
        graph,
        graph_height=height,
        details_height=160,
        show_details=True,
        show_menu=True,
        show_node_label=True,
        show_edge_label=False,
        node_hover_tooltip=True,
        edge_hover_tooltip=True,
        node_drag_fix=True,
        node_hover_neighborhood=True,
        use_collision_force=True,
        collision_force_radius=30.0,
        collision_force_strength=0.8,
        links_force_distance=64.0,
        links_force_strength=0.72,
        many_body_force_strength=-180.0,
        use_x_positioning_force=True,
        x_positioning_force_strength=0.08,
        use_y_positioning_force=True,
        y_positioning_force_strength=0.08,
        zoom_factor=0.72,
    )
    html = fig.to_html_standalone()
    html = _patch_gravis_isolated_node_hover(html)
    html = _patch_gravis_dark_theme(html)
    return html.replace(
        "</body>",
        "<style>body{margin:0;background:#0a0f14;color:#d8e2ea;"
        "font-family:Arial,sans-serif;}</style></body>",
    )


def _patch_gravis_isolated_node_hover(html: str) -> str:
    """Guard Gravis hover-neighborhood code for isolated graph nodes.

    Gravis 0.1.0 assumes every displayed node has adjacency/incidence Set
    entries. Aggregated OSINT graphs commonly contain isolated nodes, which
    makes Qt WebEngine log repeated `undefined.has` JavaScript errors on hover.
    """
    return html.replace(
        "const adjacentNodes = state.shownData.adjacency.map.get(node),\n"
        "                    incidentEdges = state.shownData.incidence.map.get(node);",
        "const adjacentNodes = state.shownData.adjacency.map.get(node) || new Set(),\n"
        "                    incidentEdges = state.shownData.incidence.map.get(node) || new Set();",
    )


def _patch_gravis_dark_theme(html: str) -> str:
    """Re-skin Gravis' light default to match the console's dark shell."""
    dark_theme = """
<style>
body {
    background: #0a0f14 !important;
    color: #d8e2ea !important;
}
svg {
    background: #0c1218 !important;
}
svg text {
    fill: #d8e2ea !important;
}
button, select, input, summary, details, label, div, span {
    color: #d8e2ea;
}
button, select, input {
    background: #18232d !important;
    border: 1px solid #32404d !important;
    border-radius: 8px !important;
}
aside, pre {
    background: #111820 !important;
    color: #d8e2ea !important;
}
details {
    background: #111820 !important;
    border: 1px solid #25313c !important;
    border-radius: 10px !important;
}
</style>
"""
    return html.replace("</head>", f"{dark_theme}</head>")


def _type_color(asset_type: str) -> str:
    colors = {
        "domain": "#60a5fa",
        "subdomain": "#22d3ee",
        "subdomain_group": "#22d3ee",
        "ip": "#a78bfa",
        "webapp": "#4ade80",
        "webapp_group": "#4ade80",
        "port": "#f87171",
        "bucket": "#fbbf24",
        "bucket_group": "#fbbf24",
        "email": "#c084fc",
        "email_domain": "#c084fc",
        "email_pattern": "#fbbf24",
        "dns_record": "#94a3b8",
        "dns_record_group": "#94a3b8",
        "waf": "#94a3b8",
        "social_media": "#64748b",
        "social_media_group": "#64748b",
        "exploit_intel": "#64748b",
        "cloud_enum": "#94a3b8",
        "breach_data": "#94a3b8",
        # Attack-graph classes (goal, vuln, access states, testable surfaces).
        "goal": "#fde047",
        "vuln": "#fb7185",
        "credential": "#c084fc",
        "access_state": "#f472b6",
        "url": "#60a5fa",
        "parameter": "#a78bfa",
        "endpoint": "#38bdf8",
        "api_endpoint": "#38bdf8",
        "web_path": "#22d3ee",
        "dom_sink": "#fb923c",
        "idor_collection": "#f43f5e",
        "js_file": "#94a3b8",
    }
    return colors.get(asset_type, "#64748b")


def _label(node: dict, enabled: bool) -> str:
    if not enabled:
        return ""
    value = str(node.get("value") or node.get("key") or "")
    return value if len(value) <= 34 else value[:31] + "..."


def _node_hover(node: dict) -> str:
    attrs = node.get("attrs", {})
    rows = [
        f"<b>{escape(str(node.get('type', 'asset')))}</b>",
        escape(str(node.get("value", ""))),
        f"<code>{escape(str(node.get('key', '')))}</code>",
        f"confidence: {escape(str(node.get('confidence', '')))}",
    ]
    if attrs.get("count"):
        rows.append(f"count: {escape(str(attrs['count']))}")
    if attrs.get("finding_count"):
        rows.append(f"findings: {escape(str(attrs['finding_count']))} "
                    f"(worst: {escape(str(attrs.get('worst_finding', '')))})")
    return "<br>".join(rows)


def _node_click(node: dict) -> str:
    attrs = node.get("attrs", {})
    sources = ", ".join(node.get("sources", []))
    rows = [
        f"<h3>{escape(str(node.get('value', node.get('key', ''))))}</h3>",
        f"<p><b>Type:</b> {escape(str(node.get('type', 'asset')))}</p>",
        f"<p><b>Confidence:</b> {escape(str(node.get('confidence', '')))}</p>",
    ]
    if sources:
        rows.append(f"<p><b>Sources:</b> {escape(sources)}</p>")
    if attrs:
        preview = escape(str(attrs)[:1500])
        rows.append(f"<pre>{preview}</pre>")
    return "".join(rows)


def graph_positions(nodes: list[dict], width: int = 820, height: int = 560) -> dict:
    grouped = defaultdict(list)
    for node in nodes:
        grouped[node.get("type", "unknown")].append(node)

    type_names = sorted(grouped)
    if not type_names:
        return {}

    center_x = width / 2
    center_y = height / 2
    type_radius = min(width, height) * 0.34
    positions = {}

    for type_index, type_name in enumerate(type_names):
        angle = (2 * pi * type_index) / max(len(type_names), 1)
        group_x = center_x + cos(angle) * type_radius
        group_y = center_y + sin(angle) * type_radius
        group = grouped[type_name]
        node_radius = 54 if len(group) > 1 else 0
        for node_index, node in enumerate(group):
            if node_radius:
                node_angle = (2 * pi * node_index) / len(group)
                x = group_x + cos(node_angle) * node_radius
                y = group_y + sin(node_angle) * node_radius
            else:
                x, y = group_x, group_y
            positions[node.get("key")] = (x, y)

    return positions
