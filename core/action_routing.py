"""Which registered action proves which graph transition.

The attack graph and the chain executor used to carry separate, shorter copies
of this mapping: the graph proposed five fixed probes and only two exploitation
goals, while the executor could name a proving action for six edge types. A
module would detect SSTI, LFI, NoSQL injection or an authorization bypass and
the pipeline had nothing to aim at it — the finding was the end of the line,
reported as "no proving action registered".

Keeping the routing in one place fixes both halves at once: the planner uses
`PROBE_ACTIONS` for blind surface probing and `CATEGORY_ACTIONS` to arm a
finding it already has, and the executor uses `EDGE_ACTIONS` /
`CATEGORY_ACTIONS` to select the same action for the same edge.

Ordering is significant. `CATEGORY_ACTIONS` is first-match-wins, so the
specific tokens ("nosql", "ssti", "authorization") come before the generic
ones they contain ("injection", "auth"). A wrong first match is not cosmetic:
it runs a SQLi oracle against an SSTI finding and reports the target clean.
"""

from __future__ import annotations

# Edge type -> candidate actions, best first. These are the generic arms used
# when an edge does not declare one. `extract` used to be empty, which is why
# no causal chain could ever carry a credential out of an SSRF or LFI: the
# thread had a producer type (token/credential) and no action able to produce
# one.
EDGE_ACTIONS: dict[str, list[str]] = {
    "exploit": [
        "web.sqli.detect",
        "web.sqli.blind_detect",
        "web.xss.reflected",
        "web.redirect.probe",
        "web.ssti.detect",
        "web.nosql.detect",
        "web.lfi.detect",
    ],
    "pivot": [
        "web.ssrf.oob_detect",
        "web.ssrf.cloud_metadata",
    ],
    "extract": [
        "web.ssrf.cloud_metadata",
        "web.lfi.detect",
    ],
    "authenticate": [
        "auth.jwt.none_alg",
        "auth.jwt.detect",
        "auth.bypass.probe",
    ],
    "escalate": [
        "auth.bypass.probe",
    ],
}

# Vuln-node category -> the action that proves it. First match wins.
CATEGORY_ACTIONS: list[tuple[str, str]] = [
    # Server-side request first: "server-side request forgery" must not fall
    # through to a generic injection probe.
    ("ssrf", "web.ssrf.oob_detect"),
    ("server-side request", "web.ssrf.oob_detect"),
    ("cloud metadata", "web.ssrf.cloud_metadata"),
    ("metadata", "web.ssrf.cloud_metadata"),
    # Specific classes before the generic word they contain.
    ("nosql", "web.nosql.detect"),
    ("ssti", "web.ssti.detect"),
    ("template injection", "web.ssti.detect"),
    ("template", "web.ssti.detect"),
    ("traversal", "web.lfi.detect"),
    ("file inclusion", "web.lfi.detect"),
    ("lfi", "web.lfi.detect"),
    ("local file", "web.lfi.detect"),
    # Authorization before "auth", which is a substring of it.
    ("authorization", "auth.bypass.probe"),
    ("access control", "auth.bypass.probe"),
    ("auth bypass", "auth.bypass.probe"),
    ("authentication bypass", "auth.bypass.probe"),
    ("privilege escalation", "auth.bypass.probe"),
    ("sql", "web.sqli.detect"),
    ("injection", "web.sqli.detect"),
    ("xss", "web.xss.reflected"),
    ("cross-site", "web.xss.reflected"),
    ("script", "web.xss.reflected"),
    ("redirect", "web.redirect.probe"),
    ("jwt", "auth.jwt.detect"),
    ("token", "auth.jwt.detect"),
    ("auth", "auth.jwt.detect"),
]

# Blind probes run against every testable surface. A `(url, param)` pair is
# worth testing before anything is known to be wrong with it. `auth.bypass`
# is deliberately absent: it needs an endpoint that actually denies anonymous
# access, which is a finding-derived surface, not a bare parameter.
PROBE_ACTIONS: list[str] = [
    "web.sqli.detect",
    "web.sqli.blind_detect",
    "web.xss.reflected",
    "web.redirect.probe",
    "web.ssrf.oob_detect",
    "web.ssti.detect",
    "web.lfi.detect",
    "web.nosql.detect",
]


def action_for_category(category: str) -> str:
    """The action that proves a finding of this category, or "".

    Returns an action id even if the current build does not register it: the
    caller decides how to report an unregistered arm, and silently returning
    "" would hide a routing table that names an action nobody implements.
    """
    text = str(category or "").strip().lower()
    if not text:
        return ""
    for token, action_id in CATEGORY_ACTIONS:
        if token in text:
            return action_id
    return ""
