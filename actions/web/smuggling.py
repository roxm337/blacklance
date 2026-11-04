"""HTTP request smuggling — a wire-level action, not a header guess.

The stage-5 module already owns the desync oracle, but nothing could arm it
from a finding or a chain: request smuggling stayed an observation with no
prover. The action runs the same CL.TE / TE.CL oracles against the endpoint and
reports only a ghost that answered as its own request (or a socket that
produced more responses than requests), the two signals a proxy that frames one
way and a back end that frames another can both produce.

Risk is HIGH and detectability is high: a desync probe touches shared parser
state, so it belongs behind an explicit risk ceiling. The H2.CL/H2.TE oracle
stays in the module, which is where an ALPN h2 client is already available.
"""

from urllib.parse import urlparse

from actions.registry import action, ActionContext, ActionResult
from core import http_smuggle


@action(
    id="web.smuggling.detect",
    risk="HIGH",
    detectability="high",
    requires=["url"],
    produces="VulnCandidate",
    idempotent=True,
    timeout=200,
    description=(
        "Prove an HTTP desync: send CL.TE and TE.CL frame-disagreement "
        "probes and require a ghost request to answer on the same socket."
    ),
    category="web",
)
async def smuggling_detect(ctx: ActionContext) -> ActionResult:
    url = str(ctx.params.get("url") or ctx.target or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return ActionResult(False, error="url must be http(s) with a host")

    ambiguous, ambiguity_note = await http_smuggle.probe_ambiguity(url)
    attempted = []
    for mode in ("cl_te", "te_cl"):
        proven, note, marker = await http_smuggle.desync_probe(url, mode)
        attempted.append({"mode": mode, "proven": proven, "note": note})
        if proven:
            label = mode.upper().replace("_", ".")
            return ActionResult(
                True, confidence="CONFIRMED",
                data={"url": url, "mode": mode, "marker": marker,
                      "ambiguity": ambiguity_note,
                      "attempted": attempted},
                evidence={"action": "web.smuggling.detect", "mode": label,
                          "proof": note, "marker": marker},
            )

    return ActionResult(
        False, confidence="TENTATIVE",
        data={"url": url, "ambiguity": ambiguity_note,
              "attempted": attempted},
        error=("no desync reproduced; server rejects dual framing headers"
               if not ambiguous else "no desync reproduced"))
