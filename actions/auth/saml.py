"""SAML analysis actions — offline, structural, no replay.

These two actions read a captured SAML message or metadata document and
report what it is made of. They send no traffic: there is nothing to send
until a specific ACS is chosen, and a signature-wrapping proof requires a
valid signed response for that ACS plus a session to observe. That replay is
a chain step, not something this action can honestly claim.

`confidence` is FIRM for the structural facts (this assertion has no
signature) and never CONFIRMED — the document is evidence, not an exploit.
"""

from actions.registry import action, ActionContext, ActionResult
from core.saml import (SamlError, analyze, analyze_metadata, decode_message)


def _summary(result: dict) -> dict:
    return {
        "message_type": result.get("message_type")
        or result.get("role", "metadata"),
        "severity": result.get("severity", "INFO"),
        "codes": result.get("codes", []),
        "findings": result.get("findings", []),
    }


@action(
    id="auth.saml.analyze",
    risk="SAFE",
    detectability="low",
    requires=["saml_response"],
    produces="SAMLAnalysis",
    idempotent=True,
    timeout=30,
    description=(
        "Analyse a captured SAML response: which elements are signed, where "
        "the NameID comes from, whether audience/conditions exist. Reports "
        "the precondition for signature wrapping, never a bypass."
    ),
    category="auth",
)
async def saml_analyze(ctx: ActionContext) -> ActionResult:
    value = ctx.params.get("saml_response") or ctx.params.get("value") or ""
    try:
        result = analyze(decode_message(value))
    except SamlError as exc:
        return ActionResult(False, error=str(exc))
    except Exception as exc:  # noqa: BLE001 - malformed input is a result
        return ActionResult(False, error=f"unparseable SAML: {exc}")

    assertions = result.get("assertions") or []
    return ActionResult(
        True,
        data={**result, "assertion_count": len(assertions),
              "unsigned_assertions": sum(
                  1 for item in assertions if not item.get("signed"))},
        confidence="FIRM" if result.get("codes") else "TENTATIVE",
        evidence=_summary(result),
    )


@action(
    id="auth.saml.metadata",
    risk="SAFE",
    detectability="low",
    requires=["metadata"],
    produces="SAMLAnalysis",
    idempotent=True,
    timeout=30,
    description=(
        "Analyse SP/IdP metadata for weak SAML configuration: signing "
        "requirements, plaintext ACS endpoints, published keys."
    ),
    category="auth",
)
async def saml_metadata(ctx: ActionContext) -> ActionResult:
    value = ctx.params.get("metadata") or ""
    try:
        result = analyze_metadata(decode_message(value))
    except SamlError as exc:
        return ActionResult(False, error=str(exc))
    except Exception as exc:  # noqa: BLE001 - malformed input is a result
        return ActionResult(False, error=f"unparseable metadata: {exc}")

    return ActionResult(
        True,
        data=result,
        confidence="FIRM" if result.get("codes") else "TENTATIVE",
        evidence=_summary(result),
    )
