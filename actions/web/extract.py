"""Impact extraction — what a proven primitive is actually worth.

`web.lfi.read` turns a confirmed file-inclusion parameter into a bounded,
redacted read of fixed high-value files. `web.sqli.extract` asks sqlmap for
database metadata (DBMS, account, schema, DBA flag) instead of dumping rows:
enough to grade the finding, not a data breach.

Both run read-only and return redacted previews. Neither walks directories nor
guesses deployment layouts, and neither is armed automatically from a bare
detection — they are escalation legs an operator (or a causal chain) chooses.
"""

from actions.registry import action, ActionContext, ActionResult
from actions.web.http_util import session_headers
from core import exfil
from tools.external import sqlmap_enumerate


@action(
    id="web.lfi.read",
    risk="MEDIUM",
    detectability="medium",
    requires=["url", "param"],
    produces="VulnCandidate",
    idempotent=True,
    timeout=300,
    description=(
        "Read a fixed list of high-value files through a confirmed inclusion "
        "parameter; returns markers, byte counts and redacted previews only."
    ),
    category="web",
)
async def lfi_read(ctx: ActionContext) -> ActionResult:
    url = str(ctx.params.get("url") or ctx.target or "").strip()
    param = str(ctx.params.get("param") or "").strip()
    if not url or not param:
        return ActionResult(False, error="url and param are required")
    method = str(ctx.params.get("method") or "GET").upper()
    files = ctx.params.get("files")
    if files is not None and not isinstance(files, (list, tuple)):
        files = None

    result = await exfil.read_files(
        url, param, method=method, headers=session_headers(ctx),
        files=[str(item) for item in files] if files else None)
    if not result.get("count"):
        return ActionResult(
            False, confidence="TENTATIVE",
            error="no high-value file was readable through this parameter")

    return ActionResult(
        True, confidence="CONFIRMED",
        data=result,
        evidence={"action": "web.lfi.read",
                  "impact": exfil.summarize_extraction(result),
                  "secrets": [secret for item in result["files"]
                              for secret in item.get("secrets") or []][:10]},
    )


@action(
    id="web.sqli.extract",
    risk="HIGH",
    detectability="high",
    requires=["url"],
    produces="VulnCandidate",
    tools=["sqlmap"],
    idempotent=True,
    timeout=900,
    description=(
        "Prove database access through a SQL injection: enumerate DBMS/banner, "
        "current user, current schema, available databases and DBA status. "
        "No row dumping."
    ),
    category="web",
)
async def sqli_extract(ctx: ActionContext) -> ActionResult:
    url = str(ctx.params.get("url") or ctx.target or "").strip()
    if not url:
        return ActionResult(False, error="url is required")
    param = str(ctx.params.get("param") or "").strip()
    if param and "?" not in url:
        url = f"{url}?{param}=1"

    result = await sqlmap_enumerate(
        url,
        timeout=int(ctx.params.get("sqlmap_timeout") or ctx.timeout or 900),
        cookie=str(ctx.params.get("cookie") or ""),
        headers=str(ctx.params.get("headers") or ""),
        database=str(ctx.params.get("database") or ""),
        tables=bool(ctx.params.get("tables")),
    )
    if not result.get("available"):
        return ActionResult(False, confidence="TENTATIVE",
                            error="sqlmap not installed")

    extracted = {
        key: result.get(key) for key in
        ("dbms", "banner", "current_user", "current_database", "is_dba",
         "databases", "tables")
        if result.get(key)
    }
    if not extracted:
        return ActionResult(
            False, confidence="TENTATIVE",
            data={"stdout": result.get("stdout", "")[:2000]},
            error="sqlmap enumerated nothing: injection not confirmed")

    return ActionResult(
        True, confidence="CONFIRMED",
        data={"url": url, **extracted},
        evidence={"action": "web.sqli.extract",
                  "impact": (f"database access as "
                             f"{result.get('current_user') or 'unknown user'}"
                             f" on {result.get('current_database') or 'unknown db'}"),
                  "is_dba": result.get("is_dba"),
                  "databases": result.get("databases", [])[:10],
                  "tables": result.get("tables", [])[:20]},
    )
