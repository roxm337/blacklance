"""I4 lab twin: a SPA whose fetch path is built from a URL parameter.

``TWIN_MODE=vuln`` joins the ``r`` query parameter into the fetch path
(``fetch('/api/' + r)``), so ``?r=..%2F..%2Fadmin%2Fsecrets`` reaches the
admin-only endpoint. ``fixed`` validates the input pattern and rejects
anything but ``reports/<digits>`` before fetching; the server also
enforces 403 on /admin/secrets.

Run directly:
    TWIN_MODE=vuln uvicorn benchmarks.labs.cspt_twin:app --port 8301
"""

from __future__ import annotations

import os
import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

MODE = os.environ.get("TWIN_MODE", "vuln")
assert MODE in ("vuln", "fixed"), "TWIN_MODE must be vuln|fixed"

ADMIN_MARKER = "osint-cspt-admin-marker"

app = FastAPI(title="CSPT Lab", version="1.0.0")

USERS = {"alice": "alice-pass"}
SESSIONS: dict[str, str] = {}
REPORTS = {
    1: {"id": 1, "owner": "alice", "note": "quarterly"},
    2: {"id": 2, "owner": "alice", "note": "annual"},
}


class LoginIn(BaseModel):
    username: str
    password: str


def _user(request: Request) -> str:
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    return SESSIONS.get(token, "")


@app.post("/api/login")
def login(body: LoginIn):
    if USERS.get(body.username) != body.password:
        raise HTTPException(status_code=401, detail="bad credentials")
    token = uuid.uuid4().hex
    SESSIONS[token] = body.username
    return {"token": token, "user": body.username}


@app.get("/api/reports/{report_id}")
def get_report(request: Request, report_id: int):
    if not _user(request):
        raise HTTPException(status_code=401, detail="login required")
    report = REPORTS.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="not found")
    return report


@app.get("/admin/secrets")
def admin_secrets(request: Request):
    if not _user(request):
        raise HTTPException(status_code=401, detail="login required")
    if MODE == "fixed":
        raise HTTPException(status_code=403, detail="forbidden")
    return {"secret": ADMIN_MARKER}


_VULN_PAGE = """<!doctype html><html><body>
<h1>Reports</h1>
<script>
const raw = new URLSearchParams(location.search).get('r') || 'reports/1';
fetch('/api/' + raw);
</script></body></html>"""

_FIXED_PAGE = """<!doctype html><html><body>
<h1>Reports</h1>
<script>
const raw = new URLSearchParams(location.search).get('r') || 'reports/1';
if (/^reports\\/\\d+$/.test(raw)) { fetch('/api/' + raw); }
</script></body></html>"""


@app.get("/app", response_class=HTMLResponse)
def page(request: Request):
    if not _user(request):
        raise HTTPException(status_code=401, detail="login required")
    return _VULN_PAGE if MODE == "vuln" else _FIXED_PAGE
