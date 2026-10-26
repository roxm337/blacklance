"""I3 lab twin: multi-tenant invoice API with a seeded cross-tenant leak.

``TWIN_MODE=vuln`` serves any invoice to any authenticated session (the
seeded BOLA defect); ``fixed`` enforces ownership with 403. Both twins
share a read-only /api/shared object (sharing check) and a working
logout (revocation check).

Run directly:
    TWIN_MODE=vuln uvicorn benchmarks.labs.authz_twin:app --port 8201
"""

from __future__ import annotations

import os
import uuid

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel

MODE = os.environ.get("TWIN_MODE", "vuln")
assert MODE in ("vuln", "fixed"), "TWIN_MODE must be vuln|fixed"

app = FastAPI(title="Authz Lab", version="1.0.0")

USERS = {
    "alice": "alice-pass",
    "bob": "bob-pass",
}
SESSIONS: dict[str, str] = {}          # token -> username
INVOICES: dict[int, dict] = {}
_SEQ = [0]
SHARED = {"shared_id": 9, "content": "shared-object-readable-by-both"}


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


@app.post("/api/logout")
def logout(request: Request):
    token = request.headers.get("Authorization", "").removeprefix("Bearer ")
    SESSIONS.pop(token, None)
    return {"status": "logged out"}


@app.get("/dashboard")
def dashboard(request: Request):
    user = _user(request)
    if not user:
        raise HTTPException(status_code=401, detail="login required")
    return {"user": user, "message": f"welcome {user}"}


@app.post("/api/invoices", status_code=201)
def create_invoice(request: Request, body: dict):
    user = _user(request)
    if not user:
        raise HTTPException(status_code=401, detail="login required")
    _SEQ[0] += 1
    INVOICES[_SEQ[0]] = {
        "id": _SEQ[0], "owner": user,
        "note": body.get("note", ""),
    }
    return {"id": _SEQ[0]}


@app.get("/api/invoices/{invoice_id}")
def get_invoice(request: Request, invoice_id: int):
    user = _user(request)
    if not user:
        raise HTTPException(status_code=401, detail="login required")
    invoice = INVOICES.get(invoice_id)
    if not invoice:
        raise HTTPException(status_code=404, detail="not found")
    if MODE == "fixed" and invoice["owner"] != user:
        raise HTTPException(status_code=403, detail="forbidden")
    return invoice


@app.delete("/api/invoices/{invoice_id}", status_code=204)
def delete_invoice(request: Request, invoice_id: int):
    user = _user(request)
    invoice = INVOICES.get(invoice_id)
    if not invoice or (MODE == "fixed" and invoice["owner"] != user):
        raise HTTPException(status_code=404, detail="not found")
    INVOICES.pop(invoice_id, None)
    return Response(status_code=204)


@app.get("/api/shared/{shared_id}")
def get_shared(request: Request, shared_id: int):
    if not _user(request):
        raise HTTPException(status_code=401, detail="login required")
    if shared_id != SHARED["shared_id"]:
        raise HTTPException(status_code=404, detail="not found")
    return SHARED
