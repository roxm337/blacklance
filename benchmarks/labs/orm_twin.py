"""I5 lab twin: an items API with a filter-inclusion defect.

``TWIN_MODE=vuln`` applies the ``q`` filter across ALL owners and lets
``include=private_note`` expose a private field on any record. ``fixed``
scopes filters to the caller's own rows and only includes private fields
on own records. Direct object reads are owner-only in BOTH modes, so the
filter lane is isolable from plain IDOR.

Run directly:
    TWIN_MODE=vuln uvicorn benchmarks.labs.orm_twin:app --port 8401
"""

from __future__ import annotations

import os
import uuid

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel

MODE = os.environ.get("TWIN_MODE", "vuln")
assert MODE in ("vuln", "fixed"), "TWIN_MODE must be vuln|fixed"

app = FastAPI(title="ORM Lab", version="1.0.0")

USERS = {"alice": "alice-pass", "bob": "bob-pass"}
SESSIONS: dict[str, str] = {}
ITEMS: dict[int, dict] = {}
_SEQ = [0]


class LoginIn(BaseModel):
    username: str
    password: str


class ItemIn(BaseModel):
    name: str
    private_note: str = ""


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


@app.get("/api/me")
def me(request: Request):
    user = _user(request)
    if not user:
        raise HTTPException(status_code=401, detail="login required")
    return {"user": user, "email": f"{user}@example.com"}


@app.post("/api/items", status_code=201)
def create_item(request: Request, body: ItemIn):
    user = _user(request)
    if not user:
        raise HTTPException(status_code=401, detail="login required")
    _SEQ[0] += 1
    ITEMS[_SEQ[0]] = {"id": _SEQ[0], "owner": user, "name": body.name,
                      "private_note": body.private_note}
    return {"id": _SEQ[0]}


@app.get("/api/items")
def list_items(request: Request, q: str = "", owner_id: str = "",
               include: str = ""):
    user = _user(request)
    if not user:
        raise HTTPException(status_code=401, detail="login required")
    rows = [dict(item) for item in ITEMS.values()]
    if q:
        # The seeded defect: the search path runs GLOBALLY in vuln mode.
        if MODE == "fixed":
            rows = [row for row in rows if row["owner"] == user]
        rows = [row for row in rows if q in row["name"]]
    else:
        # The baseline collection is scoped to the caller in BOTH modes,
        # so the filter lane is isolable from collection-level exposure.
        rows = [row for row in rows if row["owner"] == user]
    if owner_id:
        rows = [row for row in rows if row["owner"] == owner_id]
    want_private = include == "private_note"
    for row in rows:
        keeps_private = (MODE == "vuln") or row["owner"] == user
        if not (want_private and keeps_private):
            row.pop("private_note", None)
    return {"data": rows}


@app.get("/api/items/{item_id}")
def get_item(request: Request, item_id: int):
    user = _user(request)
    if not user:
        raise HTTPException(status_code=401, detail="login required")
    item = ITEMS.get(item_id)
    if not item or item["owner"] != user:
        raise HTTPException(status_code=404, detail="not found")
    return item


@app.delete("/api/items/{item_id}", status_code=204)
def delete_item(request: Request, item_id: int):
    user = _user(request)
    item = ITEMS.get(item_id)
    if not item or item["owner"] != user:
        raise HTTPException(status_code=404, detail="not found")
    ITEMS.pop(item_id, None)
    return Response(status_code=204)

