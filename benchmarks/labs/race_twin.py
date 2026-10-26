"""I6 lab twin: stateful invariants with seeded race defects.

``TWIN_MODE=vuln``:
- coupon redeem does a racy read/sleep/write (check-then-act), so a
  concurrent batch grants N times;
- payments ignore the Idempotency-Key, so a replayed key double-applies.

``fixed``: coupon uses a per-coupon lock around check-and-set; payments
dedupe on the key and replay the stored response. Serial replay is legal
in BOTH modes (first redeem/payment accepted, second rejected/no-op), so
the race lane is isolable.

Run directly:
    TWIN_MODE=vuln uvicorn benchmarks.labs.race_twin:app --port 8501
"""

from __future__ import annotations

import asyncio
import os
import uuid

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel

MODE = os.environ.get("TWIN_MODE", "vuln")
assert MODE in ("vuln", "fixed"), "TWIN_MODE must be vuln|fixed"

app = FastAPI(title="Race Lab", version="1.0.0")

USERS = {"alice": "alice-pass"}
SESSIONS: dict[str, str] = {}
COUPONS: dict[int, dict] = {}
PAYMENTS: list[dict] = []
SEEN_KEYS: dict[str, dict] = {}
COUPON_LOCKS: dict[int, asyncio.Lock] = {}
_SEQ = {"coupon": 0, "payment": 0}


class LoginIn(BaseModel):
    username: str
    password: str


class CouponIn(BaseModel):
    code: str
    value: int = 10


class PaymentIn(BaseModel):
    amount: int


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
    return {"user": user}


@app.post("/api/coupons", status_code=201)
def create_coupon(request: Request, body: CouponIn):
    if not _user(request):
        raise HTTPException(status_code=401, detail="login required")
    _SEQ["coupon"] += 1
    COUPONS[_SEQ["coupon"]] = {"id": _SEQ["coupon"], "code": body.code,
                               "grants": 0, "redeemed": False}
    return {"id": _SEQ["coupon"]}


@app.get("/api/coupons/{coupon_id}")
def get_coupon(request: Request, coupon_id: int):
    if not _user(request):
        raise HTTPException(status_code=401, detail="login required")
    coupon = COUPONS.get(coupon_id)
    if not coupon:
        raise HTTPException(status_code=404, detail="not found")
    return coupon


@app.post("/api/coupons/{coupon_id}/redeem")
async def redeem(request: Request, coupon_id: int):
    if not _user(request):
        raise HTTPException(status_code=401, detail="login required")
    coupon = COUPONS.get(coupon_id)
    if not coupon:
        raise HTTPException(status_code=404, detail="not found")
    if MODE == "fixed":
        lock = COUPON_LOCKS.setdefault(coupon_id, asyncio.Lock())
        async with lock:
            if coupon["redeemed"]:
                raise HTTPException(status_code=409, detail="already redeemed")
            coupon["redeemed"] = True
            await asyncio.sleep(0.05)  # window stays inside the lock
            coupon["grants"] += 1
        return {"id": coupon_id, "grants": coupon["grants"]}
    # vuln: check-then-act across an await
    snapshot = dict(coupon)
    await asyncio.sleep(0.05)
    if snapshot["redeemed"]:
        raise HTTPException(status_code=409, detail="already redeemed")
    coupon["redeemed"] = True
    coupon["grants"] += 1
    return {"id": coupon_id, "grants": coupon["grants"]}


@app.delete("/api/coupons/{coupon_id}", status_code=204)
def delete_coupon(request: Request, coupon_id: int):
    if not _user(request):
        raise HTTPException(status_code=401, detail="login required")
    COUPONS.pop(coupon_id, None)
    return Response(status_code=204)


@app.get("/api/account")
def account(request: Request):
    user = _user(request)
    if not user:
        raise HTTPException(status_code=401, detail="login required")
    return {"user": user, "payment_count": len(PAYMENTS)}


@app.post("/api/payments", status_code=201)
async def pay(request: Request, body: PaymentIn):
    if not _user(request):
        raise HTTPException(status_code=401, detail="login required")
    key = request.headers.get("Idempotency-Key", "")
    if MODE == "fixed":
        if not key:
            raise HTTPException(status_code=400, detail="idempotency key required")
        if key in SEEN_KEYS:
            return SEEN_KEYS[key]
        _SEQ["payment"] += 1
        payment = {"id": _SEQ["payment"], "amount": body.amount}
        PAYMENTS.append(payment)
        SEEN_KEYS[key] = payment
        return payment
    # vuln: racy check-then-act — serial replays dedupe, but concurrent
    # requests all pass the check before any key is stored.
    if key and key in SEEN_KEYS:
        return SEEN_KEYS[key]
    await asyncio.sleep(0.05)
    _SEQ["payment"] += 1
    payment = {"id": _SEQ["payment"], "amount": body.amount}
    PAYMENTS.append(payment)
    if key:
        SEEN_KEYS[key] = payment
    return payment


@app.delete("/api/payments/{payment_id}", status_code=204)
def delete_payment(request: Request, payment_id: int):
    if not _user(request):
        raise HTTPException(status_code=401, detail="login required")
    for index, payment in enumerate(PAYMENTS):
        if payment["id"] == payment_id:
            PAYMENTS.pop(index)
            break
    return Response(status_code=204)
