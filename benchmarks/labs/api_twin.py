"""I2 lab twin: a tiny order-state API with a seeded multi-step defect.

``TWIN_MODE=vuln`` accepts a negative payment amount and persists it
(``total: -1000, status: paid``) — the state machine defect. ``fixed``
rejects it with 422. The OpenAPI document chains the three operations
with x-links so schemathesis's links state machine composes the full
sequence; without links the fuzzer would never reach the defect.

Run directly:
    TWIN_MODE=vuln uvicorn benchmarks.labs.api_twin:app --port 8101
"""

from __future__ import annotations

import os

from fastapi import Body, FastAPI, HTTPException, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

MODE = os.environ.get("TWIN_MODE", "vuln")
assert MODE in ("vuln", "fixed"), "TWIN_MODE must be vuln|fixed"

app = FastAPI(title="Order Lab", version="1.0.0")

_ORDERS: dict[int, dict] = {}
_SEQ = [0]

# Server-side price table the fixed twin enforces.
PRICE_TABLE = {"juice": 250, "snack": 100}


class ItemIn(BaseModel):
    sku: str
    quantity: int = Field(ge=1, le=10)
    price: int = 0


class PayIn(BaseModel):
    # The contract BOTH twins advertise: amount >= 0. The fixed twin
    # enforces it in validation; the vulnerable twin advertises it but
    # accepts negatives anyway (the seeded defect).
    amount: int = Field(ge=0)


class Order(BaseModel):
    id: int
    total: int
    status: str


def _next_id() -> int:
    _SEQ[0] += 1
    return _SEQ[0]


@app.post("/api/orders", response_model=Order, status_code=201)
def create_order():
    order_id = _next_id()
    _ORDERS[order_id] = {"id": order_id, "total": 0, "status": "pending"}
    return _ORDERS[order_id]


@app.post("/api/orders/{order_id}/items", response_model=Order)
def add_item(order_id: int, item: ItemIn):
    if order_id not in _ORDERS:
        raise HTTPException(status_code=404, detail="unknown order")
    if MODE == "vuln":
        total = item.price * item.quantity
    else:
        if item.sku not in PRICE_TABLE:
            raise HTTPException(status_code=422, detail="unknown sku")
        total = PRICE_TABLE[item.sku] * item.quantity
    _ORDERS[order_id]["total"] = total
    return _ORDERS[order_id]


@app.post("/api/orders/{order_id}/pay", response_model=Order)
def pay(order_id: int, pay: PayIn):
    if order_id not in _ORDERS:
        raise HTTPException(status_code=404, detail="unknown order")
    _ORDERS[order_id]["total"] = pay.amount
    _ORDERS[order_id]["status"] = "paid"
    return _ORDERS[order_id]


if MODE == "vuln":
    # The vulnerable twin advertises the same amount >= 0 contract (so the
    # negative_data_rejection check generates violating payloads) but binds
    # the raw body: validation never runs. A request without the required
    # `amount` is accepted and nulls the order total — the seeded defect.
    @app.post("/api/orders/{order_id}/pay", response_model=Order,
              openapi_extra={
                  "requestBody": {
                      "required": True,
                      "content": {"application/json": {"schema": {
                          "type": "object",
                          "properties": {"amount": {
                              "type": "integer", "minimum": 0}},
                          "required": ["amount"]}}},
                  }})
    async def pay_vuln(order_id: int, payload: dict = Body(...)):
        if order_id not in _ORDERS:
            raise HTTPException(status_code=404, detail="unknown order")
        _ORDERS[order_id]["total"] = payload.get("amount")
        _ORDERS[order_id]["status"] = "paid"
        return _ORDERS[order_id]

    # The read must expose the corruption verbatim: a JSONResponse bypasses
    # response_model coercion, so total: false stays false while the schema
    # still declares an integer — the conformance violation the fuzzer and
    # the impact probe both observe.
    @app.get("/api/orders/{order_id}", response_model=Order)
    def get_order_vuln(order_id: int):
        if order_id not in _ORDERS:
            raise HTTPException(status_code=404, detail="unknown order")
        return JSONResponse(_ORDERS[order_id])


@app.get("/api/orders/{order_id}", response_model=Order)
def get_order(order_id: int):
    if order_id not in _ORDERS:
        raise HTTPException(status_code=404, detail="unknown order")
    return _ORDERS[order_id]


@app.delete("/api/orders/{order_id}", status_code=204)
def delete_order(order_id: int):
    _ORDERS.pop(order_id, None)
    return Response(status_code=204)


@app.post("/api/admin/reset", status_code=204)
def reset():
    _ORDERS.clear()
    _SEQ[0] = 0
    return Response(status_code=204)


# ── OpenAPI augmentation: x-links chaining the state machine ─────

def _add_links(spec: dict) -> dict:
    paths = spec["paths"]
    order_id_expr = {"operationRef": "createOrder", "parameters": {
        "order_id": "$response.body#/id"}}
    pay_expr = {"operationRef": "addItem", "parameters": {
        "order_id": "$response.body#/id"}}
    read_expr = {"operationRef": "payOrder", "parameters": {
        "order_id": "$response.body#/id"}}
    paths["/api/orders"]["post"].setdefault("responses", {})
    paths["/api/orders/{order_id}/items"]["post"].setdefault(
        "x-links", {"next": read_expr})
    paths["/api/orders/{order_id}/pay"]["post"].setdefault(
        "x-links", {"next": {
            "operationRef": "getOrder",
            "parameters": {"order_id": "$response.body#/id"}}})
    return spec


_openapi = app.openapi()
_openapi["paths"]["/api/orders"]["post"]["operationId"] = "createOrder"
_openapi["paths"]["/api/orders/{order_id}/items"]["post"][
    "operationId"] = "addItem"
_openapi["paths"]["/api/orders/{order_id}/pay"]["post"][
    "operationId"] = "payOrder"
_openapi["paths"]["/api/orders/{order_id}"]["get"][
    "operationId"] = "getOrder"
_openapi["paths"]["/api/orders/{order_id}/items"]["post"]["x-links"] = {
    "pay": {"operationRef": "payOrder", "parameters": {
        "order_id": "$response.body#/id"}}}
app.openapi_schema = _add_links(_openapi)


@app.get("/openapi.json")
def openapi():
    return app.openapi()
