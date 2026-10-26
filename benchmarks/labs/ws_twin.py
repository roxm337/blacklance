"""I7 lab twin: WebSocket authorization defects with a fixed counterpart.

``TWIN_MODE=vuln``:
- foreign-origin handshakes are accepted;
- any authenticated socket may read any object by id;
- any authenticated socket may subscribe to any object channel;
- sessions are checked only at handshake time, so a logged-out session
  keeps reading over the open socket.

``fixed``:
- a mismatched Origin is rejected at handshake;
- reads/subscriptions require object ownership;
- every message re-checks the session, so logout kills the socket lane.

HTTP object access is owner-only in BOTH modes, so the WebSocket lane is
isolable: the forbidden identity is denied over HTTP and only the socket
differs. Seeds are ordinary object names and are deleted after the probe.

Run directly:
    TWIN_MODE=vuln python -m benchmarks.labs.ws_twin --port 8503
"""

from __future__ import annotations

import argparse
import json
import os
import secrets

from aiohttp import web

MODE = os.environ.get("TWIN_MODE", "vuln")
assert MODE in ("vuln", "fixed"), "TWIN_MODE must be vuln|fixed"

USERS = {"alice": "alice-pass", "bob": "bob-pass"}
SESSIONS: dict[str, dict] = {}
OBJECTS: dict[int, dict] = {}
SEQ = {"id": 0}


def _session(request: web.Request) -> tuple[str, str]:
    token = request.headers.get("Authorization", "").removeprefix(
        "Bearer ").strip()
    if not token:
        token = request.cookies.get("sid", "")
    record = SESSIONS.get(token)
    if record and record.get("active"):
        return str(record["user"]), token
    return "", token


async def login(request: web.Request) -> web.Response:
    body = await request.json()
    user = str(body.get("username") or "")
    if USERS.get(user) != body.get("password"):
        return web.json_response({"error": "bad credentials"}, status=401)
    token = secrets.token_hex(16)
    SESSIONS[token] = {"user": user, "active": True}
    response = web.json_response({"token": token, "user": user})
    response.set_cookie("sid", token, httponly=True)
    return response


async def me(request: web.Request) -> web.Response:
    user, _ = _session(request)
    if not user:
        return web.json_response({"error": "login required"}, status=401)
    return web.json_response({"user": user})


async def logout(request: web.Request) -> web.Response:
    _, token = _session(request)
    if token in SESSIONS:
        SESSIONS[token]["active"] = False
    response = web.json_response({"ok": True})
    response.del_cookie("sid")
    return response


async def create_object(request: web.Request) -> web.Response:
    user, _ = _session(request)
    if not user:
        return web.json_response({"error": "login required"}, status=401)
    body = await request.json()
    SEQ["id"] += 1
    ref = SEQ["id"]
    OBJECTS[ref] = {"id": ref, "name": str(body.get("name") or ""),
                    "owner": user}
    return web.json_response({"id": ref}, status=201)


async def get_object(request: web.Request) -> web.Response:
    user, _ = _session(request)
    if not user:
        return web.json_response({"error": "login required"}, status=401)
    obj = OBJECTS.get(int(request.match_info["ref"]))
    if not obj or obj["owner"] != user:
        return web.json_response({"error": "not found"}, status=404)
    return web.json_response(obj)


async def delete_object(request: web.Request) -> web.Response:
    user, _ = _session(request)
    if not user:
        return web.json_response({"error": "login required"}, status=401)
    ref = int(request.match_info["ref"])
    obj = OBJECTS.get(ref)
    if not obj or obj["owner"] != user:
        return web.json_response({"error": "not found"}, status=404)
    OBJECTS.pop(ref, None)
    return web.Response(status=204)


async def health(request: web.Request) -> web.Response:
    return web.json_response({"ok": True, "mode": MODE})


async def websocket(request: web.Request) -> web.StreamResponse:
    user, token = _session(request)
    if not user:
        return web.json_response({"error": "login required"}, status=401)
    origin = request.headers.get("Origin", "")
    self_origin = f"http://{request.host}"
    if MODE == "fixed" and origin and origin != self_origin:
        return web.json_response({"error": "origin rejected"}, status=403)

    socket = web.WebSocketResponse()
    await socket.prepare(request)
    async for message in socket:
        if message.type != web.WSMsgType.TEXT:
            continue
        if MODE == "fixed" and not SESSIONS.get(token, {}).get("active"):
            await socket.send_str(json.dumps(
                {"type": "error", "error": "session revoked"}))
            break
        try:
            payload = json.loads(message.data)
        except (ValueError, TypeError):
            await socket.send_str(json.dumps({"type": "error"}))
            continue
        request_id = payload.get("req")
        if payload.get("type") == "read":
            ref = str(payload.get("id") or "")
            obj = OBJECTS.get(int(ref)) if ref.isdigit() else None
            if obj and (MODE != "fixed" or obj["owner"] == user):
                await socket.send_str(json.dumps({
                    "type": "read_result", "req": request_id,
                    "id": obj["id"], "name": obj["name"]}))
            else:
                await socket.send_str(json.dumps(
                    {"type": "error", "req": request_id}))
        elif payload.get("type") == "subscribe":
            channel = str(payload.get("channel") or "")
            ref = channel.removeprefix("obj-")
            obj = OBJECTS.get(int(ref)) if ref.isdigit() else None
            if obj and (MODE != "fixed" or obj["owner"] == user):
                await socket.send_str(json.dumps({
                    "type": "event", "req": request_id,
                    "channel": channel, "name": obj["name"]}))
            else:
                await socket.send_str(json.dumps(
                    {"type": "error", "req": request_id}))
        else:
            await socket.send_str(json.dumps({"type": "error"}))
    return socket


def build_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/health", health)
    app.router.add_post("/api/login", login)
    app.router.add_get("/api/me", me)
    app.router.add_post("/api/logout", logout)
    app.router.add_post("/api/objects", create_object)
    app.router.add_get("/api/objects/{ref:\\d+}", get_object)
    app.router.add_delete("/api/objects/{ref:\\d+}", delete_object)
    app.router.add_get("/ws", websocket)
    return app


app = build_app()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8503)
    args = parser.parse_args()
    web.run_app(app, host=args.host, port=args.port, print=None)


if __name__ == "__main__":
    main()
