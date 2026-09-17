"""egapi — the ONE mTLS client for the node's hidden management API.

Used by egconsole.py, egctl.py and the MCP server (egmcp.py). Replaces the four
divergent copies that previously lived in those scripts.

Node list format (tools/my-servers.json, a bare JSON array):
  [{"name": "vps-1", "host": "1.2.3.4", "port": 9443, "base": "/api-XXXX",
    "ca": "api-certs-vps/ca.crt", "cert": "api-certs-vps/client.crt",
    "key": "api-certs-vps/client.key",
    "relay": {"host": "127.0.0.1", "port": 9445, "op_key": "..."}}]

Cert paths relative to tools/ are resolved automatically. Auth is the client
certificate itself (the server requires it); server identity is not verified
(API certs are minted per-boot with local SANs) — pass verify_server=True with
a ca file to enforce full verification.
"""
import http.client
import json
import os
import ssl

TOOLS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def servers_path():
    return os.environ.get("EG_MCP_SERVERS") or os.path.join(TOOLS_DIR, "my-servers.json")


def load_servers(path=None):
    """Load the node list; resolves relative cert paths against tools/."""
    path = path or servers_path()
    with open(path, encoding="utf-8") as f:
        servers = json.load(f)
    if not isinstance(servers, list):
        raise ValueError(f"{path}: expected a bare JSON array of nodes")
    for s in servers:
        for k in ("ca", "cert", "key"):
            if s.get(k) and not os.path.isabs(s[k]):
                s[k] = os.path.normpath(os.path.join(TOOLS_DIR, s[k]))
    return servers


def pick_server(name=None, servers=None):
    """Resolve a node by name; default = EG_MCP_DEFAULT_SERVER or the first."""
    servers = servers if servers is not None else load_servers()
    if not servers:
        raise RuntimeError("no servers configured in my-servers.json")
    if not name:
        name = os.environ.get("EG_MCP_DEFAULT_SERVER") or servers[0]["name"]
    for s in servers:
        if s["name"] == name:
            return s
    raise RuntimeError(f"server '{name}' not found; known: {[x['name'] for x in servers]}")


class Api:
    """mTLS JSON client for one node (http.client; safe for threads)."""

    def __init__(self, srv, timeout=20, verify_server=False):
        self.srv = srv
        self.timeout = timeout
        self.ctx = ssl.create_default_context()
        if verify_server and srv.get("ca"):
            self.ctx.load_verify_locations(srv["ca"])
        else:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self.ctx.load_cert_chain(srv["cert"], srv["key"])

    def call(self, method, path, body=None) -> tuple:
        """Returns (status, parsed-json-or-str)."""
        conn = http.client.HTTPSConnection(self.srv["host"], self.srv.get("port", 9443),
                                           context=self.ctx, timeout=self.timeout)
        payload = json.dumps(body) if body is not None else None
        headers = {"Content-Type": "application/json"} if payload else {}
        try:
            conn.request(method, self.srv["base"] + path, payload, headers)
            r = conn.getresponse()
            raw = r.read()
            try:
                return r.status, json.loads(raw or b"{}")
            except Exception:
                return r.status, raw.decode("utf-8", "replace")[:500]
        finally:
            conn.close()
