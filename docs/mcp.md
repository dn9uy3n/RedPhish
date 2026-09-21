---
layout: default
title: MCP server
---

# MCP server (`egmcp`)

`tools/mcp/egmcp.py` is a [Model Context Protocol](https://modelcontextprotocol.io)
server (stdio transport) that lets **AI agents operate the whole platform as tools**:
phishlets, token-gated lures, captured sessions, upstream proxy, the Google relay —
including opening a captured session in a real Chrome window on the operator machine.

---

## Install

```bash
pip install -r tools/mcp/requirements.txt     # mcp SDK
pip install playwright                        # only for relay_open_session
```

## Configuration

Reuses the console node list **`tools/my-servers.json`**:

```json
[
  {
    "name": "vps-node-1",
    "host": "<node-ip>", "port": 9443, "base": "/api-XXXXXXXXXXXX",
    "ca": "api-certs-vps/ca.crt", "cert": "api-certs-vps/client.crt",
    "key": "api-certs-vps/client.key",
    "relay": { "host": "127.0.0.1", "port": 9445, "op_key": "<RELAY_OP_KEY>" }
  }
]
```

- `base` = the stealth API path (printed at node boot; also in `<cfgdir>/api/config.json`).
- `relay` block is optional — needed only for `relay_*` tools. `op_key` = the sidecar's
  `RELAY_OP_KEY` (pin it with a systemd drop-in so it survives restarts). The relay API
  listens on the node's loopback only: tunnel with
  `ssh -N -L 9445:127.0.0.1:9445 <user>@<node>`.
- Env: `EG_MCP_SERVERS` (alternate config path), `EG_MCP_DEFAULT_SERVER` (default node).

## The MCP API key

Two transports, one key rule:

- **stdio (local)** — the agent spawns `egmcp.py` as a child process on the same
  machine. No key needed: process-local trust.
- **streamable-http (remote)** — serve with `python tools/mcp/egmcp.py --http`
  (default `127.0.0.1:8306/mcp`). **Every request must carry the API key** as
  `X-API-Key: <key>` (or `Authorization: Bearer <key>`); anything else gets 401.

### Getting / rotating the key (from egconsole)

```
eg> mcpkey           # show the key + ready-made agent config snippets
eg> mcpkey new       # generate a NEW key (rotates tools/mcp/mcp.key)
```

The key lives in `tools/mcp/mcp.key` (gitignored, 0600); `EG_MCP_API_KEY` env
overrides the file. Rotating invalidates every agent config still holding the
old key — update them (the `mcpkey` output gives you copy-paste snippets with
the key already filled in).

Env for the HTTP transport: `EG_MCP_HOST` (bind — default loopback; set only
behind a tunnel/firewall), `EG_MCP_PORT` (default 8306).

## Registering with agents

### Claude Desktop / Claude Code (stdio, local)

`claude_desktop_config.json` (Desktop) or `.mcp.json` (Code):

```json
{ "mcpServers": { "RedPhish": {
    "command": "python",
    "args": ["C:/path/to/RedPhish/tools/mcp/egmcp.py"],
    "env": { "EG_MCP_DEFAULT_SERVER": "vps-node-1" } } } }
```

Claude Code also accepts it straight on the command line:
`claude mcp add RedPhish -- python <REPO>/tools/mcp/egmcp.py`.
Verify from the chat: "list my evilginx servers" (calls `servers_list`).

### Cursor (`.cursor/mcp.json`)

stdio on the same machine:

```json
{ "mcpServers": { "RedPhish": {
    "command": "python",
    "args": ["<REPO>/tools/mcp/egmcp.py"] } } }
```

or streamable-http from another machine (serve `--http` first):

```json
{ "mcpServers": { "RedPhish": {
    "url": "http://<egmcp-host>:8306/mcp",
    "headers": { "X-API-Key": "<key from: egconsole mcpkey>" } } } }
```

### ZCode

Same two shapes in the ZCode MCP config — stdio (`command`/`args`) for a local
server, or the streamable-http entry (`url` + `headers: {"X-API-Key": …}`) for
the networked one. `EG_MCP_DEFAULT_SERVER` in the server's env selects the node.

### ChatGPT (Connectors / MCP)

ChatGPT only reaches **remote** MCP servers over public HTTPS — stdio and
plain-HTTP LAN endpoints won't work. Expose the HTTP transport through an
authenticated tunnel (cloudflared / ngrok / an SSH reverse tunnel with TLS) and
register the resulting `https://…/mcp` URL as a connector, using the API key as
the connector's auth token. Keep the tunnel scoped to the campaign and tear it
down afterwards — this is an internet-reachable path to your node controls.

## Tools


### Node & phishlets

| Tool | Args | Effect |
|---|---|---|
| `servers_list` | — | configured nodes, default marker, relay availability |
| `status` | — | node heartbeat + session count |
| `phishlets_list` | — | names + enabled/disabled |
| `phishlet_enable` / `phishlet_disable` | `name` | hot switch (no restart) |
| `phishlets_reload` | — | re-read YAMLs from disk |
| `phishlet_hostname` | `name, hostname` | change base hostname |

### Lures

| Tool | Args | Effect |
|---|---|---|
| `lures_list` | `phishlet?` | lures (path, redirect, relay, token) |
| `lure_create` | `phishlet, redirect_url?, relay?` | new lure with auto gate token |
| `lure_url` | `lure_id, params?` | campaign URL + the `?t=<token>` reminder appended |
| `lure_edit` | `lure_id, fields_json` | partial edit (JSON object) |
| `lure_delete` | `lure_id` | delete |

### Sessions & browser-open

| Tool | Args | Effect |
|---|---|---|
| `sessions_list` / `session_detail` / `session_delete` | — | captured sessions CRUD |
| `session_cookies` | `session_id` | import-ready cookies + gotchas (expires/secure/`__Host-`) |
| `session_export` | `session_id, file?` | Cookie-Editor JSON file |
| **`open_session`** | `session_id, url?, chrome?, headless?` | **opens a real Chrome window on this machine signed in as the victim** (evilginx-captured session; detached process, window survives the call) |

### Upstream proxy

`proxy_status` · `proxy_set(address, port, type, username, password, routes, enabled)`
(partial — omitted fields keep values; masked password echoed back clobbers it) ·
`proxy_route_add/del(suffix)` · `proxy_on` / `proxy_off`.

### Google relay

| Tool | Args | Effect |
|---|---|---|
| `relay_sessions` | — | live relay victim sessions (needs tunnel + relay block) |
| `relay_capture` | `capture_id` | full capture: `{email, password, cookies[], ua, ts}` |
| **`relay_open_session`** | `capture_id, url?` | **opens Chrome signed in with the relay capture** (default: the victim's Gmail inbox) |

All node tools take an optional `server` argument for multi-node fleets.

## Example session (what the agent actually does)

> **Operator:** "Open the Gmail inbox for the newest session."
>
> **Agent:** `relay_sessions` → picks the newest capture → `relay_open_session <id>`
> → "Chrome opened, signed in as boyhoang37@gmail.com (Inbox (52))."

> **Operator:** "Create a new google lure pointing at mail.google.com and give me the URL."
>
> **Agent:** `lure_create phishlet=google redirect_url=https://mail.google.com` →
> `lure_url <id>` → returns `https://<host>/<path>` **plus a reminder to append the
> `?t=` token** (which the agent fetches from the lure record — and must not log it).

## Security notes

- The MCP process runs on the **operator workstation** and holds the client certs —
  never register it on shared machines.
- stdio transport: the agent talks to the server over its own process pipe; nothing
  listens on the network. The HTTP transport is key-gated (`X-API-Key`) — bind it to
  loopback or a tunnel, never expose it bare to the internet.
- `open_session` / `relay_open_session` put **live victim sessions** on your desktop —
  close the windows when done.
- Relay tunnel + `op_key` are operator-side secrets; the sidecar only accepts
  `X-Op-Key`-authenticated calls on loopback.
- Tokens, lure URLs and node IPs are campaign secrets — keep them out of chat logs and
  public artifacts.
