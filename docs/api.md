---
layout: default
title: mTLS API reference
---

# mTLS API reference

The hidden management API listens on `:9443` under a random stealth base path. All
calls require **mutual TLS**: the server presents its cert and requires the
auto-generated **client certificate**. `egconsole.py` and the
[MCP server](mcp.md) speak this API for you — the reference below is for direct
integrations.

```
https://<node>:9443/<base-path>/<endpoint>
```

**How the base path works**: generated once as `/api-<12 random chars>` at first boot
with `-api 9443`, persisted in `<cfgdir>/api/config.json` (`{"base_path": ...}`), and
reused across restarts. The local CA + server/client certs are auto-generated in
`<cfgdir>/api/`. Requests without a valid client cert fail the TLS handshake; paths
outside the base path hit no route (404 — the API's existence is not leaked).

---

## Endpoints

### Node

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/status` | — | `{"status":"ok","time":<unix>,"sessions":N}` |

### Phishlets

| Method | Path | Body | Effect |
|---|---|---|---|
| GET | `/phishlets` | — | `[{"name","enabled","hidden"},…]` |
| POST | `/phishlets/{name}/enable` | — | hot-enable (no restart) |
| POST | `/phishlets/{name}/disable` | — | hot-disable |
| POST | `/phishlets/reload` | — | re-read YAMLs from disk |
| POST | `/phishlets/{name}/hostname` | `{"hostname":"…"}` | change base hostname |

### Lures

| Method | Path | Body | Effect |
|---|---|---|---|
| GET | `/lures` | — | `[{id,phishlet,path,hostname,redirect_url,token,relay,paused},…]` |
| POST | `/lures` | `{"phishlet"(req),"path","redirect_url","token","relay":bool}` | create; `token:"auto"` → 16-char random; empty path → `/`+8 random chars; `relay:true` serves the [Google relay](google-relay.md) page at the lure path |
| GET | `/lures/{id}/url` | query: AES params (`rid`, `email`, …) | `{"url":"…"}` — **the gate token is NOT appended**; read it from the lure record and append `?t=<token>` |
| GET/PUT | `/lures/{id}` | PUT partial: `hostname,path,redirect_url,ua_filter,info,og_title,og_desc,og_image,og_url,redirector,phishlet` | lure JSON |
| DELETE | `/lures/{id}` | — | `{"deleted":"<id>"}` |

### Sessions

| Method | Path | Effect |
|---|---|---|
| GET | `/sessions` | list captured sessions |
| GET | `/sessions/{id}` | full detail: captured credentials + `tokens` = per-domain cookie sets |
| DELETE | `/sessions/{id}` | `{"deleted":"<id>"}` |

### Upstream proxy

| Method | Path | Body |
|---|---|---|
| GET | `/proxy` | — (password masked) |
| POST | `/proxy` | partial update, **pointer fields** — `{"enabled","type","address","port","username","password","routes":[…],"tlsfp"}`; omitted keys keep their values. Echoing a masked password **clobbers** it — omit the field or send the real value |

Semantics: [proxy](proxy.md).

### Puppet (evilpuppet)

| Method | Path | Body | Effect |
|---|---|---|---|
| POST | `/pp/cookies` | `{"session_token","phishlet","cookies":[{name,value,path,domain,http_only}]}` | import sidecar-collected cookies into the live session + mark botguard-verified |

## Error shapes

Non-2xx responses are JSON `{"error":"…"}`:

- TLS handshake failure — missing/invalid client cert (there is no 401; the cert *is* the auth).
- 404 — wrong base path (the endpoint doesn't exist as far as the node is concerned) or unknown resource.
- 400 — malformed JSON / invalid field values.

## Security notes

- Client key never leaves the operator machine; `my-servers.json` references it by path
  (both are gitignored).
- The base path is a capability — treat it like a secret; it appears in node boot logs
  and `<cfgdir>/api/config.json`.
- Rotate client certs by regenerating on the node (`<cfgdir>/api/`) and redeploying to
  console/MCP configs.
- For AI-agent operation prefer the [MCP server](mcp.md) — it wraps this API with
  guardrails (token reminders, masked-password warnings, sanitized cookie export).
