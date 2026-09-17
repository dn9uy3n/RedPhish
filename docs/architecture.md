---
layout: default
title: Architecture
---

# Architecture

How a request flows through the platform, and where each module lives. Written for
the maintainer changing one feature or one step of the flow — file names are the
map.

## The request lifecycle (reverse proxy, `:443`)

```
victim request (SNI = <phish_sub>.<base>)
  │
  ├─ botguard.go        JA4/UA check → non-browser gets the 141B decoy "It works!"
  │                     (trusted CIDRs skip scoring; telemetry endpoint /t/<token>)
  ├─ relay.go           path starts /__relay/*  → reverse-proxy to bgrelay :9445
  ├─ blacklist.go       IP blacklist
  ├─ http_proxy.go      host → phishlet resolution, session cookie → Session
  │   ├─ terminal_lures/
  │   │  pause flag     paused lure → block.go (benign redirect)
  │   ├─ UA filter      lure's ua_filter regex
  │   ├─ token-gate     missing/wrong ?t= → blockRedirect to redirect_url
  │   ├─ relay lure     Lure.Relay → relay.go relayPage (victim page at lure path)
  │   └─ params.go      extractParams (AES-GCM lurecrypto.go + legacy RC4)
  ├─ bodytools.go       js_inject, lure-param/URL patching (jsobf.go variants)
  ├─ hosts.go           phished↔original host mapping, session hosts
  └─ transport.go       upstream fetch: proxy routes (setProxy/applyTransport,
                        uTLS Chrome fingerprint), httpsWorker per-host certs
        │
        ▼ response
  ├─ http_proxy.go      cookie rewrite + capture → database (SQLite)
  │                     all-tokens complete → Finish + webhook.go + gophish.go
  └─ block.go           tracker image / intercepts / redirects
```

## Module map (`src/`)

| File | Role | Origin |
|---|---|---|
| `main.go` | flags + startup order (config → db → phishlets → proxy → terminal → API) | fork flags |
| `core/http_proxy.go` | HttpProxy struct + the two goproxy closures (request/response) | upstream + fork |
| `core/{relay,block,params,bodytools,hosts,transport}.go` | topical extractions of http_proxy.go (behavior-neutral split) | fork split |
| `core/terminal.go` + `terminal_lures.go` | operator REPL (config/phishlets/sessions/lures) | upstream + fork |
| `core/botguard.go`, `ja4.go` | anti-bot: JA4 allowlist, UA/GREASE heuristics, decoy | fork |
| `core/lurecrypto.go` | AES-256-GCM lure params (server-side key) | fork |
| `core/apid.go` | hidden mTLS REST API (stealth base path, client certs) | fork |
| `core/hotreload.go` | phishlet hot-reload + cert refresh gating | fork |
| `core/config.go` | config + lure CRUD + proxy routes + sub-phishlet registry | upstream + fork |
| `core/phishlet.go`, `rewrite.go` | phishlet YAML loading + rewrite_urls | upstream + fork |
| `core/jsobf.go`, `webhook.go`, `gophish.go` | obfuscation / credential webhook | fork/jsobf |
| `core/certdb.go` | certmagic wrapper, `crt/sites/*` unmanaged certs | upstream + fork |
| `database/database.go` | SQLite storage (pure-Go) | fork |
| `puppet/main.go` | evilpuppet sidecar (chromedp telemetry) | fork |

## The Google relay sidecar (`tools/relay/`)

```
victim page (relay.go serves it AT the lure path)
  └─ XHR /__relay/api/* ──► bgrelay.py :9445 (loopback)
        ├─ patchright Chromium, headful Xvfb, per-session
        ├─ HTTP→SOCKS bridge :8119 → residential exit (RELAY_SOCKS env, secret)
        ├─ mirror stream: 2x screenshots + DOM geometry (input/button/label)
        └─ capture on done → ~/bgrelay-store/<sid>.json
             operator: egconsole `open` / MCP open_session / relay_open_session
```

## Operator tooling (`tools/`)

| Path | Role |
|---|---|
| `lib/egapi.py` | the ONE mTLS API client + node list (my-servers.json) |
| `lib/cookies.py` | cookie extraction / playwright conversion / Cookie-Editor export |
| `lib/session_launcher.py` | open a real browser signed-in with a captured session |
| `egconsole.py` | operator REPL (uses lib/) |
| `egctl.py` | one-shot fleet CLI (uses lib/) |
| `mcp/egmcp.py` | MCP server for AI agents (uses lib/) |
| `relay/` | bgrelay sidecar + victim page |
| `patches/` | HISTORICAL fork-derivation patches — frozen, src/ is the truth |
| `lab/`, `make_phishlet.py`, `make_dns_zone.py`, `mint_internal_cert.sh` | authoring/lab kit |

## Deploy topology

- Node (`deploy/`): `evilginx2.service` (:443 proxy, :9443 mTLS API) +
  `bgrelay.service` (:9445 loopback). Certs: LE wildcard via
  `wildcard-cert-setup.sh` (DNS-01) or internal CA via `mint_internal_cert.sh`,
  installed under `~/.evilginx/crt/sites/` (one dir per cert — never overwrite).
- Operator workstation: client certs + `my-servers.json` (gitignored),
  egconsole/MCP, SSH tunnel for relay access.
- Change flow: edit `src/` → `deploy/sync-node.sh` (sync, build, restart,
  heartbeat) → verify via egconsole/MCP.
