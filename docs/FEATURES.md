---
layout: default
title: Feature matrix
description: Parity matrix vs Evilginx Pro + verification evidence.
---

# Feature matrix — RedPhish vs Evilginx Pro

**Base:** evilginx2 CE 3.3.0 (GPL-3.0) + clean-room extensions in `src/`.
**Sourcing rule:** public BreakDev feature descriptions + CE code only. The Pro
binary leaked into the workspace is NOT used as a decompile/extraction source.
**Target environment:** closed internal networks, zero internet egress (see
[OFFLINE_OPS](OFFLINE_OPS.html)).

## Fork status snapshot (historical v0.1–v0.5 layout)

- Original repo chain: `v0.1` (`8ab9a36`) → `v0.2` (`d6e37f4`, #10) → `v0.3`
  (`86f811c`, #14) → `v0.4` (`b154b89`, #9) → `v0.5` (`3df6cd7`, #12)
  (the living tree is now this repository's `src/` — see
  [Architecture](architecture.html))
- Added files: `core/lurecrypto.go` (#11), `core/apid.go` (#2),
  `core/botguard.go` (#4), `core/rewrite.go` (#10), `core/jsobf.go` (#9),
  `core/webhook.go` (#12), `database/database.go` (SQLite, #14)
- Modified: `core/config.go`, `core/terminal.go`, `core/http_proxy.go`,
  `main.go`
- Patch tooling kept under `tools/patches/` (HISTORICAL — see its README)

## The 14-feature matrix

| # | Pro feature | Status | Details / evidence |
|---|---------------|-----------|----------------------|
| 1 | Client-Server (many servers from one client) | 🟡 PARTIAL | API (#2) for remote session/status reads; a full fleet daemon: pending |
| 2 | Evilginx API (HTTPS + client cert + stealth) | ✅ DONE | `-api <port>`; mTLS RequireAndVerifyClientCert; random stealth path persisted (`~/.evilginx/api/`); measured: /status ok, /sessions full JSON, no-cert → `tlsv13 alert certificate required`, wrong path → 404 |
| 3 | Wildcard TLS (avoid CT logs) | 🟢 OFFLINE-ALT | The goal (no per-host CT exposure) is met with internal certs: `-developer` self-signed or internal-CA certs in `~/.evilginx/crt/sites/<host>/`; internet-facing nodes use wildcard DNS-01 (`deploy/wildcard-cert-setup.sh`) |
| 4 | Botguard (JA4 + JS telemetry, decoy content) | ✅ DONE (v1 + v2) | `-botguard`; ClientHello GREASE parsing (peekConn before vhost SNI) + UA blocklist + header heuristics (Accept-Language/Sec-Fetch/Upgrade-Insecure) → decoy page; v2 adds JA4 TLS allowlist (`ja4.go`). Measured: curl UA → block; fake-UA → score=100; full browser headers → score=60; real Chromium passes |
| 5 | Evilpuppet (background Chromium telemetry) | 🟡 UNBLOCKED-DEFERRED | Headless Chromium runs on the Ubuntu node (past the Kali VM blocker); clean-room chromedp sidecar design: [EVILPUPPET](EVILPUPPET.html); deploy when a campaign needs telemetry-based-detection resistance |
| 6 | Community phishlet DB | 🟢 OFFLINE-ALT | Not downloadable offline; the internal phishlet authoring process is standardized (`tools/make_phishlet.py` + examples) |
| 7 | External DNS provider management (CF/Route53/Gandi) | ⛔ N/A OFFLINE | Air-gapped labs use hosts/internal DNS — feature meaningless there; internet-facing nodes script DNS via `deploy/wildcard-cert-setup.sh` |
| 8 | Multi-domain (one domain per phishlet) | ✅ DONE | Suffix-lock removed from `SetSiteHostname`; cookies tracked per `GetPhishletCookieDomain`. Measured: two phishlets on two domains enabled simultaneously, full victim flow on domain 2 (200/302/200), cookie jar `.domain2.test`, complete token capture |
| 9 | JS Obfuscation (off→ultra) | ✅ DONE (v2) | v1 high/ultra + **v2 ultra string-array**: b64 chunked + reversed inside a random array + accessor rotation + join loop → atob+eval. Measured: 3 fetches = 3 different hashes; ultra probe executes in real Chromium 152 (round-trip marker through the decoder) |
| 10 | rewrite_urls (Safe Browsing evasion) | ✅ DONE (v2 path+query) | `rewrite_urls: [{from, to, query_map, drop}]`. Measured inbound: origin receives `GET /login?email=x%40y.z` (u→email, src dropped); outbound: victim sees `Location: /secure-verify?done=1&u=labuser`. Credentials+tokens captured through the fake path |
| 11 | Custom URL parameter encryption (AES-256) | ✅ DONE | AES-256-GCM, server-side persisted key (`lure_secret`), nonce‖ct b64url; measured: URL carries only the blob, legacy RC4 decode fails, server decrypts `victim=`, `camp=` into session.Params |
| 12 | Deep Gophish integration | ✅ DONE (webhook) | `-webhook <internal URL>`: JSON POST on every completed auth — event/phishlet/session/username/password/**password_sha256**/custom/params/cookie_tokens/remote_addr/useragent. Measured: receiver gets everything, sha256 matches, cookies=true; server-side push (victim never calls out). Basic CE integration (admin_url/api_key/rid) unchanged |
| 13 | Automated server deployment | 🟢 ONLINE | Offline it was N/A; internet nodes deploy via `deploy/setup_evilginx.sh` + `deploy/sync-node.sh` (one-command source updates) |
| 14 | SQLite storage | ✅ DONE | buntDB → `modernc.org/sqlite` (pure-Go, WAL, single-writer); exported API unchanged (console + REST); measured: `file data.db` = SQLite 3.x, sessions survive restarts |

## Later additions (beyond the original 14)

- **#15 Lure token-gate** — benign redirect for tokenless requests (Safe
  Browsing never sees the login page)
- **#16 CSD hardening** — Chrome client-side detection bypass, field-verified
- **#17 Upstream proxy + per-target routing** — residential egress for Google,
  direct for ms365
- **#18 Google real-browser relay** — defeats origin-bound botguard; captures
  verified end-to-end incl. Gmail replay
- **MCP server + agent skills** — full AI-agent operation incl. opening captured
  sessions in a real browser

## Quick verification (after any rebuild)

```bash
# AES lure params
printf 'lures get-url 0 k=v\nexit\n' | ./evilginx2 -p <phishlets> -developer
# mTLS API
curl --cacert ~/.evilginx/api/ca.crt --cert ~/.evilginx/api/client.crt \
     --key ~/.evilginx/api/client.key "https://127.0.0.1:<port>/api-<path>/sessions"
```
