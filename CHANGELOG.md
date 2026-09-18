# Changelog — fake-evilginx-pro (evilginx2-extended line)

Forked from [evilginx2 CE 3.3.0](https://github.com/kgretzky/evilginx2) (upstream
commit `4c0988a`). Every extension is clean-room (no reference to commercial
binaries) and verified end-to-end on the two-node lab (Kali + Ubuntu).

## v0.11 (2026-09-17) — restructure for maintainability

- **Go**: `http_proxy.go` (2327 lines) split into topical files in the same package —
  behavior-neutral moves only: `relay.go`, `block.go`, `params.go`, `bodytools.go`,
  `hosts.go`, `transport.go`; `terminal.go` → + `terminal_lures.go`. gofmt applied;
  build + lure behavior verified on the node after the split.
- **Python**: new `tools/lib/` — ONE mTLS client (`egapi.py`), ONE cookie toolkit
  (`cookies.py`), moved+deduped `session_launcher.py`. egconsole/egctl/egmcp rewired
  to the lib; the four divergent client copies and two divergent cookie converters
  are gone.
- **Secrets**: bgrelay no longer defaults RELAY_SOCKS to a hard-coded proxy URL —
  env required, fail-fast if missing. deploy/README sanitized (no live lure paths).
  History squashed to purge previously committed credentials.
- **Ops**: `deploy/sync-node.sh` — one-command sync/build/restart/smoke.
- **Docs**: new `docs/architecture.md` (request lifecycle + module map).
- `tools/patches/` marked HISTORICAL/frozen — `src/` is the source of truth.
- `servers.example.json` fixed to the bare-array format the loaders expect.

## v0.10 (2026-09-08)

- **Phishlet hot-reload**: `phishlets reload` (console), `POST /phishlets/reload`
  (API), directory auto-watch via the bundled fsnotify (`-no-watch` to disable) —
  add/edit/remove YAML without restarting the node (verified live: drop/touch/rm
  → watch +N ~N -N).
- **Config mutex**: locks every mutator (deadlock-safe via savePhishletsNL) —
  fixes the console-vs-API race found during review.
- **JA4 for Botguard**: `core/ja4.go` (FoxIO spec, parsed from the peeked
  ClientHello) + unit tests with REAL ClientHello vectors (chromium/curl/go from
  lab captures); `-bg-ja4 <prefixes>` allowlist (+50 points when outside the
  list); eviction for the botguard maps (previously unbounded growth). Live:
  curl with a full fake UA still gets the decoy (score=110), chromium passes.
- **Lure writer-API**: `GET /lures` (list), `GET/PUT/DELETE /lures/{id}` (full
  field edit + the same validation as the terminal); the id is an index
  (deleting renumbers); egctl gains
  `lures-list/lure-edit/lure-del/hostname/reload-phishlets`.
- **API hostname**: `POST /phishlets/{name}/hostname` — a fleet gap discovered
  during verification (console one-shots were invisible to the server process).

## v0.10.1 (2026-09-08)

- **Detonator-aware Botguard** (Microsoft Safe Links / Defender classification):
  referer patterns (`*.protection.outlook.com`, safelinks, smartscreen) + optional
  client CIDR ranges (`-bg-det-cidrs`); flagged sessions are pinned to the decoy,
  telemetry refused, `/status` exposes a `detonators` counter.
  Verified: a safelinks-referer request → `DETONATOR classified` + decoy;
  counter = 1. Real Chromium still passes (no safelinks referer).

## v0.9.1 (2026-09-08)

- **#5 evilpuppet-lite (code ships)**: `puppet/` sidecar (chromedp) — headless
  login through the proxy, cookie extraction, mTLS push back to the API; new
  endpoint `POST /pp/cookies` merges cookies into the live session + marks it
  botguard-verified. E2e pending: a chromium DNS quirk with /etc/hosts-only
  names (planned fix: an internal dnsmasq zone). See `docs/EVILPUPPET.md`.
- New tools: `deploy_offline.sh` (#13 offline — SSH deploy + systemd),
  `make_dns_zone.py` (#7 offline — dnsmasq zone).

## v0.9 (2026-09-08)

- **#6 authoring kit**: `make_phishlet.py` (generator + lint) + redirector
  templates (`interstitial`, `download`) in `src/redirectors/`.
- **#5 UNBLOCKED**: headless Chromium runs on the Ubuntu node (past the Kali VM
  blocker); the sidecar design is complete.
- **Final egress audit** (full flags): server-only **0 packets** — the 292
  measured packets were 100% from the Chromium snap phoning home (the simulated
  browser, not the framework).
- CE limitation found: **no phishlet hot-reload** — adding a phishlet required a
  node restart (unlike Pro). Fixed in v0.10.

## v0.8 (2026-09-08)

- **#9 v2 ultra obfuscator**: string-array (reversed chunks + rotating accessor
  + join loop → atob+eval) — a different structure on every response.
- **#10 v2 query rewrite**: `query_map` (renames victim→origin params) + `drop`
  (removes params) — bidirectional; outbound Location remaps the query too.

## v0.7 (2026-09-08)

- **#4 Botguard v2 (JS telemetry)**: a self-injecting, ultra-obfuscated JS probe;
  endpoint `/t/<HMAC-SHA256(lureKey, sid)>`; grace gating (`-bg-grace`); after
  the grace period, unverified sessions get the decoy when touching credentials;
  `-bg-ua=false` disables just the UA layer (for headless runtimes). Verified
  with real Chromium 152.

## v0.6 (2026-09-08)

- **#1 fleet**: REST API write-actions — `GET /phishlets`, `POST
  /phishlets/{name}/enable|disable`, `POST /lures`, `GET /lures/{id}/url` (AES),
  `DELETE /sessions/{id}`; `BuildLureUrl` shared by terminal + API; the
  `egctl.py` client drives multiple servers from a workstation.
- **#12 v2**: the webhook payload gains a top-level `rid` (campaign tracking via
  the AES lure params).
- **#3 offline**: `mint_internal_cert.sh` — internal CA; verified valid chain +
  zero egress when running without `-developer` and with `autocert off`.

## v0.5 (2026-09-08)

- **#12 webhook**: `-webhook URL` — one JSON POST per session on auth-complete:
  event/phishlet/session/username/password/**password_sha256**/custom/params/
  cookie_tokens/remote_addr/useragent.

## v0.4 (2026-09-08)

- **#9 JS obfuscation v1**: `-jsobf off/low/medium/high/ultra`; the `/s/<sid>/<jsid>.js`
  choke point; 3 fetches of the same URL = 3 different hashes.

## v0.3 (2026-09-08)

- **#14 SQLite**: replaced all of buntDB with modernc.org/sqlite (pure-Go, WAL);
  the exported API is unchanged; persistence across restarts.

## v0.2 (2026-09-08)

- **#10 rewrite_urls v1**: bidirectional path rewriting — the victim never sees
  the origin's real paths.

## v0.1 (2026-09-08)

- **#11 AES-256-GCM lure params**: replaces CE's RC4-key-in-the-URL with a
  server-side persisted key (`general.lure_secret`); RC4 fallback for old URLs.
- **#2 mTLS REST API**: dedicated listener, self-generated client certs, a
  random persisted stealth base path (`/status`, `/sessions`, `/sessions/{id}`).
- **#8 multi-domain**: removed the SetSiteHostname suffix-lock; tracking cookies
  follow the phishlet's own domain (`GetPhishletCookieDomain`).
- **#4 Botguard v1**: ClientHello GREASE parsing (peekConn before vhost SNI) +
  UA blocklist + header heuristics → decoy page.

## Base

- upstream evilginx2 CE 3.3.0 (`4c0988a`) — GPL-3.0, Kuba Gretzky.
