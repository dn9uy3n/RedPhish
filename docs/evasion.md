---
layout: default
title: Evasion
---

# Evasion techniques (integrated & field-verified)

Every technique below is implemented in this fork and has been verified in the
field (not theory). They are organized by the defense layer they defeat — think
in layers: a scanner, a browser, the identity provider and the blue team each
see a different, benign story.

| Defense layer | What they see | Techniques |
|---|---|---|
| Scanners / crawlers / link previews | a boring "It works!" page or a benign redirect | [Lure token-gate](#1-lure-token-gate), [Botguard decoy](#2-botguard-anti-bot) |
| TLS inspection (corporate SWG) | a Chrome-shaped TLS session | [JA4 allowlist](#2-botguard-anti-bot), [uTLS fingerprint](#3-utls-chrome-fingerprint) |
| Chrome client-side phishing detection (CSPD) | a page with no password field and no brand until you interact | [CSD hardening](#4-csd-hardening-client-side-detection) |
| Provider anti-bot (Google botguard) | a genuine Chromium on the genuine origin | [Real-browser relay](#5-real-browser-relay-origin-bound-botguard) |
| Network/infra observers | a wildcard cert, no per-host CT noise, unremarkable egress | [Wildcard certs](#6-infrastructure-visibility), [residential routing](#7-upstream-egress-routing) |
| Anyone reading lure URLs | opaque AES blobs | [AES lure params](#8-aes-lure-params), [JS obfuscation](#9-js-obfuscation) |
| Security products scanning the clickfix gate | a blank page with a spinner — no keywords, no payload, no brand | [ClickFix hardening](#10-clickfix-gate-hardening) |

---

## 1. Lure token-gate

**Defeats:** Safe Browsing classification, crawlers, chat link previews, URL
scanners — anything that arrives without the token.

Lures carry a secret `?t=<token>` (created as `"auto"` via the API). A request
missing it gets a 302 to a benign `redirect_url` (product marketing page). The
login page is **never rendered** to a classifier, which extends domain life
dramatically. The gate marker also survives reverse-redirect rewriting
(`X-Eg-Gate`).

- Where: `src/core/http_proxy.go` (lure-hit branch), Lure.Token in `config.go`
- Ops: [operations — lures](operations#lures); pause/resume via
  `PUT /lures/{id} {"paused": <unix>}`
- Doctrine: never reuse tokens across campaigns; tokens are campaign secrets.

## 2. Botguard (anti-bot)

**Defeats:** scripted clients (curl/python), scanners, bulk URL fetchers —
including the Palo Alto / Umbrella URL-filtering crawlers that auto-fetch every
link users click.

Layered scoring on every request: **JA4 TLS fingerprint allowlist** (+ UA
heuristics + TLS GREASE + JS telemetry endpoint), trusted CIDRs skip scoring.
Any non-browser gets the 141-byte decoy ("It works! This page is intentionally
boring.") — a *benign* classification that actually **helps** the domain look
dead-boring to security appliances.

- Where: `src/core/botguard.go`, `ja4.go`; flags `-botguard -bg-ja4 <prefixes>
  -bg-trusted <cidrs>`
- **Corporate TLS-inspection (field-proven)**: an SWG (Umbrella, Palo Alto)
  re-terminates TLS, so the node sees the *appliance's* JA4, not Chrome's. Each
  inspection profile yields a distinct but stable variant
  (`t13d1311c009130100` vs `t13d1310c009130100` — one digit apart). Two ways to
  allowlist a variant: the node-level `-bg-ja4` flag (applies to every phishlet,
  needs a unit edit + restart) or the per-phishlet `bg_ja4_allow` list in the
  phishlet YAML (OR-merged, hot-reload applies immediately). Read the variant
  from `journalctl` (`JA4 not in allowlist`).
- Self-testing rule: render-tests go through trusted loopback
  (`--resolve host:443:127.0.0.1`) — your curl will otherwise eat the decoy and
  you'll think the phishlet is broken.

## 3. uTLS Chrome fingerprint

**Defeats:** upstream TLS fingerprinting by the origin (JA3S-side heuristics,
datacenter-TLS blocklists).

Upstream fetches are dialed with a **uTLS Chrome ClientHello** (HelloChrome_106
shuffle family) so the identity provider sees a Chrome-shaped TLS handshake
even though the proxy is Go. Implemented in `applyTransport()`
(`src/core/transport.go`) with an ALPN-overridden custom preset.

- Gotcha for maintainers: the vendored uTLS needs `IdToSpec` exported to clone
  and override ALPN (see `tools/patches/` history); ALPN is not part of JA3 but
  is part of JA4 — h1 was chosen deliberately.

## 4. CSD hardening (client-side detection)

**Defeats:** Chrome's on-device phishing classifier (CSPD) — the "Dangerous
site" interstitial triggered by *client-side* analysis, independent of Safe
Browsing blocklists.

Two `js_inject` layers, both **field-verified** (SB-enabled Chrome, full login
flow, no flag):

1. **Password DOM disguise** — `input[type=password]` is swapped to
   `type=text` + `-webkit-text-security:disc`, held in place by a
   MutationObserver; submit value unchanged. The DOM literally contains no
   password field to classify.
2. **Brand lazy-reveal** — logo/brand assets are hidden behind a style class at
   load and restored on the first real gesture (`pointermove`/`keydown`/
   `touchstart`). The visual model has nothing to classify before interaction.

- Where: phishlet `js_inject` blocks (see ms365/google phishlets as reference;
  snippets in [phishlet authoring](phishlet-authoring#csd-hardening))
- Residual risk: interaction-time flagging is possible — plan
  capture-before-flag and burn-and-rotate by waves; never rotate hosts
  mid-victim (cookies are host-scoped).
- Detection checks run on **burner** domains, never the campaign one.

## 5. Real-browser relay (origin-bound botguard)

**Defeats:** Google's origin-bound botguard — which no MITM, proxy, IP or TLS
trick can pass (verified exhaustively: datacenter/hosting/residential exits ×
Go/Chrome TLS stacks; headless browsers are blocked even without MITM).

The Google phishlet doesn't MITM at all: victims interact with a pixel-faithful
mirror of a **real sign-in session running in a real (patchright) Chromium on
the genuine `accounts.google.com` origin**, through a residential exit. Every
keystroke and click is relayed into that browser. Botguard always sees exactly
what it wants to see.

- Where: `tools/relay/` + `src/core/relay.go`; full guide:
  [Google relay](google-relay.md)
- The relay page itself carries the CSD password disguise on its overlay input.

## 6. Infrastructure visibility

**Defeats:** passive infrastructure analysis, CT-log monitoring, port scanning
of the management plane.

- **Wildcard certificates via DNS-01** (`deploy/wildcard-cert-setup.sh`): one
  `*.base` cert per base domain — no per-hostname CT-log entries, no
  reconnaissance value; installed in `crt/sites/<name>/` (never overwrite
  another base's dir). Offline alternative: internal CA
  (`tools/mint_internal_cert.sh`, zero egress, zero CT).
- **Hidden management API** (`src/core/apid.go`): mTLS + a random stealth base
  path (`/api-<12 chars>`) — port scanners find nothing listening where they
  expect; auth *is* the client certificate.
- DNS records stay **DNS-only** (no CDN proxying — that would break MITM TLS
  and leak client IPs).

## 7. Upstream egress routing

**Defeats:** IP-reputation blocklists at the provider (datacenter ASN
blocklists) — and avoids *creating* suspicion (Entra flags residential logins
on work accounts).

Per-domain-suffix egress routing (feature #17): `google.com,gstatic.com,…` →
residential SOCKS5 exit; everything else (ms365) → node IP direct. Hot-applied
via console/API. See [proxy](proxy.md).

- Doctrine: Google → residential; MS365 work accounts → direct.
- Self-test discipline: **render-only** against Google (fake submits burn the
  exit's reputation for 30–60 min).

## 8. AES lure params

**Defeats:** URL analysis — tracking params in lure URLs are AES-256-GCM
encrypted with a **server-side key** (no key material in the URL, unlike
upstream's RC4-key-in-URL scheme).

- Where: `src/core/lurecrypto.go`, used by `params.go`.

## 9. JS obfuscation

**Defeats:** static analysis of injected JavaScript.

`-jsobf off/low/medium/high` — string-array + rotation, a new variant per
response. **Never `ultra`** (field-verified to break Microsoft login JS).

- Where: `src/core/jsobf.go`, `bodytools.go`.

---

## 10. ClickFix gate hardening

**Defeats:** content-based phishing/SE classification of the fake-captcha
gate (Safe Browsing page analysis, sandbox detonation, DLP content rules).

The clickfix templates follow the same CSD doctrine as the credential
phishing pages:

1. **Zero sensitive content at load** — instruction text, brand elements
   and the clipboard payload are all absent from the initial DOM. The
   page shows only a spinner. Content classifiers have nothing to match.
2. **Base64-encoded payload** — the command is never cleartext in the
   source; decoded at runtime via `atob()`.
3. **Lazy text injection** — all SE keywords ("Win+R", "Ctrl+V") are
   base64 strings in the source, decoded and injected into the DOM only
   when the state machine advances after a user gesture.
4. **Brand lazy-reveal** — logo and domain hidden until the first
   pointermove/keydown (same as ms365 CSD v2).
5. **Randomized fingerprint** — no byte-identical page across loads.
6. **Generic title + inline SVG favicon + noindex** — no brand
   impersonation in metadata; `Cache-Control: no-store`.

- Where: `clickfix/templates/*.html` (gitignored) + `src/core/clickfix.go`
- See [phishlet authoring — ClickFix](phishlet-authoring#clickfix-gate-fake-captcha--clipboard-payload)

## Detection hygiene (operational doctrine)

These are the *operational* evasions — they matter as much as the code:

- **Capture-before-flag**: assume the password host can get flagged after N
  interactions; the session is usually captured long before.
- **Burn-and-rotate by waves**: rotate hosts/lures between campaign waves;
  never mid-victim.
- **Burner domains** for any detection check; the operator's own browser is
  itself a sensor (client-side flagging is per-browser).
- **Render-only self-tests** through the relay (IP reputation is the scarce
  resource).
- **Decoy = feature**: the "It works!" page is deliberately boring so security
  appliances classify the domain as dead — park lures (`paused`) between waves
  and the site stays boring and stable.
