---
layout: default
title: Evilpuppet
description: Sidecar browser telemetry design + status.
---

# Evilpuppet design — for evilginx2-extended (#5)

**Status:** UNBLOCKED (headless Chromium runs fine on the Ubuntu node; the Kali
VM still hangs) · **Implementation:** deferred — needs a dedicated work session.

## Goal (per public Pro descriptions)

A real browser running on the server produces **valid browser telemetry** so the
phishing session carries machine-learning fingerprints like a real victim —
defeating detection systems based on telemetry (device fingerprinting, handler
ordering, client hints…).

## Clean-room architecture (no reference to the Pro binary)

```
[evilginx2-extended]  <--internal HTTP-->  [puppet sidecar: chromedp]
        |                                        |
        |                          drives a real (headless) Chromium
        v
   real origin (receives the chromium's traffic + telemetry)
```

1. **Sidecar** `puppet/` (Go + chromedp): receives tasks over internal HTTP —
   `POST /visit {url, session_token, wait_ms}` — drives Chromium to the real
   login page **while the victim is being proxied**, so the telemetry (the
   Chromium's TLS JA3, HTTP/2 SETTINGS, handler ordering, client hints) reaches
   the origin under the same session.
2. **Session linkage:** evilginx2 embeds the `session_token` in the victim URL
   (the AES params mechanism, #11); the sidecar uses the same token → the origin
   sees two "users" on one session: the victim (through the proxy) and the
   puppet (a real browser).
3. **Cookie pre-warm:** the puppet logs in FIRST with an org bot account (when
   the campaign allows) or just warms static pages; valid cookies are exported
   back to evilginx2 through the internal `POST /pp/cookies` endpoint (mTLS,
   like the API).
4. **Safety note:** the puppet only runs against origins explicitly authorized
   in the campaign plan; all puppet traffic goes through the same zero-egress
   containment.

## Why deferred

- Needs chromedp + sub-deps (`go get` network install — the Ubuntu node has had
  stable internet since the DNS fix).
- Everything else is in place: headless Chromium verified on Ubuntu (LAB15),
  the fleet API can host the `/pp/` endpoint, jsobf can obfuscate the
  intermediate page.
- Estimate: one focused work session (sidecar + endpoint + e2e verification
  with both curl and chromium).

## When to build it

As soon as a campaign confirms it needs to beat telemetry-based detection
(Sentinel/Abnormal-class). If the target only has an email gateway + ordinary
MFA → #5 is not needed.
