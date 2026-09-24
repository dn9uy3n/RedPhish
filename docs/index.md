---
layout: default
title: Home
---

# RedPhish

**A full-featured reverse-proxy phishing framework for authorized red teams** — an extended
fork of [evilginx2 CE 3.3.0](https://github.com/kgretzky/evilginx2) (GPL-3.0), cleanly
re-implementing Evilginx Pro-class features for internal / air-gapped environments.

> ⚠️ **Authorized use only.** This tool is for education and red-team campaigns explicitly
> authorized by the system owner. Not affiliated with BreakDev/Evilginx Pro — no binaries or
> code from the commercial product are used. Upstream GPL-3.0 applies.

---

## Documentation map

| Document | Contents |
|---|---|
| [Architecture](architecture.md) | Request lifecycle, module map, deploy topology — the maintainer's map |
| [Getting started](getting-started.md) | Build, deploy to a VPS, DNS + wildcard cert, first lure — the shortest path to a working node |
| [Evasion](evasion.md) | Every integrated evasion technique by defense layer — token-gate, botguard, CSD, uTLS, relay, infra — all field-verified |
| [Operations guide](operations.md) | Day-2 operations: the `egconsole` command reference, phishlet switching, lure lifecycle, session & cookie export, mailbox reuse |
| [Phishlet authoring](phishlet-authoring.md) | Writing phishlets: structure, auth-token capture, sub-filters, multi-domain rules, CSD hardening, token-gate |
| [Google real-browser relay](google-relay.md) | The `bgrelay` sidecar that defeats origin-bound botguard: architecture, API, capture pipeline, session replay |
| [ClickFix gate](clickfix.md) | Fake-captcha social engineering — clipboard payload with before/after position, detection-hardened templates |
| [Upstream proxy](proxy.md) | Feature #17 — per-phishlet egress routing (residential exits, datacenter blocks) |
| [egconsole](egconsole.md) | The remote operator interface — full command reference, workflows, quirks |
| [mTLS API reference](api.md) | The hidden HTTPS API: phishlets, lures, sessions, proxy, relay |
| [Troubleshooting](troubleshooting.md) | Field-proven gotchas: botguard decoys, DNS wildcard rules, cookie import, zombie chromium, IP reputation |
| [Phishlet status & features](FEATURES.md) | The full Pro-parity feature matrix |
| [Blue-team IOC notes](BLUE_TEAM_IOC.md) | What defenders can detect — honest detection notes |

## Phishlet status

| Phishlet | Status | Notes |
|---|---|---|
| `ms365` | ✅ **production-ready** | Work flow (ESTSAUTHPERSISTENT) + consumer MSA (WLSSC) capture, mailbox reuse, token-gate, CSD hardening (Chrome Safe Browsing bypass verified), JA4 allowlist |
| `google` | ✅ **production-ready via real-browser relay** | Classic MITM is impossible (Google botguard is origin-bound); solved with the `bgrelay` sidecar — victims sign in on a mirrored real `accounts.google.com` session, credentials + `.google.com` cookies captured, **cookie replay into Gmail verified** |
| `github` | ✅ **production-ready** | **Real-account E2E verified** — password + GitHub-Mobile push 2FA through the MITM, tokens intercepted. Session cookie is host-only `__Host-user_session_same_site` (modern GitHub dropped domain-wide `user_session`); TOTP-entry capture in place |
| `gitlab` | ⚠️ unverified | Cloudflare Turnstile in front of the login (renders on the phishing host); fields `user[login]/user[password]/user[otp_attempt]` |
| `atlassian` | ⚠️ unverified | SPA proxied (`id-frontend…atl-paas.net`); JSON credentials `username`/`password`; AWS WAF SDK cross-origin not yet proxied |
| `zimbra` | ⚠️ unverified (template) | On-prem target — required `{domain}` param; classic `username`/`password`, token `ZM_AUTH_TOKEN`; instantiate per target |
| `yandex` | ⚠️ unverified | Landing `/auth/` currently bounces to 360.yandex.com; React login fields need re-checking with an account |
| `aws` | ⚠️ unverified | AWS WAF 403s datacenter IPs at `/signin`; fields `username`/`password`/`mfaCode` |
| `claude` | ✅ **verified E2E** | Login-code flow (email + 6-digit code, no password), JSON creds; `sessionKey` captured and replayed into a logged-in session; CF-protected — requires `proxy: true` + residential + `tlsfp: chrome` |
| `chatgpt` | ✅ **verified E2E** | Password + OTP captured as JSON; chunked session-token `.0/.1` replayed into the victim's logged-in ChatGPT; CF + auth-cdn CORS trap documented |
| `cloudflare` | ⚠️ unverified | Dashboard login behind the CF challenge; fields `email`/`password`, session `CF_Authorization` |
| `discord` | ⚠️ unverified | SPA proxied (login renders); JSON creds `login`/`password` + TOTP `code`; bearer token in localStorage — credentials capture only |
| `akamai` | ⚠️ unverified | Control Center auth renders through the proxy; session cookie set needs an account test |

## The one-paragraph architecture

```
Victim ──► evilginx2 :443 (reverse proxy, wildcard cert, botguard JA4 filter,
            lure token-gate) ──► upstream identity provider
            │
            ├─ ms365: transparent MITM — session cookies captured, replayed
            │
            └─ google: /__relay/* + relay-lure ──► bgrelay sidecar :9445
                 (patchright headful Chromium under Xvfb, real accounts.google.com
                 via residential SOCKS exit) ──► mirror stream + input/click relay
                 ──► capture {email, password, cookies} to bgrelay-store/
```

## Repository layout

```
src/                 Go source (fork core + API + botguard + relay routes)
src/phishlets/       campaign phishlets — GITIGNORED by design, never published
deploy/              deploy scripts, systemd templates, wildcard cert script
tools/               egconsole.py (operator console), relay/ (bgrelay sidecar),
                     kit generators, offline deploy tooling
docs/                this documentation (also the GitHub Pages site)
```

## Links

- Source: [github.com/dn9uy3n/RedPhish](https://github.com/dn9uy3n/RedPhish)
- Vietnamese README: [README.vi.md](https://github.com/dn9uy3n/RedPhish/blob/main/README.vi.md)
