---
layout: default
title: Blue-team IOC
description: Defender's view — IOCs of this technology class.
---

# Blue-Team IOC Checklist — Reverse-Proxy Phishing (evilginx2)

**Source:** direct observation from an evilginx2 CE 3.3.0 lab on Kali (see the
lab setup notes; evidence in the lab `.reports/`) + reading the source
(`core/`). Applies to evilginx2 OSS and the whole class of frameworks (Evilginx
Pro, EvilProxy, EvilNoVNC…).

The mechanism to detect: the attacker runs a reverse proxy pointed at the real
login page, keeps the session alive through the proxy, and captures the
password **and** the session cookies → defeats SMS/TOTP MFA. The victim never
talks to the real origin directly.

---

## A. Before the attack — domain & certificates

| # | Control | Details |
|---|-----------|----------|
| A1 | CT-log monitoring by brand keyword | Stream new certs (crt.sh / CertStream); alert when SAN/CN contains your brand, product or SSO domain. Plain evilginx2 uses per-hostname Let's Encrypt certs (`*.attacker-domain`) — new certs appear right before a campaign. (This fork defaults to wildcard DNS-01 certs, which *reduces* this signal — see [Evasion](evasion.html).) |
| A2 | Lookalike domain sweep | Periodic `dnstwist` against the primary domain (homoglyphs, alternate TLDs, `-login`/`-sso`/`-auth` prefixes). |
| A3 | Registrar/whois monitoring | Domains registered < 30 days + MX pointing at disposable-email services (brand mutations). |

## B. When detonating a suspicious link (mail gateway / sandbox)

| # | Indicator (from the lab) | Detection logic |
|---|--------------------|-----------------|
| B1 | 302 chain right at landing | Lure URL → immediate `302` to a proxied login path (lab: `/npKorgAP` → 302 `/login`). Legitimate proxies rarely hard-302 on the very first request. |
| B2 | Odd tracking cookie set on landing | evilginx2 sets a cookie named with **8 random chars** (observed: `bdaf-1cf9`; source: `GenRandomString(8)`), value **64 hex**, `Domain=<base>`, `Path=/`, absent on the real origin. Pattern: `^[0-9a-z]{4}-[0-9a-z]{4}$` + `^[0-9a-f]{64}$`. |
| B3 | HTTP/1.1 only | The evilginx2 listener declares `NextProtos: ["http/1.1", acme-tls/1]` — **no h2**. Real origins (Google/Microsoft…) are always h2. Have the sandbox compare the phishing page's protocol with the real one. |
| B4 | Anomalous TLS certificate | Lab dev-mode: self-signed / odd CA → browser warning. Real campaigns: a valid LE cert for a never-seen domain (correlate with A1). |
| B5 | HTML differs from an origin snapshot | `sub_filters` change text/title (lab: "LAB ORIGIN" → "PRODUCTION CLONE"); `auto_filter` rewrites every origin URL to the phish domain. Fuzzy-hash (tlsh/ssdeep) the login page against the official one. |
| B6 | Injected MFA-harvesting JS | Phishlet `js_inject` inserts `<script>` blocks that don't exist on the origin — typically waiting for OTP/2FA codes. DOM-diff or a CSP report-uri will surface the foreign script. |

## C. On the origin / CDN / WAF (view from the spoofed side)

| # | Indicator | Detection logic |
|---|----------|-----------------|
| C1 | **TLS fingerprint ≠ UA** (the strongest lab IOC — measured, see notes) | evilginx2 fetches the origin with a Go `http.Transport` — the UA is passed through from the victim (the lab saw `curl/8.20.0` arrive intact) but the TLS stack is a server-side library, not Chrome/Firefox. "Browser UA + non-browser TLS fingerprint" = reverse proxy / scripted client with near-certainty. (This fork dials upstream with a uTLS Chrome ClientHello — see [Evasion](evasion.html) — which specifically defeats this rule; the no-GREASE family rule below still applies to vanilla Go stacks.) |
| C2 | Random lure path | Before `/login`, traffic always passes a random `[A-Za-z]{8}` path (lab: `/npKorgAP`) — pattern-scan access logs. |
| C3 | One session, two locations | Session cookies captured → attacker uses them in parallel with the victim: geo-impossible travel, UA changing between requests, hosting/datacenter ASN interleaved with the user's home network. |
| C4 | Odd referrer into the login page | Login-page entries referred from domains outside the official ecosystem — low volume but consistently targeted users. |

**C1 — real lab measurements (tshark 4.6.6, loopback, time-controlled):**

```
evilginx2 upstream (Go http.Transport via goproxy)  JA3_MD5 = 6fcb7aa10768c08e39459bf9b7478ab4
  → 14 cipher suites (c02b,c02f,c02c,c030,cca9,cca8,c009,c013,c00a,c014,c012,1301,1302,1303)
  → NO ALPN (Go disables auto-h2 when the Transport has a TLSClientConfig → upstream is HTTP/1.1 only)
  → NO GREASE
curl 8.20 (OpenSSL 3.5, same machine)               JA3_MD5 = c654189f0cbcfb638bb74b824e790138
  → 87 suites, ALPN h2,http/1.1, NO GREASE
Chromium 148 (headless)                             JA3 changes on EVERY connection (f4d594a0…, b827f8a6…)
  → HAS GREASE (e.g. leading cipher 0x3a3a) + extension order randomized by design
```

Measured lessons (one of them fixing our own LAB4 mis-attribution — the
87-suite c654 hash was initially blamed on evilginx2 but was actually curl):

1. **Browser JA3 is non-deterministic** (Chrome randomizes extension order) →
   matching a "browser JA3 hash" is meaningless on either side. Only **family
   rules** are usable.
2. **The no-GREASE rule (most robust):** Chromium always sends GREASE
   (0x?a?a in ciphers/groups); Go, curl and Python never do. A browser-claiming
   UA + a GREASE-less ClientHello = a server-side client impersonating a
   browser = reverse proxy.
3. **The no-ALPN / h1-only subtype (evilginx2 specifically):** evilginx2's
   upstream fetch carries no ALPN extension → always HTTP/1.1 to the origin
   while every modern browser offers h2. Origin/CDN logs showing "login page
   fetched over HTTP/1.1 + browser UA" is a proxy signature. (Other frameworks
   may differ — measure before deploying the rule.)
4. **UA pass-through:** the victim's UA is forwarded intact through the proxy
   (the lab saw the curl UA reach the origin) — so the UA, seen from the
   origin, is NOT evidence; the TLS layer is what counts.

## D. Endpoint & user

| # | Indicator | Notes |
|---|----------|---------|
| D1 | Password manager does not autofill | Autocomplete is domain-bound — it fails on lookalike domains. Train the habit: "no autofill = check the URL". |
| D2 | Certificate warning | Only in lab/dev or with sloppy certs — not reliable against real campaigns (they use valid LE). |
| D3 | Extension/agent checking URL vs page brand | Architectural defense: on new page render, compare the URL host against the org's registered SSO domain list. |

## E. Architectural recommendations (kill this attack class at the root)

1. **FIDO2 / WebAuthn / passkeys** for everything critical — origin binding
   makes captured session cookies + passwords useless (the proxy never holds
   the private key).
2. CT-log alerts (A1) + response playbook: AbuseReport to the CA / registrar /
   hoster within the first hour.
3. Origin-side session hardening: bind sessions to device fingerprints +
   WebAuthn re-auth when C3 appears; short TTLs for sensitive sessions.
4. Replica-page tarpit: the origin answers with a JS probe (a fetch only a real
   browser executes) — a Go proxy doesn't run JS → catches B-class indicators
   before the victim types a password.

## Quick query patterns

```text
# Proxy/IDS (B2): evilginx2-style tracking cookie
http.cookie ~ /^[0-9a-z]{4}-[0-9a-z]{4}=[0-9a-f]{64}/ AND http.response.headers["Set-Cookie"] contains "Path=/"

# Origin WAF (C1): browser UA + Go TLS fingerprint
tls.ja3_hash IN (known_go_http_client_hashes) AND user_agent ~ "(Chrome|Firefox|Edg)/"

# Origin access log (C2)
http.request.url.path ~ "^/[A-Za-z]{8}$" AND referer NOT IN (official_domains)
```

## Scope note

This checklist was built in a **self-hosted lab targeting only our own test
site** (`portal.labsvc.test`, self-created `labuser` accounts). It contains no
observations of third-party systems.
