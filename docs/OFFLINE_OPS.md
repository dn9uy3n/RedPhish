---
layout: default
title: Offline ops
description: Zero-egress operation — audit, containment, checklist.
---

# Offline ops — running evilginx in a sealed internal network (zero internet egress)

**Date:** 2026-09-08 · **Status:** experimentally verified on the Kali lab
**Scope:** evilginx2 CE 3.3.0 (measured directly) + containment principles that
apply to every tool in a campaign, including a properly licensed Evilginx Pro.

## 1. Network touchpoint map of evilginx2 CE (source audit + measurement)

| # | Touchpoint | When it fires | Offline status |
|---|-----------|-------------------|--------------------|
| N1 | Let's Encrypt ACME (`acme-v02.api.letsencrypt.org`) | **ONLY** with autocert on and running without `-developer` | OFF via `-developer` or `config autocert off` |
| N2 | Origin resolve + fetch (HTTPS:443) | Every victim request | Point origins at internal hosts (/etc/hosts or internal DNS) |
| N3 | DNS server :53 | When a client queries | Authoritative-only, **no forwarding** to the internet (nameserver.go has no recursion code) |
| N4 | External IP | `config ipv4 external` — set manually | Calls no service (no ipify/icanhazip in the source) |
| N5 | GoPhish client | Only when admin_url/api_key are configured | Not configured = never runs |
| N6 | Updates/telemetry | — | Doesn't exist in CE |
| N7 | **Default unauth_url = YouTube** | Invalid victims get redirected | ⚠️ **victim-side egress** — you MUST set `config unauth_url` to an internal URL |
| N8 | Session data | — | Stored locally (`~/.evilginx/data.db`), nothing uploaded |

## 2. Measurement results (Kali, tcpdump dst-based filter)

**Phase A — offline posture (`-developer`, hosts-file DNS, internal origin),
full flow startup → lure → POST creds → portal → sessions:**

```
egress packets (dst outside every private range): 0
flow: lure:200 post:302 portal:200 — capture still fully working
```

**Phase B — `autocert on`, running without `-developer`:**

```
evilginx2 log: HTTP 400 from https://acme-v02.api.letsencrypt.org/acme/new-order
(= a real internet ACME round-trip, with just one phishlet enabled)
```

→ `autocert` is the **single** default setting that pushes the tool to the
internet.

> Methodology notes (hard-won): (1) egress filters must match on **dst** —
> `not net 172.16/12` also drops packets whose *src* is in 172.x and hides real
> egress; (2) `kill -9` on tcpdump loses unflushed packets — use `-U`
> (packet-buffered) and `kill -INT`; (3) when you catch no packets, the app's
> own log (the LE HTTP 400) is still round-trip evidence.

## 3. Offline configuration checklist for CE

1. Run with `-developer` (self-signed certs for every hostname) **or**
   `config autocert off` + real certs in `~/.evilginx/crt/sites/<hostname>/`
   (`fullchain.pem` + `privkey.pem`).
2. `/etc/hosts` (or internal DNS): phish hostnames → evilginx IP, origin
   hostnames → internal IPs.
3. Point phishlet `proxy_hosts.domain` at internal origins (see the lab
   example phishlet).
4. `config ipv4 external <internal-IP>`, `config ipv4 bind <internal-IP>`.
5. `config unauth_url https://<internal-page>/` — **never leave the YouTube
   default** (N7).
6. Lure `redirect_url` points internally. Don't configure GoPhish (N5), or
   point it at an internal GoPhish.
7. Pre-campaign verification: rerun the dst-filter tcpdump (section 2) with the
   exact posture and require zero packets.

## 4. Network containment (outer ring, for EVERY tool — licensed Pro included)

Defense in depth: even if an app *promises* not to call out, still fence the
network:

```bash
# network namespace with no default route (the tightest box)
sudo ip netns add rt-internal
sudo ip link add veth0 type veth peer name veth1 netns rt-internal
sudo ip addr add 10.66.0.1/24 dev veth0 && sudo ip link set veth0 up
sudo ip netns exec rt-internal ip link set lo up
sudo ip netns exec rt-internal ip addr add 10.66.0.2/24 dev veth1
sudo ip netns exec rt-internal ip link set veth1 up
# only a route to the internal range — no default route ⇒ cannot reach the internet
sudo ip netns exec rt-internal ip route add 172.24.0.0/16 via 10.66.0.1
sudo ip netns exec rt-internal /path/to/evilginx2 -p ... -developer

# alternative: nftables egress block for a dedicated user
nft add table inet rt-egress
nft add chain inet rt-egress out "{ type filter output priority 0; }"
nft add rule inet rt-egress out oif "lo" accept
nft add rule inet rt-egress out ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } accept
nft add rule inet rt-egress out ip daddr != { private ranges } drop
```

Audit template before every campaign (measure — don't trust promises):

```bash
sudo tcpdump -i any -U -w egress.pcap "not dst net 127.0.0.0/8 and not dst net 10/8 \
  and not dst net 172.16/12 and not dst net 192.168/16 and not dst net 169.254/16 and not ip6"
# run the tool + the full workflow → expect 0 packets
```

## 5. Victim-side egress (easily forgotten in a sealed environment)

- The proxied login page must render **without** loading assets from external
  CDNs (fonts/js/icons) — an internal origin satisfies this by itself; if you
  demo against a page with external assets, the victim's browser leaks
  DNS/HTTP outward. Audit with DevTools / a HAR capture on the internal lure.
- `unauth_url`, `redirect_url` and the lure's og_* fields: all internal.
- Certificates for internal hostnames: internal CA (imported into the lab
  browsers) or self-signed (browsers warn — acceptable in a controlled
  internal demo).

## 6. Regarding Evilginx Pro (with a valid license)

- The right path for sealed environments: **ask BreakDev support** about
  offline activation / the mandatory endpoint list to allowlist. The vendor
  sells to red teamers — this is a legitimate use case they handle directly.
- If the binary misbehaves with a valid license: file a bug report (strace +
  logs + description).
- Do not patch or bypass license mechanisms in the binary — out of scope.
