---
layout: default
title: Lab setup
description: Rebuild the lab end-to-end, step by step.
---

# Evilginx2 lab (Community Edition) — Kali VM

**Date:** 2026-09-07 · **Status:** build + smoke test complete ✓

## Background

The Evilginx Pro license-cracking track (61+ sessions) was **closed** — not
pursued further, as it is DRM circumvention on a commercial product without
authorization. The replacement (user-approved): build the open-source
**evilginx2 Community Edition v3.3.0** (GPL, by Kuba Gretzky / @mrgretzky) as a
lab for learning/demonstrating reverse-proxy phishing mechanics.

## Authorization rules (mandatory)

- Lab-only, isolated, targeting **our own assets** (a self-built test site).
- Never deploy against any third-party system or account.
- Purpose: understand the mechanics (reverse proxy, session-cookie capture,
  phishlets, lures) for defensive work — phishing detection & response.

## State on the Kali VM (DESKTOP-CGQ1TVQ — 172.24.228.169)

| Component | Value |
|---|---|
| Source | `~/evilginx2-src` (github.com/kgretzky/evilginx2, master `4c0988a`) |
| Binary | `~/evilginx2-lab/evilginx2` (17.4 MB, clean build) |
| Go | 1.26.4, built `-mod=vendor` (vendor tree present — no network needed at build) |
| Runtime config | `/root/.evilginx` (when run via sudo) |
| Phishlets | `/home/kali/evilginx2-src/phishlets` (includes the `example` phishlet) |

## Rebuilding (when needed)

```bash
cd ~/evilginx2-src && go build -mod=vendor -o ~/evilginx2-lab/evilginx2 .
```

SSH-from-Windows note: wrap remote commands in **single quotes** — with double
quotes, `$HOME` gets expanded on the Windows (MSYS) side into
`/c/<windows-user>` before being sent.

## Running

Interactive console (root needed to bind 53/80/443):

```bash
cd ~/evilginx2-lab
echo kali | sudo -S sh -c './evilginx2 -p /home/kali/evilginx2-src/phishlets'
```

Verified (2026-09-08): the v3.3.0 banner appears → full subsystem init
(phishlets loaded, config, blacklist, ports 443/53, autocert, the phishlet
table) → `help` prints the full menu (config / proxy / phishlets / sessions /
lures / blacklist / test-certs).

Safe kill: `pkill -9 -x evilginx2` (use `-x` only — never `-f`).

## End-to-end demo, RUN (2026-09-08) ✓

A complete simulated victim flow in the lab; evidence in `.reports/evilginx2-lab/`:

```
lure GET 302 → proxied /login 200 "Corp Login (LAB ORIGIN)"
POST creds   → origin log: user=labuser pass=labpass123
             → evilginx2: [+++] Username/Password captured, "all authorization tokens intercepted!"
GET /portal  → 200 "Logged in as labuser" (through the proxy, full cookies)
sessions     → | 4 | lab | labuser | labpass123 | captured | 127.0.0.1 |
```

**62-LAB3 extension (2026-09-08) ✓**
- `sub_filters`: the origin keeps "LAB ORIGIN", the proxied page becomes
  "PRODUCTION CLONE" (grep count = 0 for the original text) — HTML rewriting
  demo.
- `lures edit 0 redirect_url`: after collecting the tokens, evilginx2 actively
  redirects (`[imp] redirecting to URL: https://www.labphish.test/portal (1)`);
  session 5 captured.
- Capstone: the [blue-team IOC checklist](BLUE_TEAM_IOC.html) — CT-log,
  JA3≠UA, tracking-cookie pattern, h2-only origin, FIDO2 recommendation.

### Offline run architecture (no internet / no real domain)

| Component | Address | Notes |
|---|---|---|
| evilginx2 (HTTPS + DNS) | 127.0.0.1:443 | run as `kali` via `setcap cap_net_bind_service=+ep` |
| testsite.py (TLS origin) | 127.0.0.2:443 | python stdlib, self-signed cert for `portal.labsvc.test` |
| `/etc/hosts` | www.labphish.test→127.0.0.1, portal.labsvc.test→127.0.0.2 | split DNS via hosts |

Port-splitting trick: evilginx2's upstream is always HTTPS:443
(`core/http_proxy.go:150`, `InsecureSkipVerify` :1574) → the origin must be TLS
on :443. evilginx2 binds only 127.0.0.1 (`config ipv4 bind 127.0.0.1`) leaving
127.0.0.2:443 free for the test site — no iptables needed.

### Rebuild steps

1. `sudo setcap cap_net_bind_service=+ep ~/evilginx2-lab/evilginx2` — run
   without sudo.
2. `/etc/hosts`: the two lines from the table above.
3. Origin cert: `openssl req -x509 -newkey rsa:2048 -nodes -subj
   "/CN=portal.labsvc.test" -addext subjectAltName=DNS:portal.labsvc.test` →
   `~/evilginx2-lab/certs/`.
4. One-shot console (each command once; config persists in `~/.evilginx`):

   `printf "config domain labphish.test\nconfig ipv4 external 127.0.0.1\nconfig ipv4 bind 127.0.0.1\nphishlets hostname lab labphish.test\nphishlets enable lab\nlures create lab\nlures get-url 0\nexit\n" | ./evilginx2 -p ~/evilginx2-lab/phishlets -developer`
5. Start: `nohup python3 testsite.py > testsite_out.log 2>&1 &` then
   `nohup bash -c "tail -f /dev/null | ./evilginx2 -p ~/evilginx2-lab/phishlets -developer" > serve.log 2>&1 &`
   (`tail -f /dev/null` keeps stdin open so the console doesn't exit at EOF).
6. Victim flow (curl + cookie jar; the lure step needs `-L` because evilginx2
   302s to /login): GET lure → POST creds → GET /portal.
7. View captures: `printf "sessions\nexit\n" | ./evilginx2 ...` or
   `grep '+++' serve.log`.
8. Stop: `pkill -9 -x evilginx2; kill -9 $(pgrep -x python3)`.

### Hard-won gotchas (each one caused a real failure)

- `phishlets enable` **requires** `phishlets hostname <pl> <base>` first; the
  hostname is the BASE domain (`labphish.test`) — `www` is derived from
  phish_sub. Setting `www.labphish.test` produces `www.www.labphish.test`
  (happened).
- `auth_tokens.domain` is an **exact-match map key** (`getAuthToken`,
  phishlet.go:1030). Host-only cookies (origin sets no `Domain=`) → key
  **without** a leading dot (`portal.labsvc.test`); cookies with `Domain=` →
  evilginx2 prepends the dot. One character wrong = silent `tokens: none`
  (happened; fixed, then "all authorization tokens intercepted!").
- `-developer` = self-signed certs for every hostname, skipping Let's
  Encrypt/autocert entirely — the key to running offline. Without it, enabling
  a phishlet waits 60 s on ACME then fails.
- Driving the console non-interactively: pipe `printf "cmd\nexit\n"`; a second
  one-shot run alongside the server complains "Failed to start nameserver :53"
  — harmless, it still reads the db.
- SSH from Windows: wrap remote commands in **single quotes** (`$HOME` gets
  MSYS-expanded); `--put/--get` (SFTP) fails with FileNotFoundError in this
  environment → move files with `base64 -d > file` over the exec channel.

### Defensive-view IOCs (observable from the demo)

- TLS certificate not matching the brand: self-signed / odd CA for the spoofed
  domain (developer mode).
- A `.test`/simulated domain + a random lure path (`/npKorgAP`) + an
  unrecognized tracking cookie (here `bdaf-1cf9=<sha>`,
  `Domain=labphish.test`) set at landing.
- An instant 302 when entering the lure URL → a login page identical to the
  origin but with every POST going through a different host; the original HTML
  has had its URLs rewritten (sub_filters/auto_filter).
- With real brands: a valid LE cert for a lookalike domain is a strong IOC when
  combined with CT-log monitoring (crt.sh streams) — watch for newly issued
  certs on brand-similar domains.

## Related

- `ssh_run.py` — the Windows→Kali SSH channel (paramiko, creds from
  `~/.ssh-manager/.env`).
- `/tmp/ep_work` on Kali — the pristine Pro binary, **untouched** (md5
  `29680fa4ac5215e54d623cf9e83507e0`, re-verified at the start of that
  session).
- Old worklog: `HANDOFF_SESSION47.md` (closed with the S61-CLOSE conclusion).
