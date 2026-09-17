---
layout: default
title: Troubleshooting
---

# Troubleshooting — field-proven gotchas

Every entry here was hit in real campaigns and verified. Read before the first campaign;
re-read when something "mysteriously" breaks.

---

## Symptom: lure returns a 141-byte "It works! This page is intentionally boring."

**Not a fault — the botguard decoy.** The node serves a benign page to clients it cannot
vouch for. Check `journalctl -u evilginx2 -o cat | tail`:

- `bot user-agent blocked ua='curl/…'` — curl/python-requests UAs are blocked outright.
- `JA4 not in allowlist t12d…` — the TLS fingerprint isn't allowlisted (browsers are;
  curl is not, even with a browser UA).

For a real render test, hit the node from a trusted IP (`-bg-trusted` includes
`127.0.0.1/32`) **on the node itself**:

```bash
curl -sk -L -c /tmp/cj -A "<browser UA>" \
  --resolve <host>:443:127.0.0.1 \
  "https://<host>/<lure>?t=<token>" -o page.html
```

The cookie jar matters: following redirects without it produces a decoy artifact.

## Symptom: domain resolves for subdomains but the base host gives no A record

**Wildcard `*.base` does not match `base` itself.** Cloudflare (and any RFC-compliant DNS)
needs a separate bare A record. After recreating it, remember resolvers cache the negative
answer for up to the SOA minimum TTL (Cloudflare: 1800 s); 1.1.1.1/8.8.8.8 usually pick up
the fix immediately. Always verify bare *and* wildcard after DNS surgery.

## Symptom: Google answers "This browser or app may not be secure"

Three distinct causes, check the logs:

1. **Relay session burned the exit** — dozens of fake submits (self-tests!) get the
   residential IP cooldown-scored. Wait 30–60 min or swap the exit
   (`proxy set … && proxy on`). *Self-tests must be render-only.*
2. **Classic MITM attempt** — origin-bound botguard always rejects it; use the relay.
3. **Datacenter IP on the lookup** — route Google through a residential exit
   ([proxy](proxy.md)).

## Symptom: two phishlets redirect into each other's flows

**Duplicate `phish_sub` across enabled phishlets on one base domain.** The host→phishlet
map collides and picks randomly. Keep each `phish_sub` globally unique
(ms365: `accounts`,`login`; google: `signin`,`gwww`). Also: an unknown SNI is dropped
silently — a typo'd hostname presents as a hanging browser, not an error.

## Symptom: phishlet hosts changed but pages still reference the dead domain

**Stale `general.domain`.** Changing phishlet hostnames alone leaves the global base
domain old; sub-filters render absolute URLs to a dead host and the victim's JS aborts
mid-flow. Fix `general.domain` to the new base and re-test a full flow.

## Relay (bgrelay) gotchas

| Symptom | Cause / fix |
|---|---|
| Victim page stuck on spinner forever | `page.html` updated but service not restarted — the page is loaded into RAM at start. Always `systemctl restart bgrelay` after scp. |
| Load average explodes, page loads time out | Zombie chromium from abandoned sessions — `pgrep -c chromium`, `pkill -x chromium`, restart. |
| `pkill -f "Xvfb :99"` killed my SSH session | `-f` matches your own ssh command line. Use `pkill -x Xvfb`. |
| Captured cookies fail to import | Drop negative `expires` fields entirely (not `-1`), add `secure: true` for google.com cookies, keep `__Host-` cookies URL-scoped. Reference: `tools/relay/open_gmail_session.py`. |
| Overlay clipped / drifted | Never eyeball it — measure pixels (template match, fill sampling). Vision-model QA hallucinates. |
| A new attribute crashes `/api/state` quietly | Any field exposed in `public_state` must be initialized in `RelaySession.__init__`. |

## ms365 gotchas

- **302 to `/` on the first hop is normal** — not a redirect loop.
- **Empty password capture** can be correct: passwordless accounts show
  "Password sign-in isn't available" — that's Microsoft's behavior.
- Consumer vs work cookies differ: `WLSSC` (consumer mailbox) vs
  `ESTSAUTHPERSISTENT` (work). Put the right set in `auth_tokens`.
- Don't run `-jsobf ultra` — verified to break Microsoft's login JS.

## Chrome Safe Browsing

- The Dangerous flag on the password host is **client-side** (the operator's own Chrome
  flags the page when they test). The CSD-hardening layers (password DOM disguise +
  brand lazy-reveal) are deployed and field-verified; residual risk is interaction-time
  flagging — plan burn-and-rotate by waves, never rotate mid-victim.
- Detection checks belong on **burner domains**, and never in the operator's daily browser.

## Console quirks

- The command is `lureurl` (no dash); `lure-url` is unknown syntax.
- `lureurl` output has **no** `?t=` token — tokens are campaign secrets; read them from
  the node config/API.
- Logs from the service are ANSI-colored binary blobs in journalctl — strip with
  `journalctl -u evilginx2 -o cat | sed 's/\x1b\[[0-9;]*m//g'`.
