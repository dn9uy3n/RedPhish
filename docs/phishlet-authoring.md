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
  custom:
    - {domain: login.live.com, keys: ['ESTSAUTHPERSISTENT'], type: auth}
login:
  domain: login.microsoftonline.com
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

## Token-gated lures

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
2. Trusted-loopback render (see [troubleshooting](troubleshooting.md)) — the real login
   flow must appear, not the decoy.
3. Walk the whole flow with a test account: identifier → password → MFA → landed app.
4. `sessions` shows the capture; `export <id>` and replay the cookies into a real browser.
5. Only then: detection checks from a burner, and the campaign.
