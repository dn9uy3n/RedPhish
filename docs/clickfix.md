---
layout: default
title: ClickFix gate
description: Fake-captcha social engineering — clipboard payload with before/after position and detection hardening.
---

# ClickFix — fake captcha gate

A social-engineering layer that serves a convincing "verification" page which
silently copies a command to the victim's clipboard and instructs them to run
it. When the victim clicks the fake captcha checkbox and follows the
instructions (Win+R → Ctrl+V → Enter), the payload executes on their machine.

This is configured **per-phishlet** in the YAML — no separate object to manage.

## How it works

```
Victim visits lure URL
  │
  ├─ position: before ─────────────────────────────────┐
  │   Fake captcha page (Cloudflare/recaptcha/Windows) │
  │   → checkbox click → clipboard = {command}         │
  │   → instructions: Win+R, Ctrl+V, Enter            │
  │   → verify click → redirect to phishing login      │
  │   → victim enters credentials → captured           │
  │                                                    │
  ├─ position: after ──────────────────────────────────┤
  │   Victim enters credentials → captured             │
  │   → "One more step" captcha page                   │
  │   → checkbox click → clipboard = {command}         │
  │   → instructions: Win+R, Ctrl+V, Enter            │
  │   → verify click → redirect to real site           │
  └────────────────────────────────────────────────────┘
```

## Configuration

Add the `clickfix` section to any phishlet YAML:

```yaml
clickfix:
  template: cloudflare-turnstile     # template name (see below)
  command: "powershell -w hidden -e <base64>"  # payload to clipboard
  position: before                    # "before" (pre-login) or "after" (post-capture)
```

| Field | Description |
|---|---|
| `template` | Template file name: `clickfix/templates/<name>.html` |
| `command` | Payload string copied to the victim's clipboard |
| `position` | `before` = pre-login gate; `after` = post-capture "one more step" |

Hot-reload applies immediately — edit the phishlet YAML and the gate activates
on the next victim request (no service restart).

## Templates

Templates are self-contained HTML files deployed to the node (gitignored, like
campaign phishlets). Three styles ship with the fork:

| Template | Visual style |
|---|---|
| `cloudflare-turnstile` | "Checking if you are human" + Turnstile checkbox widget |
| `windows-fix` | Windows Security dialog "Verification Required" |
| `recaptcha` | Google reCAPTCHA "I'm not a robot" checkbox |

### Placeholders

| Placeholder | Substituted by | Used in |
|---|---|---|
| `{command_b64}` | Base64-encoded command (preferred — no cleartext in source) | Both |
| `{command}` | Raw command string (legacy — cleartext) | Both |
| `{redirect_url}` | Post-verify redirect target | Both |
| `{lure_url_js}` | JS-safe lure URL with forwarder param | Auto (via replaceHtmlParams) |

### Deploying templates

```bash
scp src/clickfix/templates/*.html <node>:/path/to/clickfix/templates/
```

The Go binary loads templates from `clickfix/templates/` relative to the
phishlets directory. Create custom templates by writing a self-contained HTML
file with the placeholders above.

## Detection hardening

All templates follow the same anti-classification doctrine as the credential
phishing pages ([CSD hardening](evasion#4-csd-hardening-client-side-detection)):

1. **Zero sensitive content in the initial DOM** — instruction text ("Win+R",
   "Ctrl+V"), brand elements and the clipboard payload are all absent from the
   page at load time. The victim sees only a spinner. Content classifiers
   (Safe Browsing page analysis, sandbox detonation, DLP rules) have nothing
   to match.
2. **Base64-encoded payload** — the command is never cleartext in the page
   source; decoded at runtime via `atob()`.
3. **Lazy text injection** — all social-engineering keywords are base64
   strings in the source, decoded and injected into the DOM only when the
   state machine advances after a user gesture.
4. **Brand lazy-reveal** — logo and domain hidden behind
   `visibility:hidden` until the first `pointermove`/`keydown` (same as the
   ms365 CSD v2 pattern).
5. **Randomized fingerprint** — variable timing, random verification IDs,
   dynamic text injection order — no byte-identical page across loads.
6. **Inline SVG favicon** (brand-matched) + generic title +
   `robots: noindex,nofollow` + `Cache-Control: no-store`.

## Clipboard mechanism

The templates use two independent poisoning methods:

1. **Primary**: on checkbox click, `navigator.clipboard.writeText()` +
   `document.execCommand('copy')` (hidden textarea technique)
2. **Backup**: global `copy` event interceptor — the victim's own copy
   operations are replaced with the payload

The payload is re-armed on every checkbox click and every "Verify" click,
so multiple attempts are possible.

## Integration hooks (maintainer reference)

| Hook | File:line | Behavior |
|---|---|---|
| Pre-auth gate | `http_proxy.go` ~535 | Serves template at the lure path when `position=before` and not a forwarder URL |
| Post-auth gate | `http_proxy.go` ~1381 | Replaces `javascriptRedirect` when `position=after` and session `IsDone` |
| Template loader | `clickfix.go` | Reads from `clickfix/templates/`, validates path traversal |
| Renderer | `clickfix.go` | Substitutes `{command_b64}`, `{command}`, `{redirect_url}` |

## Related

- [Phishlet authoring](phishlet-authoring) — the `clickfix` YAML section reference
- [Evasion](evasion#10-clickfix-gate-hardening) — where this fits in the defense-layer map
- [skills/creating-phishlets](https://github.com/dn9uy3n/RedPhish/tree/main/skills/creating-phishlets) — AI-agent authoring skill
