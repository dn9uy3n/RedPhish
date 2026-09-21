<p align="center">
  <img src="docs/assets/logo.png" width="160" alt="RedPhish logo">
</p>

# RedPhish

> 🌐 English | [Tiếng Việt](README.vi.md) | **📚 Docs: [dn9uy3n.github.io/RedPhish](https://dn9uy3n.github.io/RedPhish/)**

**Reverse-proxy phishing framework for authorized red teams** — an extended fork of
[evilginx2 CE 3.3.0](https://github.com/kgretzky/evilginx2) (GPL-3.0), re-implementing
Evilginx Pro-class features clean-room for internal / air-gapped environments.

> ⚠️ **Authorized use only** — for education and red-team campaigns explicitly authorized
> by the system owner. Not affiliated with BreakDev/Evilginx Pro; no code or binaries from
> the commercial product are used. Upstream GPL-3.0 applies (`LICENSE`).

## Status

| Phishlet | Status |
|---|---|
| `ms365` | ✅ production-ready — work + consumer capture, mailbox reuse, token-gate, CSD hardening (Safe Browsing bypass field-verified) |
| `google` | ✅ production-ready via **real-browser relay** — defeats origin-bound botguard; real-account capture with number-match 2FA; cookie replay into Gmail verified |

## Key features

- **Full MITM session capture** — credentials + reusable auth cookies (SQLite store), webhook to Gophish/credential collector
- **Hidden mTLS API** — stealth base path + client certs; drive fleets from one console (`tools/egconsole.py`)
- **Botguard anti-bot** — JA4 TLS allowlist, decoy pages for scanners/curl
- **Lure token-gate** — no `?t=` token → benign redirect; Safe Browsing/crawlers never see the login page
- **CSD hardening** — Chrome client-side phishing detection bypass (field-verified)
- **Upstream proxy routing** — per-domain-suffix egress (Google → residential, MS365 → direct)
- **Google real-browser relay** — mirrored real `accounts.google.com` session; HiDPI mirror, click-relay, capture `{email, password, cookies}`
- **ClickFix gate** — fake-captcha social-engineering page (clipboard payload) with configurable before/after position; hardened against content classification
- **MCP server** — AI agents (Claude/ZCode) operate the node as tools: phishlets, lures, sessions, proxy, relay — including opening captured sessions in a real browser ([docs/mcp](https://dn9uy3n.github.io/RedPhish/mcp.html), agent skills in [`skills/`](skills/))
- **JS obfuscation, AES lure params, multi-domain, wildcard-cert tooling, offline deploy kit**

Full matrix with verification evidence: [docs/FEATURES.md](docs/FEATURES.md).

## Quick start

```bash
git clone https://github.com/dn9uy3n/RedPhish.git
cd RedPhish/src && go build -o ../evilginx2 . && cd ..
./evilginx2 -phishlet <your.yaml> -api 9443 -botguard
```

Deploy runbook (VPS, DNS, wildcard cert, first lure):
[docs/getting-started](https://dn9uy3n.github.io/RedPhish/getting-started.html).
Day-2 operations + phishlet switching:
[docs/operations](https://dn9uy3n.github.io/RedPhish/operations.html).

> ⚠️ **No phishlets are included in this public repository** — campaign phishlets
> (`src/phishlets/*.yaml`) are gitignored by design, so this framework cannot be
> used out-of-the-box against anyone. This is deliberate: ready-made phishlets for
> real identity providers are trivially abusable for unlawful phishing.
>
> **Authorized researchers and red teamers** can author phishlets for their own
> scoped engagements using the bundled resources:
> [`skills/creating-phishlets`](skills/creating-phishlets/SKILL.md) (AI-agent
> authoring skill), the [phishlet authoring guide](https://dn9uy3n.github.io/RedPhish/phishlet-authoring.html)
> and the generator (`tools/make_phishlet.py`), with lab examples in
> [`examples/phishlets/`](examples/phishlets/).

## Roadmap

Done:

- [x] Phishlet hot-reload — add/edit/remove without restart
- [x] JA4 botguard (h2 Akamai fingerprint remaining)
- [x] Lure writer-API (GET/PUT/DELETE) + token-gate vs Safe Browsing
- [x] CSD hardening — Chrome client-side detection bypass (field-verified)
- [x] Upstream proxy with per-domain-suffix routing (#17)
- [x] Google real-browser relay (#18) — ms365 + google both production-ready
- [x] Relay exit pool + cooldown rotation (comma-separated RELAY_SOCKS)
- [x] Relay captures auto-import into the session store (one-click open)
- [x] Automated detection self-checks (`tools/detect_check.sh`)
- [x] ClickFix gate — fake captcha + clipboard payload, before/after position, detection-hardened
- [x] Per-phishlet JA4 exceptions — `bg_ja4_allow` in phishlet YAML, merged with `-bg-ja4`
- [x] MCP server for AI-agent operation + agent skills (`skills/`)
- [x] Documentation site ([dn9uy3n.github.io/RedPhish](https://dn9uy3n.github.io/RedPhish/))

Next:

- [ ] Fleet console — unified multi-node view (sessions + lures across nodes)
- [ ] HTTP/2 Akamai TLS fingerprint for botguard

Deferred (not a current threat-model blocker):

- [ ] Evilpuppet e2e — sidecar browser telemetry for Sentinel/Abnormal-class ML
  detection. The shipped code (own session, no victim linkage, no mouse/typing
  simulation) adds no capability over the relay (#18) + MITM (ms365) + JS
  telemetry (botguard v2) already in production. Revisit when a target flags
  sessions post-login despite correct cookies (the Sentinel signal).
- [ ] Evilpuppet proper — /visit endpoint + AES session_token linkage +
  interaction simulation; build only if the Sentinel/Abnormal use-case materializes.

## Credits & license

- Upstream: [kgretzky/evilginx2](https://github.com/kgretzky/evilginx2) by Kuba Gretzky (GPL-3.0)
- This fork: clean-room Pro-class extensions — same GPL-3.0, see [`LICENSE`](LICENSE)
- Documentation: [dn9uy3n.github.io/RedPhish](https://dn9uy3n.github.io/RedPhish/)
