# fake-evilginx-pro

> 🌐 English | [Tiếng Việt](README.vi.md) | **📚 Docs: [dn9uy3n.github.io/fake-evilginx-pro](https://dn9uy3n.github.io/fake-evilginx-pro/)**

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
- **MCP server** — AI agents (Claude/ZCode) operate the node as tools: phishlets, lures, sessions, proxy, relay — including opening captured sessions in a real browser ([docs/mcp](https://dn9uy3n.github.io/fake-evilginx-pro/mcp.html), agent skills in [`skills/`](skills/))
- **JS obfuscation, AES lure params, multi-domain, wildcard-cert tooling, offline deploy kit**

Full matrix with verification evidence: [docs/FEATURES.md](docs/FEATURES.md).

## Quick start

```bash
git clone https://github.com/dn9uy3n/fake-evilginx-pro.git
cd fake-evilginx-pro/src && go build -o ../evilginx2 . && cd ..
./evilginx2 -phishlet <your.yaml> -api 9443 -botguard
```

Deploy runbook (VPS, DNS, wildcard cert, first lure):
[docs/getting-started](https://dn9uy3n.github.io/fake-evilginx-pro/getting-started.html).
Day-2 operations + phishlet switching:
[docs/operations](https://dn9uy3n.github.io/fake-evilginx-pro/operations.html).

> Campaign phishlets (`src/phishlets/*.yaml`) are **gitignored by design** — never shipped.

## Roadmap

Done:

- [x] Phishlet hot-reload — add/edit/remove without restart
- [x] JA4 botguard (h2 Akamai fingerprint remaining)
- [x] Lure writer-API (GET/PUT/DELETE) + token-gate vs Safe Browsing
- [x] CSD hardening — Chrome client-side detection bypass (field-verified)
- [x] Upstream proxy with per-domain-suffix routing (#17)
- [x] Google real-browser relay (#18) — ms365 + google both production-ready
- [x] MCP server for AI-agent operation + agent skills (`skills/`)
- [x] Documentation site ([dn9uy3n.github.io/fake-evilginx-pro](https://dn9uy3n.github.io/fake-evilginx-pro/))

Next:

- [ ] Per-phishlet JA4 exceptions — a `bg_ja4_allow` option in phishlet YAML (corporate TLS-inspection variants), merged with the node-level `-bg-ja4` allowlist
- [ ] Relay: automatic residential-exit rotation + cooldown handling (proxy pool)
- [ ] Relay captures auto-import into the console session store (one-click mailbox open)
- [ ] Evilpuppet e2e — sidecar browser telemetry (chromium DNS quirk on the lab node)
- [ ] HTTP/2 Akamai TLS fingerprint for botguard
- [ ] Fleet console — unified multi-node view (sessions + lures across nodes)
- [ ] Automated detection self-checks on burner domains

## Credits & license

- Upstream: [kgretzky/evilginx2](https://github.com/kgretzky/evilginx2) by Kuba Gretzky (GPL-3.0)
- This fork: clean-room Pro-class extensions — same GPL-3.0, see [`LICENSE`](LICENSE)
- Documentation: [dn9uy3n.github.io/fake-evilginx-pro](https://dn9uy3n.github.io/fake-evilginx-pro/)
