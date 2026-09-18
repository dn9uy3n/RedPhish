# tools/

The complete operator toolchain of fake-evilginx-pro. v0.11 layout (see
`docs/architecture.md` for the full map):

```
tools/
├── lib/            shared library (the single source — import from here)
├── egconsole.py    operator REPL (the main console)
├── egctl.py        one-shot fleet CLI
├── mcp/            MCP server for AI agents (Claude/ZCode)
├── relay/          bgrelay sidecar (Google real-browser relay) + victim page
├── lab/            self-hosted lab environment
├── patches/        HISTORICAL — how the fork was first built (frozen)
└── authoring kit   make_phishlet / make_dns_zone / mint_internal_cert / deploy_offline / ja3
```

## lib/ — shared library

| File | Role |
|------|-----------|
| `lib/egapi.py` | **The ONE mTLS API client** + node list (`my-servers.json`, bare array). egconsole/egctl/egmcp all import from here — never write another client. |
| `lib/cookies.py` | Cookie extraction → playwright (both verified semantics via the `samesite`/`force_secure` params) + Cookie-Editor export |
| `lib/session_launcher.py` | Opens a real Chrome/Edge signed in with session cookies (`launch_with_cookies` + CLI; `__Host-` cookies via url per RFC 6265bis) |

## Main tools

| Tool | Role | Example |
|------|-----------|-------|
| `egconsole.py` | **Operator console** — REPL driving the node over the mTLS API (phishlets, lures, sessions, proxy, export, open) | `python egconsole.py` → `help` |
| `egctl.py` | One-shot fleet CLI | `python egctl.py my-servers.json status` |
| `mcp/egmcp.py` | MCP server (27 tools) for AI agents — see `tools/mcp/requirements.txt` | xem `docs/mcp.md` |
| `make_phishlet.py` | Sinh phishlet YAML + lint (authoring kit) | `python make_phishlet.py --name m1 --phish-domain lab.test --orig-host portal.lab.test --cookie SESS` |
| `mint_internal_cert.sh` | Internal CA + certs for hostnames (replaces ACME, zero egress, no CT logs) | `./mint_internal_cert.sh www.lab.test lab.test` |
| `deploy_offline.sh` | Auto-deploy the fork to internal hosts over SSH + systemd | `./deploy_offline.sh 192.168.1.50 ubuntu pass /tmp/src.tar.gz` |
| `make_dns_zone.py` | Generate a dnsmasq zone for the phish domain (internal multi-host DNS) | `python make_dns_zone.py --domain lab.test --ip 192.168.1.10` |
| `ja3.py` | JA3 md5 calculator piped from tshark (TLS-fingerprint auditing) | xem `docs/BLUE_TEAM_IOC.md` |

Operator config (gitignored): `my-servers.json` (node + certs + relay block),
`console.json` (SSH for `tail`/`puppet`), `servers.example.json` (format template).

## lab/ — self-hosted lab environment

| File | Role |
|------|-----------|
| `testsite.py` | Simulated origin: HTTPS login (127.0.0.2:443), self-signed cert, request log |
| `webhook_rx.py` | :9090 receiver logging `-webhook` credential JSON to `webhook_rx.log` |
| `verify_bg2.py` | Botguard v2 verifier (probe decoding + gating flow) |
| `test_jsobf_decode.py` | Decodes ultra string-array payloads (round-trip proof) |

Note: `testsite.py`/`webhook_rx.py` locate their BASE via `$HOME/evilginx2-lab` —
override with an env var or edit the constant if placed elsewhere.

## patches/ — HISTORICAL (frozen)

The patch scripts used to build the fork originally (2026-09). **Not the source
of truth** — edit `src/` directly. See `patches/README.md` for context and the
re-derive-from-upstream procedure if ever needed.
