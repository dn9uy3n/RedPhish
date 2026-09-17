# tools/

Toàn bộ toolchain vận hành của fake-evilginx-pro. Cấu trúc v0.11 (xem
`docs/architecture.md` cho bản đồ tổng thể):

```
tools/
├── lib/            thư viện dùng chung (một nguồn duy nhất — import từ đây)
├── egconsole.py    operator REPL (console chính)
├── egctl.py        one-shot fleet CLI
├── mcp/            MCP server cho AI agent (Claude/ZCode)
├── relay/          bgrelay sidecar (Google real-browser relay) + trang victim
├── lab/            môi trường lab tự dựng
├── patches/        HISTORICAL — cách tạo fork ban đầu (frozen)
└── authoring kit   make_phishlet / make_dns_zone / mint_internal_cert / deploy_offline / ja3
```

## lib/ — thư viện dùng chung

| File | Chức năng |
|------|-----------|
| `lib/egapi.py` | **MTLS API client duy nhất** + node list (`my-servers.json`, bare array). egconsole/egctl/egmcp đều import từ đây — không tự viết client mới. |
| `lib/cookies.py` | Cookie extraction → playwright (2 semantics đã verify qua tham số `samesite`/`force_secure`) + Cookie-Editor export |
| `lib/session_launcher.py` | Mở Chrome/Edge thật đã đăng nhập bằng cookies session (`launch_with_cookies` + CLI; `__Host-` qua url theo RFC 6265bis) |

## Tools chính

| Tool | Chức năng | Ví dụ |
|------|-----------|-------|
| `egconsole.py` | **Operator console** — REPL điều khiển node qua mTLS API (phishlets, lures, sessions, proxy, export, open) | `python egconsole.py` → `help` |
| `egctl.py` | One-shot fleet CLI | `python egctl.py my-servers.json status` |
| `mcp/egmcp.py` | MCP server (27 tools) cho AI agent — đọc `tools/mcp/requirements.txt` | xem `docs/mcp.md` |
| `make_phishlet.py` | Sinh phishlet YAML + lint (authoring kit) | `python make_phishlet.py --name m1 --phish-domain lab.test --orig-host portal.lab.test --cookie SESS` |
| `mint_internal_cert.sh` | Internal CA + cert cho hostname (thay ACME, zero egress, không CT-log) | `./mint_internal_cert.sh www.lab.test lab.test` |
| `deploy_offline.sh` | Auto-deploy fork lên host nội bộ qua SSH + systemd | `./deploy_offline.sh 192.168.1.50 ubuntu pass /tmp/src.tar.gz` |
| `make_dns_zone.py` | Sinh dnsmasq zone cho phish domain (DNS nội bộ đa máy) | `python make_dns_zone.py --domain lab.test --ip 192.168.1.10` |
| `ja3.py` | JA3 md5 calculator từ pipe tshark (audit TLS fingerprint) | xem `docs/BLUE_TEAM_IOC.md` |

Config operator (gitignored): `my-servers.json` (node + cert + relay block),
`console.json` (SSH cho `tail`/`puppet`), `servers.example.json` (mẫu format).

## lab/ — môi trường lab tự dựng

| File | Chức năng |
|------|-----------|
| `testsite.py` | Origin mô phỏng: HTTPS login (127.0.0.2:443), cert tự sinh, log request |
| `webhook_rx.py` | Receiver :9090 ghi JSON creds từ `-webhook` vào `webhook_rx.log` |
| `verify_bg2.py` | Verifier Botguard v2 (probe decode + gating flow) |
| `test_jsobf_decode.py` | Decode payload ultra string-array (chứng minh round-trip) |

Lưu ý: `testsite.py`/`webhook_rx.py` tự定位 BASE theo `$HOME/evilginx2-lab` —
đổi bằng biến môi trường hoặc sửa hằng nếu đặt chỗ khác.

## patches/ — HISTORICAL (frozen)

Bộ patch scripts đã dùng để tạo fork ban đầu (2026-09). **Không phải nguồn sự
thật** — sửa code trực tiếp trong `src/`. Xem `patches/README.md` cho ngữ cảnh
và quy trình re-derive từ upstream nếu cần.
