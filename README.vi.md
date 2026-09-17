# fake-evilginx-pro

> 🌐 [English](README.md) | Tiếng Việt | **📚 Tài liệu: [dn9uy3n.github.io/fake-evilginx-pro](https://dn9uy3n.github.io/fake-evilginx-pro/)**

**Framework phishing reverse-proxy cho red team được ủy quyền** — fork mở rộng từ
[evilginx2 CE 3.3.0](https://github.com/kgretzky/evilginx2) (GPL-3.0), tái triển khai
clean-room các tính năng cấp Evilginx Pro cho môi trường nội bộ / air-gapped.

> ⚠️ **Chỉ dùng khi được ủy quyền** — cho giáo dục và chiến dịch red-team có chấp thuận
> rõ ràng của chủ hệ thống. Không liên quan BreakDev/Evilginx Pro; không dùng mã hay binary
> nào của sản phẩm thương mại. Áp dụng GPL-3.0 từ upstream (`LICENSE`).

## Trạng thái

| Phishlet | Trạng thái |
|---|---|
| `ms365` | ✅ production-ready — work + consumer capture, mailbox reuse, token-gate, CSD hardening (bypass Safe Browsing verify thực chiến) |
| `google` | ✅ production-ready qua **real-browser relay** — vượt botguard gắn origin; capture account thật kèm number-match 2FA; replay cookie mở Gmail verified |

## Tính năng chính

- **MITM capture session trọn vẹn** — credentials + cookie auth tái sử dụng (store SQLite), webhook sang Gophish/credential collector
- **API mTLS ẩn** — stealth base path + client cert; điều hành fleet từ 1 console (`tools/egconsole.py`)
- **Botguard chống bot** — JA4 TLS allowlist, trang decoy cho scanner/curl
- **Lure token-gate** — thiếu `?t=` → redirect benign; Safe Browsing/crawler không bao giờ thấy trang login
- **CSD hardening** — bypass Chrome client-side phishing detection (verify thực chiến)
- **Upstream proxy routing** — egress theo suffix domain (Google → residential, MS365 → direct)
- **Google real-browser relay** — mirror của phiên `accounts.google.com` thật; mirror 2× nét native, click-relay, capture `{email, password, cookies}`
- **MCP server** — AI agent (Claude/ZCode) điều hành node qua tools: phishlets, lures, sessions, proxy, relay — kể cả mở session capture trong trình duyệt thật ([docs/mcp](https://dn9uy3n.github.io/fake-evilginx-pro/mcp.html), skill agent trong [`skills/`](skills/))
- **JS obfuscation, AES lure params, multi-domain, bộ công cụ wildcard-cert, deploy offline**

Ma trận đầy đủ + bằng chứng verify: [docs/FEATURES.md](docs/FEATURES.md).

## Chạy nhanh

```bash
git clone https://github.com/dn9uy3n/fake-evilginx-pro.git
cd fake-evilginx-pro/src && go build -o ../evilginx2 . && cd ..
./evilginx2 -phishlet <your.yaml> -api 9443 -botguard
```

Runbook deploy (VPS, DNS, wildcard cert, lure đầu tiên):
[docs/getting-started](https://dn9uy3n.github.io/fake-evilginx-pro/getting-started.html).
Vận hành hàng ngày + chuyển đổi phishlet:
[docs/operations](https://dn9uy3n.github.io/fake-evilginx-pro/operations.html).

> Phishlet chiến dịch (`src/phishlets/*.yaml`) được **gitignore chủ đích** — không bao giờ
> ship kèm repo.

## Roadmap

Đã xong:

- [x] Phishlet hot-reload — thêm/sửa/xoá không cần restart
- [x] JA4 botguard (còn h2 Akamai fingerprint)
- [x] Lure writer-API (GET/PUT/DELETE) + token-gate chống Safe Browsing
- [x] CSD hardening — bypass Chrome client-side detection (verify thực chiến)
- [x] Upstream proxy routing theo suffix domain (#17)
- [x] Google real-browser relay (#18) — ms365 + google cùng production-ready
- [x] MCP server cho AI agent + bộ skill agent (`skills/`)
- [x] Trang tài liệu ([dn9uy3n.github.io/fake-evilginx-pro](https://dn9uy3n.github.io/fake-evilginx-pro/))

Kế tiếp:

- [ ] Ngoại lệ JA4 theo phishlet — tùy chọn `bg_ja4_allow` trong YAML (biến thể TLS-inspection của mạng công ty), gộp với allowlist cấp node `-bg-ja4`
- [ ] Relay: tự xoay residential exit + xử lý cooldown (proxy pool)
- [ ] Auto-import capture relay vào session store của console (mở mailbox 1 click)
- [ ] Evilpuppet e2e — browser telemetry sidecar (quirk DNS chromium trên node lab)
- [ ] HTTP/2 Akamai TLS fingerprint cho botguard
- [ ] Console fleet — xem thống nhất nhiều node (sessions + lures cross-node)
- [ ] Tự động hoá detection self-check trên burner domain

## Credits & license

- Upstream: [kgretzky/evilginx2](https://github.com/kgretzky/evilginx2) của Kuba Gretzky (GPL-3.0)
- Fork này: các extension cấp Pro clean-room — cùng GPL-3.0, xem [`LICENSE`](LICENSE)
- Tài liệu: [dn9uy3n.github.io/fake-evilginx-pro](https://dn9uy3n.github.io/fake-evilginx-pro/)
