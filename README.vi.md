<p align="center">
  <img src="docs/assets/logo.png" width="160" alt="RedPhish logo">
</p>

# RedPhish

> 🌐 [English](README.md) | Tiếng Việt | **📚 Tài liệu: [dn9uy3n.github.io/RedPhish](https://dn9uy3n.github.io/RedPhish/)**

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

### Template ClickFix

| Template | Giao diện | Vị trí |
|---|---|---|
| `cloudflare-turnstile` | Cloudflare "Checking if you are human" + Turnstile checkbox | trước / sau |
| `windows-fix` | Replica campaign thật: widget reCAPTCHA → panel hướng dẫn, đuôi clipboard "I am not a robot" thống nhất | trước / sau |
| `recaptcha` | Widget reCAPTCHA tối giản trên trang trắng (title `reCAPTCHA`, logo chính thức) | trước / sau |

Mỗi template âm thầm copy command payload vào clipboard nạn nhân và hướng dẫn
chạy (Win+R → Ctrl+V → Enter). Lệnh wrapped luôn kết thúc bằng
`;'I am not a robot - reCAPTCHA Verification ID: XXXX'` — ID 4 chữ số sinh
ngẫu nhiên mỗi request và khớp với số hiển thị trên trang. Template được
gitignored (riêng cho campaign, giống phishlet). Xem
[hướng dẫn ClickFix](https://dn9uy3n.github.io/RedPhish/clickfix.html) để biết chi tiết.

## Tính năng chính

- **MITM capture session trọn vẹn** — credentials + cookie auth tái sử dụng (store SQLite), webhook sang Gophish/credential collector
- **API mTLS ẩn** — stealth base path + client cert; điều hành fleet từ 1 console (`tools/egconsole.py`)
- **Botguard chống bot** — JA4 TLS allowlist, trang decoy cho scanner/curl
- **Lure token-gate** — thiếu `?t=` → redirect benign; Safe Browsing/crawler không bao giờ thấy trang login
- **CSD hardening** — bypass Chrome client-side phishing detection (verify thực chiến)
- **Upstream proxy routing** — egress theo suffix domain (Google → residential, MS365 → direct)
- **Google real-browser relay** — mirror của phiên `accounts.google.com` thật; mirror 2× nét native, click-relay, capture `{email, password, cookies}`
- **ClickFix gate** — trang fake captcha social-engineering (clipboard payload) với vị trí before/after; hardening chống content classification
- **MCP server** — AI agent (Claude/ZCode) điều hành node qua tools: phishlets, lures, sessions, proxy, relay — kể cả mở session capture trong trình duyệt thật ([docs/mcp](https://dn9uy3n.github.io/RedPhish/mcp.html), skill agent trong [`skills/`](skills/))
- **JS obfuscation, AES lure params, multi-domain, bộ công cụ wildcard-cert, deploy offline**

Ma trận đầy đủ + bằng chứng verify: [docs/FEATURES.md](docs/FEATURES.md).

## Chạy nhanh

```bash
git clone https://github.com/dn9uy3n/RedPhish.git
cd RedPhish/src && go build -o ../evilginx2 . && cd ..
./evilginx2 -phishlet <your.yaml> -api 9443 -botguard
```

Runbook deploy (VPS, DNS, wildcard cert, lure đầu tiên):
[docs/getting-started](https://dn9uy3n.github.io/RedPhish/getting-started.html).
Vận hành hàng ngày + chuyển đổi phishlet:
[docs/operations](https://dn9uy3n.github.io/RedPhish/operations.html).

> ⚠️ **Repo công khai KHÔNG kèm sẵn phishlet nào** — phishlet chiến dịch
> (`src/phishlets/*.yaml`) được gitignore chủ đích, framework này không thể dùng
> ngay để tấn công bất kỳ ai. Có chủ đích như vậy: phishlet dựng sẵn nhắm nhà cung
> cấp danh tính thật dễ bị lợi dụng cho phishing trái phép.
>
> **Nhà nghiên cứu và red teamer được ủy quyền** có thể tự viết phishlet cho chiến
> dịch trong phạm vi của mình bằng các tài nguyên kèm theo:
> [`skills/creating-phishlets`](skills/creating-phishlets/SKILL.md) (skill tác giả
> cho AI agent), [hướng dẫn soạn phishlet](https://dn9uy3n.github.io/RedPhish/phishlet-authoring.html)
> và bộ sinh (`tools/make_phishlet.py`), kèm ví dụ lab tại
> [`examples/phishlets/`](examples/phishlets/).

## Roadmap

Đã xong:

- [x] Phishlet hot-reload — thêm/sửa/xoá không cần restart
- [x] JA4 botguard (còn h2 Akamai fingerprint)
- [x] Lure writer-API (GET/PUT/DELETE) + token-gate chống Safe Browsing
- [x] CSD hardening — bypass Chrome client-side detection (verify thực chiến)
- [x] Upstream proxy routing theo suffix domain (#17)
- [x] Google real-browser relay (#18) — ms365 + google cùng production-ready
- [x] Relay exit pool + xoay cooldown (RELAY_SOCKS nhiều exit cách nhau dấu phẩy)
- [x] Auto-import capture relay vào session store (mở 1 click)
- [x] Detection self-check tự động (`tools/detect_check.sh`)
- [x] ClickFix gate — fake captcha + clipboard payload, before/after, hardening detection
- [x] Ngoại lệ JA4 theo phishlet — `bg_ja4_allow` trong YAML, gộp với `-bg-ja4` cấp node
- [x] MCP server cho AI agent + bộ skill agent (`skills/`)
- [x] Trang tài liệu ([dn9uy3n.github.io/RedPhish](https://dn9uy3n.github.io/RedPhish/))

Kế tiếp:

- [ ] Console fleet — xem thống nhất nhiều node (sessions + lures cross-node)
- [ ] HTTP/2 Akamai TLS fingerprint cho botguard

Trì hoãn (không phải blocker của threat model hiện tại):

- [ ] Evilpuppet e2e — browser telemetry sidecar cho hệ ML detection lớp
  Sentinel/Abnormal. Code hiện có (session riêng, không link victim, không mô phỏng
  mouse/typing) không cộng năng lực gì trên nền relay (#18) + MITM (ms365) + JS
  telemetry (botguard v2) đã production. Quay lại khi target flag session sau login
  dù cookies đúng (tín hiệu Sentinel).
- [ ] Evilpuppet đúng nghĩa — /visit endpoint + AES linkage session_token + mô phỏng
  tương tác; chỉ build khi use-case Sentinel/Abnormal xuất hiện thực tế.

## Credits & license

- Upstream: [kgretzky/evilginx2](https://github.com/kgretzky/evilginx2) của Kuba Gretzky (GPL-3.0)
- Fork này: các extension cấp Pro clean-room — cùng GPL-3.0, xem [`LICENSE`](LICENSE)
- Tài liệu: [dn9uy3n.github.io/RedPhish](https://dn9uy3n.github.io/RedPhish/)
