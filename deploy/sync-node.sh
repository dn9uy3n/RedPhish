#!/bin/sh
# sync-node.sh — one-command deploy of source changes to the node.
# Syncs src/ (Go), rebuilds the binary, syncs the relay sidecar, restarts services.
#
# Usage:  SSH_ID=/path/to/key ./sync-node.sh [user@host]
# Env:    SSH_ID     — path to the SSH private key (required)
#         REMOTE_DIR — node source dir (default /home/ubuntu/evilginx2-lab)
set -e

NODE="${1:-ubuntu@3.1.162.128}"
KEY="${SSH_ID:?SSH_ID=/path/to/key required}"
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
REMOTE_DIR="${REMOTE_DIR:-/home/ubuntu/evilginx2-lab}"

echo "== [1/3] sync Go source + relay sidecar -> $NODE"
scp -i "$KEY" -q "$ROOT"/src/go.mod "$ROOT"/src/go.sum "$NODE:$REMOTE_DIR/src/"
scp -i "$KEY" -q "$ROOT"/src/*.go "$NODE:$REMOTE_DIR/src/" 2>/dev/null || true
scp -i "$KEY" -q -r "$ROOT"/src/core "$ROOT"/src/database "$ROOT"/src/log "$ROOT"/src/parser "$NODE:$REMOTE_DIR/src/"
scp -i "$KEY" -q "$ROOT"/tools/relay/bgrelay.py "$ROOT"/tools/relay/page.html "$NODE:/home/ubuntu/bgrelay/"

echo "== [2/3] build on node + restart services"
ssh -i "$KEY" "$NODE" "cd $REMOTE_DIR/src && go build -o ../evilginx2 . \
  && sudo systemctl restart evilginx2 bgrelay && sleep 3 \
  && systemctl is-active evilginx2 bgrelay"

echo "== [3/3] smoke (mTLS API heartbeat via node-local certs)"
ssh -i "$KEY" "$NODE" 'python3 - << "EOF"
import json, ssl, http.client, os
cfg = os.path.expanduser("~/.evilginx/config.json")
api = os.path.expanduser("~/.evilginx/api/config.json")
base = json.load(open(api))["base_path"]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
ctx.load_cert_chain(os.path.expanduser("~/.evilginx/api/client.crt"), os.path.expanduser("~/.evilginx/api/client.key"))
c = http.client.HTTPSConnection("127.0.0.1", 9443, context=ctx, timeout=10)
c.request("GET", base + "/status")
r = c.getresponse()
print("api /status:", r.status, r.read().decode()[:80])
EOF'
echo "DONE — verify lures/sessions via egconsole or MCP before handing to users."
