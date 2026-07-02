#!/usr/bin/env bash
# Exercises the fakeinternet appliance end-to-end:
#   1. Runs a sandboxed container that resolves and connects to canary-test.example.com
#   2. Confirms that 8.8.8.8 is unreachable from inside detonet
#   3. Shows a summary of fakeinternet log entries
#
# Called by: make demo-fake  (which ensures fakeinternet-start runs first)
set -euo pipefail

DETONET_NAME="${DETONET_NAME:-detonet}"
SANDBOX_IMAGE="${SANDBOX_IMAGE:-pkgids-sandbox}"
FAKEINTERNET_NAME="${FAKEINTERNET_NAME:-pkgids-fakeinternet}"
LOGS_DIR="${FAKEINTERNET_LOGS:-$(pwd)/logs/fakeinternet}"

echo "=== pkgids demo-fake ==="
echo ""

# ── verify the appliance container is running ─────────────────────────────────
if ! docker ps --format '{{.Names}}' | grep -qx "${FAKEINTERNET_NAME}"; then
    echo "ERROR: fakeinternet container '${FAKEINTERNET_NAME}' is not running." >&2
    echo "       Run 'make fakeinternet-start' first." >&2
    exit 1
fi
echo "[ok] Fakeinternet appliance is running."
echo ""

# ── sandboxed DNS + HTTP probe ────────────────────────────────────────────────
echo "[1/3] Sandboxed DNS + HTTP probe (canary-test.example.com) ..."
docker run --rm \
    --network "$DETONET_NAME" \
    --runtime runsc \
    --memory 128m --cpus 0.25 --pids-limit 32 \
    "$SANDBOX_IMAGE" \
    python3 - <<'PYEOF'
import socket, urllib.request

host = "canary-test.example.com"

try:
    ip = socket.gethostbyname(host)
    print("  DNS:", host, "->", ip, "(captured by fakeinternet)")
except Exception as e:
    print("  DNS: error:", e)

try:
    with urllib.request.urlopen("http://" + host + "/", timeout=5) as r:
        print("  HTTP: status", r.status, r.reason)
except Exception as e:
    print("  HTTP:", type(e).__name__, str(e)[:100])
PYEOF

echo ""

# ── confirm real internet is blocked ─────────────────────────────────────────
echo "[2/3] Confirming real internet (8.8.8.8:53) is unreachable ..."
EGRESS=$(docker run --rm \
    --network "$DETONET_NAME" \
    --runtime runsc \
    --memory 64m --cpus 0.1 --pids-limit 16 \
    "$SANDBOX_IMAGE" \
    python3 -c "
import socket
socket.setdefaulttimeout(5)
try:
    socket.create_connection(('8.8.8.8', 53))
    print('REACHABLE')
except Exception:
    print('BLOCKED')
" 2>/dev/null || echo "BLOCKED")

if echo "$EGRESS" | grep -q "BLOCKED"; then
    echo "  [ok] Real internet: BLOCKED (as expected)"
else
    echo "  [WARN] Real internet appears reachable — check Docker iptables rules."
fi
echo ""

# ── fakeinternet log summary ──────────────────────────────────────────────────
echo "[3/3] Fakeinternet log summary ($LOGS_DIR) ..."
if [ -d "$LOGS_DIR" ]; then
    TOTAL=$(find "$LOGS_DIR" -name "*.jsonl" -exec wc -l {} + 2>/dev/null \
            | tail -1 | awk '{print $1}' || echo 0)
    echo "  $TOTAL total log entries"
    find "$LOGS_DIR" -name "*.jsonl" | sort | while read -r f; do
        printf "  %s: %d entries\n" "$(basename "$f")" "$(wc -l < "$f")"
    done
else
    echo "  Log directory not found: $LOGS_DIR"
fi

echo ""
echo "=== demo complete ==="