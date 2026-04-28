#!/usr/bin/env bash
#
# stop-local.sh — Stop the local HTTP/HTTPS Relay Proxy
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/.proxy.pid"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

if [ ! -f "$PID_FILE" ]; then
    echo -e "${RED}[ERROR]${NC} No proxy PID file found at $PID_FILE"
    echo "  The proxy may not be running, or was started manually."
    echo ""
    echo "  To find and kill it manually:"
    echo "    ps aux | grep proxy.py"
    echo "    kill <PID>"
    exit 1
fi

PID=$(cat "$PID_FILE")

if kill -0 "$PID" 2>/dev/null; then
    echo "Stopping proxy (PID: $PID)..."
    kill "$PID" 2>/dev/null || true

    # Wait for graceful shutdown
    for i in $(seq 1 5); do
        if ! kill -0 "$PID" 2>/dev/null; then
            break
        fi
        sleep 1
    done

    # Force kill if still running
    if kill -0 "$PID" 2>/dev/null; then
        echo "Force stopping proxy..."
        kill -9 "$PID" 2>/dev/null || true
    fi

    echo -e "${GREEN}[OK]${NC} Proxy stopped."
else
    echo "Proxy (PID: $PID) is not running. Cleaning up PID file."
fi

rm -f "$PID_FILE"
