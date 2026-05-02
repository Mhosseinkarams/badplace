#!/usr/bin/env bash
#
# stop-local.sh — Stop the local HTTP/HTTPS Relay Proxy
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/.proxy.pid"
RUNTIME_FILE="$SCRIPT_DIR/.proxy.runtime.json"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

stop_pid() {
    local pid="$1"
    local label="${2:-proxy}"

    if ! kill -0 "$pid" 2>/dev/null; then
        return 0
    fi

    echo "Stopping $label (PID: $pid)..."
    kill "$pid" 2>/dev/null || true

    for i in $(seq 1 5); do
        if ! kill -0 "$pid" 2>/dev/null; then
            break
        fi
        sleep 1
    done

    if kill -0 "$pid" 2>/dev/null; then
        echo "Force stopping $label..."
        kill -9 "$pid" 2>/dev/null || true
    fi
}

project_proxy_pids() {
    local pid cwd
    for pid in $(pgrep -f "[p]roxy.py --config config.local.yaml" 2>/dev/null || true); do
        cwd="$(readlink "/proc/$pid/cwd" 2>/dev/null || true)"
        if [ "$cwd" = "$SCRIPT_DIR" ]; then
            echo "$pid"
        fi
    done
}

STOPPED=false

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")

    if kill -0 "$PID" 2>/dev/null; then
        stop_pid "$PID" "proxy"
        STOPPED=true
    else
        echo "Proxy (PID: $PID) is not running. Cleaning up PID file."
    fi

    rm -f "$PID_FILE"
else
    echo -e "${YELLOW}[WARN]${NC} No proxy PID file found at $PID_FILE"
fi

for PID in $(project_proxy_pids); do
    stop_pid "$PID" "stale project proxy"
    STOPPED=true
done

if [ "$STOPPED" = true ]; then
    echo -e "${GREEN}[OK]${NC} Proxy stopped."
else
    echo "No running project proxy processes found."
fi

rm -f "$RUNTIME_FILE"
