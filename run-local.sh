#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PID_FILE="$SCRIPT_DIR/.proxy.pid"
RUNTIME_FILE="$SCRIPT_DIR/.proxy.runtime.json"

project_proxy_pids() {
    local pid cwd
    for pid in $(pgrep -f "[p]roxy.py --config config.local.yaml" 2>/dev/null || true); do
        cwd="$(readlink "/proc/$pid/cwd" 2>/dev/null || true)"
        if [ "$cwd" = "$SCRIPT_DIR" ]; then
            echo "$pid"
        fi
    done
}

cat .banner
echo ""

if [ ! -f "config.local.yaml" ]; then
    echo -e "${RED}[ERROR]${NC} config.local.yaml not found!"
    exit 1
fi

EXISTING_PIDS="$(project_proxy_pids | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
if [ -n "$EXISTING_PIDS" ]; then
    if [ "${STOP_EXISTING:-0}" = "1" ]; then
        echo -e "${YELLOW}[WARN]${NC} Existing project proxy process(es) found: $EXISTING_PIDS"
        ./stop-local.sh
    else
        echo -e "${RED}[ERROR]${NC} Project proxy is already running: $EXISTING_PIDS"
        echo "  Stop it first with: ./stop-local.sh"
        echo "  Or restart in one command: STOP_EXISTING=1 ./run-local.sh"
        exit 1
    fi
fi

if grep -q 'relay_url: ""' config.local.yaml && grep -q 'apps_script_url: ""' config.local.yaml && [ -z "${RELAY_URL:-}" ] && [ -z "${APPS_SCRIPT_URL:-}" ]; then
    echo -e "${RED}[ERROR]${NC} relay_url or apps_script_url not configured."
    echo ""
    echo "  Set it in config.local.yaml:"
    echo "    relay_url: 'https://your-relay-url.com'"
    echo "    # or"
    echo "    apps_script_url: 'https://script.google.com/macros/s/...'"
    echo ""
    echo "  Or via environment variable:"
    echo "    export RELAY_URL='https://your-relay-url.com'"
    echo "    # or"
    echo "    export APPS_SCRIPT_URL='https://script.google.com/macros/s/...'"
    echo ""
    exit 1
fi

echo -e "${YELLOW}[1/4]${NC} Setting up Python virtual environment..."
if [ ! -d ".venv" ]; then
    python3 -m venv .venv
fi
source .venv/bin/activate
PYTHON="$SCRIPT_DIR/.venv/bin/python"
PIP="$SCRIPT_DIR/.venv/bin/pip"
echo -e "${GREEN}[OK]${NC} Virtual environment ready."

echo -e "${YELLOW}[2/4]${NC} Installing dependencies..."
REQ_HASH="$("$PYTHON" -c "import hashlib; print(hashlib.sha256(open('requirements.txt','rb').read()).hexdigest())")"
REQ_STAMP=".venv/.requirements.sha256"
if [ ! -f "$REQ_STAMP" ] || [ "$(cat "$REQ_STAMP")" != "$REQ_HASH" ]; then
    "$PIP" install -q -r requirements.txt
    echo "$REQ_HASH" > "$REQ_STAMP"
    echo -e "${GREEN}[OK]${NC} Dependencies installed."
else
    echo -e "${GREEN}[OK]${NC} Dependencies already current."
fi

BIND_PORT=$("$PYTHON" -c "import yaml; cfg=yaml.safe_load(open('config.local.yaml')); print(cfg.get('bind_port', 8085))")
SOCKS_PORT=$("$PYTHON" -c "import yaml; cfg=yaml.safe_load(open('config.local.yaml')); print(cfg.get('socks_port', 1082))")

echo -e "${YELLOW}[3/4]${NC} Running connectivity checks..."
CONNECTIVITY_OK=true
check_url() {
    local url="$1"
    local label="$2"
    if curl -4IsS --connect-timeout 8 "$url" > /dev/null 2>&1; then
        echo -e "  ${GREEN}[OK]${NC}  $label"
    else
        echo -e "  ${YELLOW}[WARN]${NC} $label"
        CONNECTIVITY_OK=false
    fi
}
check_url "https://script.google.com" "Google Scripts"
check_url "https://script.googleusercontent.com" "Google Scripts CDN"
check_url "https://www.google.com/generate_204" "Google Connectivity"

if [ "$CONNECTIVITY_OK" = false ]; then
    echo -e "${YELLOW}[WARN]${NC} Some connectivity checks failed. The proxy will still start, but relay requests may fail if the backend is not reachable."
    echo -e "  If you want to abort instead, set STRICT_CHECKS=1 and rerun."
    if [ "${STRICT_CHECKS:-0}" = "1" ]; then
        echo -e "${RED}[ABORT]${NC} Strict connectivity checks enabled."
        exit 1
    fi
fi

echo -e "${YELLOW}[4/4]${NC} Starting local proxy..."
rm -f "$RUNTIME_FILE"
PROXY_RUNTIME_FILE="$RUNTIME_FILE" "$PYTHON" proxy.py --config config.local.yaml &
PROXY_PID=$!
echo "$PROXY_PID" > "$PID_FILE"
sleep 2

if [ -f "$RUNTIME_FILE" ]; then
    BIND_PORT=$("$PYTHON" -c "import json; print(json.load(open('$RUNTIME_FILE'))['bind_port'])")
    SOCKS_PORT=$("$PYTHON" -c "import json; data=json.load(open('$RUNTIME_FILE')); print(data.get('socks_port') or '')")
else
    BIND_PORT=$("$PYTHON" -c "import yaml; cfg=yaml.safe_load(open('config.local.yaml')); print(cfg.get('bind_port', 8085))")
    SOCKS_PORT=$("$PYTHON" -c "import yaml; cfg=yaml.safe_load(open('config.local.yaml')); print(cfg.get('socks_port', 1082))")
fi

if kill -0 "$PROXY_PID" 2>/dev/null; then
    echo ""
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}  Proxy started successfully!${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo ""
    echo -e "  PID: ${CYAN}$PROXY_PID${NC}"
    echo ""
    echo -e "  ${YELLOW}Proxy Settings:${NC}"
    echo -e "    HTTP Proxy:   ${CYAN}127.0.0.1:$BIND_PORT${NC}"
    echo -e "    HTTPS Proxy:  ${CYAN}127.0.0.1:$BIND_PORT${NC}"
    echo -e "    SOCKS5 Proxy: ${CYAN}127.0.0.1:$SOCKS_PORT${NC}"
    echo ""
    echo -e "  ${YELLOW}Health Endpoints:${NC}"
    echo -e "    ${CYAN}http://127.0.0.1:$BIND_PORT/health${NC}"
    echo -e "    ${CYAN}http://127.0.0.1:$BIND_PORT/test-google${NC}"
    echo -e "    ${CYAN}http://127.0.0.1:$BIND_PORT/test-relay${NC}"
    echo ""
    echo -e "  ${YELLOW}Stop:${NC}  ./stop-local.sh"
    echo ""
    echo -e "  ${YELLOW}Browser:${NC}"
    echo -e "    chromium --proxy-server='http://127.0.0.1:$BIND_PORT' \\"
    echo -e "              --user-data-dir='/tmp/proxy-browser-profile'"
    echo ""
else
    echo -e "${RED}[ERROR]${NC} Proxy failed to start."
    rm -f "$PID_FILE"
    exit 1
fi

set +e
wait "$PROXY_PID"
EXIT_CODE=$?
set -e
rm -f "$PID_FILE" "$RUNTIME_FILE"
exit "$EXIT_CODE"
