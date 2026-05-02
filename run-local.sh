#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

cat .banner
echo ""

if [ ! -f "config.local.yaml" ]; then
    echo -e "${RED}[ERROR]${NC} config.local.yaml not found!"
    exit 1
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
echo -e "${GREEN}[OK]${NC} Virtual environment ready."

echo -e "${YELLOW}[2/4]${NC} Installing dependencies..."
pip install -q -r requirements.txt
echo -e "${GREEN}[OK]${NC} Dependencies installed."

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
PID_FILE="$SCRIPT_DIR/.proxy.pid"
python3 proxy.py --config config.local.yaml &
PROXY_PID=$!
echo "$PROXY_PID" > "$PID_FILE"
sleep 2

if kill -0 "$PROXY_PID" 2>/dev/null; then
    echo ""
    echo -e "${GREEN}============================================${NC}"
    echo -e "${GREEN}  Proxy started successfully!${NC}"
    echo -e "${GREEN}============================================${NC}"
    echo ""
    echo -e "  PID: ${CYAN}$PROXY_PID${NC}"
    echo ""
    echo -e "  ${YELLOW}Proxy Settings:${NC}"
    echo -e "    HTTP Proxy:   ${CYAN}127.0.0.1:8085${NC}"
    echo -e "    HTTPS Proxy:  ${CYAN}127.0.0.1:8085${NC}"
    echo -e "    SOCKS5 Proxy: ${CYAN}127.0.0.1:1081${NC}"
    echo ""
    echo -e "  ${YELLOW}Health Endpoints:${NC}"
    echo -e "    ${CYAN}http://127.0.0.1:8085/health${NC}"
    echo -e "    ${CYAN}http://127.0.0.1:8085/test-google${NC}"
    echo -e "    ${CYAN}http://127.0.0.1:8085/test-relay${NC}"
    echo ""
    echo -e "  ${YELLOW}Stop:${NC}  ./stop-local.sh"
    echo ""
    echo -e "  ${YELLOW}Browser:${NC}"
    echo -e "    chromium --proxy-server='http://127.0.0.1:8085' \\"
    echo -e "              --user-data-dir='/tmp/proxy-browser-profile'"
    echo ""
else
    echo -e "${RED}[ERROR]${NC} Proxy failed to start."
    rm -f "$PID_FILE"
    exit 1
fi

wait "$PROXY_PID"
