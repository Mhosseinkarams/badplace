#!/usr/bin/env bash
# v7lthronyx — Set system-wide HTTP/HTTPS proxy environment.
#
# This sets the http_proxy/https_proxy environment variables for
# the CURRENT shell. Many CLI tools (curl, wget, git, apt, npm,
# pip, ...) honour these. It is NOT a real VPN — apps that ignore
# these variables (most GUI apps, browsers without explicit config)
# will bypass the proxy.
#
# Usage:   source scripts/system-proxy-on.sh
# Disable: source scripts/system-proxy-off.sh

PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-8085}"

export http_proxy="http://${PROXY_HOST}:${PROXY_PORT}"
export https_proxy="http://${PROXY_HOST}:${PROXY_PORT}"
export HTTP_PROXY="$http_proxy"
export HTTPS_PROXY="$https_proxy"
export ftp_proxy="$http_proxy"
export FTP_PROXY="$http_proxy"
export all_proxy="socks5://${PROXY_HOST}:${SOCKS_PORT:-1080}"
export ALL_PROXY="$all_proxy"
export no_proxy="localhost,127.0.0.1,::1"
export NO_PROXY="$no_proxy"

echo "[v7lthronyx] proxy env vars set:"
echo "  http_proxy=$http_proxy"
echo "  all_proxy=$all_proxy"
echo "  no_proxy=$no_proxy"
echo ""
echo "Test:  curl -v https://ifconfig.me"
echo "Off:   source scripts/system-proxy-off.sh"
