#!/usr/bin/env bash
# v7lthronyx — Unset system-wide proxy env vars.
# Usage: source scripts/system-proxy-off.sh

unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY
unset ftp_proxy FTP_PROXY all_proxy ALL_PROXY
unset no_proxy NO_PROXY

echo "[v7lthronyx] proxy env vars cleared."
