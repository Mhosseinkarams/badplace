#!/usr/bin/env bash
# v7lthronyx — Transparent TCP redirect via iptables (Linux only).
#
# WHAT THIS DOES
#   Redirects outbound TCP traffic (default ports 80/443) for a chosen
#   user to a local redsocks-style listener (here, the v7lthronyx proxy
#   running on 127.0.0.1:8085). Apps don't need to know about the proxy.
#
# REQUIREMENTS
#   * Run as root (uses iptables).
#   * The local proxy must be running.
#   * Apps that use raw sockets, QUIC/UDP, or VPN protocols will NOT be
#     captured — this is TCP-only and HTTP-aware on this proxy.
#   * IMPORTANT: HTTPS (443) traffic redirected here will reach the
#     CONNECT path; the proxy currently tunnels CONNECT directly out
#     of THIS host (not via the relay). For real cover-through-relay
#     for HTTPS you need MITM mode + relay-side fetch (advanced).
#
# USAGE
#   sudo PROXY_PORT=8085 TARGET_USER=$USER ./scripts/transparent-redirect.sh on
#   sudo ./scripts/transparent-redirect.sh off

set -euo pipefail

PROXY_PORT="${PROXY_PORT:-8085}"
TARGET_USER="${TARGET_USER:-${SUDO_USER:-$USER}}"
PORTS="${PORTS:-80,443}"

if [[ $EUID -ne 0 ]]; then
  echo "[ERROR] Must run as root."
  exit 1
fi

UID_VAL="$(id -u "$TARGET_USER")"

action="${1:-}"
case "$action" in
  on)
    echo "[v7lthronyx] enabling transparent redirect:"
    echo "  user=$TARGET_USER (uid=$UID_VAL) ports=$PORTS -> 127.0.0.1:$PROXY_PORT"
    iptables -t nat -N V7LTHRONYX 2>/dev/null || true
    iptables -t nat -F V7LTHRONYX
    iptables -t nat -A V7LTHRONYX -p tcp -m multiport --dports "$PORTS" \
      -j REDIRECT --to-ports "$PROXY_PORT"
    iptables -t nat -C OUTPUT -m owner --uid-owner "$UID_VAL" -j V7LTHRONYX 2>/dev/null \
      || iptables -t nat -A OUTPUT -m owner --uid-owner "$UID_VAL" -j V7LTHRONYX
    echo "[v7lthronyx] enabled."
    ;;
  off)
    echo "[v7lthronyx] disabling transparent redirect..."
    iptables -t nat -D OUTPUT -m owner --uid-owner "$UID_VAL" -j V7LTHRONYX 2>/dev/null || true
    iptables -t nat -F V7LTHRONYX 2>/dev/null || true
    iptables -t nat -X V7LTHRONYX 2>/dev/null || true
    echo "[v7lthronyx] disabled."
    ;;
  status)
    iptables -t nat -L V7LTHRONYX -n -v 2>/dev/null || echo "[v7lthronyx] chain not present."
    iptables -t nat -L OUTPUT -n -v | grep -E 'V7LTHRONYX|owner' || true
    ;;
  *)
    echo "Usage: $0 {on|off|status}"
    exit 2
    ;;
esac
