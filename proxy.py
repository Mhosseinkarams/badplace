#!/usr/bin/env python3
"""
RELAY PROXY — Local Mode
Forwards HTTP traffic through a relay server (Vercel / Google Apps Script).
Binds to 127.0.0.1 only. Not a VPN. Not an open proxy.

Usage:
    python3 proxy.py
    python3 proxy.py --config ./config.local.yaml
"""

import argparse
import json
import os
import signal
import sys
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

import requests
import yaml

DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.local.yaml"


def load_config(config_path: Path) -> dict:
    if not config_path.exists():
        print(f"[ERROR] Config file not found: {config_path}")
        sys.exit(1)

    with open(config_path, "r") as f:
        cfg = yaml.safe_load(f) or {}

    env_url = os.environ.get("RELAY_URL", "").strip()
    if env_url:
        cfg["relay_url"] = env_url

    env_as_url = os.environ.get("APPS_SCRIPT_URL", "").strip()
    if env_as_url and not cfg.get("relay_url"):
        cfg["relay_url"] = env_as_url
        if cfg.get("mode") == "apps_script":
            cfg["apps_script_url"] = env_as_url

    mode = cfg.get("mode", "vercel")

    if mode == "apps_script":
        if not cfg.get("apps_script_url") and not cfg.get("relay_url"):
            print("[ERROR] apps_script_url not set in config or APPS_SCRIPT_URL env var.")
            sys.exit(1)
    elif mode == "vercel":
        if not cfg.get("relay_url"):
            print("[ERROR] relay_url not set in config or RELAY_URL env var.")
            print("        Example: export RELAY_URL='https://your-project.vercel.app'")
            sys.exit(1)
    else:
        print(f"[ERROR] Unsupported mode: {mode}. Supported: 'vercel', 'apps_script'")
        sys.exit(1)

    return cfg


def get_relay_url(cfg: dict) -> str:
    mode = cfg.get("mode", "vercel")
    if mode == "apps_script":
        return cfg.get("apps_script_url") or cfg.get("relay_url", "")
    return cfg.get("relay_url", "")


CHECK_URLS = [
    ("https://script.google.com", "Google Scripts (script.google.com)"),
    ("https://script.googleusercontent.com", "Google Scripts CDN (script.googleusercontent.com)"),
    ("https://www.google.com/generate_204", "Google Connectivity (generate_204)"),
]


def run_connectivity_checks(relay_url: str = "") -> bool:
    print("")
    print("=" * 60)
    print("  Connectivity Checks")
    print("=" * 60)
    all_ok = True

    for url, label in CHECK_URLS:
        try:
            r = requests.head(url, timeout=8, allow_redirects=True)
            if r.status_code < 500:
                print(f"  [OK]  {label}")
            else:
                print(f"  [WARN] {label} — HTTP {r.status_code}")
        except requests.exceptions.Timeout:
            print(f"  [WARN] {label} — Connection timed out (8s)")
        except requests.exceptions.ConnectionError as e:
            print(f"  [WARN] {label} — Connection error (non-critical)")
        except Exception as e:
            print(f"  [WARN] {label} — {e}")

    if relay_url:
        try:
            r = requests.get(relay_url, timeout=10, allow_redirects=True)
            if r.status_code == 200:
                print(f"  [OK]  Relay URL — reachable")
            else:
                print(f"  [WARN] Relay URL — HTTP {r.status_code}")
        except Exception as e:
            print(f"  [WARN] Relay URL — {e}")

    print("=" * 60)
    print("  Connectivity checks completed.")
    print("=" * 60)
    print("")
    return True


def check_and_warn_mitm(cfg: dict):
    if not cfg.get("mitm_enabled", False):
        return

    print("")
    print("!" * 60)
    print("  WARNING: HTTPS MITM (Man-in-the-Middle) is ENABLED.")
    print("  This allows the proxy to decrypt HTTPS traffic.")
    print("  You will need to install a Root CA certificate in your")
    print("  browser or system trust store.")
    print("  Only enable this if you understand the implications.")
    print("!" * 60)
    print("")

    ca_dir = Path(cfg.get("ca_dir", "./ca"))
    ca_dir.mkdir(parents=True, exist_ok=True)

    ca_key = ca_dir / "ca.key"
    ca_cert = ca_dir / "ca.pem"

    if not ca_key.exists() or not ca_cert.exists():
        print("[INFO] Generating CA certificate and key...")
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        with open(ca_key, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        os.chmod(ca_key, 0o600)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Local Relay Proxy CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Local Relay Proxy CA"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )

        with open(ca_cert, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        print(f"[INFO] CA certificate generated: {ca_cert}")
        print(f"[INFO] CA key generated (chmod 600): {ca_key}")
    else:
        print(f"[INFO] Using existing CA certificate: {ca_cert}")
        print(f"[INFO] Using existing CA key (chmod 600): {ca_key}")


class RelayProxyHandler(BaseHTTPRequestHandler):
    relay_url = ""
    log_full_urls = False
    log_cookies = False
    log_authorization = False
    log_request_bodies = False

    def do_GET(self):
        self._handle_request("GET")

    def do_POST(self):
        self._handle_request("POST")

    def do_PUT(self):
        self._handle_request("PUT")

    def do_DELETE(self):
        self._handle_request("DELETE")

    def do_PATCH(self):
        self._handle_request("PATCH")

    def do_CONNECT(self):
        self.send_response(200)
        self.end_headers()

    def _handle_request(self, method):
        if self.path.startswith("/health"):
            self._json_response(200, {"status": "ok", "mode": "relay"})
            return

        if self.path.startswith("/test-google"):
            results = []
            for url, label in CHECK_URLS:
                try:
                    r = requests.head(url, timeout=8, allow_redirects=True)
                    results.append({"url": label, "status": r.status_code, "ok": r.status_code < 500})
                except Exception as ex:
                    results.append({"url": label, "error": str(ex), "ok": False})
            self._json_response(200, {"test": "google-connectivity", "results": results})
            return

        if self.path.startswith("/test-relay"):
            try:
                r = requests.post(
                    self.relay_url,
                    json={"method": "GET", "url": "https://httpbin.org/get", "headers": {}},
                    timeout=15, allow_redirects=True,
                )
                self._json_response(200, {
                    "test": "relay", "relay_status": r.status_code,
                    "ok": r.status_code == 200, "relay_response_preview": r.text[:500],
                })
            except Exception as ex:
                self._json_response(200, {"test": "relay", "error": str(ex), "ok": False})
            return

        url = self.path
        if not url.startswith("http"):
            url = f"http://{self.headers.get('Host', 'unknown')}{url}"

        if self.log_full_urls:
            print(f"[REQ] {method} {url}")
        else:
            parsed = urllib.parse.urlparse(url)
            safe_path = parsed.path if len(parsed.path) < 80 else parsed.path[:77] + "..."
            print(f"[REQ] {method} {parsed.hostname}{safe_path}")

        headers_dict = dict(self.headers)
        for h in list(headers_dict.keys()):
            if h.lower() in ('host', 'proxy-connection', 'connection', 'content-length', 'transfer-encoding', 'accept-encoding'):
                del headers_dict[h]
        if not self.log_cookies:
            headers_dict.pop("Cookie", None)
            headers_dict.pop("cookie", None)
        if not self.log_authorization:
            headers_dict.pop("Authorization", None)
            headers_dict.pop("authorization", None)
            headers_dict.pop("Proxy-Authorization", None)
            headers_dict.pop("proxy-authorization", None)

        payload = {"method": method, "url": url, "headers": headers_dict}

        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            body = self.rfile.read(content_length)
            if self.log_request_bodies:
                payload["body"] = body.decode("utf-8", errors="replace")
            else:
                payload["body"] = f"<body omitted, {content_length} bytes>"

        try:
            resp = requests.post(
                self.relay_url, json=payload, timeout=60,
                allow_redirects=True, headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    status_code = data.get("status", 200)
                    response_body = data.get("body", "")
                    self.send_response(status_code)
                    self.send_header("Content-Type", "text/plain")
                    if isinstance(response_body, str):
                        body_bytes = response_body.encode("utf-8", errors="replace")
                    else:
                        body_bytes = response_body
                    self.send_header("Content-Length", str(len(body_bytes)))
                    self.end_headers()
                    self.wfile.write(body_bytes)
                except (json.JSONDecodeError, KeyError, TypeError):
                    self._text_response(502, "Invalid relay response")
            else:
                self._text_response(502, f"Relay returned HTTP {resp.status_code}")
        except requests.exceptions.Timeout:
            self._text_response(504, "Relay timeout")
        except requests.exceptions.ConnectionError as e:
            self._text_response(502, f"Relay connection error: {e}")
        except Exception as e:
            self._text_response(502, f"Relay error: {e}")

    def _json_response(self, status_code, data):
        body = json.dumps(data, indent=2)
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body.encode())))
        self.end_headers()
        self.wfile.write(body.encode())

    def _text_response(self, status_code, text):
        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(text.encode())))
        self.end_headers()
        self.wfile.write(text.encode())

    def log_message(self, format, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description="HTTP/HTTPS Relay Proxy (Local Mode)")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to config YAML file")
    args = parser.parse_args()

    config_path = Path(args.config)
    cfg = load_config(config_path)

    bind_host = cfg.get("bind_host", "127.0.0.1")
    bind_port = cfg.get("bind_port", 8085)
    mode = cfg.get("mode", "vercel")
    relay_url = get_relay_url(cfg)

    connectivity_ok = run_connectivity_checks(relay_url)
    if not connectivity_ok:
        print("[ABORT] Relay may not work on this connection.")
        sys.exit(1)

    check_and_warn_mitm(cfg)

    RelayProxyHandler.relay_url = relay_url
    RelayProxyHandler.log_full_urls = cfg.get("log_full_urls", False)
    RelayProxyHandler.log_cookies = cfg.get("log_cookies", False)
    RelayProxyHandler.log_authorization = cfg.get("log_authorization", False)
    RelayProxyHandler.log_request_bodies = cfg.get("log_request_bodies", False)

    print("Starting local proxy...")
    print("")
    print("=" * 60)
    print("  Proxy Settings")
    print("=" * 60)
    print(f"  Mode:             {mode}")
    print(f"  Relay URL:        {relay_url}")
    print(f"  HTTP Proxy Host:  {bind_host}")
    print(f"  HTTP Proxy Port:  {bind_port}")
    print(f"  HTTPS Proxy Host: {bind_host}")
    print(f"  HTTPS Proxy Port: {bind_port}")
    if cfg.get("mitm_enabled", False):
        ca_dir = Path(cfg.get("ca_dir", "./ca"))
        print(f"  CA Certificate:   {ca_dir / 'ca.pem'}")
    else:
        print("  HTTPS MITM:       Disabled (CONNECT tunnels pass through)")
    print("=" * 60)
    print("")
    print("  Browser Proxy Settings:")
    print(f"    HTTP Proxy:  {bind_host}:{bind_port}")
    print(f"    HTTPS Proxy: {bind_host}:{bind_port}")
    print(f"    No Proxy:    localhost,127.0.0.1")
    print("")
    print("  For a separate browser profile (recommended):")
    print(f"    Chromium:  chromium --proxy-server='http://{bind_host}:{bind_port}' \\")
    print(f"                         --user-data-dir='/tmp/proxy-browser-profile'")
    print(f"    Firefox:   about:preferences → Network Settings → Manual proxy")
    print(f"               HTTP Proxy: {bind_host}  Port: {bind_port}")
    print(f"               Also use for HTTPS: yes")
    print("")
    print("  Health Endpoints:")
    print(f"    http://{bind_host}:{bind_port}/health        — Proxy status")
    print(f"    http://{bind_host}:{bind_port}/test-google   — Test Google connectivity")
    print(f"    http://{bind_host}:{bind_port}/test-relay    — Test relay")
    print("")
    print("  NOTE: This is NOT a VPN. It only works for apps/browsers")
    print("  that are explicitly configured to use this local proxy.")
    print("  Traffic is forwarded through your relay server.")
    print("=" * 60)
    print("")

    server = HTTPServer((bind_host, bind_port), RelayProxyHandler)
    print(f"[INFO] Proxy is running on {bind_host}:{bind_port}. Press Ctrl+C to stop.")
    print("")

    def signal_handler(sig, frame):
        print("\n[INFO] Stopping proxy...")
        server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[INFO] Proxy stopped by user.")
        server.server_close()


if __name__ == "__main__":
    main()
