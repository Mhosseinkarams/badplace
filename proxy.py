"""
v7lthronyx RELAY PROXY — Local Mode
====================================
Forwards HTTP/HTTPS traffic through a relay (Vercel / Google Apps Script).
Binds to 127.0.0.1 only. NOT a VPN — only apps configured to use it.

Author : v7lthronyx (Aiden Azad)
GitHub : github.com/v74all/badplace
License: MIT

Usage:
    python3 proxy.py
    python3 proxy.py --config ./config.local.yaml
"""

import argparse
import base64
import errno
import http.client
import json
import os
import select
import signal
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Optional

import requests
import yaml

# --- Certificate Generation Imports ---
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
# ------------------------------------


DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.local.yaml"

V7_BANNER = r"""
            _____ _   _
__   __    |  ___| | | |
\ \ / /___ | |_  | |_| |__  _ __ ___  _ __  _   ___  __
 \ V /____||  _| | __| '_ \| '__/ _ \| '_ \| | | \ \/ /
  | ||____|| |   | |_| | | | | | (_) | | | | |_| |>  <
  \_/      |_|    \__|_| |_|_|  \___/|_| |_|\__, /_/\_/
                                            |___/
            R E L A Y   P R O X Y   v3.1
       Author : v7lthronyx (Aiden Azad)
       GitHub : github.com/v74all/badplace
"""


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

    if "mitm_enabled" not in cfg:
        cfg["mitm_enabled"] = True

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

    for url, label in CHECK_URLS:
        try:
            r = requests.head(url, timeout=8, allow_redirects=True)
            if r.status_code < 500:
                print(f"  [OK]  {label}")
            else:
                print(f"  [WARN] {label} — HTTP {r.status_code}")
        except requests.exceptions.Timeout:
            print(f"  [WARN] {label} — Connection timed out (8s)")
        except requests.exceptions.ConnectionError:
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
            print(f"  [WARN] Relay URL — {str(e)[:120]}")

    print("=" * 60)
    print("  Connectivity checks completed.")
    print("=" * 60)
    print("")
    return True


# ----------------------------------------------------------------------
#  MITM CA and certificate generation
# ----------------------------------------------------------------------
class CertManager:
    def __init__(self, ca_dir: Path):
        self.ca_dir = ca_dir
        self.ca_key_path = ca_dir / "ca.key"
        self.ca_cert_path = ca_dir / "ca.pem"
        self.certs = {}
        self._lock = threading.Lock()
        self._load_or_generate_ca()

    def _load_or_generate_ca(self):
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        if not self.ca_key_path.exists() or not self.ca_cert_path.exists():
            print("[INFO] Generating CA certificate and key...")
            self._generate_ca()
        else:
            print(f"[INFO] Using existing CA certificate: {self.ca_cert_path}")
            with open(self.ca_key_path, "rb") as f:
                self.ca_key = serialization.load_pem_private_key(f.read(), password=None)
            with open(self.ca_cert_path, "rb") as f:
                self.ca_cert = x509.load_pem_x509_certificate(f.read())

    def _generate_ca(self):
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(self.ca_key_path, "wb") as f:
            f.write(self.ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        os.chmod(self.ca_key_path, 0o600)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "v7lthronyx Relay Proxy CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "v7lthronyx Relay Proxy CA"),
        ])

        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ), critical=True)
            .sign(self.ca_key, hashes.SHA256())
        )

        with open(self.ca_cert_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

        print(f"[INFO] CA certificate generated: {self.ca_cert_path}")

    def get_cert(self, hostname: str):
        with self._lock:
            if hostname in self.certs:
                cert, key, expiry = self.certs[hostname]
                if expiry > datetime.datetime.now(datetime.timezone.utc):
                    return cert, key

            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ])

            alt_names = [x509.DNSName(hostname)]
            try:
                if '.' in hostname:
                    alt_names.append(x509.DNSName(f"*.{'.'.join(hostname.split('.')[1:])}"))
            except Exception:
                pass

            cert = (
                x509.CertificateBuilder()
                .subject_name(subject).issuer_name(self.ca_cert.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
                .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=90))
                .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ), critical=True)
                .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(self.ca_key, hashes.SHA256(), self.ca_cert.public_key())
            )

            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            key_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            self.certs[hostname] = (cert_pem, key_pem, cert.not_valid_after_utc)
            return cert_pem, key_pem


def check_and_warn_mitm(cfg: dict):
    if not cfg.get("mitm_enabled", False):
        print("[INFO] HTTPS MITM is DISABLED. CONNECT requests will be rejected.")
        return

    print("")
    print("!" * 60)
    print("  WARNING: HTTPS MITM is ENABLED.")
    print("  You will need to install the Root CA in your browser.")
    print(f"  CA Certificate: {Path(cfg.get('ca_dir', './ca')) / 'ca.pem'}")
    print("!" * 60)
    print("")


def find_free_port(host: str, start_port: int, max_tries: int = 100) -> Optional[int]:
    if start_port == 0:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((host, 0))
            return sock.getsockname()[1]

    port = int(start_port)
    for offset in range(max_tries):
        candidate = port + offset
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((host, candidate))
                return candidate
        except OSError as e:
            if e.errno in (errno.EADDRINUSE, errno.EACCES):
                continue
            raise
    return None


# ----------------------------------------------------------------------
#  DNS-over-HTTPS resolver
# ----------------------------------------------------------------------
class DoHResolver:
    DEFAULT_PROVIDERS = [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve",
    ]
    BOOTSTRAP_IPS = {
        "cloudflare-dns.com": ("1.1.1.1", "1.0.0.1"),
        "dns.google": ("8.8.8.8", "8.8.4.4"),
    }

    def __init__(self, providers=None, ttl=300):
        self.providers = providers or self.DEFAULT_PROVIDERS
        self.ttl = ttl
        self._cache = {}
        self._lock = threading.Lock()

    def resolve(self, host: str) -> str:
        if not host:
            return host
        if self._is_ip_literal(host):
            return host
        now = time.time()
        with self._lock:
            entry = self._cache.get(host)
            if entry and entry[1] > now:
                return entry[0]
        for provider in self.providers:
            try:
                data = self._query_provider(provider, host)
                if not data:
                    continue
                for ans in data.get("Answer", []):
                    if ans.get("type") == 1:
                        ip = ans["data"]
                        with self._lock:
                            self._cache[host] = (ip, now + self.ttl)
                        return ip
            except Exception:
                continue
        return host

    @staticmethod
    def _is_ip_literal(host: str) -> bool:
        for family in (socket.AF_INET, socket.AF_INET6):
            try:
                socket.inet_pton(family, host)
                return True
            except OSError:
                continue
        return False

    def _query_provider(self, provider: str, host: str) -> Optional[dict]:
        parsed = urllib.parse.urlparse(provider)
        provider_host = parsed.hostname
        if not provider_host:
            return None

        bootstrap_ips = self.BOOTSTRAP_IPS.get(provider_host, ())
        if parsed.scheme == "https" and bootstrap_ips:
            for ip in bootstrap_ips:
                try:
                    data = self._https_json_query(parsed, provider_host, ip, host)
                    if data:
                        return data
                except Exception:
                    continue

        try:
            r = requests.get(
                provider,
                params={"name": host, "type": "A"},
                headers={"Accept": "application/dns-json"},
                timeout=5,
            )
            if r.status_code != 200:
                return None
            return r.json()
        except Exception:
            return None

    def _https_json_query(
        self,
        parsed: urllib.parse.ParseResult,
        provider_host: str,
        connect_host: str,
        host: str,
    ) -> Optional[dict]:
        port = parsed.port or 443
        path = parsed.path or "/dns-query"
        query = urllib.parse.urlencode({"name": host, "type": "A"})
        if parsed.query:
            query = f"{parsed.query}&{query}"
        target = f"{path}?{query}"

        context = ssl.create_default_context()
        raw_sock = socket.create_connection((connect_host, port), timeout=5)
        with context.wrap_socket(raw_sock, server_hostname=provider_host) as tls_sock:
            request = (
                f"GET {target} HTTP/1.1\r\n"
                f"Host: {provider_host}\r\n"
                "Accept: application/dns-json\r\n"
                "Connection: close\r\n"
                "\r\n"
            )
            tls_sock.sendall(request.encode("ascii"))
            response = http.client.HTTPResponse(tls_sock)
            response.begin()
            body = response.read()
            if response.status != 200:
                return None
            return json.loads(body.decode("utf-8"))


# ----------------------------------------------------------------------
#  HTTP / HTTPS proxy handler
# ----------------------------------------------------------------------
class RelayProxyHandler(BaseHTTPRequestHandler):
    relay_url = ""
    log_full_urls = False
    log_cookies = False
    log_authorization = False
    log_request_bodies = False
    resolver: DoHResolver = None
    cert_manager: CertManager = None
    mitm_enabled = False
    connect_timeout = 30
    relay_follow_redirects = True   # kept for potential future use, but not directly used in new logic

    _relay_session = None

    @classmethod
    def get_relay_session(cls):
        """Plain requests session for relay (no DoH)."""
        if cls._relay_session is None:
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry

            cls._relay_session = requests.Session()

            retry_strategy = Retry(
                total=3,
                backoff_factor=0.5,
                status_forcelist=[500, 502, 503, 504],
                allowed_methods=["POST", "GET"]
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            cls._relay_session.mount("http://", adapter)
            cls._relay_session.mount("https://", adapter)
        return cls._relay_session

    protocol_version = "HTTP/1.1"

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

    def do_HEAD(self):
        self._handle_request("HEAD")

    def do_OPTIONS(self):
        self._handle_request("OPTIONS")

    # ----- HTTPS CONNECT tunnel / MITM -----
    def do_CONNECT(self):
        if not self.mitm_enabled:
            print("[CONNECT] MITM disabled, rejecting CONNECT request.")
            self._safe_text_response(403, "HTTPS CONNECT not allowed (MITM disabled)")
            return

        try:
            host, _, port_str = self.path.partition(":")
            port = int(port_str) if port_str else 443
        except ValueError:
            self._safe_text_response(400, "Bad CONNECT target")
            return

        print(f"[CONNECT] Intercepting HTTPS to {host}:{port}")

        self.send_response(200, "Connection Established")
        self.end_headers()

        try:
            cert_pem, key_pem = self.cert_manager.get_cert(host)
            temp_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

            import tempfile
            with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as cert_file:
                cert_file.write(cert_pem)
                cert_path = cert_file.name

            with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as key_file:
                key_file.write(key_pem)
                key_path = key_file.name

            try:
                temp_ssl_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            finally:
                try:
                    os.unlink(cert_path)
                    os.unlink(key_path)
                except Exception:
                    pass

            self.connection = temp_ssl_context.wrap_socket(
                self.connection, server_side=True, do_handshake_on_connect=True
            )
            self.rfile = self.connection.makefile("rb", -1)
            self.wfile = self.connection.makefile("wb", 0)

            self.raw_requestline = self.rfile.readline(65537)
            if not self.raw_requestline:
                return

            if not self.parse_request():
                return

            self._handle_request(self.command)

        except ssl.SSLError as e:
            print(f"[CONNECT] SSL Handshake failed with client for {host}: {e}")
        except Exception as e:
            print(f"[CONNECT] Error during MITM for {host}: {e}")
        finally:
            self.close_connection = True

    # ----- HTTP request through relay -----
    def _handle_request(self, method):
        # Internal health endpoints
        if self.path.startswith("/health"):
            self._safe_json_response(200, {
                "status": "ok", "mode": "relay", "version": "3.1",
                "mitm_enabled": self.mitm_enabled
            })
            return

        if self.path.startswith("/test-google"):
            results = []
            for url, label in CHECK_URLS:
                try:
                    r = requests.head(url, timeout=8, allow_redirects=True)
                    results.append({"url": label, "status": r.status_code, "ok": r.status_code < 500})
                except Exception as ex:
                    results.append({"url": label, "error": str(ex), "ok": False})
            self._safe_json_response(200, {"test": "google-connectivity", "results": results})
            return

        if self.path.startswith("/test-relay"):
            try:
                test_url = "https://httpbin.org/get"
                resp_relay = self._send_to_relay("GET", test_url, {})
                if resp_relay.get("status") == 200:
                    self._safe_json_response(200, {
                        "test": "relay", "relay_status": resp_relay.get("status"),
                        "ok": True, "relay_response_preview": str(resp_relay.get("body", ""))[:500],
                    })
                else:
                    self._safe_json_response(200, {
                        "test": "relay", "relay_status": resp_relay.get("status", "N/A"),
                        "ok": False, "error": resp_relay.get("error", "Unknown error from relay"),
                    })
            except Exception as ex:
                self._safe_json_response(200, {"test": "relay", "error": str(ex), "ok": False})
            return

        # Determine the full URL
        url = self.path
        if not url.startswith("http"):
            host_header = self.headers.get('Host', 'unknown')
            scheme = "https" if isinstance(self.connection, ssl.SSLSocket) else "http"
            url = f"{scheme}://{host_header}{url}"

        if self.log_full_urls:
            print(f"[REQ] {method} {url}")
        else:
            parsed = urllib.parse.urlparse(url)
            safe_path = parsed.path if len(parsed.path) < 80 else parsed.path[:77] + "..."
            print(f"[REQ] {method} {parsed.hostname}{safe_path}")

        headers_dict = dict(self.headers)
        for h in list(headers_dict.keys()):
            if h.lower() in ('host', 'proxy-connection', 'connection', 'content-length',
                             'transfer-encoding', 'accept-encoding'):
                del headers_dict[h]

        if not self.log_cookies:
            headers_dict.pop("Cookie", None)
            headers_dict.pop("cookie", None)
        if not self.log_authorization:
            for k in ("Authorization", "authorization", "Proxy-Authorization", "proxy-authorization"):
                headers_dict.pop(k, None)

        body = b""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            try:
                body = self.rfile.read(content_length)
            except Exception as e:
                print(f"[ERROR] Failed to read request body: {e}")
                self._safe_text_response(500, "Failed to read request body")
                return

        resp_relay = self._send_to_relay(method, url, headers_dict, body)

        status_code = resp_relay.get("status", 500)

        if "error" in resp_relay:
            print(f"[DEBUG] Relay response: status={status_code}, error={resp_relay['error']}")
        else:
            print(f"[DEBUG] Relay response: status={status_code}")

        if "body_b64" in resp_relay:
            response_body = base64.b64decode(resp_relay["body_b64"])
        elif "body" in resp_relay:
            body_content = resp_relay["body"]
            response_body = body_content if isinstance(body_content, bytes) else body_content.encode("utf-8", errors="replace")
        else:
            response_body = b""

        response_headers = resp_relay.get("headers", {})

        try:
            self.send_response(status_code)
            for h_name, h_value in response_headers.items():
                if h_name.lower() in ('connection', 'content-length', 'transfer-encoding'):
                    continue
                if isinstance(h_value, list):
                    for val in h_value:
                        self.send_header(h_name, val)
                else:
                    self.send_header(h_name, h_value)
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        except OSError as e:
            if e.errno not in (errno.EPIPE, errno.ECONNRESET):
                raise
        finally:
            self.close_connection = True

    # =================================================================
    #  GOOGLE APPS SCRIPT RELAY LOGIC  (Iran-filtering optimised)
    # =================================================================
    def _send_to_relay(self, method: str, url: str, headers: dict, body: bytes = b"") -> dict:
        """
        Handles Google Apps Script's POST‑Redirect‑GET flow:
          1) POST the payload to /exec
          2) If we get a 302, extract the redirect URL and send a GET
          3) Otherwise return the status as-is
        
        Optimised for Iranian filtering conditions where only Google services
        (script.google.com, script.googleusercontent.com) are accessible.
        """
        payload = {
            "method": method,
            "url": url,
            "headers": headers,
            "followRedirects": True,
            "validateSsl": True
        }

        if body:
            try:
                payload["body"] = body.decode("utf-8")
            except UnicodeDecodeError:
                payload["body_b64"] = base64.b64encode(body).decode("ascii")

        if self.log_full_urls:
            print(f"[RELAY] {method} {url}")
        else:
            parsed = urllib.parse.urlparse(url)
            print(f"[RELAY] {method} {parsed.hostname}...")

        try:
            session = self.get_relay_session()

            # ---------- Step 1: initial POST ----------
            resp = session.post(
                self.relay_url,
                json=payload,
                timeout=(8, 45),          # increased timeout for slow Iranian connections
                allow_redirects=False,      # we handle the redirect ourselves
                headers={"Content-Type": "application/json"},
            )

            # ---------- Step 2: handle the Google Apps Script redirect ----------
            if resp.status_code in (301, 302, 303, 307, 308):
                redirect_url = resp.headers.get("Location")
                if redirect_url:
                    if self.log_full_urls:
                        print(f"[RELAY] Following redirect to {redirect_url[:120]}...")
                    # Google Apps Script expects a GET on the one-time URL
                    resp = session.get(
                        redirect_url,
                        timeout=(8, 45),
                        allow_redirects=True,
                    )
                else:
                    return {"status": 502, "error": "Relay returned redirect without Location header"}

            # ---------- Step 3: parse the final response ----------
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    return data
                except json.JSONDecodeError:
                    # Sometimes GAS returns HTML error pages
                    return {"status": 502, "error": "Invalid JSON from relay (maybe GAS error page)"}
            else:
                err_msg = f"Relay returned HTTP {resp.status_code}"
                try:
                    text = resp.text[:200]
                    if text:
                        err_msg += f": {text}"
                except Exception:
                    pass
                return {"status": resp.status_code, "error": err_msg}

        except requests.exceptions.Timeout:
            return {"status": 504, "error": "Relay timeout — ممکن است اینترنت شما کند باشد یا script.google.com مسدود شده باشد"}
        except requests.exceptions.ConnectionError as e:
            return {"status": 502, "error": f"Relay connection error: {str(e)[:200]} — آیا script.google.com باز است؟"}
        except Exception as e:
            return {"status": 502, "error": f"Relay error: {str(e)[:200]}"}

    # ----- safe response wrappers -----
    def _safe_json_response(self, status_code, data):
        body = json.dumps(data, indent=2).encode()
        self._safe_raw_response(status_code, body, content_type="application/json")

    def _safe_text_response(self, status_code, text):
        self._safe_raw_response(status_code, text.encode(), content_type="text/plain")

    def _safe_raw_response(self, status_code, body_bytes, content_type="text/plain"):
        try:
            self.send_response(status_code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body_bytes)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body_bytes)
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass
        except OSError as e:
            if e.errno not in (errno.EPIPE, errno.ECONNRESET):
                pass
        finally:
            self.close_connection = True

    def log_message(self, format, *args):
        pass

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            self.close_connection = True
        except ssl.SSLError:
            self.close_connection = True
        except socket.error as e:
            if e.errno not in (errno.ECONNRESET, errno.EPIPE):
                raise
            self.close_connection = True


# ----------------------------------------------------------------------
#  SOCKS5 server
# ----------------------------------------------------------------------
class Socks5Server(threading.Thread):
    def __init__(self, host, port, resolver: DoHResolver, cert_manager: CertManager, mitm_enabled: bool, connect_timeout=30):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.resolver = resolver
        self.cert_manager = cert_manager
        self.mitm_enabled = mitm_enabled
        self.connect_timeout = connect_timeout
        self._sock = None
        self._stop = threading.Event()
        self.ready = threading.Event()
        self.error = None

    def stop(self):
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def run(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        requested_port = self.port
        attempt_port = self.port
        for attempt in range(20):
            try:
                self._sock.bind((self.host, attempt_port))
                self._sock.listen(64)
                self.port = attempt_port
                break
            except OSError as e:
                if e.errno == errno.EADDRINUSE:
                    attempt_port += 1
                    continue
                self.error = f"bind failed {self.host}:{attempt_port} — {e}"
                print(f"[SOCKS5] {self.error}")
                self.ready.set()
                return
        else:
            self.error = f"could not bind to any port starting at {self.port}"
            print(f"[SOCKS5] {self.error}")
            self.ready.set()
            return

        if self.port != requested_port:
            print(f"[WARN] SOCKS5 port {requested_port} was changed because the original port was in use.")
        print(f"[SOCKS5] listening on {self.host}:{self.port}")
        self.ready.set()
        while not self._stop.is_set():
            try:
                client, addr = self._sock.accept()
            except OSError:
                break
            t = threading.Thread(target=self._handle_client, args=(client,), daemon=True)
            t.start()

    def _recv_exact(self, sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("short read")
            buf += chunk
        return buf

    def _handle_client(self, client: socket.socket):
        try:
            client.settimeout(self.connect_timeout)
            ver_nmethods = self._recv_exact(client, 2)
            if ver_nmethods[0] != 0x05:
                return
            nmethods = ver_nmethods[1]
            self._recv_exact(client, nmethods)
            client.sendall(b"\x05\x00")

            header = self._recv_exact(client, 4)
            if header[0] != 0x05 or header[1] != 0x01:
                client.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            atyp = header[3]
            if atyp == 0x01:
                addr_bytes = self._recv_exact(client, 4)
                host = socket.inet_ntoa(addr_bytes)
            elif atyp == 0x03:
                length = self._recv_exact(client, 1)[0]
                host = self._recv_exact(client, length).decode("idna")
            elif atyp == 0x04:
                addr_bytes = self._recv_exact(client, 16)
                host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            else:
                client.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                return
            port = struct.unpack("!H", self._recv_exact(client, 2))[0]

            client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")

            dummy_server = ThreadingHTTPServer(('127.0.0.1', 0), RelayProxyHandler)
            dummy_server.relay_url = RelayProxyHandler.relay_url
            dummy_server.log_full_urls = RelayProxyHandler.log_full_urls
            dummy_server.log_cookies = RelayProxyHandler.log_cookies
            dummy_server.log_authorization = RelayProxyHandler.log_authorization
            dummy_server.log_request_bodies = RelayProxyHandler.log_request_bodies
            dummy_server.resolver = RelayProxyHandler.resolver
            dummy_server.cert_manager = RelayProxyHandler.cert_manager
            dummy_server.mitm_enabled = RelayProxyHandler.mitm_enabled
            dummy_server.connect_timeout = RelayProxyHandler.connect_timeout
            dummy_server.relay_follow_redirects = RelayProxyHandler.relay_follow_redirects

            handler = RelayProxyHandler(client, client.getpeername(), dummy_server)
            handler.raw_requestline = handler.rfile.readline(65537)

            if handler.raw_requestline:
                if handler.raw_requestline.startswith(b"CONNECT"):
                    handler.path = handler.raw_requestline.split()[1].decode('ascii')
                    handler.do_CONNECT()
                else:
                    if handler.parse_request():
                        handler._handle_request(handler.raw_requestline.split()[0].decode('ascii'))
        except Exception as e:
            print(f"[SOCKS5] error: {e}")
        finally:
            try:
                client.close()
            except OSError:
                pass


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    parser = argparse.ArgumentParser(description="v7lthronyx Relay Proxy (Local Mode)")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to config YAML file")
    args = parser.parse_args()

    config_path = Path(args.config)
    cfg = load_config(config_path)

    bind_host = cfg.get("bind_host", "127.0.0.1")
    bind_port = cfg.get("bind_port", 8085)
    socks_enabled = cfg.get("socks_enabled", True)
    socks_port = cfg.get("socks_port", 1080)
    doh_enabled = cfg.get("doh_enabled", True)
    doh_providers = cfg.get("doh_providers") or None
    mode = cfg.get("mode", "vercel")
    relay_url = get_relay_url(cfg)
    mitm_enabled = cfg.get("mitm_enabled", True)
    ca_dir = Path(cfg.get("ca_dir", "./ca"))
    relay_follow_redirects = cfg.get("relay_follow_redirects", True)   # kept for potential future use

    print(V7_BANNER)

    check_and_warn_mitm(cfg)

    resolver = DoHResolver(providers=doh_providers) if doh_enabled else None
    cert_manager = CertManager(ca_dir) if mitm_enabled else None

    RelayProxyHandler.relay_url = relay_url
    RelayProxyHandler.log_full_urls = cfg.get("log_full_urls", False)
    RelayProxyHandler.log_cookies = cfg.get("log_cookies", False)
    RelayProxyHandler.log_authorization = cfg.get("log_authorization", False)
    RelayProxyHandler.log_request_bodies = cfg.get("log_request_bodies", False)
    RelayProxyHandler.resolver = resolver
    RelayProxyHandler.cert_manager = cert_manager
    RelayProxyHandler.mitm_enabled = mitm_enabled
    RelayProxyHandler.relay_follow_redirects = relay_follow_redirects

    # Find available ports
    requested_socks_port = socks_port
    if socks_enabled:
        allocated_socks_port = find_free_port(bind_host, socks_port)
        if allocated_socks_port is None:
            print(f"[ERROR] Unable to find an available SOCKS5 port starting at {socks_port}")
            sys.exit(1)
        if allocated_socks_port != socks_port:
            print(f"[WARN] SOCKS5 port {socks_port} is in use, using {allocated_socks_port} instead.")
            socks_port = allocated_socks_port

    requested_bind_port = bind_port
    allocated_bind_port = find_free_port(bind_host, bind_port)
    if allocated_bind_port is None:
        print(f"[ERROR] Unable to find an available HTTP proxy port starting at {bind_port}")
        sys.exit(1)
    bind_port = allocated_bind_port
    if bind_port != requested_bind_port:
        print(f"[WARN] HTTP proxy port {requested_bind_port} is in use, using {bind_port} instead.")

    socks_server = None
    server = None
    attempt_bind_port = bind_port
    for attempt in range(20):
        try:
            server = ThreadingHTTPServer((bind_host, attempt_bind_port), RelayProxyHandler)
            bind_port = attempt_bind_port
            break
        except OSError as e:
            if e.errno == errno.EADDRINUSE:
                attempt_bind_port += 1
                continue
            raise
    else:
        print(f"[ERROR] Could not bind HTTP server to any port starting at {bind_port}")
        sys.exit(1)

    if bind_port != requested_bind_port and bind_port != allocated_bind_port:
        print(f"[WARN] HTTP proxy port changed again during bind; using {bind_port}.")

    if socks_enabled:
        socks_server = Socks5Server(bind_host, socks_port, resolver, cert_manager, mitm_enabled)
        socks_server.start()
        if not socks_server.ready.wait(timeout=5):
            print("[ERROR] SOCKS5 server did not finish startup.")
            server.server_close()
            sys.exit(1)
        if socks_server.error:
            print(f"[ERROR] SOCKS5 server failed: {socks_server.error}")
            server.server_close()
            sys.exit(1)
        socks_port = socks_server.port

    runtime_file = Path(os.environ.get("PROXY_RUNTIME_FILE", str(config_path.parent / ".proxy.runtime.json")))
    runtime_info = {
        "pid": os.getpid(),
        "bind_host": bind_host,
        "bind_port": bind_port,
        "socks_enabled": socks_enabled,
        "socks_port": socks_port if socks_enabled else None,
        "requested_bind_port": requested_bind_port,
        "requested_socks_port": requested_socks_port if socks_enabled else None,
        "mitm_enabled": mitm_enabled,
    }
    try:
        with open(runtime_file, "w") as f:
            json.dump(runtime_info, f, indent=2)
    except OSError as e:
        print(f"[WARN] Unable to write runtime info file {runtime_file}: {e}")

    print("Starting v7lthronyx proxy...")
    print("")
    print("=" * 60)
    print("  Proxy Settings")
    print("=" * 60)
    print(f"  Mode:             {mode}")
    print(f"  Relay URL:        {relay_url}")
    print(f"  HTTP Proxy:       http://{bind_host}:{bind_port}")
    if socks_enabled:
        print(f"  SOCKS5 Proxy:     socks5://{bind_host}:{socks_port}")
    print(f"  DNS-over-HTTPS:   {'enabled' if doh_enabled else 'disabled'}")
    print(f"  HTTPS MITM:       {'enabled' if mitm_enabled else 'disabled (CONNECT will be rejected)'}")
    print("=" * 60)
    print("")
    print("  Browser Proxy Settings:")
    print(f"    HTTP/HTTPS Proxy:  {bind_host}:{bind_port}")
    if socks_enabled:
        print(f"    SOCKS5 Proxy:      {bind_host}:{socks_port}")
    print(f"    No Proxy:          localhost,127.0.0.1")
    print("")
    print("  Health Endpoints:")
    print(f"    http://{bind_host}:{bind_port}/health")
    print(f"    http://{bind_host}:{bind_port}/test-google")
    print(f"    http://{bind_host}:{bind_port}/test-relay")
    print("")
    print("  NOTE: This is NOT a VPN. Apps must be configured to use it.")
    print("        For system-wide redirect, see scripts/system-proxy-on.sh")
    print("=" * 60)
    print("")

    print(f"[INFO] Proxy is running on {bind_host}:{bind_port}. Press Ctrl+C to stop.")
    print("")

    def signal_handler(sig, frame):
        print("\n[INFO] Stopping proxy...")
        if socks_server:
            socks_server.stop()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[INFO] Proxy stopped by user.")
    finally:
        if socks_server:
            socks_server.stop()
        if RelayProxyHandler._relay_session:
            RelayProxyHandler._relay_session.close()
        server.server_close()
        try:
            runtime_file.unlink(missing_ok=True)
        except OSError:
            pass


if __name__ == "__main__":
    main()
