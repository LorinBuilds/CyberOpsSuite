"""IP Logger for IP Rotator module."""

from __future__ import annotations

import csv
import datetime
import ipaddress
import socket
import ssl
import sys
import urllib.request
from pathlib import Path

# Resolve project root
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.utils.paths import config_root

# 9150 = Tor Browser, 9050 = Tor Expert Bundle / system tor service.
SOCKS_PORTS: tuple[int, ...] = (9150, 9050)
# (host, path) pairs that return the caller's public IP as plain text.
_IP_ENDPOINTS: tuple[tuple[str, str], ...] = (
    ("api.ipify.org", "/?format=text"),
    ("icanhazip.com", "/"),
    ("checkip.amazonaws.com", "/"),
)


def _valid_ip(text: str) -> str | None:
    text = text.strip()
    try:
        ipaddress.ip_address(text)
        return text
    except ValueError:
        return None


def _socks5h_get(host: str, path: str, socks_port: int, timeout: float) -> str | None:
    """HTTPS GET through a local SOCKS5 proxy; DNS is resolved by the proxy (socks5h)."""
    raw = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
    try:
        raw.settimeout(timeout)
        raw.sendall(b"\x05\x01\x00")  # version 5, one method: no auth
        if raw.recv(2) != b"\x05\x00":
            raise OSError("SOCKS5 handshake refused")

        name = host.encode("idna")
        raw.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + (443).to_bytes(2, "big"))
        head = raw.recv(4)
        if len(head) < 4 or head[1] != 0:
            raise OSError("SOCKS5 connect failed (Tor may still be bootstrapping)")
        skip = {1: 4, 4: 16}.get(head[3])
        if skip is None:  # domain-name address
            skip = raw.recv(1)[0]
        remaining = skip + 2
        while remaining > 0:
            part = raw.recv(remaining)
            if not part:
                raise OSError("SOCKS5 reply truncated")
            remaining -= len(part)

        context = ssl.create_default_context()
        with context.wrap_socket(raw, server_hostname=host) as tls:
            request = (
                f"GET {path} HTTP/1.0\r\nHost: {host}\r\n"
                "User-Agent: CyberOpsSuite-IPRotator\r\nConnection: close\r\n\r\n"
            )
            tls.sendall(request.encode("ascii"))
            data = b""
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                data += chunk
        _head, _sep, body = data.partition(b"\r\n\r\n")
        return _valid_ip(body.decode("utf-8", "replace"))
    finally:
        try:
            raw.close()
        except OSError:
            pass


class IPLogger:
    def __init__(self):
        self.log_dir = config_root("IPRotator")
        self.csv_file = self.log_dir / "ip_history.csv"

        if not self.csv_file.exists():
            with open(self.csv_file, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "IP Address", "Status"])

    def get_current_ip(self) -> str:
        """Get the public IP *as seen through Tor* (SOCKS5h on 9150 / 9050)."""
        reachable = False
        for port in SOCKS_PORTS:
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1.5).close()
            except OSError:
                continue
            reachable = True
            for host, path in _IP_ENDPOINTS:
                try:
                    ip = _socks5h_get(host, path, port, timeout=15)
                except (OSError, ssl.SSLError, ValueError):
                    continue
                if ip:
                    return ip
        if not reachable:
            return "Error: Tor SOCKS proxy not running (127.0.0.1:9150 / 9050)"
        return "Error: Could not fetch IP through Tor"

    def log_current_ip(self):
        """Fetch current IP via Tor and save it to CSV."""
        ip = self.get_current_ip()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        status = "Success" if not ip.startswith("Error") else "Failed"

        with open(self.csv_file, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([now, ip, status])

        return ip

    def get_log_path(self) -> str:
        return str(self.csv_file)

    def get_real_ip(self) -> str:
        """Get the real system IP (without Tor proxy)."""
        for host, path in _IP_ENDPOINTS:
            try:
                req = urllib.request.Request(f"https://{host}{path}")
                with urllib.request.urlopen(req, timeout=5) as response:
                    ip = _valid_ip(response.read().decode("utf-8", "replace"))
                if ip:
                    return ip
            except Exception:
                continue
        return "Unknown"
