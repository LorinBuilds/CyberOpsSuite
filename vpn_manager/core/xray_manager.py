"""Xray-core configuration and process manager for CyberOpsSuite.

Handles VLESS and VMess profiles, translates them into Xray-core JSON
configurations, validates the config, and starts/stops the Xray process.

Profile storage
---------------
Profiles are stored as JSON under the platform's standard config
directory:

* Windows: ``%APPDATA%\\CyberOpsSuite\\VpnManager\\profiles.json``
* Linux:   ``~/.config/CyberOpsSuite/VpnManager/profiles.json``

Xray logs (stdout+stderr) are written to ``xray.log`` in the same
directory, so a crashed core can be debugged without changing the
code.

Lifecycle
---------
:class:`XrayManager` registers an ``atexit`` handler so that a running
Xray process is always terminated when the Python interpreter exits —
even if the user closes the window unexpectedly. Orphan Xray processes
from a previous crash are detected and killed at startup.
"""

from __future__ import annotations

import atexit
import base64
import json
import os
import shutil
import socket
import struct
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from core.utils.paths import config_root
from core.utils.subprocess_utils import get_no_window_kwargs


# ---------------------------------------------------------------- paths

APP_DIR_NAME = "VpnManager"

#: Default local SOCKS5 port.
DEFAULT_SOCKS_PORT = 10808

#: Cloudflare trace endpoint used to verify the tunnel.
TRACE_HOST = "1.1.1.1"
TRACE_PORT = 80
TRACE_PATH = "/cdn-cgi/trace"

#: Speed-test endpoints (HTTP, no TLS — approximate but fast).
SPEED_HOST = "speed.cloudflare.com"
SPEED_DOWN_PATH = "/__down?bytes=10000000"
SPEED_UP_PATH = "/__up"


class VPNError(Exception):
    """Raised for all user-facing VPN errors."""


def _config_root() -> Path:
    """Return the per-user config directory for the VPN Manager.

    Delegates to :func:`core.utils.paths.config_root` so the location
    matches the rest of the suite (Windows: %APPDATA%, Linux: ~/.config).
    """
    return config_root(APP_DIR_NAME)


def config_dir() -> Path:
    """Return the directory used for profiles, active config, and logs."""
    return _config_root()


def profiles_path() -> Path:
    return config_dir() / "profiles.json"


def active_config_path() -> Path:
    return config_dir() / "active_config.json"


def xray_log_path() -> Path:
    return config_dir() / "xray.log"


# ---------------------------------------------------------------- manager

class XrayManager:
    """Manage Xray profiles and the Xray-core process."""

    def __init__(self, base_dir: Path | str | None = None) -> None:
        self.base_dir: Path = Path(base_dir) if base_dir else config_dir()
        self.base_dir.mkdir(parents=True, exist_ok=True)

        self.profiles_file = self.base_dir / "profiles.json"
        self.config_file = self.base_dir / "active_config.json"
        self.log_file = self.base_dir / "xray.log"

        self.process: subprocess.Popen | None = None
        self._lock = threading.Lock()
        self.profiles: list[dict] = self._load_profiles()

        atexit.register(self._atexit_cleanup)
        self._kill_orphans()

    # -------------------------------------------------------- lifecycle

    def _atexit_cleanup(self) -> None:
        try:
            self.disconnect()
        except Exception:
            pass

    def _kill_orphans(self) -> None:
        """Kill any orphaned Xray processes from a previous crash.

        Windows uses ``taskkill``; Linux uses ``pkill``. macOS is not
        supported by CyberOpsSuite.
        """
        try:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/F", "/IM", "xray.exe"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    **get_no_window_kwargs()
                )
            else:
                subprocess.run(
                    ["pkill", "-f", "/xray"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
        except (OSError, subprocess.SubprocessError):
            pass

    # --------------------------------------------------------- profiles

    def _load_profiles(self) -> list[dict]:
        try:
            data = json.loads(self.profiles_file.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except (OSError, ValueError):
            return []

    def _save(self) -> None:
        tmp = self.profiles_file.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(self.profiles, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        os.replace(tmp, self.profiles_file)

    # ------------------------------------------------------- import logic

    @staticmethod
    def _decode_b64(text: str) -> str:
        text = text.strip()
        text += "=" * (-len(text) % 4)
        try:
            return base64.urlsafe_b64decode(text.encode()).decode("utf-8-sig")
        except Exception:
            return ""

    def import_text(self, text: str) -> list[dict]:
        text = (text or "").strip()
        if not text:
            raise VPNError("Empty link or subscription text.")

        candidates = [line.strip() for line in text.splitlines() if line.strip()]

        if len(candidates) == 1 and not candidates[0].lower().startswith(
            ("vless://", "vmess://", "http://", "https://")
        ):
            decoded = self._decode_b64(candidates[0])
            if decoded and ("://" in decoded or "\n" in decoded):
                candidates = [x.strip() for x in decoded.splitlines() if x.strip()]

        elif len(candidates) == 1 and candidates[0].lower().startswith(
            ("http://", "https://")
        ):
            url = candidates[0]
            try:
                request = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": "CyberOpsSuite-VPN/1.0",
                        "Accept": "text/plain",
                    },
                )
                with urllib.request.urlopen(request, timeout=12) as response:
                    if response.status != 200:
                        raise VPNError(
                            f"Subscription returned HTTP {response.status}."
                        )
                    payload = response.read(1024 * 1024).decode(
                        "utf-8-sig", errors="replace"
                    ).strip()
                decoded = self._decode_b64(payload)
                body = decoded if (decoded and "://" in decoded) else payload
                candidates = [x.strip() for x in body.splitlines() if x.strip()]
            except VPNError:
                raise
            except Exception as exc:
                raise VPNError(f"Could not download subscription: {exc}") from exc

        added: list[dict] = []
        for item in candidates:
            try:
                profile = self.parse_link(item)
                if not any(p.get("uri") == profile["uri"] for p in self.profiles):
                    self.profiles.append(profile)
                    added.append(profile)
            except VPNError:
                continue

        if not added:
            raise VPNError(
                "No supported link found. Provide vless:// or vmess:// links."
            )

        self._save()
        return added

    @staticmethod
    def parse_link(uri: str) -> dict:
        uri = uri.strip()

        if uri.startswith("vless://"):
            parsed = urllib.parse.urlsplit(uri)
            if not parsed.hostname or not parsed.username:
                raise VPNError("Invalid VLESS link: missing host or UUID.")
            q = urllib.parse.parse_qs(parsed.query)
            params = {k: v[0] for k, v in q.items() if v}
            name = urllib.parse.unquote(parsed.fragment) or f"VLESS • {parsed.hostname}"
            return {
                "id": str(uuid.uuid4()),
                "name": name,
                "protocol": "vless",
                "address": parsed.hostname,
                "port": parsed.port or 443,
                "uuid": urllib.parse.unquote(parsed.username),
                "params": params,
                "uri": uri,
            }

        if uri.startswith("vmess://"):
            raw = uri[8:]
            data = XrayManager._decode_b64(raw)
            try:
                obj = json.loads(data)
            except Exception as exc:
                raise VPNError("Invalid VMess link format.") from exc
            address = obj.get("add")
            uid = obj.get("id")
            if not address or not uid:
                raise VPNError("VMess link is missing address or UUID.")
            return {
                "id": str(uuid.uuid4()),
                "name": obj.get("ps") or f"VMess • {address}",
                "protocol": "vmess",
                "address": address,
                "port": int(obj.get("port", 443)),
                "uuid": uid,
                "params": {
                    "security": obj.get("tls", ""),
                    "network": obj.get("net", "tcp"),
                    "path": obj.get("path", ""),
                    "host": obj.get("host", ""),
                    "sni": obj.get("sni", ""),
                },
                "uri": uri,
            }

        raise VPNError("Only VLESS and VMess links are supported.")

    # ---------------------------------------------------- config builder

    @staticmethod
    def _stream(profile: dict) -> dict:
        """Build the Xray streamSettings block for a profile.

        Uses the profile's own ``fp`` (fingerprint) when present, because
        some servers only accept specific fingerprints (``edge``, ``ios``,
        ...). Falls back to ``chrome`` which is the most widely compatible
        value.

        ``spiderX`` is omitted so the server uses its default.
        """
        p = profile.get("params", {})
        network = p.get("type") or p.get("network") or "tcp"
        security = p.get("security", "none")

        # Honour the profile's fingerprint; fall back to chrome.
        chosen_fp = (p.get("fp") or "chrome").strip() or "chrome"

        stream: dict[str, Any] = {
            "network": network,
            "security": "tls" if security in ("tls", "reality") else "none",
        }

        # ---------------- transport layer ----------------
        if network in ("ws", "websocket"):
            ws: dict[str, Any] = {"path": p.get("path", "/") or "/"}
            if p.get("host"):
                ws["headers"] = {"Host": p["host"]}
            stream["wsSettings"] = ws
            stream["network"] = "ws"

        elif network == "grpc":
            stream["grpcSettings"] = {
                "serviceName": p.get("serviceName") or p.get("service_name", ""),
            }

        elif network in ("xhttp", "splithttp"):
            xhttp: dict[str, Any] = {
                "path": p.get("path", "/") or "/",
                "mode": p.get("mode", "auto") or "auto",
            }
            if p.get("host"):
                xhttp["host"] = p["host"]
            # Parse the "extra" JSON field from the link (xmux etc.).
            extra_raw = p.get("extra")
            if extra_raw:
                try:
                    xhttp["extra"] = json.loads(extra_raw)
                except (ValueError, TypeError):
                    pass
            stream["xhttpSettings"] = xhttp
            stream["network"] = "xhttp"

        # ---------------- TLS layer ----------------
        if security == "tls" or p.get("sni"):
            tls: dict[str, Any] = {
                "serverName": (
                    p.get("sni")
                    or p.get("servername")
                    or p.get("host")
                    or profile["address"]
                ),
                "allowInsecure": False,
                "fingerprint": chosen_fp,
            }
            alpn = p.get("alpn")
            if alpn:
                tls["alpn"] = [x.strip() for x in alpn.split(",")]
            stream["tlsSettings"] = tls

        # ---------------- Reality layer ----------------
        if security == "reality":
            stream["security"] = "reality"
            stream["realitySettings"] = {
                "serverName": p.get("sni") or profile["address"],
                "fingerprint": chosen_fp,
                "publicKey": p.get("pbk", ""),
                "shortId": p.get("sid", ""),
                # spiderX omitted — server uses its default.
            }

        return stream

    def build_config(self, profile: dict, local_port: int = DEFAULT_SOCKS_PORT) -> dict:
        """Build a complete Xray-core JSON configuration.

        Routing rules:
        * Private IPs (LAN) → direct
        * Iranian domains → direct (faster + no tunnel load)
        * Everything else → proxy

        Sniffing is enabled so HTTP/TLS/QUIC traffic is routed by the
        real destination hostname, which fixes YouTube and many CDNs.
        Mux reduces handshake overhead for many-parallel-connection apps.
        """
        protocol = profile["protocol"]
        params = profile.get("params", {})

        user: dict[str, Any] = {"id": profile["uuid"]}
        if protocol == "vless":
            user["encryption"] = "none"
            # Vision flow is only required (and only safe) for VLESS +
            # Reality over TCP. For xhttp/ws/grpc + Reality, adding it
            # breaks the handshake on many servers.
            network = params.get("type") or params.get("network") or "tcp"
            flow = params.get("flow")
            if (
                not flow
                and params.get("security") == "reality"
                and network == "tcp"
            ):
                flow = "xtls-rprx-vision"
            if flow:
                user["flow"] = flow
        else:
            user.update({"alterId": 0, "security": "auto"})
            flow = params.get("flow")
            if flow:
                user["flow"] = flow

        outbound = {
            "tag": "proxy",
            "protocol": protocol,
            "settings": {
                "vnext": [{
                    "address": profile["address"],
                    "port": int(profile["port"]),
                    "users": [user],
                }],
            },
            "streamSettings": self._stream(profile),
        }

        # Mux is only safe on plain TCP transports. It breaks
        # xhttp/ws/grpc on many servers, so we only enable it for tcp.
        network = params.get("type") or params.get("network") or "tcp"
        if network == "tcp":
            outbound["mux"] = {
                "enabled": True,
                "concurrency": 8,
                "xudpConcurrency": 16,
                "xudpProxyUDP443": "reject",
            }

        return {
            "log": {"loglevel": "warning"},
            "dns": {
                "servers": [
                    {
                        "address": "1.1.1.1",
                        "domains": ["geosite:geolocation-!cn"],
                    },
                    "1.1.1.1",
                    "8.8.8.8",
                ],
                "queryStrategy": "UseIP",
            },
            "inbounds": [
                {
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "port": int(local_port),
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True},
                    "sniffing": {
                        "enabled": True,
                        "destOverride": ["http", "tls", "quic"],
                        "routeOnly": False,
                    },
                },
                {
                    "tag": "http-in",
                    "listen": "127.0.0.1",
                    "port": int(local_port) + 1,
                    "protocol": "http",
                    "settings": {},
                    "sniffing": {
                        "enabled": True,
                        "destOverride": ["http", "tls", "quic"],
                        "routeOnly": False,
                    },
                },
            ],
            "outbounds": [
                outbound,
                {
                    "tag": "direct",
                    "protocol": "freedom",
                    "settings": {"domainStrategy": "UseIPv4"},
                },
                {"tag": "block", "protocol": "blackhole"},
            ],
            "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [
                    {
                        "type": "field",
                        "outboundTag": "direct",
                        "ip": [
                            "127.0.0.0/8",
                            "10.0.0.0/8",
                            "172.16.0.0/12",
                            "192.168.0.0/16",
                            "169.254.0.0/16",
                            "::1/128",
                            "fc00::/7",
                            "fe80::/10",
                        ],
                    },
                    {
                        "type": "field",
                        "outboundTag": "direct",
                        "domain": [
                            "geosite:category-ir",
                            "geosite:private",
                        ],
                    },
                    {
                        "type": "field",
                        "outboundTag": "proxy",
                        "network": "tcp,udp",
                    },
                ],
            },
        }

    # ----------------------------------------------------- process control

    def find_xray(self, path: str = "") -> str:
        """Return the path to the Xray executable, or '' if not found.

        On Windows: ``bin/xray.exe``
        On Linux:   ``bin/xray``
        macOS is not supported.
        """
        bin_dir = Path(__file__).resolve().parents[2] / "bin"

        if os.name == "nt":
            platform_binary = bin_dir / "xray.exe"
        else:
            platform_binary = bin_dir / "xray"

        candidates = [
            path,
            os.environ.get("XRAY_EXECUTABLE", ""),
            str(platform_binary),
            str(bin_dir / "xray.exe"),
            str(bin_dir / "xray"),
            shutil.which("xray") or "",
        ]

        for c in candidates:
            if c and Path(c).is_file():
                return str(Path(c).resolve())
        return ""

    def connect(self, profile: dict, executable: str = "", local_port: int = DEFAULT_SOCKS_PORT) -> bool:
        """Start Xray with the given profile.

        If another profile is already connected, it is disconnected first.
        """
        self.disconnect()

        with self._lock:
            binary = self.find_xray(executable)
            if not binary:
                raise VPNError(
                    "Xray-core not found. Place xray.exe (Windows) or "
                    "xray (Linux) in the project's bin/ folder, or choose "
                    "its path."
                )

            config = self.build_config(profile, local_port)
            self.config_file.write_text(
                json.dumps(config, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )

            try:
                test = subprocess.run(
                    [binary, "run", "-test", "-c", str(self.config_file)],
                    capture_output=True, text=True, timeout=10,
                    **get_no_window_kwargs()
                )
            except subprocess.TimeoutExpired as exc:
                raise VPNError("Xray config validation timed out.") from exc
            except OSError as exc:
                raise VPNError(f"Could not run Xray: {exc}") from exc

            if test.returncode != 0:
                raise VPNError(
                    (test.stderr or test.stdout or "Xray config validation failed")
                    .strip()[-1200:]
                )

            try:
                log_handle = self.log_file.open("a", encoding="utf-8")
            except OSError:
                log_handle = subprocess.DEVNULL

            kwargs: dict[str, Any] = {
                "stdout": log_handle,
                "stderr": subprocess.STDOUT,
                "cwd": str(self.base_dir),
                **get_no_window_kwargs()
            }

            try:
                self.process = subprocess.Popen(
                    [binary, "run", "-c", str(self.config_file)],
                    **kwargs,
                )
            except OSError as exc:
                raise VPNError(f"Could not start Xray: {exc}") from exc

            return True

    def disconnect(self) -> None:
        """Terminate the running Xray process, if any."""
        with self._lock:
            p = self.process
            if not p:
                return
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    p.kill()
                    try:
                        p.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pass
            self.process = None

    def connected(self) -> bool:
        return bool(self.process and self.process.poll() is None)

    # ------------------------------------------------------- profile edit

    def remove(self, profile_id: str) -> None:
        self.profiles = [p for p in self.profiles if p.get("id") != profile_id]
        self._save()

    def read_log_tail(self, max_bytes: int = 8000) -> str:
        try:
            size = self.log_file.stat().st_size
            with self.log_file.open("rb") as handle:
                if size > max_bytes:
                    handle.seek(size - max_bytes)
                return handle.read().decode("utf-8", errors="replace")
        except (OSError, ValueError):
            return ""

    # ----------------------------------------------------------- proxy I/O

    def _open_socks(self, host: str, port: int, timeout: float = 5.0) -> socket.socket:
        sock = socket.create_connection(("127.0.0.1", DEFAULT_SOCKS_PORT), timeout=timeout)
        sock.settimeout(timeout)

        sock.sendall(b"\x05\x01\x00")
        resp = sock.recv(2)
        if resp != b"\x05\x00":
            sock.close()
            raise OSError("SOCKS5 greeting failed.")

        try:
            packed_ip = socket.inet_aton(host)
            req = b"\x05\x01\x00\x01" + packed_ip + struct.pack(">H", port)
        except OSError:
            host_bytes = host.encode("idna") if host.isascii() else host.encode("utf-8")
            if len(host_bytes) > 255:
                sock.close()
                raise OSError("Hostname too long for SOCKS5.")
            req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + struct.pack(">H", port)

        sock.sendall(req)
        resp = sock.recv(10)
        if not resp or resp[1] != 0:
            sock.close()
            raise OSError(f"SOCKS5 connect failed (code={resp[1] if len(resp) > 1 else '?'}).")
        return sock

    # ----------------------------------------------------------- verification

    def test_connection(self, timeout: float = 8.0) -> tuple[bool, str]:
        if not self.connected():
            return False, "Xray process is not running."

        try:
            start = time.perf_counter()
            sock = self._open_socks(TRACE_HOST, TRACE_PORT, timeout=timeout)
            http = (
                f"GET {TRACE_PATH} HTTP/1.1\r\n"
                f"Host: {TRACE_HOST}\r\n"
                f"User-Agent: CyberOpsSuite/1.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            sock.sendall(http)

            chunks: list[bytes] = []
            total = 0
            while total < 8192:
                data = sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
                total += len(data)
            sock.close()

            elapsed = (time.perf_counter() - start) * 1000.0
            body = b"".join(chunks).decode("utf-8", errors="replace")

            ip = ""
            for line in body.splitlines():
                if line.startswith("ip="):
                    ip = line[3:].strip()
                    break

            if not ip:
                return False, "Tunnel responded but no IP in trace response."

            return True, f"Connected — outbound IP: {ip} ({elapsed:.0f} ms)"
        except socket.timeout:
            return False, "Proxy timeout — server did not respond."
        except OSError as exc:
            return False, f"Proxy error: {exc}"
        except Exception as exc:
            return False, f"Verification failed: {exc}"

    # ----------------------------------------------------------- speed test

    def measure_down_speed(self, duration: float = 3.0) -> float:
        if not self.connected():
            return 0.0

        try:
            sock = self._open_socks(SPEED_HOST, 80, timeout=5.0)
            sock.settimeout(duration + 3.0)
            sock.sendall(
                f"GET {SPEED_DOWN_PATH} HTTP/1.1\r\n"
                f"Host: {SPEED_HOST}\r\n"
                f"User-Agent: CyberOpsSuite/1.0\r\n"
                f"Connection: close\r\n\r\n".encode("ascii")
            )

            start = time.perf_counter()
            total = 0
            while time.perf_counter() - start < duration:
                try:
                    data = sock.recv(65536)
                except socket.timeout:
                    break
                if not data:
                    break
                total += len(data)
            elapsed = time.perf_counter() - start
            sock.close()

            if elapsed <= 0:
                return 0.0
            return (total * 8) / (elapsed * 1_000_000)
        except Exception:
            return 0.0

    def measure_up_speed(self, duration: float = 3.0) -> float:
        if not self.connected():
            return 0.0

        try:
            sock = self._open_socks(SPEED_HOST, 80, timeout=5.0)
            sock.settimeout(duration + 3.0)

            chunk = b"x" * 65536
            total_bytes = 8 * 1024 * 1024
            sock.sendall(
                f"POST {SPEED_UP_PATH} HTTP/1.1\r\n"
                f"Host: {SPEED_HOST}\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Content-Length: {total_bytes}\r\n"
                f"Connection: close\r\n\r\n".encode("ascii")
            )

            start = time.perf_counter()
            sent = 0
            while sent < total_bytes and time.perf_counter() - start < duration:
                to_send = min(len(chunk), total_bytes - sent)
                sock.sendall(chunk[:to_send])
                sent += to_send
            elapsed = time.perf_counter() - start
            sock.close()

            if elapsed <= 0:
                return 0.0
            return (sent * 8) / (elapsed * 1_000_000)
        except Exception:
            return 0.0

    # -------------------------------------------------------------- ping

    @staticmethod
    def ping_profile(profile: dict, timeout: float = 3.0) -> float | None:
        host = profile.get("address")
        port = profile.get("port")
        if not host or not port:
            return None

        try:
            start = time.perf_counter()
            with socket.create_connection((host, int(port)), timeout=timeout):
                elapsed = (time.perf_counter() - start) * 1000.0
            return round(elapsed, 1)
        except (OSError, ValueError, TimeoutError):
            return None