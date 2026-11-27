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

import signal
import ssl

try:  # Inside the full CyberOpsSuite project.
    from core.utils.paths import config_root
    from core.utils.subprocess_utils import get_no_window_kwargs
except ImportError:  # Standalone fallback so CLI/API still work.
    def config_root(app_name: str) -> Path:
        if os.name == "nt":
            base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        else:
            base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
        path = base / "CyberOpsSuite" / app_name
        path.mkdir(parents=True, exist_ok=True)
        return path

    def get_no_window_kwargs() -> dict:
        if os.name == "nt":
            return {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)}
        return {}


# ---------------------------------------------------------------- paths

APP_DIR_NAME = "VpnManager"

#: Default local SOCKS5 port.
DEFAULT_SOCKS_PORT = 10808

#: Cloudflare trace endpoint used to verify the tunnel.
TRACE_HOST = "1.1.1.1"
TRACE_PORT = 80
TRACE_PATH = "/cdn-cgi/trace"

#: Lightweight "is the tunnel alive" checks (HTTPS, tried in order).
CHECK_URLS = (
    ("cp.cloudflare.com", "/generate_204"),
    ("www.gstatic.com", "/generate_204"),
)

#: Sites the per-profile tester opens through the tunnel.
SITE_TESTS = (
    ("YouTube", "www.youtube.com", "/generate_204"),
    ("Instagram", "www.instagram.com", "/"),
    ("X", "x.com", "/"),
    ("Telegram", "web.telegram.org", "/"),
)

#: Speed-test endpoints (HTTPS through the SOCKS tunnel).
SPEED_HOST = "speed.cloudflare.com"
SPEED_PORT = 443
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
        self.pid_file = self.base_dir / "xray.pid"
        self.local_port: int = DEFAULT_SOCKS_PORT
        self.sysproxy_file = self.base_dir / "sysproxy.json"
        #: When True, connect() points the OS proxy at Xray's HTTP port.
        self.use_system_proxy: bool = False
        self.sysproxy_error: str = ""
        self._tls_context: ssl.SSLContext | None = None  # test hook

        self.process: subprocess.Popen | None = None
        self._lock = threading.Lock()
        self.profiles: list[dict] = self._load_profiles()

        atexit.register(self._atexit_cleanup)
        self._kill_orphans()
        self.clear_system_proxy()  # undo a proxy left by a crashed run

    # -------------------------------------------------------- lifecycle

    def _atexit_cleanup(self) -> None:
        try:
            self.disconnect()
        except Exception:
            pass

    def _pid_is_xray(self, pid: int) -> bool:
        """True only if *pid* is alive and really is an Xray process."""
        try:
            if os.name == "nt":
                out = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
                    capture_output=True, text=True, check=False,
                    **get_no_window_kwargs()
                ).stdout.lower()
                return "xray" in out
            cmd = Path(f"/proc/{pid}/cmdline").read_bytes().lower()
            return b"xray" in cmd
        except (OSError, subprocess.SubprocessError):
            return False

    def _kill_orphans(self) -> None:
        """Kill the Xray process left behind by OUR previous run (pid file).

        The old version killed every ``xray.exe`` / anything matching
        ``/xray`` on the machine, which also killed other apps (v2rayN,
        Nekoray, ...). Now only the PID we started ourselves is touched.
        """
        try:
            pid = int(self.pid_file.read_text().strip())
        except (OSError, ValueError):
            return
        try:
            if self._pid_is_xray(pid):
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/F", "/PID", str(pid)],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        check=False, **get_no_window_kwargs()
                    )
                else:
                    os.kill(pid, signal.SIGTERM)
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            self.pid_file.unlink()
        except OSError:
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
                # VMess share links keep the gRPC service name in "path".
                "serviceName": (
                    p.get("serviceName") or p.get("service_name") or p.get("path", "")
                ),
            }

        elif network == "httpupgrade":
            hu: dict[str, Any] = {"path": p.get("path", "/") or "/"}
            if p.get("host"):
                hu["host"] = p["host"]
            stream["httpupgradeSettings"] = hu

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
        if security == "tls":
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
            # Certificate pin from the link (pcs / pinSHA256): lets servers
            # with a self-signed cert work without allowInsecure.
            pin = (p.get("pcs") or p.get("pinSHA256") or "").replace(":", "").strip().lower()
            if pin:
                tls["pinnedPeerCertSha256"] = [x for x in pin.split(",") if x]
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
            # Use the link's own encryption (VLESS "mlkem768x25519plus..."
            # post-quantum encryption) and flow. Never invent a flow: if the
            # link has none, the server has none, and forcing Vision breaks it.
            user["encryption"] = params.get("encryption") or "none"
            flow = params.get("flow")
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

        # Mux is intentionally NOT enabled: it stalls many servers and was a
        # common source of timeouts. Hiddify/v2rayN also default to off.

        return {
            "log": {"loglevel": "warning"},
            "dns": {
                "servers": [
                    {
                        "address": "localhost",
                        "domains": ["geosite:category-ir", "domain:ir"],
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
                "domainStrategy": "AsIs",
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
                log_start = self.log_file.stat().st_size
            except OSError:
                log_start = 0
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

            self.local_port = int(local_port)
            try:
                self.pid_file.write_text(str(self.process.pid))
            except OSError:
                pass

            # Wait until Xray really listens (or dies). Without this the
            # first test ran before the port was open and "connected" was
            # reported even when Xray had crashed a moment later.
            deadline = time.monotonic() + 8.0
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    tail = self._log_since(log_start)
                    self.process = None
                    raise VPNError(
                        "Xray exited right after start.\n\n"
                        + (tail or "No log output — check the Xray binary and geo files.")
                    )
                try:
                    socket.create_connection(("127.0.0.1", self.local_port), timeout=0.3).close()
                    if self.use_system_proxy:
                        self.set_system_proxy()
                    return True
                except OSError:
                    time.sleep(0.15)

            tail = self._log_since(log_start)
            p = self.process
            self.process = None
            try:
                p.terminate()
            except OSError:
                pass
            raise VPNError(
                f"Xray did not open local port {self.local_port} within 8s.\n\n"
                + (tail or "")
            )

    def _log_since(self, offset: int, limit: int = 1200) -> str:
        try:
            with self.log_file.open("rb") as handle:
                handle.seek(offset)
                return handle.read().decode("utf-8", errors="replace").strip()[-limit:]
        except OSError:
            return ""

    def disconnect(self) -> None:
        """Terminate the running Xray process, if any."""
        self.clear_system_proxy()
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
            try:
                self.pid_file.unlink()
            except OSError:
                pass

    # ------------------------------------------------------ system proxy

    _WIN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    _BYPASS = ("localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.2*;"
               "172.30.*;172.31.*;192.168.*;<local>")

    @staticmethod
    def _win_refresh() -> None:
        import ctypes
        wininet = ctypes.windll.wininet
        wininet.InternetSetOptionW(0, 39, 0, 0)  # SETTINGS_CHANGED
        wininet.InternetSetOptionW(0, 37, 0, 0)  # REFRESH

    def set_system_proxy(self) -> bool:
        """Point the OS proxy at Xray's HTTP inbound (port + 1).

        Windows: per-user Internet Settings (used by Chrome, Edge, Firefox
        with 'use system proxy', most apps). Linux: GNOME gsettings.
        The previous values are saved and restored by clear_system_proxy().
        """
        self.sysproxy_error = ""
        host, port = "127.0.0.1", self.local_port + 1
        try:
            if os.name == "nt":
                import winreg
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self._WIN_KEY, 0,
                                    winreg.KEY_ALL_ACCESS) as key:
                    if not self.sysproxy_file.exists():
                        prev = {}
                        for name in ("ProxyEnable", "ProxyServer", "ProxyOverride"):
                            try:
                                prev[name] = winreg.QueryValueEx(key, name)[0]
                            except OSError:
                                prev[name] = None
                        self.sysproxy_file.write_text(json.dumps(prev), encoding="utf-8")
                    winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"{host}:{port}")
                    winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, self._BYPASS)
                    winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                self._win_refresh()
            elif shutil.which("gsettings"):
                if not self.sysproxy_file.exists():
                    mode = subprocess.run(
                        ["gsettings", "get", "org.gnome.system.proxy", "mode"],
                        capture_output=True, text=True, check=False).stdout.strip().strip("'")
                    self.sysproxy_file.write_text(json.dumps({"mode": mode or "none"}), encoding="utf-8")
                for schema in ("http", "https"):
                    base = f"org.gnome.system.proxy.{schema}"
                    subprocess.run(["gsettings", "set", base, "host", host], check=False)
                    subprocess.run(["gsettings", "set", base, "port", str(port)], check=False)
                subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"], check=False)
            else:
                self.sysproxy_error = "System proxy is not supported on this desktop."
                return False
            return True
        except Exception as exc:  # registry/gsettings failures must not break connect
            self.sysproxy_error = f"Could not set system proxy: {exc}"
            return False

    def clear_system_proxy(self) -> None:
        """Restore the OS proxy settings saved by set_system_proxy()."""
        if not self.sysproxy_file.exists():
            return
        try:
            prev = json.loads(self.sysproxy_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            prev = {}
        try:
            if os.name == "nt":
                import winreg
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self._WIN_KEY, 0,
                                    winreg.KEY_ALL_ACCESS) as key:
                    for name, kind in (("ProxyServer", winreg.REG_SZ),
                                       ("ProxyOverride", winreg.REG_SZ),
                                       ("ProxyEnable", winreg.REG_DWORD)):
                        old = prev.get(name)
                        if old is None:
                            try:
                                winreg.DeleteValue(key, name)
                            except OSError:
                                pass
                        else:
                            winreg.SetValueEx(key, name, 0, kind, old)
                    if prev.get("ProxyEnable") is None:
                        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                self._win_refresh()
            elif shutil.which("gsettings"):
                subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode",
                                prev.get("mode", "none")], check=False)
        except Exception:
            pass
        try:
            self.sysproxy_file.unlink()
        except OSError:
            pass

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

    def _open_socks(self, host: str, port: int, timeout: float = 5.0,
                    socks_port: int | None = None) -> socket.socket:
        sock = socket.create_connection(("127.0.0.1", socks_port or self.local_port), timeout=timeout)
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

    def _https_get(self, host: str, path: str, timeout: float = 8.0,
                   socks_port: int | None = None,
                   context: ssl.SSLContext | None = None) -> tuple[int, float]:
        """GET https://host/path through the SOCKS tunnel -> (status, ms)."""
        start = time.perf_counter()
        sock = self._open_socks(host, 443, timeout=timeout, socks_port=socks_port)
        try:
            ctx = context or self._tls_context or ssl.create_default_context()
            tls = ctx.wrap_socket(sock, server_hostname=host)
            tls.settimeout(timeout)
            tls.sendall(
                f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                f"User-Agent: Mozilla/5.0 CyberOpsSuite\r\nAccept: */*\r\n"
                f"Connection: close\r\n\r\n".encode("ascii")
            )
            buf = b""
            while b"\r\n" not in buf and len(buf) < 4096:
                chunk = tls.recv(1024)
                if not chunk:
                    break
                buf += chunk
            line = buf.split(b"\r\n", 1)[0].decode("latin-1")
            parts = line.split()
            if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
                raise OSError(f"bad response {line[:50]!r}")
            return int(parts[1]), (time.perf_counter() - start) * 1000.0
        finally:
            sock.close()

    def test_connection(self, timeout: float = 8.0) -> tuple[bool, str]:
        """Check that the tunnel really carries HTTPS traffic."""
        if not self.connected():
            return False, "Xray process is not running."

        last = "No response."
        for host, path in CHECK_URLS:
            try:
                status, ms = self._https_get(host, path, timeout=timeout)
                if status < 500:
                    return True, f"Connected — {host} answered {status} ({ms:.0f} ms)"
                last = f"{host} returned HTTP {status}"
            except socket.timeout:
                last = "Proxy timeout — server did not respond."
            except OSError as exc:
                last = f"Proxy error: {exc}"
            except Exception as exc:
                last = f"Verification failed: {exc}"
        return False, last

    # ------------------------------------------------- per-profile site test

    def test_profile_sites(self, profile: dict, executable: str = "",
                           socks_port: int = 21080, sites=SITE_TESTS,
                           timeout: float = 8.0,
                           context: ssl.SSLContext | None = None) -> dict:
        """Start a throw-away Xray for *profile* and open each site through it.

        Runs on its own ports, so it never disturbs the active connection.
        """
        binary = self.find_xray(executable)
        if not binary:
            raise VPNError("Xray-core not found (see Locate xray).")

        cfg_path = self.base_dir / f"test_{socks_port}.json"
        log_path = self.base_dir / f"test_{socks_port}.log"
        cfg_path.write_text(json.dumps(self.build_config(profile, socks_port)), encoding="utf-8")
        result: dict[str, Any] = {
            "id": profile.get("id"), "name": profile.get("name", "?"),
            "error": "", "sites": {},
        }
        proc = None
        try:
            with log_path.open("wb") as log:
                proc = subprocess.Popen(
                    [binary, "run", "-c", str(cfg_path)],
                    stdout=log, stderr=subprocess.STDOUT, cwd=str(self.base_dir),
                    **get_no_window_kwargs()
                )
            deadline = time.monotonic() + 8.0
            ready = False
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    break
                try:
                    socket.create_connection(("127.0.0.1", socks_port), timeout=0.3).close()
                    ready = True
                    break
                except OSError:
                    time.sleep(0.15)
            if not ready:
                try:
                    tail = log_path.read_text(encoding="utf-8", errors="replace").strip()[-300:]
                except OSError:
                    tail = ""
                result["error"] = tail or "Xray did not start."
                return result

            for name, host, path in sites:
                try:
                    status, ms = self._https_get(host, path, timeout=timeout,
                                                 socks_port=socks_port, context=context)
                    result["sites"][name] = {
                        "ok": status < 500 and status != 407,
                        "status": status, "ms": round(ms),
                    }
                except socket.timeout:
                    result["sites"][name] = {"ok": False, "error": "timeout"}
                except Exception as exc:
                    result["sites"][name] = {"ok": False, "error": str(exc)[:40]}
            return result
        finally:
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
            for f in (cfg_path, log_path):
                try:
                    f.unlink()
                except OSError:
                    pass

    def test_all_profiles(self, profiles: list[dict], executable: str = "",
                          jobs: int = 4, progress=None, **kwargs) -> list[dict]:
        """Test every profile (parallel, own ports); best result first."""
        from concurrent.futures import ThreadPoolExecutor

        def one(item):
            i, prof = item
            try:
                res = self.test_profile_sites(prof, executable,
                                              socks_port=21080 + 2 * i, **kwargs)
            except Exception as exc:
                res = {"id": prof.get("id"), "name": prof.get("name", "?"),
                       "error": str(exc), "sites": {}}
            if progress:
                try:
                    progress(res)
                except Exception:
                    pass
            return res

        with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
            results = list(pool.map(one, enumerate(profiles)))

        def key(r):
            oks = [v for v in r["sites"].values() if v.get("ok")]
            avg = sum(v["ms"] for v in oks) / len(oks) if oks else 1e9
            return (-len(oks), avg)

        return sorted(results, key=key)

    @staticmethod
    def format_site_results(results: list[dict]) -> str:
        lines = []
        for r in results:
            sites = r.get("sites", {})
            if r.get("error"):
                lines.append(f"✗ 0/{len(SITE_TESTS)}  {r['name']}  —  {r['error'][:80]}")
                continue
            oks = sum(1 for v in sites.values() if v.get("ok"))
            parts = []
            for name, v in sites.items():
                parts.append(f"{name} {v['status']} {v['ms']}ms" if v.get("ok")
                             else f"{name} ✗ {v.get('error', v.get('status', '?'))}")
            mark = "✓" if oks == len(sites) and sites else ("~" if oks else "✗")
            lines.append(f"{mark} {oks}/{len(sites)}  {r['name']}  —  " + "  |  ".join(parts))
        return "\n".join(lines)

    # ----------------------------------------------------------- speed test

    def _open_tls(self, timeout: float):
        sock = self._open_socks(SPEED_HOST, SPEED_PORT, timeout=timeout)
        ctx = ssl.create_default_context()
        return ctx.wrap_socket(sock, server_hostname=SPEED_HOST)

    def measure_down_speed(self, duration: float = 3.0) -> float:
        if not self.connected():
            return 0.0
        try:
            sock = self._open_tls(5.0)
            sock.settimeout(duration + 3.0)
            sock.sendall(
                f"GET {SPEED_DOWN_PATH} HTTP/1.1\r\n"
                f"Host: {SPEED_HOST}\r\n"
                f"User-Agent: CyberOpsSuite/1.0\r\n"
                f"Connection: close\r\n\r\n".encode("ascii")
            )
            # Read headers first so they are not counted as payload.
            head = b""
            while b"\r\n\r\n" not in head and len(head) < 16384:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                head += chunk
            header, _, body = head.partition(b"\r\n\r\n")
            if b" 200" not in header.split(b"\r\n", 1)[0]:
                sock.close()
                return 0.0

            start = time.perf_counter()
            total = len(body)
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
            sock = self._open_tls(5.0)
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