"""Tor controller for IP Rotator.

Talks to Tor's ControlPort directly (control-spec: PROTOCOLINFO, SAFECOOKIE /
COOKIE / NULL / HASHEDPASSWORD authentication, SIGNAL NEWNYM), so the optional
``stem`` package is **not required**. If the built-in client cannot
authenticate and ``stem`` happens to be installed, it is used as a fallback.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import socket
from pathlib import Path

# 9151 = Tor Browser, 9051 = Tor Expert Bundle / system tor service.
DEFAULT_CONTROL_PORTS: tuple[int, ...] = (9151, 9051)

_SAFECOOKIE_SERVER_KEY = b"Tor safe cookie authentication server-to-controller hash"
_SAFECOOKIE_CLIENT_KEY = b"Tor safe cookie authentication controller-to-server hash"


class TorControlError(Exception):
    """Raised when the Tor ControlPort conversation fails."""


class _Connection:
    """Minimal line-based Tor control-port client."""

    def __init__(self, host: str, port: int, timeout: float = 5.0) -> None:
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self._buf = b""

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self) -> "_Connection":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def send(self, line: str) -> None:
        self.sock.sendall(line.encode("utf-8") + b"\r\n")

    def _readline(self) -> str:
        while b"\r\n" not in self._buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise TorControlError("Tor closed the control connection.")
            self._buf += chunk
        line, _, self._buf = self._buf.partition(b"\r\n")
        return line.decode("utf-8", "replace")

    def read_reply(self) -> tuple[int, list[str]]:
        """Read one complete reply -> (status code, text lines)."""
        lines: list[str] = []
        while True:
            line = self._readline()
            if len(line) < 4 or not line[:3].isdigit():
                raise TorControlError(f"Unexpected reply from Tor: {line!r}")
            code, sep, text = int(line[:3]), line[3], line[4:]
            lines.append(text)
            if sep == "+":  # data block, terminated by a lone "."
                while True:
                    extra = self._readline()
                    if extra == ".":
                        break
                    lines.append(extra)
            elif sep == " ":
                return code, lines
            elif sep != "-":
                raise TorControlError(f"Malformed reply from Tor: {line!r}")

    def command(self, line: str) -> tuple[int, list[str]]:
        self.send(line)
        return self.read_reply()


def _unescape(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value)


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _authenticate(conn: _Connection, password: str | None) -> None:
    code, lines = conn.command("PROTOCOLINFO 1")
    if code != 250:
        raise TorControlError(f"PROTOCOLINFO failed: {' '.join(lines)}")

    methods: set[str] = set()
    cookie_file: str | None = None
    for line in lines:
        if line.startswith("AUTH "):
            found = re.search(r"METHODS=([A-Z,]+)", line)
            if found:
                methods = set(found.group(1).split(","))
            cookie = re.search(r'COOKIEFILE="((?:[^"\\]|\\.)*)"', line)
            if cookie:
                cookie_file = _unescape(cookie.group(1))

    last_error = "no usable authentication method"

    if "NULL" in methods:
        code, lines = conn.command("AUTHENTICATE")
        if code == 250:
            return
        last_error = " ".join(lines)

    cookie_bytes: bytes | None = None
    if cookie_file and ({"SAFECOOKIE", "COOKIE"} & methods):
        try:
            cookie_bytes = Path(cookie_file).read_bytes()
        except OSError as exc:
            last_error = f"cannot read Tor cookie file ({exc})"

    if cookie_bytes and "SAFECOOKIE" in methods:
        client_nonce = secrets.token_bytes(32)
        code, lines = conn.command(f"AUTHCHALLENGE SAFECOOKIE {client_nonce.hex()}")
        match = re.match(
            r"AUTHCHALLENGE SERVERHASH=([0-9A-Fa-f]+) SERVERNONCE=([0-9A-Fa-f]+)",
            lines[0] if lines else "",
        )
        if code == 250 and match:
            server_hash = bytes.fromhex(match.group(1))
            server_nonce = bytes.fromhex(match.group(2))
            message = cookie_bytes + client_nonce + server_nonce
            expected = hmac.new(_SAFECOOKIE_SERVER_KEY, message, hashlib.sha256).digest()
            if not hmac.compare_digest(expected, server_hash):
                raise TorControlError("Tor failed the SAFECOOKIE server check.")
            client_hash = hmac.new(_SAFECOOKIE_CLIENT_KEY, message, hashlib.sha256).digest()
            code, lines = conn.command(f"AUTHENTICATE {client_hash.hex()}")
            if code == 250:
                return
            last_error = " ".join(lines)
        else:
            last_error = " ".join(lines)
            # Tor closes nothing on a refused challenge, but start clean anyway.

    if cookie_bytes and "COOKIE" in methods:
        code, lines = conn.command(f"AUTHENTICATE {cookie_bytes.hex()}")
        if code == 250:
            return
        last_error = " ".join(lines)

    if password and "HASHEDPASSWORD" in methods:
        code, lines = conn.command(f"AUTHENTICATE {_quote(password)}")
        if code == 250:
            return
        last_error = " ".join(lines)
    elif "HASHEDPASSWORD" in methods and not cookie_bytes and "NULL" not in methods:
        last_error = "ControlPort needs a password (set the TOR_CONTROL_PASSWORD environment variable)"

    raise TorControlError(f"Authentication failed: {last_error}")


class TorController:
    def __init__(
        self,
        host: str = "127.0.0.1",
        control_port: int | None = None,
        socks_port: int = 9050,
        password: str | None = None,
    ) -> None:
        self.host = host
        self.control_port = control_port  # None -> auto-detect (9151, then 9051)
        self.socks_port = socks_port
        self.password = password or os.environ.get("TOR_CONTROL_PASSWORD")
        self.last_control_port: int | None = None

    def _candidate_ports(self) -> tuple[int, ...]:
        return (self.control_port,) if self.control_port else DEFAULT_CONTROL_PORTS

    def _newnym_builtin(self, port: int) -> None:
        with _Connection(self.host, port) as conn:
            _authenticate(conn, self.password)
            code, lines = conn.command("SIGNAL NEWNYM")
            if code != 250:
                raise TorControlError(f"NEWNYM refused: {' '.join(lines)}")

    def _newnym_stem(self, port: int) -> None:
        from stem import Signal  # optional fallback
        from stem.control import Controller

        with Controller.from_port(address=self.host, port=port) as controller:
            controller.authenticate(password=self.password)
            controller.signal(Signal.NEWNYM)

    def change_identity(self) -> tuple[bool, str]:
        """Send NEWNYM to Tor so the next circuits use a new exit IP."""
        refused: list[int] = []
        auth_errors: list[str] = []

        for port in self._candidate_ports():
            try:
                self._newnym_builtin(port)
            except TorControlError as exc:
                try:  # optional stem fallback, only if it is installed
                    self._newnym_stem(port)
                except Exception:
                    auth_errors.append(f"port {port}: {exc}")
                    continue
            except OSError:  # refused / timeout / reset -> nothing usable here
                refused.append(port)
                continue
            self.last_control_port = port
            return True, (
                f"New identity requested via ControlPort {port}. "
                "The IP changes within a few seconds (Tor allows ~1 request / 10 s)."
            )

        if auth_errors:
            return False, "Tor is running but refused access: " + "; ".join(auth_errors)
        tried = ", ".join(str(p) for p in refused or self._candidate_ports())
        return False, (
            f"Could not reach the Tor ControlPort (tried {tried}). "
            "Start Tor Browser, or enable 'ControlPort 9051' + 'CookieAuthentication 1' in torrc."
        )
