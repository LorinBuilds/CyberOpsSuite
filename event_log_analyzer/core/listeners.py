"""Shared infrastructure for the UDP network log sources (Syslog, NetFlow).

Both listeners used to duplicate the socket/thread/queue code. It now lives
here once, together with the things both of them were missing:

* a validated allow-list (typos used to silently block every sender),
* reliable "port already in use" detection (``SO_REUSEADDR`` on UDP lets two
  programs bind the same port, so the old error never appeared),
* counters so the GUI can show *why* nothing arrives (rejected sender,
  malformed packet, unsupported NetFlow version, full queue...).

Everything here is read-only: the listeners only receive datagrams.
"""

from __future__ import annotations

import errno
import ipaddress
import queue
import socket
import threading
from dataclasses import dataclass

from .parser import LogEntry

#: Windows error codes that ``errno`` does not map portably.
_WSAEADDRINUSE = 10048
_WSAEACCES = 10013


class AllowListError(ValueError):
    """Raised when the allow-list contains something that is not an IP address."""


def parse_allow_list(text: str) -> set[str]:
    """Parse ``"10.0.0.1, 10.0.0.2"`` into a normalised set of IP strings.

    Commas, semicolons and whitespace are accepted as separators. An empty
    string means "accept everyone". Invalid entries raise
    :class:`AllowListError` instead of being silently ignored.
    """
    result: set[str] = set()
    for part in text.replace(";", ",").replace(" ", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            result.add(str(ipaddress.ip_address(part)))
        except ValueError:
            raise AllowListError(f"'{part}' is not a valid IP address.") from None
    return result


def guess_local_ip() -> str:
    """Best-effort LAN address of this machine (no packet is actually sent)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("10.255.255.255", 1))
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


@dataclass
class ListenerStats:
    """Counters updated by the listener thread and read by the GUI."""

    packets: int = 0          # datagrams received from allowed senders
    events: int = 0           # LogEntry objects produced
    rejected: int = 0         # datagrams from senders outside the allow-list
    malformed: int = 0        # datagrams that produced no event
    unsupported: int = 0      # e.g. NetFlow v9 / IPFIX (only v5 is supported)
    queue_dropped: int = 0    # events lost because the GUI/consumer was too slow
    last_unsupported: str = ""


class UdpListener:
    """Background UDP receiver that turns datagrams into :class:`LogEntry` objects.

    Subclasses implement :meth:`handle_datagram`.
    """

    name = "UDP"

    def __init__(
        self,
        port: int,
        host: str = "0.0.0.0",
        allow_ips: set[str] | None = None,
        max_queue: int = 20000,
    ):
        self.port = port
        self.host = host
        self.allow_ips = set(allow_ips or ())
        self.out_queue: queue.Queue[LogEntry] = queue.Queue(maxsize=max_queue)
        self.stats = ListenerStats()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._running = threading.Event()

    # ------------------------------------------------------------ to override

    def handle_datagram(self, data: bytes, source_ip: str) -> list[LogEntry]:
        raise NotImplementedError

    # --------------------------------------------------------------- lifecycle

    @property
    def running(self) -> bool:
        return self._running.is_set()

    @property
    def dropped(self) -> int:  # kept for backwards compatibility
        return self.stats.queue_dropped

    def start(self) -> None:
        if self._running.is_set():
            return
        family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        # Do NOT set SO_REUSEADDR: for UDP it lets a second program bind the
        # same port, which hides "port already in use" and steals packets.
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):  # Windows
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            except OSError:
                pass
        try:  # bigger buffer = fewer lost packets during bursts (best effort)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        except OSError:
            pass
        try:
            sock.bind((self.host, self.port))
        except OSError as exc:
            sock.close()
            raise RuntimeError(self._bind_error_message(exc)) from exc

        sock.settimeout(0.5)
        self._sock = sock
        self.stats = ListenerStats()
        self._running.set()
        self._thread = threading.Thread(
            target=self._loop, name=f"{self.name}-listener", daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._running.clear()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=1.5)
            self._thread = None

    def _bind_error_message(self, exc: OSError) -> str:
        code = exc.errno
        where = f"UDP {self.host}:{self.port}"
        if code in (errno.EADDRINUSE, _WSAEADDRINUSE):
            return (
                f"{where} is already in use by another program. "
                "Close it or choose a different port."
            )
        if code in (errno.EACCES, _WSAEACCES):
            hint = (
                "Ports below 1024 need administrator/root rights, "
                "so try a port such as 5140 (Syslog) or 2055 (NetFlow)."
                if self.port < 1024
                else "Another program may be using this port exclusively."
            )
            return f"Permission denied for {where}. {hint}"
        return f"Could not listen on {where}: {exc}"

    # -------------------------------------------------------------------- loop

    def drain(self, limit: int = 1000) -> list[LogEntry]:
        """Return up to *limit* queued events without blocking."""
        items: list[LogEntry] = []
        while len(items) < limit:
            try:
                items.append(self.out_queue.get_nowait())
            except queue.Empty:
                break
        return items

    def _loop(self) -> None:
        sock = self._sock
        if sock is None:
            return
        stats = self.stats
        while self._running.is_set():
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break

            source_ip = addr[0]
            if self.allow_ips and source_ip not in self.allow_ips:
                stats.rejected += 1
                continue
            stats.packets += 1

            unsupported_before = stats.unsupported
            try:
                entries = self.handle_datagram(data, source_ip)
            except Exception:  # a bad packet must never kill the listener
                entries = []
            if not entries:
                if stats.unsupported == unsupported_before:
                    stats.malformed += 1
                continue

            for entry in entries:
                try:
                    self.out_queue.put_nowait(entry)
                    stats.events += 1
                except queue.Full:
                    stats.queue_dropped += 1
