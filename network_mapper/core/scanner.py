"""Network scanning primitives for CyberOpsSuite Network Mapper.

The scanner performs two kinds of probes:

* ICMP reachability using the platform's ``ping`` binary (cheap, but often
  blocked on hardened hosts).
* TCP connect probes against a configurable set of ports (slower per port
  but survives ICMP filtering, and an accepted connection is hard evidence
  that a host is up).

Both probes run concurrently: hosts are scanned in parallel with each other,
and the ports of a single host are scanned in parallel as well. The public
entry point is :meth:`NetworkScanner.scan_network`, which streams results
through an optional callback so the GUI can update while work is ongoing.
"""

from __future__ import annotations

import platform
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Iterable, Sequence

from .services import detect_service
from core.utils.subprocess_utils import get_no_window_kwargs


DEFAULT_PORTS: tuple[int, ...] = (22, 80, 443, 3389)
DEFAULT_HOST_WORKERS = 100
DEFAULT_PORT_WORKERS = 8
DEFAULT_TIMEOUT = 0.45

ResultCallback = Callable[["HostResult"], None]


@dataclass
class HostResult:
    """Outcome of scanning a single IPv4 address."""

    ip: str
    online: bool
    open_ports: list[int] = field(default_factory=list)
    services: dict[int, str] = field(default_factory=dict)


class NetworkScanner:
    """Concurrent ICMP + TCP scanner.

    Parameters
    ----------
    ports:
        TCP ports to probe on every host. Defaults to :data:`DEFAULT_PORTS`.
    max_host_workers:
        How many hosts to probe simultaneously.
    max_port_workers:
        How many ports of a *single* host to probe simultaneously.
    timeout:
        Per-port TCP connect timeout, in seconds.
    """

    def __init__(
        self,
        ports: Iterable[int] | None = None,
        max_host_workers: int = DEFAULT_HOST_WORKERS,
        max_port_workers: int = DEFAULT_PORT_WORKERS,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.ports: list[int] = sorted({int(p) for p in (ports or DEFAULT_PORTS)})
        self.max_host_workers = max(1, min(int(max_host_workers), 512))
        self.max_port_workers = max(1, min(int(max_port_workers), 64))
        self.timeout = max(0.1, min(float(timeout), 3.0))

        # Resolve platform-specific ping flags once, not per host.
        self._is_windows = platform.system().lower() == "windows"
        self._is_macos = platform.system().lower() == "darwin"
        self._ping_command = self._build_ping_command()

    # ------------------------------------------------------------------ ping

    def _build_ping_command(self) -> Callable[[str], list[str]]:
        """Return a function that builds the platform's ``ping`` argv."""
        if self._is_windows:
            # -n count, -w timeout in milliseconds
            return lambda ip: ["ping", "-n", "1", "-w", "1000", ip]
        if self._is_macos:
            # macOS uses -W in milliseconds, not seconds.
            return lambda ip: ["ping", "-c", "1", "-W", "1000", ip]
        # Linux and other POSIX: -c count, -W timeout in seconds
        return lambda ip: ["ping", "-c", "1", "-W", "1", ip]

    def ping(self, ip: str) -> bool:
        """Return ``True`` if the host answers ICMP within ~1 second."""
        try:
            completed = subprocess.run(
                self._ping_command(ip),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
                **get_no_window_kwargs()
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return completed.returncode == 0

    # ------------------------------------------------------------------ port

    def scan_port(self, ip: str, port: int) -> bool:
        """Return ``True`` if a TCP connection to ``ip:port`` succeeds."""
        try:
            with socket.create_connection((ip, port), timeout=self.timeout):
                return True
        except (OSError, TimeoutError):
            return False

    def _scan_ports(self, ip: str, controller=None) -> list[int]:
        """Probe every configured port on ``ip`` in parallel."""
        if not self.ports:
            return []

        workers = min(self.max_port_workers, len(self.ports))
        open_ports: list[int] = []

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(self.scan_port, ip, port): port for port in self.ports}
            for future in as_completed(futures):
                if controller and controller.stopped:
                    break
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception:
                    # A failing probe should never abort the whole host.
                    continue

        return sorted(open_ports)

    # ------------------------------------------------------------------ host

    def scan_host(self, ip: str, controller=None) -> HostResult:
        """Scan a single host: ICMP first, then TCP probes if needed.

        TCP is always attempted even when ICMP fails, because many hosts
        block ping but expose services.
        """
        if controller is not None and hasattr(controller, "wait_if_paused"):
            controller.wait_if_paused()

        icmp_online = self.ping(ip)
        open_ports = self._scan_ports(ip, controller)

        online = icmp_online or bool(open_ports)
        services = {port: detect_service(port) for port in open_ports}
        return HostResult(ip=ip, online=online, open_ports=open_ports, services=services)

    # --------------------------------------------------------------- network

    def scan_network(
        self,
        ip_list: Sequence[str],
        controller=None,
        on_result: ResultCallback | None = None,
    ) -> list[HostResult]:
        """Scan every IP in ``ip_list`` concurrently.

        Parameters
        ----------
        ip_list:
            Addresses to scan.
        controller:
            Optional object exposing ``stopped`` (bool) and, ideally,
            ``wait_if_paused()``. Used to allow the GUI to cancel or pause.
        on_result:
            Called from the *worker thread* as soon as each host finishes.
            The GUI is expected to marshal this onto its own thread (for
            example, by pushing into a :class:`queue.Queue`).

        Returns
        -------
        list[HostResult]
            Results in completion order. Partially filled if the controller
            requested a stop.
        """
        if not ip_list:
            return []

        results: list[HostResult] = []
        workers = min(self.max_host_workers, len(ip_list))

        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(self.scan_host, ip, controller): ip
                for ip in ip_list
            }

            for future in as_completed(futures):
                if controller and controller.stopped:
                    # Cancel anything still queued; running probes finish.
                    for pending in futures:
                        pending.cancel()
                    break

                try:
                    result = future.result()
                except Exception:
                    # A single host failing must not kill the whole scan.
                    ip = futures[future]
                    result = HostResult(ip=ip, online=False)

                results.append(result)
                if on_result is not None:
                    try:
                        on_result(result)
                    except Exception:
                        # Never let a GUI callback break the scan loop.
                        pass

        return results