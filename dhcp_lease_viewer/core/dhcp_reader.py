"""Cross-platform local DHCP and network diagnostics."""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import subprocess
from typing import Any

from core.utils.subprocess_utils import get_no_window_kwargs

DEFAULT_TIMEOUT = 12


def _run(args: list[str], timeout: int = DEFAULT_TIMEOUT) -> str:
    completed = subprocess.run(
        args, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout,
        **get_no_window_kwargs()
    )
    if completed.returncode:
        message = (completed.stderr or "").strip() or f"Command failed: {args[0]}"
        raise RuntimeError(message)
    return completed.stdout


class DHCPLease:
    """A single DHCP lease observed on the local machine."""

    __slots__ = ("ip", "mac", "hostname", "start", "end", "dhcp_server", "adapter")

    def __init__(
        self, ip: str, mac: str, hostname: str,
        start: dt.datetime | None, end: dt.datetime | None,
        dhcp_server: str = "", adapter: str = "",
    ) -> None:
        self.ip = ip
        self.mac = mac
        self.hostname = hostname
        self.start = start
        self.end = end
        self.dhcp_server = dhcp_server
        self.adapter = adapter

    @property
    def remaining(self) -> dt.timedelta | None:
        return self.end - dt.datetime.now() if self.end else None

    def __repr__(self) -> str:
        return f"DHCPLease(ip={self.ip!r}, mac={self.mac!r}, hostname={self.hostname!r})"


# ------------------------------------------------------------------ Windows

_WINDOWS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$items = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled = TRUE AND DHCPEnabled = TRUE" | ForEach-Object {
 $cfg=$_
 $start=if($cfg.DHCPLeaseObtained){([datetime]$cfg.DHCPLeaseObtained).ToString('yyyy-MM-dd HH:mm:ss')}else{$null}
 $end=if($cfg.DHCPLeaseExpires){([datetime]$cfg.DHCPLeaseExpires).ToString('yyyy-MM-dd HH:mm:ss')}else{$null}
 foreach($address in @($cfg.IPAddress)){if($address -match '^\d{1,3}(\.\d{1,3}){3}$'){
 [pscustomobject]@{ip=$address;mac=[string]$cfg.MACAddress;hostname=[string]$cfg.DNSHostName;start=$start;end=$end;dhcp_server=[string]$cfg.DHCPServer;adapter=[string]$cfg.Description}
 }}
})
ConvertTo-Json -InputObject @($items) -Depth 4 -Compress
"""

_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def _read_windows_leases() -> list[DHCPLease]:
    output = _run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-Command", _WINDOWS_SCRIPT],
        timeout=15,
    ).strip()
    records: list[dict[str, Any]] = json.loads(output) if output else []
    if isinstance(records, dict):
        records = [records]

    leases: list[DHCPLease] = []
    for record in records:
        try:
            ip = ipaddress.ip_address(record.get("ip", ""))
            start = (
                dt.datetime.strptime(record["start"], _DATE_FORMAT)
                if record.get("start") else None
            )
            end = (
                dt.datetime.strptime(record["end"], _DATE_FORMAT)
                if record.get("end") else None
            )
            if ip.version != 4 or ip.is_loopback or ip.is_link_local:
                continue
        except (ValueError, TypeError, KeyError):
            continue

        leases.append(DHCPLease(
            ip=str(ip),
            mac=str(record.get("mac") or "—").replace("-", ":").upper(),
            hostname=str(record.get("hostname") or socket.gethostname()),
            start=start, end=end,
            dhcp_server=str(record.get("dhcp_server") or ""),
            adapter=str(record.get("adapter") or ""),
        ))
    return leases


# -------------------------------------------------------------------- Linux

_LINUX_LEASE_DIR = "/run/systemd/netif/leases"


def _read_linux_leases() -> list[DHCPLease]:
    result: list[DHCPLease] = []
    if not os.path.isdir(_LINUX_LEASE_DIR):
        return result

    for name in os.listdir(_LINUX_LEASE_DIR):
        path = os.path.join(_LINUX_LEASE_DIR, name)
        try:
            values: dict[str, str] = {}
            with open(path, encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    if "=" in line:
                        key, value = line.rstrip("\n").split("=", 1)
                        values[key] = value

            ip = ipaddress.ip_address(values.get("ADDRESS", ""))
            if ip.version != 4:
                continue

            lifetime = values.get("LIFETIME", "")
            end = (
                dt.datetime.now() + dt.timedelta(seconds=int(lifetime))
                if lifetime.isdigit() else None
            )
            result.append(DHCPLease(
                ip=str(ip),
                mac=values.get("CLIENTID", "—"),
                hostname=socket.gethostname(),
                start=None, end=end,
                dhcp_server=values.get("SERVER_ADDRESS", ""),
                adapter=name,
            ))
        except (OSError, ValueError):
            continue
    return result


# ------------------------------------------------------------------- public


def read_dhcp_leases() -> list[DHCPLease]:
    if os.name == "nt":
        return _read_windows_leases()
    if platform.system() == "Linux":
        return _read_linux_leases()
    raise RuntimeError(f"Unsupported operating system: {platform.system()}")


# ------------------------------------------------------------ local diagnostics

_WINDOWS_DIAG_SCRIPT = r"""
$ErrorActionPreference='SilentlyContinue'
Get-NetIPConfiguration | ForEach-Object {
  [pscustomobject]@{
    Gateway=(@($_.IPv4DefaultGateway.NextHop) -join ', ')
    DNS=(@($_.DNSServer.ServerAddresses) -join ', ')
  }
} | ConvertTo-Json -Compress
"""


def get_network_diagnostics() -> dict[str, Any]:
    """Return a local-only snapshot of network configuration."""
    system = platform.system()
    data: dict[str, Any] = {
        "hostname": socket.gethostname(),
        "os": f"{system} {platform.release()}",
        "addresses": [],
        "gateways": [],
        "dns": [],
        "notes": [],
    }

    try:
        for item in socket.getaddrinfo(socket.gethostname(), None, type=socket.SOCK_DGRAM):
            ip = item[4][0].split("%", 1)[0]
            try:
                obj = ipaddress.ip_address(ip)
                if not obj.is_loopback and not obj.is_link_local and ip not in data["addresses"]:
                    data["addresses"].append(ip)
            except ValueError:
                pass
    except socket.gaierror:
        pass

    if os.name == "nt":
        try:
            output = _run(
                ["powershell.exe", "-NoProfile", "-Command", _WINDOWS_DIAG_SCRIPT],
                timeout=15,
            ).strip()
            rows = json.loads(output) if output else []
            if isinstance(rows, dict):
                rows = [rows]
            for row in rows:
                for key, target in (("Gateway", "gateways"), ("DNS", "dns")):
                    for value in str(row.get(key) or "").split(", "):
                        if value and value not in data[target]:
                            data[target].append(value)
        except Exception as exc:
            data["notes"].append(f"Windows interface query failed: {exc}")
    elif system == "Linux":
        if shutil.which("ip"):
            try:
                for line in _run(["ip", "route", "show", "default"]).splitlines():
                    match = re.search(r"\bvia\s+(\S+)", line)
                    if match and match.group(1) not in data["gateways"]:
                        data["gateways"].append(match.group(1))
            except Exception as exc:
                data["notes"].append(f"Gateway query failed: {exc}")
        try:
            with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    match = re.match(r"\s*nameserver\s+(\S+)", line)
                    if match and match.group(1) not in data["dns"]:
                        data["dns"].append(match.group(1))
        except OSError as exc:
            data["notes"].append(f"DNS query failed: {exc}")

    return data


# ------------------------------------------------------------ remote diagnostics

# PowerShell script that runs on the REMOTE Windows server.
_REMOTE_WINDOWS_DIAG_SCRIPT = r"""
$ErrorActionPreference='SilentlyContinue'
$hostname = $env:COMPUTERNAME
$os = (Get-CimInstance Win32_OperatingSystem).Caption
$addrs = @(Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object {$_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*'} |
    Select-Object -ExpandProperty IPAddress)
$gws = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' |
    Select-Object -ExpandProperty NextHop)
$dns = @(Get-DnsClientServerAddress -AddressFamily IPv4 |
    Where-Object {$_.ServerAddresses.Count -gt 0} |
    ForEach-Object {$_.ServerAddresses})
[pscustomobject]@{
    hostname = [string]$hostname
    os = [string]$os
    addresses = $addrs
    gateways = $gws
    dns = $dns
} | ConvertTo-Json -Depth 4 -Compress
"""

# Shell command that runs on the REMOTE Linux server.
_REMOTE_LINUX_DIAG_SCRIPT = r"""
hostname
uname -sr
echo "---IP---"
hostname -I 2>/dev/null || ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}'
echo "---GW---"
ip route | grep default | awk '{print $3}'
echo "---DNS---"
grep -E '^\s*nameserver' /etc/resolv.conf 2>/dev/null | awk '{print $2}'
"""


def _parse_windows_diag(out: str, data: dict[str, Any]) -> bool:
    text = out.lstrip("\ufeff").strip()
    if not text:
        return False
    obj = json.loads(text)
    if isinstance(obj, list):
        obj = obj[0] if obj else {}
    data["hostname"] = str(obj.get("hostname", ""))
    data["os"] = str(obj.get("os", ""))
    for key in ("addresses", "gateways", "dns"):
        value = obj.get(key) or []
        data[key] = [value] if isinstance(value, str) else list(value)
    return True


def _parse_linux_diag(out: str, data: dict[str, Any]) -> None:
    section = ""
    for line in out.splitlines():
        line = line.rstrip()
        if line.startswith("---IP---"):
            section = "ip"
            continue
        if line.startswith("---GW---"):
            section = "gw"
            continue
        if line.startswith("---DNS---"):
            section = "dns"
            continue

        if section == "" and not data["hostname"]:
            data["hostname"] = line
        elif section == "" and not data["os"]:
            data["os"] = line
        elif section == "ip" and line:
            for tok in line.split():
                if tok not in data["addresses"]:
                    data["addresses"].append(tok)
        elif section == "gw" and line:
            data["gateways"].append(line.strip())
        elif section == "dns" and line:
            data["dns"].append(line.strip())


def get_remote_diagnostics(
    server: str,
    *,
    username: str | None = None,
    password: str | None = None,
    key_path: str | None = None,
    backend: str = "auto",
    timeout: int = 30,
) -> dict[str, Any]:
    """Return network diagnostics from a REMOTE server (read-only).

    Windows: PowerShell Invoke-Command (WinRM) with the supplied credentials.
    Linux:   SSH (key/agent, or password via paramiko).
    Mirrors the shape of :func:`get_network_diagnostics`.
    """
    from dhcp_lease_viewer.core import remote_reader as rr

    data: dict[str, Any] = {
        "hostname": "", "os": "", "addresses": [],
        "gateways": [], "dns": [], "notes": [],
    }

    try:
        server = rr._validate_server(server)
        username = rr._validate_username(username)
        rr._validate_credentials(username, password)
        key_path = rr._resolve_key_path(key_path)
        backends = rr.resolve_backends(server, backend)
    except rr.RemoteDhcpError as exc:
        data["notes"].append(str(exc))
        return data

    for name in backends:
        try:
            if name == "windows":
                out = rr.run_remote_powershell_block(
                    server, _REMOTE_WINDOWS_DIAG_SCRIPT,
                    username=username, password=password, timeout=timeout,
                )
                if _parse_windows_diag(out, data):
                    return data
                data["notes"].append("Windows remote query returned no data.")
            else:
                out = rr.run_ssh_script(
                    server, _REMOTE_LINUX_DIAG_SCRIPT,
                    username=username, password=password,
                    key_path=key_path, timeout=timeout,
                )
                _parse_linux_diag(out, data)
                return data
        except (rr.RemoteDhcpError, ValueError) as exc:
            label = "Windows" if name == "windows" else "Linux"
            data["notes"].append(f"{label} remote query failed: {exc}")

    if not data["hostname"]:
        data["notes"].append(
            "No response from remote server. Check connectivity, "
            "credentials, and firewall rules."
        )
    return data
