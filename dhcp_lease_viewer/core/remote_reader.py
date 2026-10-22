"""Read DHCP leases from remote servers (Windows or Linux) — read-only.

Windows backend
    PowerShell + the ``DhcpServer`` module (RSAT) installed on THIS machine.
    A CIM session (WinRM, ports 5985/5986) is opened to the target server, so
    alternate credentials are really used. Every scope is enumerated.

Linux backend
    SSH. Key / agent authentication uses the system ``ssh`` client; password
    authentication uses ``paramiko`` (``pip install paramiko``). Supported lease
    stores: ISC dhcpd, dnsmasq (also OpenWrt) and Kea (memfile CSV).

Nothing here ever modifies the remote server.
"""

from __future__ import annotations

import base64
import csv
import io
import ipaddress
import json
import os
import posixpath
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from core.utils.subprocess_utils import get_no_window_kwargs


DEFAULT_TIMEOUT = 45
Backend = Literal["auto", "windows", "linux"]

WINRM_PORTS = (5985, 5986)
SSH_PORT = 22


class RemoteDhcpError(RuntimeError):
    """Raised when remote DHCP enumeration fails for any reason."""


@dataclass
class RemoteLease:
    ip: str
    mac: str
    hostname: str
    start: datetime | None
    end: datetime | None
    dhcp_server: str
    scope_id: str = ""
    client_id: str = ""
    address_state: str = ""
    lease_type: str = ""
    source: str = ""


# ============================================================
# Validation
# ============================================================

_HOST_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:\-]*$")
_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@\\\-]*$")


def _validate_server(server: str) -> str:
    name = (server or "").strip()
    if not name:
        raise RemoteDhcpError("Server name cannot be empty.")
    if len(name) > 253 or not _HOST_RE.match(name):
        raise RemoteDhcpError(
            "Server name contains unsupported characters.\n"
            "Use a hostname or an IP address (letters, digits, '.', '-', '_', ':')."
        )
    return name


def _validate_username(username: str | None) -> str | None:
    if not username:
        return None
    user = username.strip()
    if len(user) > 256 or not _USER_RE.match(user):
        raise RemoteDhcpError(
            "Username contains unsupported characters.\n"
            "Allowed: letters, digits, '.', '-', '_', '@' and '\\' (DOMAIN\\user)."
        )
    return user


def _validate_credentials(username: str | None, password: str | None) -> None:
    # A username alone is valid (SSH key / agent). A password alone is not.
    if password and not username:
        raise RemoteDhcpError("A password was given without a username.")


def _resolve_key_path(key_path: str | None) -> str | None:
    if not key_path:
        return None
    path = Path(os.path.expanduser(key_path.strip()))
    if not path.is_file():
        raise RemoteDhcpError(f"SSH key file not found:\n{path}")
    return str(path)


def _port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def resolve_backends(server: str, backend: str) -> list[str]:
    """Return the backends worth trying, after a quick TCP reachability probe.

    Failing fast on a closed port avoids waiting for a 45 s timeout.
    """
    backend = (backend or "auto").lower()
    winrm_open = any(_port_open(server, p) for p in WINRM_PORTS)
    ssh_open = _port_open(server, SSH_PORT)

    if backend == "windows":
        if not winrm_open:
            raise RemoteDhcpError(
                f"Cannot reach {server} on WinRM (TCP 5985 / 5986).\n\n"
                "Check the name/IP, the firewall, and that WinRM is enabled on the "
                "server:  Enable-PSRemoting -Force"
            )
        return ["windows"]

    if backend == "linux":
        if not ssh_open:
            raise RemoteDhcpError(
                f"Cannot reach {server} on SSH (TCP 22).\n\n"
                "Check the name/IP, the firewall, and that sshd is running."
            )
        return ["linux"]

    order: list[str] = []
    if winrm_open:
        order.append("windows")
    if ssh_open:
        order.append("linux")
    if not order:
        raise RemoteDhcpError(
            f"Cannot reach {server} on WinRM (TCP 5985/5986) or SSH (TCP 22).\n\n"
            "Check the name/IP, DNS, VPN and firewall rules."
        )
    return order


# ============================================================
# PowerShell helpers
# ============================================================

def _find_powershell() -> str:
    shell = shutil.which("powershell") or shutil.which("pwsh")
    if not shell:
        raise RemoteDhcpError(
            "PowerShell is not available on this machine. "
            "Use the Linux (SSH) backend instead."
        )
    return shell


def _clean_ps_error(text: str) -> str:
    """Turn PowerShell CLIXML error output into plain text."""
    text = (text or "").strip()
    if text.startswith("#< CLIXML") or "<Objs " in text:
        parts = re.findall(r'<S S="Error">(.*?)</S>', text, flags=re.S)
        if parts:
            text = "".join(parts)
            text = text.replace("_x000D__x000A_", "\n").replace("_x000D_", "")
            text = re.sub(r"_x[0-9A-Fa-f]{4}_", "", text)
    return text.strip()


def run_powershell(
    script: str,
    *,
    env_extra: dict[str, str] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    """Run a (static) script with -EncodedCommand. Dynamic values go via env."""
    shell = _find_powershell()
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")

    env = os.environ.copy()
    for key in ("DHCP_VIEWER_USER", "DHCP_VIEWER_PASSWORD",
                "DHCP_VIEWER_SERVER", "DHCP_VIEWER_REMOTE_SCRIPT"):
        env.pop(key, None)
    env.update(env_extra or {})

    try:
        completed = subprocess.run(
            [shell, "-NoLogo", "-NoProfile", "-NonInteractive",
             "-EncodedCommand", encoded],
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            env=env,
            **get_no_window_kwargs(),
        )
    except subprocess.TimeoutExpired:
        raise RemoteDhcpError(
            f"Windows (WinRM) connection timed out after {timeout} seconds."
        ) from None
    except OSError as exc:
        raise RemoteDhcpError(f"Could not start PowerShell: {exc}") from exc

    if completed.returncode != 0:
        message = _clean_ps_error(completed.stderr or completed.stdout or "")
        raise RemoteDhcpError(_friendly_windows_error(message))

    return completed.stdout


def _credential_env(server: str, username: str | None, password: str | None) -> dict[str, str]:
    env = {"DHCP_VIEWER_SERVER": server}
    if username:
        env["DHCP_VIEWER_USER"] = username
        env["DHCP_VIEWER_PASSWORD"] = password or ""
    return env


def _friendly_windows_error(message: str) -> str:
    lowered = message.casefold()

    module_missing = (
        "dhcp_module_missing" in lowered
        or ("dhcpserver" in lowered and ("not loaded" in lowered or "not found" in lowered))
        or ("get-dhcpserverv4" in lowered and "not recognized" in lowered)
    )
    if module_missing:
        return (
            "The DhcpServer PowerShell module (RSAT: DHCP Server Tools) is not "
            "installed on THIS computer.\n\n"
            "Windows 10/11 (PowerShell as Administrator):\n"
            "  Add-WindowsCapability -Online -Name Rsat.DHCP.Tools~~~~0.0.1.0\n\n"
            "Windows Server:\n"
            "  Install-WindowsFeature RSAT-DHCP"
        )
    if "servernottrusted" in lowered or "trustedhosts" in lowered:
        return (
            "The client does not trust the target server yet "
            "(typical when connecting by IP address or from a workgroup PC).\n\n"
            "Fix on THIS machine (PowerShell as Administrator):\n\n"
            "  Set-Item WSMan:\\localhost\\Client\\TrustedHosts "
            "-Value '<server-or-ip>' -Force\n\n"
            f"Original error: {message}"
        )
    if (
        ("access" in lowered and "denied" in lowered)
        or "unauthorized" in lowered
        or "logon failure" in lowered
        or "user name or password" in lowered
    ):
        return (
            "Access denied. The account must be allowed to use WinRM on the "
            "server and be a member of the 'DHCP Users' group (or Administrators).\n\n"
            f"Original error: {message}"
        )
    if (
        "cannot find the computer" in lowered
        or "no such host" in lowered
        or "name resolution" in lowered
        or "could not be resolved" in lowered
    ):
        return (
            "The target server could not be found. Check the name, DNS, and "
            "network connectivity.\n\n"
            f"Original error: {message}"
        )
    if "winrm" in lowered or "wsman" in lowered:
        return (
            "WinRM communication failed. On the target server, make sure it is "
            "enabled with: Enable-PSRemoting -Force\n\n"
            f"Original error: {message}"
        )
    if "dhcp" in lowered and ("service" in lowered or "not a dhcp" in lowered):
        return (
            "The target does not appear to run the DHCP Server role/service.\n\n"
            f"Original error: {message}"
        )
    return message or "Unknown remote error (Windows backend)."


# ============================================================
# Windows backend
# ============================================================

# Static script: server / credentials come from environment variables, never
# from string interpolation, so there is no injection surface.
_WINDOWS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$cim = $null
try {
    if (-not (Get-Module -ListAvailable -Name DhcpServer)) {
        throw 'DHCP_MODULE_MISSING'
    }
    Import-Module DhcpServer
    $server = $env:DHCP_VIEWER_SERVER

    if ($env:DHCP_VIEWER_USER) {
        $sec  = ConvertTo-SecureString $env:DHCP_VIEWER_PASSWORD -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($env:DHCP_VIEWER_USER, $sec)
        $cim  = New-CimSession -ComputerName $server -Credential $cred
    } else {
        $cim  = New-CimSession -ComputerName $server
    }

    $items = New-Object System.Collections.Generic.List[object]
    foreach ($scope in @(Get-DhcpServerv4Scope -CimSession $cim)) {
        $duration = $scope.LeaseDuration
        foreach ($lease in @(Get-DhcpServerv4Lease -CimSession $cim -ScopeId $scope.ScopeId -AllLeases)) {
            $expiry = $lease.LeaseExpiryTime
            $start  = $null
            if ($expiry -and $duration -and $duration.TotalSeconds -gt 0) {
                $start = $expiry - $duration
            }
            $items.Add([pscustomobject]@{
                ip            = [string]$lease.IPAddress
                mac           = [string]$lease.ClientId
                hostname      = [string]$lease.HostName
                start         = if ($start)  { $start.ToString('yyyy-MM-dd HH:mm:ss') }  else { $null }
                end           = if ($expiry) { $expiry.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                dhcp_server   = [string]$lease.ServerIP
                scope_id      = [string]$lease.ScopeId
                client_id     = [string]$lease.ClientId
                address_state = [string]$lease.AddressState
                lease_type    = [string]$lease.ClientType
            })
        }
    }
    ConvertTo-Json -InputObject @($items) -Depth 4 -Compress
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
} finally {
    if ($cim) { Remove-CimSession -CimSession $cim -ErrorAction SilentlyContinue }
}
"""

# Runs an arbitrary (static) script block on the remote Windows machine.
_WINDOWS_INVOKE_WRAPPER = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
try {
    $sb = [scriptblock]::Create($env:DHCP_VIEWER_REMOTE_SCRIPT)
    if ($env:DHCP_VIEWER_USER) {
        $sec  = ConvertTo-SecureString $env:DHCP_VIEWER_PASSWORD -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($env:DHCP_VIEWER_USER, $sec)
        Invoke-Command -ComputerName $env:DHCP_VIEWER_SERVER -Credential $cred -ScriptBlock $sb
    } else {
        Invoke-Command -ComputerName $env:DHCP_VIEWER_SERVER -ScriptBlock $sb
    }
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
"""

_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def run_remote_powershell_block(
    server: str,
    remote_script: str,
    *,
    username: str | None = None,
    password: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    """Invoke-Command a static script block on a remote Windows host."""
    env = _credential_env(server, username, password)
    env["DHCP_VIEWER_REMOTE_SCRIPT"] = remote_script
    return run_powershell(_WINDOWS_INVOKE_WRAPPER, env_extra=env, timeout=timeout)


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(str(value), _DATE_FORMAT)
    except ValueError:
        return None


def _parse_windows_leases(raw: str, server: str) -> list[RemoteLease]:
    text = raw.lstrip("\ufeff").strip()
    if not text:
        return []
    try:
        data: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RemoteDhcpError(
            f"Could not parse remote DHCP data (Windows): {exc}"
        ) from exc

    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise RemoteDhcpError("Unexpected data returned by the remote server.")

    leases: list[RemoteLease] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        ip_text = str(item.get("ip") or "").strip()
        try:
            ip_obj = ipaddress.ip_address(ip_text)
        except ValueError:
            continue
        if ip_obj.version != 4:
            continue

        leases.append(RemoteLease(
            ip=str(ip_obj),
            mac=str(item.get("mac") or "—").replace("-", ":").upper(),
            hostname=str(item.get("hostname") or "—"),
            start=_parse_dt(item.get("start")),
            end=_parse_dt(item.get("end")),
            dhcp_server=str(item.get("dhcp_server") or server),
            scope_id=str(item.get("scope_id") or ""),
            client_id=str(item.get("client_id") or ""),
            address_state=str(item.get("address_state") or ""),
            lease_type=str(item.get("lease_type") or ""),
            source="windows",
        ))
    return leases


def _read_windows(
    server: str,
    *,
    username: str | None,
    password: str | None,
    timeout: int,
) -> list[RemoteLease]:
    output = run_powershell(
        _WINDOWS_SCRIPT,
        env_extra=_credential_env(server, username, password),
        timeout=timeout,
    )
    return _parse_windows_leases(output, server)


# ============================================================
# SSH helpers (Linux backend)
# ============================================================

def _friendly_linux_error(message: str) -> str:
    lowered = message.casefold()

    if "permission denied" in lowered or "authentication failed" in lowered:
        return (
            "SSH authentication failed. Check the username, password, "
            "SSH key, or the server's authorized_keys file.\n\n"
            f"Original error: {message}"
        )
    if "connection refused" in lowered:
        return (
            "The target server refused the SSH connection. "
            "Is sshd running on port 22?\n\n"
            f"Original error: {message}"
        )
    if (
        "no route to host" in lowered
        or "could not resolve" in lowered
        or "name or service not known" in lowered
        or "getaddrinfo" in lowered
    ):
        return (
            "The target server could not be reached. Check the hostname, "
            "DNS, and network connectivity.\n\n"
            f"Original error: {message}"
        )
    if "host key verification failed" in lowered or "remote host identification" in lowered:
        return (
            "SSH host key verification failed (the server's key changed or is "
            "not trusted). If you expected this, remove the old key with:\n\n"
            "  ssh-keygen -R <server>\n\n"
            f"Original error: {message}"
        )
    return message or "Unknown remote error (Linux backend)."


def _ssh_with_system_client(
    server: str,
    script: str,
    *,
    username: str | None,
    key_path: str | None,
    timeout: int,
) -> str:
    ssh = shutil.which("ssh")
    if not ssh:
        raise RemoteDhcpError(
            "The 'ssh' command was not found. Install the OpenSSH client "
            "(Windows: Settings → Optional features → OpenSSH Client)."
        )

    target = f"{username}@{server}" if username else server
    cmd = [
        ssh,
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "BatchMode=yes",
        "-o", "LogLevel=ERROR",
        "-o", f"ConnectTimeout={max(5, timeout // 3)}",
    ]
    if key_path:
        cmd += ["-i", key_path]
    # "--" stops option parsing, so a hostile target can never become an option.
    cmd += ["--", target, "sh", "-s"]

    try:
        completed = subprocess.run(
            cmd,
            input=script,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            **get_no_window_kwargs(),
        )
    except subprocess.TimeoutExpired:
        raise RemoteDhcpError(
            f"Linux (SSH) connection timed out after {timeout} seconds."
        ) from None
    except OSError as exc:
        raise RemoteDhcpError(f"Could not start SSH: {exc}") from exc

    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout or "").strip()
        raise RemoteDhcpError(_friendly_linux_error(message))
    return completed.stdout


def _known_hosts_path() -> str:
    return str(Path.home() / ".cyberops_known_hosts")


def _ssh_with_paramiko(
    server: str,
    script: str,
    *,
    username: str,
    password: str | None,
    key_path: str | None,
    timeout: int,
) -> str:
    try:
        import paramiko  # type: ignore
    except ImportError:
        raise RemoteDhcpError(
            "Password-based SSH needs the 'paramiko' package:\n\n"
            "  pip install paramiko\n\n"
            "Or use SSH key authentication (recommended)."
        ) from None

    client = paramiko.SSHClient()
    try:
        client.load_system_host_keys()
    except (OSError, paramiko.SSHException):
        pass
    known_hosts = _known_hosts_path()
    try:
        if os.path.exists(known_hosts):
            client.load_host_keys(known_hosts)
    except (OSError, paramiko.SSHException):
        pass
    # Trust-on-first-use (same idea as ssh's accept-new); changed keys are rejected.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            server,
            port=SSH_PORT,
            username=username,
            password=password,
            key_filename=key_path,
            timeout=max(5, timeout // 3),
            banner_timeout=timeout,
            auth_timeout=timeout,
            allow_agent=not password,
            look_for_keys=not password,
        )
        try:
            client.save_host_keys(known_hosts)
        except OSError:
            pass

        stdin, stdout, stderr = client.exec_command("sh -s", timeout=timeout)
        stdin.write(script)
        stdin.channel.shutdown_write()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        status = stdout.channel.recv_exit_status()
    except paramiko.AuthenticationException:
        raise RemoteDhcpError(
            _friendly_linux_error("Permission denied (authentication failed)")
        ) from None
    except paramiko.BadHostKeyException as exc:
        raise RemoteDhcpError(
            _friendly_linux_error(f"Host key verification failed: {exc}")
        ) from None
    except (paramiko.SSHException, OSError, EOFError) as exc:
        raise RemoteDhcpError(_friendly_linux_error(str(exc))) from None
    finally:
        client.close()

    if status != 0:
        raise RemoteDhcpError(_friendly_linux_error((err or out).strip()))
    return out


def run_ssh_script(
    server: str,
    script: str,
    *,
    username: str | None = None,
    password: str | None = None,
    key_path: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    """Run a POSIX shell script on the server (via stdin of ``sh -s``)."""
    if password:
        if not username:
            raise RemoteDhcpError("A password was given without a username.")
        return _ssh_with_paramiko(
            server, script, username=username, password=password,
            key_path=key_path, timeout=timeout,
        )
    return _ssh_with_system_client(
        server, script, username=username, key_path=key_path, timeout=timeout,
    )


# ============================================================
# Linux lease parsing
# ============================================================

_LINUX_REMOTE_SCRIPT = r"""
for f in \
  /var/lib/dhcp/dhcpd.leases \
  /var/lib/dhcpd/dhcpd.leases \
  /var/db/dhcpd/dhcpd.leases \
  /var/db/dhcpd.leases \
  /var/lib/misc/dnsmasq.leases \
  /var/lib/dnsmasq/dnsmasq.leases \
  /tmp/dhcp.leases \
  /var/lib/kea/kea-leases4.csv; do
  if [ -e "$f" ]; then
    if [ -r "$f" ]; then
      echo "=== FILE: $f ==="
      cat "$f"
      echo "=== END: $f ==="
    elif sudo -n true 2>/dev/null; then
      echo "=== FILE: $f ==="
      sudo -n cat "$f"
      echo "=== END: $f ==="
    else
      echo "=== UNREADABLE: $f ==="
    fi
  fi
done
"""

CHECKED_LINUX_FILES = (
    "/var/lib/dhcp/dhcpd.leases",
    "/var/lib/dhcpd/dhcpd.leases",
    "/var/db/dhcpd/dhcpd.leases",
    "/var/db/dhcpd.leases",
    "/var/lib/misc/dnsmasq.leases",
    "/var/lib/dnsmasq/dnsmasq.leases",
    "/tmp/dhcp.leases",
    "/var/lib/kea/kea-leases4.csv",
)

_MARKER_RE = re.compile(r"^=== (FILE|END|UNREADABLE): (.+?) ===$")


def _norm_mac(mac: str) -> str:
    mac = (mac or "").strip()
    if not mac or mac in {"*", "-"}:
        return "—"
    return mac.replace("-", ":").upper()


def _from_epoch(value: int) -> datetime | None:
    try:
        return datetime.fromtimestamp(value)
    except (OverflowError, OSError, ValueError):
        return None


def _split_sections(output: str) -> tuple[list[tuple[str, str]], list[str]]:
    sections: list[tuple[str, str]] = []
    unreadable: list[str] = []
    current: str | None = None
    buffer: list[str] = []

    for raw in output.splitlines():
        line = raw.rstrip("\r")
        match = _MARKER_RE.match(line)
        if match:
            kind, path = match.groups()
            if kind == "FILE":
                current, buffer = path, []
            elif kind == "END" and current is not None:
                sections.append((current, "\n".join(buffer)))
                current, buffer = None, []
            elif kind == "UNREADABLE":
                unreadable.append(path)
            continue
        if current is not None:
            buffer.append(line)

    if current is not None:  # truncated output
        sections.append((current, "\n".join(buffer)))
    return sections, unreadable


def _file_kind(path: str) -> str:
    name = posixpath.basename(path).lower()
    if name.endswith(".csv") or "kea" in path.lower():
        return "kea"
    if "dnsmasq" in name or name == "dhcp.leases":
        return "dnsmasq"
    if "dhcpd" in name:
        return "isc"
    return "unknown"


# ---- dnsmasq ---------------------------------------------------------------

def _parse_dnsmasq(text: str, server: str) -> list[RemoteLease]:
    leases: list[RemoteLease] = []
    for line in text.splitlines():
        parts = line.split()
        # "duid ..." and other non-lease lines don't start with a number.
        if len(parts) < 4 or not parts[0].isdigit():
            continue
        epoch, mac, ip, host = parts[:4]
        client_id = parts[4] if len(parts) > 4 else ""
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if ip_obj.version != 4:
            continue

        epoch_i = int(epoch)
        leases.append(RemoteLease(
            ip=str(ip_obj),
            mac=_norm_mac(mac),
            hostname=host if host != "*" else "—",
            start=None,
            end=None if epoch_i == 0 else _from_epoch(epoch_i),
            dhcp_server=server,
            client_id="" if client_id == "*" else client_id,
            address_state="active",
            lease_type="infinite" if epoch_i == 0 else "dynamic",
            source="linux (dnsmasq)",
        ))
    return leases


# ---- Kea (memfile CSV) -----------------------------------------------------

def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _parse_kea(text: str, server: str, include_inactive: bool) -> list[RemoteLease]:
    latest: dict[str, dict[str, str]] = {}
    for row in csv.DictReader(io.StringIO(text)):
        address = (row.get("address") or "").strip()
        if address:
            latest[address] = row  # the memfile is append-only: last row wins

    state_names = {0: "active", 1: "declined", 2: "expired"}
    leases: list[RemoteLease] = []
    for address, row in latest.items():
        try:
            ip_obj = ipaddress.ip_address(address)
        except ValueError:
            continue
        if ip_obj.version != 4:
            continue

        lifetime = _to_int(row.get("valid_lifetime"))
        expire = _to_int(row.get("expire"))
        state = _to_int(row.get("state"))
        deleted = lifetime == 0
        if not include_inactive and (deleted or state == 2):
            continue

        end = _from_epoch(expire) if expire else None
        start = _from_epoch(expire - lifetime) if expire and lifetime else None
        hostname = (row.get("hostname") or "").strip().rstrip(".")

        leases.append(RemoteLease(
            ip=str(ip_obj),
            mac=_norm_mac(row.get("hwaddr", "")),
            hostname=hostname or "—",
            start=start,
            end=end,
            dhcp_server=server,
            scope_id=(row.get("subnet_id") or "").strip(),
            client_id=(row.get("client_id") or "").strip(),
            address_state="expired" if deleted else state_names.get(state, str(state)),
            lease_type="dynamic",
            source="linux (kea)",
        ))
    return leases


# ---- ISC dhcpd -------------------------------------------------------------

_ISC_LEASE_RE = re.compile(r"^lease\s+(\d+\.\d+\.\d+\.\d+)\s*\{")
_ISC_TIME_RE = r"(?:\d\s+(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})|epoch\s+(\d+))"
_ISC_STARTS_RE = re.compile(rf"^starts\s+{_ISC_TIME_RE}")
_ISC_ENDS_RE = re.compile(rf"^ends\s+{_ISC_TIME_RE}")
_ISC_ENDS_NEVER_RE = re.compile(r"^ends\s+never")
_ISC_STATE_RE = re.compile(r"^binding\s+state\s+(\w+)")
_ISC_MAC_RE = re.compile(r"^hardware\s+ethernet\s+([0-9a-fA-F:]+)")
_ISC_HOST_RE = re.compile(r'^client-hostname\s+"([^"]*)"')


def _isc_time(date_text: str | None, epoch_text: str | None) -> datetime | None:
    if epoch_text:
        return _from_epoch(int(epoch_text))
    if date_text:
        try:
            parsed = datetime.strptime(date_text, "%Y/%m/%d %H:%M:%S")
        except ValueError:
            return None
        # ISC writes UTC by default; show local time like the other backends.
        return parsed.replace(tzinfo=timezone.utc).astimezone().replace(tzinfo=None)
    return None


def _parse_isc(text: str, server: str, include_inactive: bool) -> list[RemoteLease]:
    """dhcpd.leases is an append-only journal: the LAST block of an IP wins."""
    latest: dict[str, dict[str, Any]] = {}
    current_ip: str | None = None
    record: dict[str, Any] = {}
    depth = 0

    for raw in text.splitlines():
        line = raw.strip()
        if current_ip is None:
            match = _ISC_LEASE_RE.match(line)
            if match:
                current_ip, record, depth = match.group(1), {}, 1
            continue

        depth += line.count("{") - line.count("}")
        if depth <= 0:
            latest[current_ip] = record
            current_ip = None
            continue

        if (m := _ISC_STARTS_RE.match(line)):
            record["start"] = _isc_time(m.group(1), m.group(2))
        elif _ISC_ENDS_NEVER_RE.match(line):
            record["end"], record["never"] = None, True
        elif (m := _ISC_ENDS_RE.match(line)):
            record["end"] = _isc_time(m.group(1), m.group(2))
        elif (m := _ISC_STATE_RE.match(line)):
            record["state"] = m.group(1).lower()
        elif (m := _ISC_MAC_RE.match(line)):
            record["mac"] = m.group(1)
        elif (m := _ISC_HOST_RE.match(line)):
            record["host"] = m.group(1)

    leases: list[RemoteLease] = []
    for ip, rec in latest.items():
        state = rec.get("state", "")
        if not include_inactive and state not in {"active", "abandoned"}:
            continue
        leases.append(RemoteLease(
            ip=ip,
            mac=_norm_mac(rec.get("mac", "")),
            hostname=rec.get("host") or "—",
            start=rec.get("start"),
            end=rec.get("end"),
            dhcp_server=server,
            address_state=state,
            lease_type="infinite" if rec.get("never") else "dynamic",
            source="linux (isc)",
        ))
    return leases


# ---- entry points ----------------------------------------------------------

def parse_linux_leases(
    output: str, server: str, include_inactive: bool = False,
) -> tuple[list[RemoteLease], list[str]]:
    """Parse the marker-delimited output of ``_LINUX_REMOTE_SCRIPT``.

    Returns ``(leases, unreadable_files)``.
    """
    sections, unreadable = _split_sections(output)
    leases: list[RemoteLease] = []
    for path, text in sections:
        kind = _file_kind(path)
        if kind == "dnsmasq":
            leases.extend(_parse_dnsmasq(text, server))
        elif kind == "kea":
            leases.extend(_parse_kea(text, server, include_inactive))
        elif kind == "isc":
            leases.extend(_parse_isc(text, server, include_inactive))
    return leases, unreadable


def _read_linux(
    server: str,
    *,
    username: str | None,
    password: str | None,
    key_path: str | None,
    timeout: int,
    include_inactive: bool,
) -> list[RemoteLease]:
    output = run_ssh_script(
        server, _LINUX_REMOTE_SCRIPT,
        username=username, password=password, key_path=key_path, timeout=timeout,
    )
    sections, unreadable = _split_sections(output)

    if not sections:
        checked = "\n".join(f"  • {p}" for p in CHECKED_LINUX_FILES)
        if unreadable:
            names = "\n".join(f"  • {p}" for p in unreadable)
            raise RemoteDhcpError(
                "Lease files exist on the server but this account cannot read them:\n\n"
                f"{names}\n\n"
                "Add the account to the group that owns the file, or allow "
                "passwordless 'sudo cat' for it.\n\n"
                "This tool only reads leases; it never modifies them."
            )
        raise RemoteDhcpError(
            "SSH connection succeeded but no DHCP lease files were found "
            f"on the server.\n\nChecked:\n{checked}\n\n"
            "This tool only reads leases; it never modifies them."
        )

    leases, _ = parse_linux_leases(output, server, include_inactive)
    return leases


# ============================================================
# Public entry point
# ============================================================

def _sort_key(lease: RemoteLease) -> int:
    try:
        return int(ipaddress.ip_address(lease.ip))
    except ValueError:
        return 0


def read_remote_dhcp_leases(
    server: str,
    *,
    username: str | None = None,
    password: str | None = None,
    key_path: str | None = None,
    backend: Backend = "auto",
    timeout: int = DEFAULT_TIMEOUT,
    include_inactive: bool = False,
) -> list[RemoteLease]:
    server = _validate_server(server)
    username = _validate_username(username)
    _validate_credentials(username, password)
    key_path = _resolve_key_path(key_path)

    backends = resolve_backends(server, backend)

    errors: list[tuple[str, str]] = []
    for name in backends:
        try:
            if name == "windows":
                leases = _read_windows(
                    server, username=username, password=password, timeout=timeout,
                )
            else:
                leases = _read_linux(
                    server, username=username, password=password, key_path=key_path,
                    timeout=timeout, include_inactive=include_inactive,
                )
        except RemoteDhcpError as exc:
            errors.append((name, str(exc)))
            continue
        leases.sort(key=_sort_key)
        return leases

    if len(errors) == 1:
        raise RemoteDhcpError(errors[0][1])
    raise RemoteDhcpError(
        "Could not read DHCP leases from the server using any backend.\n\n"
        + "\n\n".join(f"[{name.capitalize()}] {msg}" for name, msg in errors)
    )
