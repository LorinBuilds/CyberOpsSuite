"""Check and inspect local system services.

Supports Windows (``sc query``) and Linux (``systemctl``). The functions
here are read-only by default: they never start, stop, or modify a service
unless you explicitly call the control functions. All results are returned
as plain dataclasses so they can be easily rendered by the GUI or
serialized for logging.

Windows parsing uses locale-independent numeric state codes so the tool
works on non-English installs.
"""

from __future__ import annotations

import json
import platform
import re
import subprocess
import time
from dataclasses import dataclass
from core.utils.subprocess_utils import get_no_window_kwargs


#: Default timeout for a single service query (seconds).
DEFAULT_TIMEOUT = 4

#: Delay between stop and start during a restart (seconds).
RESTART_DELAY = 1.0


# Windows state codes (from ``sc query`` output):
# https://learn.microsoft.com/en-us/windows/win32/services/service-status
_STATE_RUNNING = 4
_STATE_STOPPED = 1
_STATE_PAUSED = 7
_STATE_START_PENDING = 2
_STATE_STOP_PENDING = 3
_STATE_CONTINUE_PENDING = 5
_STATE_PAUSE_PENDING = 6

_STATE_LABELS = {
    _STATE_STOPPED: "Stopped",
    _STATE_START_PENDING: "Starting",
    _STATE_STOP_PENDING: "Stopping",
    _STATE_RUNNING: "Running",
    _STATE_CONTINUE_PENDING: "Resuming",
    _STATE_PAUSE_PENDING: "Pausing",
    _STATE_PAUSED: "Paused",
}

# Windows start type codes (from ``sc qc`` output).
_START_TYPE_LABELS = {
    0: "Boot",
    1: "System",
    2: "Automatic",
    3: "Manual",
    4: "Disabled",
}

# Regexes for ``sc`` output parsing.
_SC_STATE_RE = re.compile(r"STATE\s*:\s*(\d+)\s*\(\s*(\w+)")
_SC_PID_RE = re.compile(r"PID\s*:\s*(\d+)", re.IGNORECASE)
_SC_DISPLAY_RE = re.compile(r"DISPLAY_NAME\s*:\s*(.+)", re.IGNORECASE)
_SC_START_TYPE_RE = re.compile(r"START_TYPE\s*:\s*(\d+)\s+(\w+)")

#: Common categories mapped from service name prefixes.
_CATEGORY_HINTS: dict[str, str] = {
    "NTDS": "Directory", "DNS": "Network", "KDC": "Security",
    "Netlogon": "Security", "W32Time": "Time",
    "LanmanServer": "File Share", "LanmanWorkstation": "File Share",
    "Spooler": "Printing", "W3SVC": "Web", "WAS": "Web",
    "IISADMIN": "Web", "HTTP": "Web", "DHCPServer": "Network",
    "Dnscache": "Network", "RpcSs": "Core", "DcomLaunch": "Core",
    "Winmgmt": "Management", "EventLog": "Core", "Schedule": "Tasks",
}


@dataclass
class ServiceInfo:
    """Read-only snapshot of a single service."""

    name: str
    status: str = "Unknown"
    display_name: str = ""
    start_type: str = ""
    pid: int | None = None
    category: str = ""

    @property
    def is_running(self) -> bool:
        return self.status == "Running"


def _guess_category(name: str) -> str:
    """Best-effort category label for a service name."""
    for key, cat in _CATEGORY_HINTS.items():
        if key.casefold() == name.casefold():
            return cat
    return "Other"


# ------------------------------------------------------------- public API

def check_service(name: str, timeout: int = DEFAULT_TIMEOUT) -> bool:
    """Return ``True`` when the named service is currently running.

    This is a lightweight wrapper around :func:`get_service_details` for
    callers that only need a boolean.
    """
    return get_service_details(name, timeout=timeout).is_running


def get_service_details(
    name: str,
    timeout: int = DEFAULT_TIMEOUT,
) -> ServiceInfo:
    """Return a :class:`ServiceInfo` for *name*.

    On error (missing service, permission issue, unsupported OS) a
    ``ServiceInfo`` with ``status="Unknown"`` is returned; the caller
    never has to handle exceptions.
    """
    if not name or not isinstance(name, str):
        return ServiceInfo(name=str(name or ""), status="Unknown")

    system = platform.system().lower()
    try:
        if system == "windows":
            return _details_windows(name, timeout)
        if system == "linux":
            return _details_linux(name, timeout)
    except (OSError, subprocess.SubprocessError):
        pass
    return ServiceInfo(name=name, status="Unknown")


# ------------------------------------------------------------- actions

def start_service(name: str, timeout: int = 15) -> tuple[bool, str]:
    """Start the named service.

    Returns ``(success, message)``. Requires Administrator privileges
    on Windows; on Linux, root or polkit authorization is required.
    """
    return _control_service(name, "start", timeout)


def stop_service(name: str, timeout: int = 15) -> tuple[bool, str]:
    """Stop the named service.

    Returns ``(success, message)``. Requires Administrator privileges.
    """
    return _control_service(name, "stop", timeout)


def restart_service(name: str, timeout: int = 30) -> tuple[bool, str]:
    """Restart the named service (stop, then start).

    Returns ``(success, message)``. Requires Administrator privileges.
    """
    if not name or not isinstance(name, str):
        return False, "Service name is empty."

    system = platform.system().lower()

    # Try a native restart command first when available.
    if system == "windows":
        return _restart_windows(name, timeout)
    if system == "linux":
        return _control_linux(name, "restart", timeout)
    return False, f"Unsupported OS: {platform.system()}"


def _control_service(name: str, action: str, timeout: int) -> tuple[bool, str]:
    """Dispatch to the platform-specific control function."""
    if not name or not isinstance(name, str):
        return False, "Service name is empty."

    system = platform.system().lower()
    try:
        if system == "windows":
            return _control_windows(name, action, timeout)
        if system == "linux":
            return _control_linux(name, action, timeout)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"Error: {exc}"
    return False, f"Unsupported OS: {platform.system()}"


def _control_windows(name: str, action: str, timeout: int) -> tuple[bool, str]:
    """Run ``sc <action> <name>`` and report the result."""
    try:
        result = subprocess.run(
            ["sc", action, name],
            capture_output=True,
            text=True,
            errors="ignore",
            timeout=timeout,
            check=False,
            **get_no_window_kwargs()
        )
    except subprocess.TimeoutExpired:
        return False, f"Timed out after {timeout} seconds."
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)

    output = ((result.stdout or "") + (result.stderr or "")).strip()

    # sc returns 0 for success but prints an error message on failure.
    if result.returncode == 0 and "FAILED" not in output.upper():
        return True, f"Service '{name}' {action}ed successfully."

    # Try to give a friendly message based on the error.
    lowered = output.casefold()
    if "access is denied" in lowered or "denied" in lowered:
        return False, (
            "Access denied.\n\n"
            "Start/Stop requires Administrator privileges.\n"
            "Run the application as Administrator and try again."
        )
    if "does not exist" in lowered or "not installed" in lowered:
        return False, f"Service '{name}' does not exist."

    return False, output or "Unknown error."


def _restart_windows(name: str, timeout: int) -> tuple[bool, str]:
    """Restart a Windows service: stop, wait, then start.

    Uses a two-step stop+start because ``sc`` has no native restart verb.
    If the service is not running, it is started directly.
    """
    # If the service is already stopped, just start it.
    details = get_service_details(name, timeout=min(timeout, DEFAULT_TIMEOUT))
    if details.status == "Not found":
        return False, f"Service '{name}' does not exist."

    if details.is_running:
        ok, msg = _control_windows(name, "stop", timeout)
        if not ok:
            return False, f"Stop failed: {msg}"

        # Give the service a moment to fully stop before starting it again.
        time.sleep(RESTART_DELAY)

    return _control_windows(name, "start", timeout)


def _control_linux(name: str, action: str, timeout: int) -> tuple[bool, str]:
    """Run ``systemctl <action> <name>`` and report the result."""
    try:
        result = subprocess.run(
            ["systemctl", action, name],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            **get_no_window_kwargs()
        )
    except subprocess.TimeoutExpired:
        return False, f"Timed out after {timeout} seconds."
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)

    if result.returncode == 0:
        return True, f"Service '{name}' {action}ed successfully."

    message = ((result.stderr or "") + (result.stdout or "")).strip()
    lowered = message.casefold()
    if "permission denied" in lowered or "access denied" in lowered:
        return False, (
            "Access denied.\n\n"
            "Start/Stop requires root or polkit authorization."
        )
    if "not found" in lowered or "not loaded" in lowered:
        return False, f"Service '{name}' does not exist."

    return False, message or "Unknown error."


# --------------------------------------------------------------- Windows

def _details_windows(name: str, timeout: int) -> ServiceInfo:
    """Query ``sc queryex`` and ``sc qc`` for status, display name and PID.

    ``sc queryex`` gives the runtime state and PID, but its output does
    not always contain ``DISPLAY_NAME``. ``sc qc`` gives the display
    name and start type but not the current state, so we combine both.
    """
    # --- sc queryex: state + PID ---
    try:
        result = subprocess.run(
            ["sc", "queryex", name],
            capture_output=True,
            text=True,
            errors="ignore",
            timeout=timeout,
            check=False,
            **get_no_window_kwargs()
        )
    except (OSError, subprocess.SubprocessError):
        return ServiceInfo(name=name, status="Unknown")

    output = result.stdout or ""

    # Service not found: sc prints to stdout with returncode != 0.
    if result.returncode != 0:
        return ServiceInfo(name=name, status="Not found")

    # --- status ---
    status = "Unknown"
    state_match = _SC_STATE_RE.search(output)
    if state_match:
        code = int(state_match.group(1))
        status = _STATE_LABELS.get(code, state_match.group(2).title())
    elif "RUNNING" in output.upper():
        status = "Running"
    elif "STOPPED" in output.upper():
        status = "Stopped"

    # --- PID ---
    pid: int | None = None
    pid_match = _SC_PID_RE.search(output)
    if pid_match:
        try:
            value = int(pid_match.group(1))
            pid = value if value > 0 else None
        except ValueError:
            pid = None

    # --- sc qc: display name + start type ---
    display_name = ""
    start_type = ""
    try:
        qc_result = subprocess.run(
            ["sc", "qc", name],
            capture_output=True,
            text=True,
            errors="ignore",
            timeout=timeout,
            check=False,
            **get_no_window_kwargs()
        )
    except (OSError, subprocess.SubprocessError):
        qc_result = None

    if qc_result is not None and qc_result.stdout:
        qc_output = qc_result.stdout

        disp_match = _SC_DISPLAY_RE.search(qc_output)
        if disp_match:
            display_name = disp_match.group(1).strip()

        st_match = _SC_START_TYPE_RE.search(qc_output)
        if st_match:
            code = int(st_match.group(1))
            start_type = _START_TYPE_LABELS.get(code, st_match.group(2).title())

    return ServiceInfo(
        name=name,
        status=status,
        display_name=display_name,
        start_type=start_type,
        pid=pid,
        category=_guess_category(name),
    )


def list_all_services(timeout: int = 15) -> list[ServiceInfo]:
    """Return a list of every service installed on the machine.

    On Windows this calls ``Get-Service`` via PowerShell which is
    significantly faster than parsing ``sc query type= service``.
    On Linux it uses ``systemctl list-units --type=service``.
    """
    system = platform.system().lower()
    try:
        if system == "windows":
            return _list_all_windows(timeout)
        if system == "linux":
            return _list_all_linux(timeout)
    except (OSError, subprocess.SubprocessError):
        pass
    return []


def _list_all_windows(timeout: int) -> list[ServiceInfo]:
    """Use PowerShell ``Get-Service`` to list every service."""
    script = (
        "Get-Service | "
        "Select-Object Name,DisplayName,Status,StartType | "
        "ConvertTo-Json -Compress -Depth 3"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
            **get_no_window_kwargs()
        )
    except (OSError, subprocess.SubprocessError):
        return []

    raw = (result.stdout or "").lstrip("\ufeff").strip()
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return []

    status_map = {
        "Running": "Running",
        "Stopped": "Stopped",
        "Paused": "Paused",
        "StartPending": "Starting",
        "StopPending": "Stopping",
        "PausePending": "Pausing",
        "ContinuePending": "Resuming",
    }
    start_map = {
        "Automatic": "Automatic",
        "Manual": "Manual",
        "Disabled": "Disabled",
        "Boot": "Boot",
        "System": "System",
    }

    services: list[ServiceInfo] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        name = str(item.get("Name") or "").strip()
        if not name:
            continue
        services.append(ServiceInfo(
            name=name,
            status=status_map.get(
                str(item.get("Status") or ""),
                str(item.get("Status") or "Unknown"),
            ),
            display_name=str(item.get("DisplayName") or ""),
            start_type=start_map.get(
                str(item.get("StartType") or ""),
                str(item.get("StartType") or ""),
            ),
            pid=None,
            category=_guess_category(name),
        ))
    services.sort(key=lambda s: s.name.casefold())
    return services


def _list_all_linux(timeout: int) -> list[ServiceInfo]:
    """Use ``systemctl list-units`` to list services."""
    try:
        result = subprocess.run(
            [
                "systemctl", "list-units",
                "--type=service", "--all", "--no-pager",
                "--no-legend", "--plain",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            **get_no_window_kwargs()
        )
    except (OSError, subprocess.SubprocessError):
        return []

    services: list[ServiceInfo] = []
    for line in (result.stdout or "").splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        unit = parts[0]
        active = parts[2]  # e.g. "active", "inactive"
        sub = parts[3]     # e.g. "running", "dead"
        status_map = {
            "active": "Running" if sub == "running" else "Active",
            "inactive": "Stopped",
            "failed": "Failed",
        }
        unit_name = unit.removesuffix(".service")
        services.append(ServiceInfo(
            name=unit_name,
            status=status_map.get(active, active.title()),
            display_name="",
            start_type="",
            pid=None,
            category=_guess_category(unit_name),
        ))
    services.sort(key=lambda s: s.name.casefold())
    return services


# ----------------------------------------------------------------- Linux

def _details_linux(name: str, timeout: int) -> ServiceInfo:
    """Query ``systemctl show`` for state, description and main PID."""
    try:
        result = subprocess.run(
            [
                "systemctl",
                "show",
                name,
                "--property=ActiveState,SubState,Description,MainPID,UnitFileState",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            **get_no_window_kwargs()
        )
    except (OSError, subprocess.SubprocessError):
        return ServiceInfo(name=name, status="Unknown")

    props: dict[str, str] = {}
    for line in (result.stdout or "").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            props[key.strip()] = value.strip()

    # ActiveState is the primary status.
    active = props.get("ActiveState", "").strip()
    status_map = {
        "active": "Running",
        "inactive": "Stopped",
        "failed": "Failed",
        "activating": "Starting",
        "deactivating": "Stopping",
    }
    status = status_map.get(active, active.title() or "Unknown")

    pid: int | None = None
    main_pid = props.get("MainPID", "0")
    try:
        value = int(main_pid)
        if value > 0:
            pid = value
    except ValueError:
        pid = None

    return ServiceInfo(
        name=name,
        status=status,
        display_name=props.get("Description", "") or "",
        start_type=props.get("UnitFileState", "") or "",
        pid=pid,
        category=_guess_category(name),
    )