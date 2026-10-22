"""Read-only access to the local Windows event logs through PowerShell.

Only the fixed ``SYSTEM_LOGS`` allow-list is accepted and the event count
is a validated integer, so no user-controlled text ever reaches the
PowerShell command.

On Linux systems this module raises :class:`EventLogError` and directs
the caller to :mod:`event_log_analyzer.core.linux_events` instead.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Callable
from typing import Any

from .levels import normalize_level
from .parser import LogEntry


SYSTEM_LOGS: tuple[str, ...] = ("Application", "System", "Security")
MIN_EVENTS = 1
MAX_EVENTS = 5000
DEFAULT_TIMEOUT = 35


class EventLogError(RuntimeError):
    """Raised when Windows events cannot be read."""


def validate_request(log_name: str, limit: object) -> tuple[str, int]:
    """Validate and normalise the log name and the event count.

    Returns ``(canonical_log_name, limit)`` or raises ``ValueError``.
    """
    wanted = str(log_name).strip().casefold()
    canonical = next(
        (name for name in SYSTEM_LOGS if name.casefold() == wanted),
        None,
    )
    if canonical is None:
        raise ValueError(f"Log must be one of: {', '.join(SYSTEM_LOGS)}.")

    if isinstance(limit, bool):
        raise ValueError("Event limit must be a whole number.")
    try:
        count = int(limit)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        raise ValueError("Event limit must be a whole number.") from None
    if not MIN_EVENTS <= count <= MAX_EVENTS:
        raise ValueError(f"Event limit must be between {MIN_EVENTS} and {MAX_EVENTS}.")
    return canonical, count


def find_powershell() -> str | None:
    """Return the path of Windows PowerShell or PowerShell 7, if installed.

    Prefers ``pwsh`` (PowerShell 7+, cross-platform) and falls back to
    the legacy ``powershell.exe`` on Windows.
    """
    return shutil.which("pwsh") or shutil.which("powershell")


def build_script(log_name: str, limit: int) -> str:
    """Return the PowerShell command. Arguments must already be validated."""
    return (
        "$ErrorActionPreference='Stop'; "
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "
        f"Get-WinEvent -LogName '{log_name}' -MaxEvents {limit} | "
        "Select-Object "
        "@{Name='TimeCreated';Expression={$_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')}}, "
        "@{Name='Level';Expression={$_.LevelDisplayName}}, "
        "Id, ProviderName, LogName, MachineName, Message | "
        "ConvertTo-Json -Depth 3 -Compress"
    )


def parse_powershell_output(raw: str, log_name: str) -> list[LogEntry]:
    """Convert the JSON produced by :func:`build_script` into ``LogEntry`` objects."""
    text = raw.lstrip("\ufeff").strip()
    if not text:
        return []
    try:
        data: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EventLogError(f"Could not parse Windows event data: {exc}") from exc
    if isinstance(data, dict):  # PowerShell emits a bare object for a single event
        data = [data]
    if not isinstance(data, list):
        raise EventLogError("Unexpected data returned by PowerShell.")

    entries: list[LogEntry] = []
    for item in data:
        if not isinstance(item, dict):
            continue
        entries.append(
            LogEntry(
                timestamp=str(item.get("TimeCreated") or ""),
                level=normalize_level(item.get("Level")),
                message=str(item.get("Message") or "(No message available)"),
                source=str(item.get("ProviderName") or ""),
                event_id=str(item.get("Id") if item.get("Id") is not None else ""),
                log_name=str(item.get("LogName") or log_name),
                machine=str(item.get("MachineName") or ""),
                raw=item,
            )
        )
    return entries


def read_windows_events(
    log_name: str,
    limit: int = 300,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    runner: Callable[..., Any] | None = None,
    shell: str | None = None,
) -> list[LogEntry]:
    """Read the newest *limit* events of a Windows log (read-only).

    ``runner`` and ``shell`` exist so tests can run without Windows.
    Raises :class:`EventLogError` with a user-friendly message on failure.

    On non-Windows systems this function raises
    :class:`EventLogError` immediately, directing the caller to the
    Linux journal backend.
    """
    try:
        log_name, limit = validate_request(log_name, limit)
    except ValueError as exc:
        raise EventLogError(str(exc)) from exc

    if runner is None:
        if os.name != "nt":
            raise EventLogError(
                "Windows Event Logs are only available on Windows. "
                "On Linux use the systemd journal backend instead."
            )
        runner = subprocess.run

    shell = shell or find_powershell()
    if not shell:
        raise EventLogError(
            "PowerShell was not found. On Windows, install PowerShell 7 "
            "or use the systemd journal backend on Linux."
        )

    command = [
        shell, "-NoProfile", "-NonInteractive", "-Command",
        build_script(log_name, limit),
    ]
    try:
        result = runner(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        raise EventLogError(
            "Reading the event log timed out. Try a smaller number of events."
        ) from None
    except OSError as exc:
        raise EventLogError(f"Could not start PowerShell: {exc}") from exc

    if result.returncode != 0:
        message = (result.stderr or result.stdout or "").strip()
        lowered = message.casefold()
        if "no events were found" in lowered:
            return []
        if "unauthorized" in lowered or ("access" in lowered and "denied" in lowered):
            message += "\n\nRun the program as Administrator to read the Security log."
        raise EventLogError(message or "Windows could not read this event log.")

    return parse_powershell_output(result.stdout or "", log_name)