"""Read-only access to the local Linux systemd journal.

Uses ``journalctl -o json`` to fetch recent events and converts them
into the same :class:`LogEntry` representation used by the Windows
backend, so the rest of the application does not need to care which
platform it is running on.

Only read operations are performed. The journal is never modified.

Requirements
------------
* systemd-based Linux distribution
* ``journalctl`` available on ``$PATH``
* read access to the requested log (usually requires membership in the
  ``systemd-journal`` group, or ``sudo``)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Callable
from datetime import datetime
from typing import Any

from .levels import normalize_level
from .parser import LogEntry


#: Systemd journal names mapped to their internal identifier.
SYSTEM_JOURNALS: tuple[str, ...] = ("System", "User", "Kernel")

#: Limits on the number of events a single call may request.
MIN_EVENTS = 1
MAX_EVENTS = 5000

#: Default subprocess timeout (seconds).
DEFAULT_TIMEOUT = 35


class JournalError(RuntimeError):
    """Raised when the systemd journal cannot be read."""


#: Map the human-friendly "log name" to a journalctl filter.
_JOURNAL_FILTERS: dict[str, list[str]] = {
    "System": [],                      # full system journal
    "User": ["--user"],                # user journal
    "Kernel": ["-k"],                  # kernel messages
}


def validate_request(log_name: str, limit: object) -> tuple[str, int]:
    """Validate and normalise the log name and the event count.

    Returns ``(canonical_log_name, limit)`` or raises ``ValueError``.
    """
    wanted = str(log_name).strip().casefold()
    canonical = next(
        (name for name in SYSTEM_JOURNALS if name.casefold() == wanted),
        None,
    )
    if canonical is None:
        raise ValueError(
            f"Log must be one of: {', '.join(SYSTEM_JOURNALS)}."
        )

    if isinstance(limit, bool):
        raise ValueError("Event limit must be a whole number.")
    try:
        count = int(limit)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        raise ValueError("Event limit must be a whole number.") from None
    if not MIN_EVENTS <= count <= MAX_EVENTS:
        raise ValueError(
            f"Event limit must be between {MIN_EVENTS} and {MAX_EVENTS}."
        )
    return canonical, count


def find_journalctl() -> str | None:
    """Return the path to ``journalctl`` if available, else ``None``."""
    return shutil.which("journalctl")


def build_command(log_name: str, limit: int) -> list[str]:
    """Return the ``journalctl`` command for the given log and limit.

    Parameters must already be validated via :func:`validate_request`.
    """
    filters = _JOURNAL_FILTERS.get(log_name, [])
    return [
        "journalctl",
        *filters,
        "-o", "json",
        "-n", str(limit),
        "--no-pager",
        "--no-hostname",
    ]


def parse_journal_output(raw: str, log_name: str) -> list[LogEntry]:
    """Convert the newline-delimited JSON produced by ``journalctl -o json``
    into a list of :class:`LogEntry` objects.
    """
    entries: list[LogEntry] = []
    for line in raw.splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            item = json.loads(text)
        except json.JSONDecodeError:
            continue
        if not isinstance(item, dict):
            continue
        entries.append(_entry_from_journal(item, log_name))
    return entries


def _entry_from_journal(item: dict[str, Any], log_name: str) -> LogEntry:
    """Translate a single journalctl JSON object into a :class:`LogEntry`."""
    # Prefer the user-visible MESSAGE, fall back to a plain message field.
    message = str(
        item.get("MESSAGE")
        or item.get("message")
        or "(No message available)"
    )

    # Priority is a number; some builds provide PRIORITY as a string.
    priority = item.get("PRIORITY")
    level = _priority_to_level(priority)

    # Timestamp: journalctl emits __REALTIME_TIMESTAMP in microseconds.
    timestamp = ""
    realtime = item.get("__REALTIME_TIMESTAMP")
    if realtime is not None:
        try:
            micros = int(realtime)
            timestamp = datetime.fromtimestamp(micros / 1_000_000).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        except (ValueError, OSError):
            timestamp = ""
    if not timestamp:
        # Fall back to the SYSLOG_IDENTIFIER-free ISO field if present.
        timestamp = str(item.get("_SOURCE_REALTIME_TIMESTAMP") or "")

    source = str(
        item.get("SYSLOG_IDENTIFIER")
        or item.get("_COMM")
        or item.get("_SYSTEMD_UNIT")
        or ""
    )

    event_id = str(item.get("SYSLOG_FACILITY") or "")
    unit = str(item.get("_SYSTEMD_UNIT") or "")
    if unit and not source:
        source = unit

    return LogEntry(
        timestamp=timestamp,
        level=level,
        message=message,
        source=source,
        event_id=event_id,
        log_name=log_name,
        machine=str(item.get("_HOSTNAME") or ""),
        raw=item,
    )


def _priority_to_level(priority: Any) -> str:
    """Convert a syslog priority (0–7) to a canonical level name."""
    if priority is None:
        return "INFO"
    try:
        value = int(priority)
    except (TypeError, ValueError):
        return normalize_level(priority)
    # Syslog priorities: 0=emerg, 1=alert, 2=crit, 3=err,
    #                    4=warning, 5=notice, 6=info, 7=debug
    mapping = {
        0: "CRITICAL",
        1: "CRITICAL",
        2: "CRITICAL",
        3: "ERROR",
        4: "WARNING",
        5: "INFO",
        6: "INFO",
        7: "DEBUG",
    }
    return mapping.get(value, "INFO")


def read_linux_journal(
    log_name: str,
    limit: int = 300,
    *,
    timeout: int = DEFAULT_TIMEOUT,
    runner: Callable[..., Any] | None = None,
    journalctl: str | None = None,
) -> list[LogEntry]:
    """Read the newest *limit* events from the local systemd journal.

    Parameters
    ----------
    log_name:
        One of :data:`SYSTEM_JOURNALS` (``"System"``, ``"User"``, ``"Kernel"``).
    limit:
        Number of events to request (1–:data:`MAX_EVENTS`).
    timeout:
        Maximum time to wait for ``journalctl``.
    runner:
        Optional callable used instead of :func:`subprocess.run` (for tests).
    journalctl:
        Optional path to the ``journalctl`` binary (defaults to ``$PATH``).

    Raises
    ------
    JournalError
        For any failure (missing binary, permission denied, parse error).
    """
    try:
        log_name, limit = validate_request(log_name, limit)
    except ValueError as exc:
        raise JournalError(str(exc)) from exc

    if runner is None:
        if os.name == "nt":
            raise JournalError(
                "The systemd journal is only available on Linux. "
                "Choose a Windows log or analyze a log file instead."
            )
        runner = subprocess.run

    binary = journalctl or find_journalctl()
    if not binary:
        raise JournalError(
            "journalctl was not found. Analyze a log file instead."
        )

    command = [binary, *build_command(log_name, limit)[1:]]
    try:
        result = runner(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired:
        raise JournalError(
            "Reading the systemd journal timed out. Try a smaller number of events."
        ) from None
    except OSError as exc:
        raise JournalError(f"Could not start journalctl: {exc}") from exc

    if result.returncode != 0:
        message = (result.stderr or result.stdout or "").strip()
        lowered = message.casefold()
        if "permission denied" in lowered or "access denied" in lowered:
            message += (
                "\n\nAdd your user to the 'systemd-journal' group, "
                "or run the program with sudo."
            )
        raise JournalError(message or "journalctl returned a non-zero exit code.")

    return parse_journal_output(result.stdout or "", log_name)