"""JSON Lines parsing for Event Log Analyzer."""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from .levels import normalize_level

#: Column order used for CSV / JSON exports.
CSV_FIELDS: tuple[str, ...] = (
    "timestamp",
    "level",
    "event_id",
    "source",
    "log_name",
    "machine",
    "message",
)


@dataclass
class LogEntry:
    """A single normalised log event."""

    timestamp: str = ""
    level: str = "INFO"
    message: str = ""
    source: str = ""
    event_id: str = ""
    log_name: str = ""
    machine: str = ""
    raw: dict[str, Any] | None = field(default=None, repr=False, compare=False)

    def to_dict(self) -> dict[str, str]:
        """Return the exportable fields (the ``raw`` payload is not included)."""
        return {name: getattr(self, name) for name in CSV_FIELDS}


@dataclass(frozen=True)
class ParseIssue:
    """A line that could not be parsed."""

    line: int
    error: str

    def __str__(self) -> str:
        return f"Line {self.line}: {self.error}"


def _first(data: dict[str, Any], *keys: str, default: Any = "") -> Any:
    """Return the first non-null value among *keys*."""
    for key in keys:
        value = data.get(key)
        if value is not None:
            return value
    return default


def entry_from_dict(data: dict[str, Any]) -> LogEntry:
    """Build a ``LogEntry`` from a decoded JSON object, accepting common field aliases."""
    return LogEntry(
        timestamp=str(_first(data, "timestamp", "time")),
        level=normalize_level(_first(data, "level", "severity", default=None)),
        message=str(_first(data, "message", "msg")),
        source=str(_first(data, "source", "provider")),
        event_id=str(_first(data, "event_id", "eventId")),
        log_name=str(_first(data, "log_name", "logName")),
        machine=str(_first(data, "machine", "host", "hostname")),
        raw=data,
    )


def parse_line(line: str) -> LogEntry:
    """Parse one JSON object per line. Raises ``ValueError`` for anything else."""
    try:
        data = json.loads(line)
    except RecursionError as exc:  # pathological nesting such as "[[[[[..."
        raise ValueError("JSON nesting is too deep") from exc
    if not isinstance(data, dict):
        raise ValueError("Each JSON line must be an object")
    return entry_from_dict(data)


def parse_lines(
    lines: Iterable[str], *, max_entries: int | None = None
) -> tuple[list[LogEntry], list[ParseIssue]]:
    """Parse JSON Lines from any iterable of strings.

    Blank lines are skipped, invalid lines are reported as ``ParseIssue`` objects
    (1-based line numbers) and never abort the run. Parsing stops early once
    *max_entries* valid events were collected.
    """
    entries: list[LogEntry] = []
    issues: list[ParseIssue] = []
    for line_number, line in enumerate(lines, start=1):
        text = line.strip()
        if not text:
            continue
        try:
            entries.append(parse_line(text))
        except ValueError as exc:
            issues.append(ParseIssue(line_number, str(exc)))
            continue
        if max_entries is not None and len(entries) >= max_entries:
            break
    return entries, issues


class LogParser:
    """Parse a JSON Lines file from disk.

    ``errors`` holds human-readable messages for lines that were skipped and
    ``issues`` the same information as structured ``ParseIssue`` objects.
    """

    def __init__(self, file_path: str, *, max_entries: int | None = None):
        self.file_path = file_path
        self.max_entries = max_entries
        self.errors: list[str] = []
        self.issues: list[ParseIssue] = []

    def parse(self) -> list[LogEntry]:
        self.errors = []
        self.issues = []

        if not os.path.isfile(self.file_path):
            raise FileNotFoundError(f"Log file not found: {self.file_path}")

        try:
            with open(self.file_path, encoding="utf-8-sig", errors="replace") as handle:
                entries, issues = parse_lines(handle, max_entries=self.max_entries)
        except OSError as exc:
            raise OSError(f"Could not read log file: {exc}") from exc

        self.issues = issues
        self.errors = [str(issue) for issue in issues]
        return entries
