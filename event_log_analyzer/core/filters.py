"""Filtering helpers shared by the CLI, the API and the GUI."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from .levels import normalize_level
from .parser import LogEntry

#: Fields searched by the CLI and API.
DEFAULT_SEARCH_FIELDS: tuple[str, ...] = ("message", "source", "event_id")
#: Fields searched by the GUI search box.
ALL_SEARCH_FIELDS: tuple[str, ...] = (
    "timestamp",
    "level",
    "event_id",
    "source",
    "message",
    "log_name",
)


def filter_entries(
    entries: Iterable[LogEntry],
    *,
    level: str = "ALL",
    search: str | None = None,
    limit: int | None = None,
    fields: Sequence[str] = DEFAULT_SEARCH_FIELDS,
) -> list[LogEntry]:
    """Filter events by level and case-insensitive text, optionally capping the result.

    ``limit=None`` (or a value below 1) means "no limit".
    """
    wanted = None if str(level).strip().upper() == "ALL" else normalize_level(level)
    needle = search.strip().casefold() if search else ""
    cap = limit if limit is not None and limit > 0 else None

    result: list[LogEntry] = []
    for entry in entries:
        if wanted is not None and normalize_level(entry.level) != wanted:
            continue
        if needle:
            haystack = " ".join(str(getattr(entry, name, "")) for name in fields)
            if needle not in haystack.casefold():
                continue
        result.append(entry)
        if cap is not None and len(result) >= cap:
            break
    return result
