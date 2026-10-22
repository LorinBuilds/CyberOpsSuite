"""Severity-level normalisation shared by the CLI, the API and the GUI."""

from __future__ import annotations

CANONICAL_LEVELS: tuple[str, ...] = ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG")
FILTER_LEVELS: tuple[str, ...] = ("ALL", *CANONICAL_LEVELS)

_ALIASES = {
    "CRIT": "CRITICAL",
    "FATAL": "CRITICAL",
    "ALERT": "CRITICAL",
    "EMERGENCY": "CRITICAL",
    "ERR": "ERROR",
    "WARN": "WARNING",
    "INFORMATION": "INFO",
    "INFORMATIONAL": "INFO",
    "NOTICE": "INFO",
    "VERBOSE": "DEBUG",
    "TRACE": "DEBUG",
}


def normalize_level(value: object, default: str = "INFO") -> str:
    """Return a canonical upper-case level name.

    ``None`` and blank values become *default*. Known aliases (``warn``,
    ``Information``, ``Verbose`` ...) are mapped to one of ``CANONICAL_LEVELS``.
    Unknown values are kept, upper-cased, so no information is lost.
    """
    text = "" if value is None else str(value).strip().upper()
    if not text:
        return default
    return _ALIASES.get(text, text)
