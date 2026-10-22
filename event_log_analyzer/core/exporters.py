"""CSV / JSON export helpers.

Log messages are untrusted input. A cell that starts with ``=``, ``+``, ``-`` or
``@`` can be executed as a formula when the CSV is opened in Excel or LibreOffice
("CSV injection"), so such cells are prefixed with an apostrophe.
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Sequence
from typing import TextIO

from .parser import CSV_FIELDS, LogEntry

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_cell(value: object) -> str:
    """Neutralise spreadsheet formulas in a CSV cell."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def write_csv(entries: Iterable[LogEntry], handle: TextIO) -> int:
    """Write *entries* as CSV to *handle* and return the number of rows written.

    Open files with ``newline=""`` so the csv module controls line endings.
    """
    writer = csv.writer(handle, lineterminator="\n")
    writer.writerow(CSV_FIELDS)
    count = 0
    for entry in entries:
        data = entry.to_dict()
        writer.writerow([sanitize_cell(data[name]) for name in CSV_FIELDS])
        count += 1
    return count


def entries_to_json(entries: Sequence[LogEntry], *, indent: int | None = 2) -> str:
    """Serialise events to a JSON document: ``{"count": n, "events": [...]}``."""
    payload = {"count": len(entries), "events": [entry.to_dict() for entry in entries]}
    return json.dumps(payload, indent=indent, ensure_ascii=False)
