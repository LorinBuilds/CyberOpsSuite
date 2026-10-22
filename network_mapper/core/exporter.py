"""Report exporters for CyberOpsSuite Network Mapper.

Produces JSON, CSV and HTML reports from a list of :class:`HostResult`
objects. Log messages and host data are treated as untrusted input: CSV
cells are prefixed to neutralise spreadsheet formulas and HTML values are
escaped before being written.
"""

from __future__ import annotations

import csv
import html
import json
from collections.abc import Iterable, Sequence
from typing import Any, Protocol


class _HostLike(Protocol):
    """Minimal interface the exporters rely on."""
    ip: str
    online: bool
    open_ports: list[int]
    services: dict[int, str]


#: CSV column order.
CSV_FIELDS: tuple[str, ...] = ("IP", "Status", "Open Ports", "Services")

#: Characters that can turn a CSV cell into a spreadsheet formula.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _sanitize(value: object) -> str:
    """Neutralise spreadsheet formula injection in a CSV cell."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def _format_ports(ports: Iterable[int]) -> str:
    return ", ".join(str(p) for p in ports)


def _format_services(services: dict[int, str]) -> str:
    return ", ".join(f"{port}: {name}" for port, name in services.items())


def _to_row(result: _HostLike) -> dict[str, Any]:
    """Build the JSON-friendly representation of a single host."""
    return {
        "ip": result.ip,
        "online": bool(result.online),
        "open_ports": list(result.open_ports),
        "services": dict(getattr(result, "services", {})),
    }


# --------------------------------------------------------------------- JSON


def export_json(results: Sequence[_HostLike], path: str) -> None:
    """Write *results* as a pretty-printed JSON array."""
    payload = [_to_row(r) for r in results]
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------- CSV


def export_csv(results: Sequence[_HostLike], path: str) -> None:
    """Write *results* as CSV. Formula-injection prefixes are neutralised."""
    with open(path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle, lineterminator="\n")
        writer.writerow(CSV_FIELDS)
        for r in results:
            writer.writerow([
                _sanitize(r.ip),
                "Online" if r.online else "No response",
                _sanitize(_format_ports(r.open_ports)),
                _sanitize(_format_services(getattr(r, "services", {}))),
            ])


# --------------------------------------------------------------------- HTML

_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Network Mapper Report</title>
<style>
  body {{ font: 15px system-ui, sans-serif; background: #0b1220; color: #e5edf8; padding: 28px; }}
  h1 {{ color: #65d6ad; }}
  p.note {{ color: #8fa8c6; }}
  table {{ width: 100%; border-collapse: collapse; background: #111c2e; }}
  th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #26364c; }}
  th {{ color: #8fa8c6; background: #17263b; }}
  tr.online td:first-child {{ color: #65d6ad; }}
  tr.offline td:first-child {{ color: #66758b; }}
</style>
</head>
<body>
<h1>Network Mapper Report</h1>
<p class="note">
  TCP reachability and common-port results. A missing response does not prove
  a host is offline.
</p>
<table>
  <thead>
    <tr><th>IP</th><th>Status</th><th>Open Ports</th><th>Services</th></tr>
  </thead>
  <tbody>
{rows}
  </tbody>
</table>
</body>
</html>
"""


def _html_row(result: _HostLike) -> str:
    css_class = "online" if result.online else "offline"
    status = "Online" if result.online else "No response"
    return (
        f'    <tr class="{css_class}">'
        f"<td>{html.escape(str(result.ip))}</td>"
        f"<td>{html.escape(status)}</td>"
        f"<td>{html.escape(_format_ports(result.open_ports))}</td>"
        f"<td>{html.escape(_format_services(getattr(result, 'services', {})))}</td>"
        f"</tr>"
    )


def export_html(results: Sequence[_HostLike], path: str) -> None:
    """Write *results* as a self-contained HTML report."""
    rows = "\n".join(_html_row(r) for r in results)
    document = _HTML_TEMPLATE.format(rows=rows)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(document)