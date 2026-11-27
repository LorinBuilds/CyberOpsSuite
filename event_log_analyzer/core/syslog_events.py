"""Read-only UDP Syslog listener for Event Log Analyzer.

Listens on a configurable UDP port (default 5140 to avoid needing root)
and parses RFC 3164 (BSD) and RFC 5424 (IETF) syslog messages into the
same LogEntry representation used by the Windows / Linux backends.

Security note: Syslog has no authentication. An optional allow-list of
source IPs is enforced; if empty, all senders are accepted (test mode).
"""

from __future__ import annotations

import re
import socket
from datetime import datetime, timedelta

from .levels import normalize_level
from .listeners import UdpListener
from .parser import LogEntry

DEFAULT_SYSLOG_PORT = 5140

_SEVERITY_MAP = {
    0: "CRITICAL", 1: "CRITICAL", 2: "CRITICAL", 3: "ERROR",
    4: "WARNING", 5: "INFO", 6: "INFO", 7: "DEBUG",
}

_SEVERITY_NAMES = {
    0: "emerg", 1: "alert", 2: "crit", 3: "err",
    4: "warning", 5: "notice", 6: "info", 7: "debug",
}

_FACILITY_NAMES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth",
    5: "syslog", 6: "lpr", 7: "news", 8: "uucp", 9: "cron",
    10: "authpriv", 11: "ftp", 12: "ntp", 13: "security", 14: "console",
    15: "solaris-cron", 16: "local0", 17: "local1",
    18: "local2", 19: "local3", 20: "local4", 21: "local5",
    22: "local6", 23: "local7",
}

# One or more RFC 5424 structured-data elements, e.g. [a b="c"][d e="f\]"]
_SD = r"(?:\[(?:[^\]\\]|\\.)*\])+"

_RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d{1,2}) "
    r"(?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<proc>\S+) "
    rf"(?P<msgid>\S+) (?P<sd>-|{_SD})(?: (?P<msg>.*))?$",
    re.DOTALL,
)

# <34>Oct 11 22:14:15 host tag[123]: message   (tag and pid are optional)
_RFC3164_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>"
    r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) "
    r"(?:(?P<tag>[^\s:\[]+)(?:\[(?P<pid>[^\]]*)\])?:\s?)?"
    r"(?P<msg>.*)$",
    re.DOTALL,
)

# <13>message without any header (some embedded devices)
_PRI_ONLY_RE = re.compile(r"^<(?P<pri>\d{1,3})>(?P<msg>.*)$", re.DOTALL)

_NIL = "-"


def _decode_priority(pri: int) -> tuple[str, str, int]:
    """Return ``(facility_name, canonical_level, severity_code)``."""
    facility_code, severity_code = divmod(pri, 8)
    facility = _FACILITY_NAMES.get(facility_code, f"fac{facility_code}")
    return facility, _SEVERITY_MAP.get(severity_code, "INFO"), severity_code


def _valid_pri(text: str) -> int | None:
    value = int(text)
    return value if 0 <= value <= 191 else None  # 23 facilities * 8 + 7 = 191


def _parse_bsd_timestamp(text: str, now: datetime | None = None) -> str:
    """Turn ``Oct 11 22:14:15`` into ``YYYY-MM-DD HH:MM:SS``.

    RFC 3164 has no year. A date that would land in the future (a December
    message received in January) belongs to the previous year.
    """
    now = now or datetime.now()
    try:
        parsed = datetime.strptime(
            f"{now.year} {' '.join(text.split())}", "%Y %b %d %H:%M:%S"
        )
    except ValueError:
        return text
    if parsed - now > timedelta(days=1):
        try:
            parsed = parsed.replace(year=now.year - 1)
        except ValueError:  # Feb 29
            return text
    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def _normalize_iso_timestamp(text: str) -> str:
    """RFC 5424 ISO-8601 -> local ``YYYY-MM-DD HH:MM:SS`` (same format as every other source)."""
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone()  # to the viewer's local time
    return parsed.strftime("%Y-%m-%d %H:%M:%S")


def parse_syslog_message(raw: str, source_ip: str) -> LogEntry:
    """Parse one syslog line into a LogEntry. Never raises."""
    text = raw.strip()
    facility = "syslog"
    severity = "INFO"
    severity_code: int | None = None
    timestamp = ""
    host = ""
    app = ""
    pid = ""
    message = text
    event_id = "SYSLOG-RAW"
    fmt = "raw"

    m5424 = _RFC5424_RE.match(text)
    m3164 = None if m5424 else _RFC3164_RE.match(text)
    m_pri = None if (m5424 or m3164) else _PRI_ONLY_RE.match(text)

    if m5424 and (pri := _valid_pri(m5424.group("pri"))) is not None:
        fmt = "RFC5424"
        facility, severity, severity_code = _decode_priority(pri)
        ts = m5424.group("ts")
        timestamp = "" if ts == _NIL else _normalize_iso_timestamp(ts)
        host = "" if m5424.group("host") == _NIL else m5424.group("host")
        app = "" if m5424.group("app") == _NIL else m5424.group("app")
        pid = "" if m5424.group("proc") == _NIL else m5424.group("proc")
        message = (m5424.group("msg") or "").lstrip("\ufeff")
        event_id = f"SYSLOG-{facility}"
    elif m3164 and (pri := _valid_pri(m3164.group("pri"))) is not None:
        fmt = "RFC3164"
        facility, severity, severity_code = _decode_priority(pri)
        timestamp = _parse_bsd_timestamp(m3164.group("ts"))
        host = m3164.group("host")
        app = (m3164.group("tag") or "").strip()
        pid = m3164.group("pid") or ""
        message = m3164.group("msg")
        event_id = f"SYSLOG-{facility}"
    elif m_pri and (pri := _valid_pri(m_pri.group("pri"))) is not None:
        fmt = "PRI-only"
        facility, severity, severity_code = _decode_priority(pri)
        message = m_pri.group("msg").strip()
        event_id = f"SYSLOG-{facility}"

    raw_fields = {
        "source_ip": source_ip,
        "format": fmt,
        "facility": facility,
        "severity": severity,
        "raw": text,
    }
    if severity_code is not None:
        raw_fields["severity_name"] = _SEVERITY_NAMES.get(severity_code, "")
    if pid:
        raw_fields["pid"] = pid

    return LogEntry(
        timestamp=timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        level=normalize_level(severity),
        message=message,
        source=app or host or source_ip,
        event_id=event_id,
        log_name="Syslog",
        machine=host or source_ip,
        raw=raw_fields,
    )


class SyslogListener(UdpListener):
    """Background UDP listener that pushes parsed LogEntry objects into a queue."""

    name = "Syslog"

    def __init__(
        self,
        port: int = DEFAULT_SYSLOG_PORT,
        host: str = "0.0.0.0",
        allow_ips: set[str] | None = None,
        max_queue: int = 20000,
    ):
        super().__init__(port=port, host=host, allow_ips=allow_ips, max_queue=max_queue)

    def handle_datagram(self, data: bytes, source_ip: str) -> list[LogEntry]:
        text = data.decode("utf-8", errors="replace").rstrip("\x00\r\n")
        if not text.strip():
            return []
        return [parse_syslog_message(text, source_ip)]


def send_test_message(port: int = DEFAULT_SYSLOG_PORT, host: str = "127.0.0.1") -> str:
    """Send one RFC 5424 test message to ``host:port`` and return its text.

    Lets users confirm the listener works before configuring a real device.
    """
    stamp = datetime.now().astimezone().isoformat(timespec="seconds")
    message = (
        f"<134>1 {stamp} event-log-analyzer test - - - "
        "Test message from Event Log Analyzer"
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(message.encode("utf-8"), (host, port))
    return message
