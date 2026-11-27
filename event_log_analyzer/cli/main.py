"""Command-line interface for Event Log Analyzer."""

from __future__ import annotations

import argparse
import io
import sys
import time
from collections.abc import Sequence

from event_log_analyzer import __version__
from event_log_analyzer.core.exporters import entries_to_json, write_csv
from event_log_analyzer.core.filters import filter_entries
from event_log_analyzer.core.levels import FILTER_LEVELS
from event_log_analyzer.core.linux_events import SYSTEM_JOURNALS, JournalError, read_linux_journal
from event_log_analyzer.core.listeners import AllowListError, parse_allow_list
from event_log_analyzer.core.netflow_events import DEFAULT_NETFLOW_PORT, NetFlowListener
from event_log_analyzer.core.parser import LogEntry, LogParser
from event_log_analyzer.core.syslog_events import DEFAULT_SYSLOG_PORT, SyslogListener
from event_log_analyzer.core.windows_events import (
    MAX_EVENTS,
    MIN_EVENTS,
    SYSTEM_LOGS,
    EventLogError,
    read_windows_events,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="event-log-analyzer",
        description=(
            "Parse, filter and search JSON Lines log files, local Windows event logs, "
            "the Linux journal, or live Syslog / NetFlow traffic."
        ),
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="Path to a JSON Lines log file (.log, .txt or .jsonl)",
    )
    parser.add_argument(
        "--windows",
        metavar="LOG",
        choices=SYSTEM_LOGS,
        help="Read a local Windows event log instead of a file: " + ", ".join(SYSTEM_LOGS),
    )
    parser.add_argument(
        "--linux",
        metavar="LOG",
        choices=SYSTEM_JOURNALS,
        help="Read the local systemd journal instead of a file: " + ", ".join(SYSTEM_JOURNALS),
    )
    parser.add_argument(
        "--listen",
        choices=("syslog", "netflow"),
        help="Capture live network events over UDP (Syslog or NetFlow v5)",
    )
    parser.add_argument(
        "--port",
        type=int,
        help=f"UDP port for --listen (default: {DEFAULT_SYSLOG_PORT} syslog, {DEFAULT_NETFLOW_PORT} netflow)",
    )
    parser.add_argument(
        "--allow",
        default="",
        metavar="IPS",
        help="Comma-separated sender IPs accepted by --listen (default: all)",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help="Seconds to capture with --listen; 0 = until Ctrl+C (default: 30)",
    )
    parser.add_argument(
        "--max-events",
        type=int,
        default=300,
        help=f"Events to request with --windows / --linux ({MIN_EVENTS}-{MAX_EVENTS}, default: 300)",
    )
    parser.add_argument(
        "--level",
        type=str.upper,
        choices=FILTER_LEVELS,
        default="ALL",
        help="Filter events by level (default: ALL)",
    )
    parser.add_argument(
        "--search",
        help="Case-insensitive text to look for in the message, source and event ID",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Maximum number of displayed events; use 0 for all (default: 50)",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "csv"),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument("--output", "-o", metavar="PATH", help="Write the result to a file")
    parser.add_argument(
        "--errors",
        action="store_true",
        help="Show lines of the log file that could not be parsed",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def render_text(entries: Sequence[LogEntry], total: int) -> str:
    lines = [f"Events found: {total}"]
    if not entries:
        lines.append("No events matched your filters.")
    for index, entry in enumerate(entries, start=1):
        lines.append("")
        lines.append(f"[{index}] {entry.timestamp} | {entry.level}")
        if entry.source:
            lines.append(f"Source: {entry.source}")
        if entry.event_id:
            lines.append(f"Event ID: {entry.event_id}")
        lines.append(f"Message: {entry.message}")
    return "\n".join(lines) + "\n"


def render(entries: Sequence[LogEntry], total: int, fmt: str) -> str:
    if fmt == "json":
        return entries_to_json(entries) + "\n"
    if fmt == "csv":
        buffer = io.StringIO()
        write_csv(entries, buffer)
        return buffer.getvalue()
    return render_text(entries, total)


def capture_network(
    kind: str, port: int | None, allow: set[str], duration: int
) -> tuple[list[LogEntry], object]:
    """Listen for *duration* seconds (0 = until Ctrl+C) and return the events."""
    if kind == "syslog":
        listener = SyslogListener(port=port or DEFAULT_SYSLOG_PORT, allow_ips=allow)
    else:
        listener = NetFlowListener(port=port or DEFAULT_NETFLOW_PORT, allow_ips=allow)
    listener.start()  # RuntimeError with a readable message if the port is busy
    limit = f"{duration} s" if duration else "Ctrl+C"
    print(
        f"Listening for {kind} on UDP {listener.port} (stops after {limit})...",
        file=sys.stderr,
    )
    entries: list[LogEntry] = []
    deadline = time.monotonic() + duration if duration else None
    try:
        while deadline is None or time.monotonic() < deadline:
            time.sleep(0.2)
            entries.extend(listener.drain(10000))
    except KeyboardInterrupt:
        pass
    finally:
        listener.stop()
        entries.extend(listener.drain(10000))
    return entries, listener.stats


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.limit < 0:
        parser.error("--limit cannot be negative")
    sources = [bool(args.file), bool(args.windows), bool(args.linux), bool(args.listen)]
    if sum(sources) != 1:
        parser.error("provide exactly one source: a log FILE, --windows LOG, --linux LOG or --listen KIND")
    if args.duration < 0:
        parser.error("--duration cannot be negative")
    if args.port is not None and not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    # Never crash on consoles that cannot print some characters found in logs.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    issues: list[str] = []
    try:
        if args.windows:
            entries = read_windows_events(args.windows, args.max_events)
        elif args.linux:
            entries = read_linux_journal(args.linux, args.max_events)
        elif args.listen:
            entries, stats = capture_network(
                args.listen, args.port, parse_allow_list(args.allow), args.duration
            )
            print(
                f"Captured {stats.events} events ({stats.packets} packets, "
                f"{stats.rejected} rejected, {stats.malformed} malformed, "
                f"{stats.unsupported} unsupported).",
                file=sys.stderr,
            )
        else:
            log_parser = LogParser(args.file)
            entries = log_parser.parse()
            issues = log_parser.errors
    except (OSError, ValueError, RuntimeError, EventLogError, JournalError, AllowListError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    matched = filter_entries(entries, level=args.level, search=args.search)
    shown = matched if args.limit == 0 else matched[: args.limit]
    output = render(shown, len(matched), args.format)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8", newline="") as handle:
                handle.write(output)
        except OSError as exc:
            print(f"Error: could not write {args.output}: {exc}", file=sys.stderr)
            return 1
        print(f"Wrote {len(shown)} events to {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(output)

    if args.errors and issues:
        print(f"\nParsing issues: {len(issues)}", file=sys.stderr)
        for issue in issues:
            print(f"- {issue}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
