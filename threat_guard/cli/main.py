from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

from threat_guard.engine.scanner import ThreatScanner
from threat_guard.engine.audit import local_security_audit
from threat_guard.engine.integrity import create_baseline, compare_baseline
from threat_guard.engine.rootkit import rootkit_indicators
from threat_guard.engine.hardening import server_hardening_checks
from threat_guard.engine.log_analyzer import analyze_log_file
from threat_guard.engine.reports import to_json, write_report


COMMANDS = {"scan", "full", "audit", "rootkit", "hardening",
            "baseline-create", "baseline-compare", "log-analyze"}


def _print_and_export(payload: dict, json_out: Path | None = None,
                      html_out: Path | None = None, csv_out: Path | None = None) -> None:
    print(to_json(payload))
    for out, fmt in ((json_out, "json"), (html_out, "html"), (csv_out, "csv")):
        if out:
            write_report(payload, out, fmt)


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="threat_guard", description="ThreatGuard read-only defensive toolkit")
    sub = parser.add_subparsers(dest="command")

    # scan
    p_scan = sub.add_parser("scan", help="Scan a file or directory")
    p_scan.add_argument("target")
    p_scan.add_argument("--hash-db", type=Path)
    p_scan.add_argument("--yara", type=Path)
    p_scan.add_argument("--signatures", type=Path)
    p_scan.add_argument("--no-clamav", action="store_true")
    p_scan.add_argument("--json-out", type=Path)
    p_scan.add_argument("--html-out", type=Path)
    p_scan.add_argument("--csv-out", type=Path)

    p_full = sub.add_parser(
        "full", help="Review everything: all drives, event logs, autostart, processes, network")
    p_full.add_argument("--json-out", type=Path)
    p_full.add_argument("--html-out", type=Path)
    p_full.add_argument("--csv-out", type=Path)

    sub.add_parser("audit", help="Run the local security audit")
    sub.add_parser("rootkit", help="Check for rootkit indicators")
    sub.add_parser("hardening", help="Run server hardening checks")

    p_bc = sub.add_parser("baseline-create", help="Create a SHA-256 file baseline")
    p_bc.add_argument("target")
    p_bc.add_argument("output")

    p_bcmp = sub.add_parser("baseline-compare", help="Compare against a baseline")
    p_bcmp.add_argument("target")
    p_bcmp.add_argument("baseline")

    p_log = sub.add_parser("log-analyze", help="Analyze a log file for suspicious patterns")
    p_log.add_argument("path")

    argv = sys.argv[1:]
    if argv and argv[0] not in COMMANDS and argv[0] not in {"-h", "--help"}:
        argv = ["scan"] + argv          # backward compatibility
    elif not argv:
        argv = ["--help"]
    args = parser.parse_args(argv)

    if args.command == "scan":
        scanner = ThreatScanner(
            hash_db=args.hash_db, yara_rules=args.yara,
            use_clamav=not args.no_clamav, signature_db=args.signatures,
        )
        report = scanner.scan(args.target)
        _print_and_export(report.to_dict(), args.json_out, args.html_out, args.csv_out)
        return 1 if report.findings else 0

    if args.command == "full":
        from threat_guard.engine.protection import full_review, make_scanner
        report = full_review(None, make_scanner())
        _print_and_export(report, args.json_out, args.html_out, args.csv_out)
        return 1 if report["findings"] else 0
    if args.command == "audit":
        _print_and_export({"checks": local_security_audit()})
        return 0
    if args.command == "rootkit":
        _print_and_export({"checks": rootkit_indicators()})
        return 0
    if args.command == "hardening":
        _print_and_export({"checks": server_hardening_checks()})
        return 0
    if args.command == "baseline-create":
        _print_and_export(create_baseline(args.target, args.output))
        return 0
    if args.command == "baseline-compare":
        _print_and_export(compare_baseline(args.target, args.baseline))
        return 0
    if args.command == "log-analyze":
        _print_and_export(analyze_log_file(args.path))
        return 0
    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())