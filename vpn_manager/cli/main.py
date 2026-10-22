"""Command-line interface for the CyberOpsSuite VPN Manager.

Provides a small set of subcommands for managing Xray profiles and
running the local proxy from scripts or terminals.

Usage
-----
::

    python -m vpn_manager.cli.main list
    python -m vpn_manager.cli.main import "vless://..."
    python -m vpn_manager.cli.main connect <profile-id>
    python -m vpn_manager.cli.main status
    python -m vpn_manager.cli.main disconnect
    python -m vpn_manager.cli.main remove <profile-id>
"""

from __future__ import annotations

import argparse
import sys

from vpn_manager.core.xray_manager import (
    DEFAULT_SOCKS_PORT,
    VPNError,
    XrayManager,
)


def _print_profiles(manager: XrayManager) -> int:
    profiles = manager.profiles
    if not profiles:
        print("No profiles yet. Use 'import <link>' to add one.")
        return 0

    print(f"{'ID':36}  {'PROTO':6}  {'NAME':30}  {'ADDRESS':40}  PORT")
    print("-" * 120)
    for p in profiles:
        print(
            f"{p.get('id', ''):36}  "
            f"{str(p.get('protocol', '')).upper():6}  "
            f"{str(p.get('name', ''))[:30]:30}  "
            f"{str(p.get('address', ''))[:40]:40}  "
            f"{p.get('port', '')}"
        )
    return 0


def _find_profile(manager: XrayManager, profile_id: str) -> dict | None:
    """Find a profile by full id or by unique id prefix."""
    for p in manager.profiles:
        if p.get("id") == profile_id:
            return p
    # Prefix match, but only if unique.
    matches = [p for p in manager.profiles if p.get("id", "").startswith(profile_id)]
    if len(matches) == 1:
        return matches[0]
    return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vpnctl",
        description="CyberOpsSuite VPN Manager CLI",
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s 1.0.0",
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    sub.add_parser("list", help="List saved profiles")

    imp = sub.add_parser("import", help="Import a VLESS/VMess link or subscription URL")
    imp.add_argument("link", help="vless://, vmess:// or http(s):// subscription URL")

    con = sub.add_parser("connect", help="Start Xray with the given profile")
    con.add_argument("profile_id", help="Profile ID (or unique prefix)")
    con.add_argument(
        "--port", type=int, default=DEFAULT_SOCKS_PORT,
        help=f"Local SOCKS5 port (default: {DEFAULT_SOCKS_PORT})",
    )
    con.add_argument(
        "--xray", default="",
        help="Path to the Xray executable (default: bin/xray)",
    )

    sub.add_parser("disconnect", help="Stop the running Xray process")
    sub.add_parser("status", help="Show the current connection status")

    rm = sub.add_parser("remove", help="Remove a saved profile")
    rm.add_argument("profile_id", help="Profile ID (or unique prefix)")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    try:
        manager = XrayManager()
    except Exception as exc:
        print(f"ERROR: could not load profiles: {exc}", file=sys.stderr)
        return 1

    try:
        if args.command == "list":
            return _print_profiles(manager)

        if args.command == "import":
            added = manager.import_text(args.link)
            for p in added:
                print(f"+ {p['id'][:8]}…  {p['name']}  ({p['protocol']})")
            print(f"Imported {len(added)} profile(s).")
            return 0

        if args.command == "remove":
            profile = _find_profile(manager, args.profile_id)
            if profile is None:
                print(f"ERROR: no profile matches {args.profile_id!r}", file=sys.stderr)
                return 1
            manager.remove(profile["id"])
            print(f"Removed: {profile['name']}")
            return 0

        if args.command == "connect":
            profile = _find_profile(manager, args.profile_id)
            if profile is None:
                print(f"ERROR: no profile matches {args.profile_id!r}", file=sys.stderr)
                return 1
            manager.connect(profile, executable=args.xray, local_port=args.port)
            ok, msg = manager.test_connection(timeout=8.0)
            print(f"{'OK' if ok else 'WARN'}: {msg}")
            if ok:
                print(f"Local SOCKS5 proxy: 127.0.0.1:{args.port}")
                print(f"Local HTTP proxy:   127.0.0.1:{args.port + 1}")
                print("Press Ctrl+C or run 'disconnect' to stop.")
                try:
                    while manager.connected():
                        import time
                        time.sleep(1)
                except KeyboardInterrupt:
                    print("\nStopping…")
            return 0 if ok else 2

        if args.command == "disconnect":
            manager.disconnect()
            print("Disconnected.")
            return 0

        if args.command == "status":
            if manager.connected():
                ok, msg = manager.test_connection(timeout=6.0)
                print(f"Connected — {msg}" if ok else f"Connected (unverified) — {msg}")
            else:
                print("Not connected.")
            return 0

    except VPNError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        try:
            manager.disconnect()
        except Exception:
            pass
        return 130

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())