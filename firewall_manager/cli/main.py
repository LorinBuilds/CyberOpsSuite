"""Command-line interface for CyberOpsSuite Firewall Manager."""
import argparse
import sys
from firewall_manager.core.firewall import FirewallManager


def main(argv=None):
    parser = argparse.ArgumentParser(prog="firewallctl", description="CyberOpsSuite Firewall Rule Manager")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("list", help="List saved CyberOps rules")
    add = sub.add_parser("add", help="Add a firewall rule")
    add.add_argument("--action", required=True, choices=["allow", "block"])
    add.add_argument("--ip", required=True)
    add.add_argument("--port", required=True, type=int)
    add.add_argument("--protocol", required=True, choices=["tcp", "udp"])
    add.add_argument("--direction", choices=["inbound", "outbound"], default="outbound")
    for cmd in ("remove", "enable", "disable"):
        p = sub.add_parser(cmd)
        p.add_argument("--id", required=True, type=int)
    sub.add_parser("apply", help="Apply saved JSON rules to Windows Firewall")
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    try:
        fw = FirewallManager()
        if args.command == "list":
            for r in fw.list_rules():
                print(f"[{r.rule_id}] {r.action.upper()} {r.ip}:{r.port}/{r.protocol} {r.direction.upper()} {'ENABLED' if r.enabled else 'DISABLED'}")
        elif args.command == "add":
            r = fw.add_rule(args.action, args.ip, args.port, args.protocol, args.direction)
            print(f"Added CyberOps_{r.rule_id}")
        elif args.command == "remove":
            fw.remove_rule(args.id); print(f"Removed CyberOps_{args.id}")
        elif args.command == "enable":
            fw.enable_rule(args.id); print(f"Enabled CyberOps_{args.id}")
        elif args.command == "disable":
            fw.disable_rule(args.id); print(f"Disabled CyberOps_{args.id}")
        elif args.command == "apply":
            print(fw.custom_mode())
        return 0
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
