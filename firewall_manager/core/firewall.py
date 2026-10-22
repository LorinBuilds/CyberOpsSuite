"""Firewall manager for CyberOpsSuite.

Supports two platforms:

* **Windows** — ``netsh advfirewall`` backend. The JSON file is the
  source of truth for CyberOps-owned rules. OS mutations are performed
  only for rules in the ``CyberOps_<integer>`` namespace, except the
  explicit system-rule and reset methods.

* **Linux** — ``ufw``, ``nft``, or ``iptables`` backend, selected
  automatically in that order. Only ``CyberOps`` rules are touched;
  existing system rules are never modified except by explicit reset.
"""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from core.utils.paths import config_root, project_root
from core.utils.subprocess_utils import get_no_window_kwargs


#: Directory for the rules JSON and backups (user config).
APP_DIR_NAME = "FirewallManager"

#: Legacy fallback: the project-local file used by earlier versions.
LEGACY_RULES_PATH = project_root() / "exports" / "json" / "firewall_rules.json"


def rules_path() -> Path:
    """Return the canonical rules JSON file path."""
    return config_root(APP_DIR_NAME) / "firewall_rules.json"


def backup_dir() -> Path:
    """Return the backup directory (created on demand)."""
    path = config_root(APP_DIR_NAME) / "backups"
    path.mkdir(parents=True, exist_ok=True)
    return path


class Rule:
    """A single CyberOps firewall rule."""

    def __init__(
        self,
        rule_id,
        action,
        ip,
        port,
        protocol,
        direction: str = "inbound",
        enabled=True,
    ):
        self.rule_id = int(rule_id)
        self.action = str(action).lower()
        self.ip = str(ip)
        self.port = int(port) if str(port).isdigit() else port
        self.protocol = str(protocol).upper()
        self.direction = str(direction).lower()
        self.enabled = (
            enabled if isinstance(enabled, bool)
            else str(enabled).lower() in {"true", "yes", "1", "enabled"}
        )

    def to_dict(self):
        return {
            "id": self.rule_id,
            "action": self.action,
            "ip": self.ip,
            "port": self.port,
            "protocol": self.protocol,
            "direction": self.direction,
            "enabled": self.enabled,
        }


class FirewallManager:
    """Cross-platform firewall rule manager.

    On Windows, uses ``netsh advfirewall``.
    On Linux, prefers ``ufw``, then ``nft``, then ``iptables``.
    """

    def __init__(self, path: Path | str | None = None, *, runner=None):
        self.path = Path(path) if path is not None else rules_path()
        self.rules: list[Rule] = []
        # اعمال get_no_window_kwargs در همین لایه انجام می‌شود
        self._runner = runner or (lambda *a, **kw: subprocess.run(*a, **kw, **get_no_window_kwargs()))
        self._system = platform.system().lower()

        # Linux backend detection.
        self._linux_backend: str = ""
        if self._system == "linux":
            self._linux_backend = self._detect_linux_backend()

        self.load()

    # ------------------------------------------------------- platform

    @staticmethod
    def _detect_linux_backend() -> str:
        """Return 'ufw', 'nft', 'iptables', or '' if none are available."""
        if shutil.which("ufw"):
            return "ufw"
        if shutil.which("nft"):
            return "nft"
        if shutil.which("iptables"):
            return "iptables"
        return ""

    def _is_windows(self) -> bool:
        return self._system == "windows" or os.name == "nt"

    def _is_linux(self) -> bool:
        return self._system == "linux"

    # ------------------------------------------------------- process run

    def _run(self, args: list, *, check=True, timeout=15):
        """Run a system command and return the result."""
        try:
            result = self._runner(
                list(map(str, args)),
                capture_output=True,
                text=True,
                shell=False,
                timeout=timeout,
                # creationflags حذف شد چون در _runner اعمال می‌شود
            )
        except (OSError, subprocess.SubprocessError) as exc:
            if check:
                raise RuntimeError(f"Could not run command: {exc}") from exc
            raise
        if check and result.returncode != 0:
            details = (
                result.stderr or result.stdout or "Unknown system error"
            ).strip()
            raise RuntimeError(
                f"Command failed (exit code {result.returncode}): {details}"
            )
        return result

    def _run_netsh(self, args, *, check=True, timeout=15):
        """Windows-only: run netsh."""
        return self._run(["netsh", *args], check=check, timeout=timeout)

    def _run_linux(self, args, *, check=True, timeout=15):
        """Linux-only: run the detected backend."""
        if not self._linux_backend:
            raise RuntimeError(
                "No Linux firewall backend found. Install ufw, nft, or iptables."
            )
        return self._run([self._linux_backend, *args], check=check, timeout=timeout)

    # ------------------------------------------------------- validation

    @staticmethod
    def validate_rule(rule: Rule) -> None:
        if rule.rule_id < 1:
            raise ValueError("Rule id must be a positive integer.")
        if rule.action not in {"allow", "block"}:
            raise ValueError(f"Rule {rule.rule_id}: action must be allow or block.")
        if rule.direction not in {"inbound", "outbound"}:
            raise ValueError(
                f"Rule {rule.rule_id}: direction must be inbound or outbound."
            )
        if rule.protocol not in {"TCP", "UDP", "ANY", "6", "17", "256"}:
            raise ValueError(
                f"Rule {rule.rule_id}: unsupported protocol {rule.protocol!r}."
            )
        try:
            port = int(rule.port)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Rule {rule.rule_id}: port must be 1–65535.") from exc
        if not 1 <= port <= 65535:
            raise ValueError(f"Rule {rule.rule_id}: port must be 1–65535.")
        ip_value = rule.ip.strip()
        if not ip_value or (
            ip_value.casefold() != "any"
            and ip_value.casefold() != "localsubnet"
        ):
            try:
                ipaddress.ip_network(ip_value, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"Rule {rule.rule_id}: ip must be any, LocalSubnet, "
                    f"an IP, or a CIDR network."
                ) from exc
        if not isinstance(rule.enabled, bool):
            raise ValueError(f"Rule {rule.rule_id}: enabled must be a boolean.")

    # ------------------------------------------------------------- load

    def load(self) -> None:
        # Migrate from the legacy project-local file if needed.
        if not self.path.exists() and LEGACY_RULES_PATH.exists():
            self.path = LEGACY_RULES_PATH

        if not self.path.exists():
            self.rules = []
            self.save(backup=False)
            return

        try:
            with self.path.open("r", encoding="utf-8-sig") as stream:
                data = json.load(stream)
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(
                f"Cannot read rules JSON at {self.path}: {exc}"
            ) from exc

        if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
            raise ValueError(
                "Rules JSON must be an object containing a 'rules' list."
            )

        parsed: list[Rule] = []
        seen: set[int] = set()
        for index, item in enumerate(data["rules"], start=1):
            if not isinstance(item, dict):
                raise ValueError(f"Rule entry {index} must be a JSON object.")
            required = {"id", "action", "ip", "port", "protocol"}
            missing = required - item.keys()
            if missing:
                raise ValueError(
                    f"Rule entry {index} is missing: {', '.join(sorted(missing))}."
                )
            try:
                rule = Rule(
                    item["id"], item["action"], item["ip"], item["port"],
                    item["protocol"], item.get("direction", "inbound"),
                    item.get("enabled", True),
                )
                self.validate_rule(rule)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Invalid rule entry {index}: {exc}") from exc
            if rule.rule_id in seen:
                raise ValueError(f"Duplicate rule id: {rule.rule_id}.")
            seen.add(rule.rule_id)
            parsed.append(rule)
        self.rules = parsed

    # ------------------------------------------------------------- save

    def _make_backup(self) -> Path | None:
        if not self.path.exists():
            return None
        destination = backup_dir() / (
            f"firewall_rules_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json.bak"
        )
        shutil.copy2(self.path, destination)
        return destination

    def save(self, *, backup=True) -> None:
        data = {"rules": [r.to_dict() for r in self.rules]}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if backup and self.path.exists():
            self._make_backup()

        fd, temp_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent,
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
                json.dump(data, stream, indent=4, ensure_ascii=False)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_name, self.path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def restore_backup(self, backup_path: Path | str) -> None:
        source = Path(backup_path)
        if not source.is_file():
            raise FileNotFoundError(f"Backup not found: {source}")
        with source.open("r", encoding="utf-8-sig") as stream:
            json.load(stream)
        self._make_backup()
        shutil.copy2(source, self.path)
        self.load()

    def list_rules(self):
        return list(self.rules)
    
    # ============================================================
    # Windows backend (netsh)
    # ============================================================

    @staticmethod
    def _port_key(direction):
        return "localport" if direction == "inbound" else "remoteport"

    def _windows_command_for_rule(self, rule: Rule) -> list:
        """Build the netsh command for a rule."""
        self.validate_rule(rule)
        return [
            "advfirewall", "firewall", "add", "rule",
            f"name=CyberOps_{rule.rule_id}",
            f"dir={'in' if rule.direction == 'inbound' else 'out'}",
            f"action={rule.action}",
            f"protocol={rule.protocol}",
            f"{self._port_key(rule.direction)}={rule.port}",
            f"remoteip={rule.ip}",
            f"enable={'yes' if rule.enabled else 'no'}",
        ]

    def _windows_apply_rule(self, rule: Rule) -> str:
        """Idempotently replace the CyberOps_<id> rule."""
        command = self._windows_command_for_rule(rule)
        name = f"CyberOps_{rule.rule_id}"
        self._run_netsh(
            ["advfirewall", "firewall", "delete", "rule", f"name={name}"],
            check=False,
        )
        self._run_netsh(command)
        return "applied" if rule.enabled else "disabled"

    def _windows_delete_rule(self, rule: Rule) -> None:
        self._run_netsh([
            "advfirewall", "firewall", "delete", "rule",
            f"name=CyberOps_{rule.rule_id}",
        ])

    def _windows_enable_system_rule(self, name: str) -> None:
        self._run_netsh([
            "advfirewall", "firewall", "set", "rule",
            f"name={name}", "new", "enable=yes",
        ])

    def _windows_disable_system_rule(self, name: str) -> None:
        self._run_netsh([
            "advfirewall", "firewall", "set", "rule",
            f"name={name}", "new", "enable=no",
        ])

    def _windows_delete_system_rule(self, name: str) -> None:
        """Delete a system rule by display name (admin required)."""
        self._run_netsh([
            "advfirewall", "firewall", "delete", "rule", f"name={name}",
        ])

    def _windows_get_system_rules_raw(self) -> str:
        return self._run_netsh(
            ["advfirewall", "firewall", "show", "rule", "name=all"]
        ).stdout

    def _windows_get_system_rules(self) -> list[dict]:
        raw = self._windows_get_system_rules_raw()
        rules, current = [], {}
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("Rule Name:"):
                if current:
                    rules.append(current)
                current = {"name": line.split(":", 1)[1].strip()}
            elif ":" in line and current:
                key, value = (x.strip() for x in line.split(":", 1))
                mapping = {
                    "Enabled": "enabled", "Action": "action",
                    "Direction": "direction", "LocalPort": "port",
                    "Protocol": "protocol", "RemoteIP": "remoteip",
                }
                if key in mapping:
                    val = value
                    if key == "Direction":
                        val = "inbound" if value.lower() == "in" else "outbound"
                    current[mapping[key]] = val
        if current:
            rules.append(current)
        return rules

    def _windows_reset(self) -> bool:
        return self._run_netsh(["advfirewall", "reset"]).returncode == 0

    def _windows_set_profile(
        self,
        inbound: str = "blockinbound",
        outbound: str = "allowoutbound",
    ) -> None:
        self._run_netsh(["advfirewall", "set", "allprofiles", "state", "on"])
        self._run_netsh([
            "advfirewall", "set", "allprofiles", "firewallpolicy",
            f"{inbound},{outbound}",
        ])

    def _windows_quick_scan(self) -> dict:
        rules = self._windows_get_system_rules()
        state = self._run_netsh(
            ["advfirewall", "show", "allprofiles"], check=False,
        ).stdout.lower()

        if "state" in state and "on" in state:
            firewall_status = "On"
        elif "state" in state and "off" in state:
            firewall_status = "Off"
        else:
            firewall_status = "Unknown"

        ports = {
            r.get("port") for r in rules
            if r.get("port") not in (None, "", "Any")
        }
        return {
            "internet_status": "Unknown (netsh only)",
            "firewall_status": firewall_status,
            "total_rules": len(rules),
            "enabled_rules": sum(
                r.get("enabled", "").lower() == "yes" for r in rules
            ),
            "blocked_rules": sum(
                r.get("action", "").lower() == "block" for r in rules
            ),
            "open_ports": len(ports),
            "security_score": None,
        }

    # ============================================================
    # Linux backend (ufw / nft / iptables)
    # ============================================================

    def _linux_add_rule(self, rule: Rule) -> str:
        """Add or replace a rule via the detected Linux backend."""
        self.validate_rule(rule)
        action = "allow" if rule.action == "allow" else "deny"
        proto = rule.protocol.lower() if rule.protocol in ("TCP", "UDP") else "any"
        port = rule.port

        backend = self._linux_backend

        if backend == "ufw":
            if not rule.enabled:
                self._linux_delete_rule(rule)
                return "disabled"

            direction = "in" if rule.direction == "inbound" else "out"
            args = [
                action,
                direction,
                "proto", proto,
                "from", "any",
                "to", "any",
                "port", str(port),
            ]
            self._run_linux(args)
            return "applied"

        if backend == "nft":
            chain = "input" if rule.direction == "inbound" else "output"
            verdict = "accept" if rule.action == "allow" else "drop"

            # Delete existing CyberOps rule (best effort).
            self._run_linux(
                ["delete", "rule", "inet", "filter", chain,
                 "handle", str(rule.rule_id)],
                check=False,
            )

            if not rule.enabled:
                return "disabled"

            args = ["add", "rule", "inet", "filter", chain]
            if rule.ip and rule.ip.casefold() not in ("any", "localsubnet"):
                args += ["ip", "saddr", rule.ip]
            if proto in ("tcp", "udp"):
                args += [proto, "dport", str(port)]
            else:
                args += ["th", "dport", str(port)]
            args += [verdict]

            self._run_linux(args)
            return "applied"

        if backend == "iptables":
            chain = "INPUT" if rule.direction == "inbound" else "OUTPUT"
            target = "ACCEPT" if rule.action == "allow" else "DROP"

            args_del = ["-D", chain]
            if rule.ip and rule.ip.casefold() not in ("any", "localsubnet"):
                args_del += ["-s", rule.ip]
            if proto in ("tcp", "udp"):
                args_del += ["-p", proto, "--dport", str(port)]
            args_del += ["-j", target]
            self._run_linux(args_del, check=False)

            if not rule.enabled:
                return "disabled"

            args_add = ["-A", chain]
            if rule.ip and rule.ip.casefold() not in ("any", "localsubnet"):
                args_add += ["-s", rule.ip]
            if proto in ("tcp", "udp"):
                args_add += ["-p", proto, "--dport", str(port)]
            args_add += ["-j", target]

            self._run_linux(args_add)
            return "applied"

        raise RuntimeError(
            "No Linux firewall backend detected "
            "(install ufw, nft, or iptables)."
        )

    def _linux_delete_rule(self, rule: Rule) -> None:
        backend = self._linux_backend
        proto = rule.protocol.lower() if rule.protocol in ("TCP", "UDP") else "any"
        port = rule.port

        if backend == "ufw":
            action = "allow" if rule.action == "allow" else "deny"
            direction = "in" if rule.direction == "inbound" else "out"
            self._run_linux(
                [
                    "delete", action, direction,
                    "proto", proto,
                    "from", "any", "to", "any", "port", str(port),
                ],
                check=False,
            )
            return

        if backend == "nft":
            chain = "input" if rule.direction == "inbound" else "output"
            self._run_linux(
                [
                    "delete", "rule", "inet", "filter", chain,
                    "handle", str(rule.rule_id),
                ],
                check=False,
            )
            return

        if backend == "iptables":
            chain = "INPUT" if rule.direction == "inbound" else "OUTPUT"
            target = "ACCEPT" if rule.action == "allow" else "DROP"
            args = ["-D", chain]
            if rule.ip and rule.ip.casefold() not in ("any", "localsubnet"):
                args += ["-s", rule.ip]
            if proto in ("tcp", "udp"):
                args += ["-p", proto, "--dport", str(port)]
            args += ["-j", target]
            self._run_linux(args, check=False)
            return

    def _linux_enable_system_rule(self, name: str) -> None:
        # Linux has no direct equivalent of "named system rules" in ufw/nft.
        raise RuntimeError(
            "Enabling a named system rule is not supported on Linux. "
            "Use CyberOps rules instead."
        )

    def _linux_disable_system_rule(self, name: str) -> None:
        raise RuntimeError(
            "Disabling a named system rule is not supported on Linux. "
            "Use CyberOps rules instead."
        )

    def _linux_delete_system_rule(self, name: str) -> None:
        raise RuntimeError(
            "Deleting a named system rule is not supported on Linux. "
            "Use CyberOps rules instead."
        )

    def _linux_get_system_rules(self) -> list[dict]:
        """List rules for the detected backend (best-effort parse).

        Returns a list of dicts with the same keys used on Windows:
        name, action, port, protocol, direction, enabled.
        """
        rules: list[dict] = []
        backend = self._linux_backend

        try:
            if backend == "ufw":
                out = self._run_linux(["status", "numbered"], check=False).stdout
                for line in out.splitlines():
                    # Format: "[ 1] 22/tcp    ALLOW IN   Anywhere"
                    if not line.startswith("["):
                        continue
                    try:
                        rest = line.split("]", 1)[1].strip()
                        parts = rest.split()
                        if len(parts) < 3:
                            continue
                        # parts[0] = port/proto, parts[1] = action, parts[2] = direction
                        port_proto = parts[0]
                        action = parts[1].lower()
                        direction = parts[2].lower() if len(parts) > 2 else "in"

                        port = ""
                        proto = ""
                        if "/" in port_proto:
                            port, _, proto = port_proto.partition("/")

                        rules.append({
                            "name": f"ufw-{line[1:line.index(']')].strip()}",
                            "action": "allow" if action == "allow" else "block",
                            "port": port,
                            "protocol": proto.upper(),
                            "direction": "inbound" if direction == "in" else "outbound",
                            "enabled": "yes",
                        })
                    except Exception:
                        continue

            elif backend == "nft":
                out = self._run_linux(["list", "ruleset"], check=False).stdout
                counter = 0
                for line in out.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if line.startswith("chain"):
                        continue
                    # Only look at lines that end with a verdict.
                    if "accept" in line or "drop" in line or "reject" in line:
                        counter += 1
                        action = "allow" if "accept" in line else "block"
                        # Try to extract dport.
                        port = ""
                        proto = ""
                        if "dport" in line:
                            try:
                                after = line.split("dport", 1)[1].split()
                                port = after[0]
                                # Look backwards for proto.
                                before = line.split("dport", 1)[0].split()
                                if before:
                                    proto = before[-1].upper()
                            except Exception:
                                pass
                        rules.append({
                            "name": f"nft-{counter}",
                            "action": action,
                            "port": port,
                            "protocol": proto,
                            "direction": "inbound",
                            "enabled": "yes",
                        })

            elif backend == "iptables":
                out = self._run_linux(
                    ["-L", "-n", "--line-numbers"], check=False,
                ).stdout
                current_chain = ""
                for line in out.splitlines():
                    line = line.rstrip()
                    if line.startswith("Chain "):
                        current_chain = line.split()[1]
                        continue
                    parts = line.split()
                    if len(parts) < 3 or not parts[0].isdigit():
                        continue
                    # parts[0]=num, parts[1]=target, parts[2]=prot, ...
                    target = parts[1].upper()
                    proto = parts[2]
                    port = ""
                    # Find dpt:443
                    for p in parts:
                        if p.startswith("dpt:"):
                            port = p[4:]
                    action = "allow" if target == "ACCEPT" else "block"
                    rules.append({
                        "name": f"iptables-{current_chain}-{parts[0]}",
                        "action": action,
                        "port": port,
                        "protocol": proto.upper(),
                        "direction": "inbound" if current_chain == "INPUT" else "outbound",
                        "enabled": "yes",
                    })
        except Exception:
            pass

        return rules

    def _linux_reset(self) -> bool:
        """Reset CyberOps rules only; never touch system-wide defaults.

        Note: a full OS-level reset (like ``netsh advfirewall reset``) is
        not offered on Linux because it would wipe the user's entire
        firewall configuration, which is almost never what they want.
        """
        try:
            for rule in list(self.rules):
                try:
                    self._linux_delete_rule(rule)
                except Exception:
                    continue
            return True
        except Exception:
            return False

    def _linux_quick_scan(self) -> dict:
        """Return a best-effort firewall snapshot on Linux."""
        rules = self._linux_get_system_rules()
        backend = self._linux_backend or "none"

        # Try to detect firewall state.
        status = "Unknown"
        try:
            if backend == "ufw":
                out = self._run_linux(["status"], check=False).stdout.lower()
                status = "On" if "status: active" in out else "Off"
            elif backend == "nft":
                out = self._run_linux(["list", "ruleset"], check=False).stdout
                status = "On" if out.strip() else "Off"
            elif backend == "iptables":
                out = self._run_linux(["-L", "-n"], check=False).stdout
                # Check if default policy is ACCEPT or DROP.
                if "policy ACCEPT" in out and "policy DROP" not in out:
                    status = "On (permissive)"
                elif "policy DROP" in out:
                    status = "On (restrictive)"
                else:
                    status = "Off"
        except Exception:
            status = "Unknown"

        # Count open ports from parsed rules.
        open_ports: set[str] = set()
        for r in rules:
            if r.get("action") == "allow" and r.get("port"):
                open_ports.add(r["port"])

        enabled_rules = sum(
            1 for r in rules if str(r.get("enabled", "")).lower() == "yes"
        )
        blocked_rules = sum(
            1 for r in rules if r.get("action") == "block"
        )

        return {
            "internet_status": "Unknown",
            "firewall_status": f"{status} ({backend})",
            "total_rules": len(rules),
            "enabled_rules": enabled_rules,
            "blocked_rules": blocked_rules,
            "open_ports": len(open_ports),
            "security_score": None,
        }

    # ============================================================
    # Public dispatch methods
    # ============================================================

    def apply_json_rule_to_system(self, rule: Rule) -> str:
        """Apply a single rule to the OS (idempotent)."""
        if self._is_windows():
            return self._windows_apply_rule(rule)
        if self._is_linux():
            return self._linux_add_rule(rule)
        raise RuntimeError(f"Unsupported OS: {self._system}")

    def apply_all_json_rules(self) -> dict:
        summary = {"applied": 0, "disabled": 0, "failed": []}
        for rule in self.rules:
            try:
                status = self.apply_json_rule_to_system(rule)
                summary[status] += 1
            except Exception as exc:
                summary["failed"].append({"id": rule.rule_id, "error": str(exc)})
        if summary["failed"]:
            details = "; ".join(
                f"rule {x['id']}: {x['error']}" for x in summary["failed"]
            )
            raise RuntimeError(
                f"Custom Mode incomplete: {summary['applied']} applied, "
                f"{summary['disabled']} disabled, "
                f"{len(summary['failed'])} failed. {details}"
            )
        return summary

    def add_rule(self, action, ip, port, protocol, direction="outbound") -> Rule:
        rule_id = max((r.rule_id for r in self.rules), default=0) + 1
        rule = Rule(rule_id, action, ip, port, protocol, direction, True)
        self.validate_rule(rule)
        # Apply first; persist only if the OS accepts the rule.
        self.apply_json_rule_to_system(rule)
        self.rules.append(rule)
        self.save()
        return rule

    def remove_rule(self, rule_id) -> None:
        found = next((r for r in self.rules if r.rule_id == int(rule_id)), None)
        if found is None:
            raise ValueError(f"No saved CyberOps rule with id {rule_id}.")

        # Remove from the OS first.
        if self._is_windows():
            self._windows_delete_rule(found)
        elif self._is_linux():
            self._linux_delete_rule(found)

        self.rules = [r for r in self.rules if r.rule_id != found.rule_id]
        self.save()

    def _set_enabled(self, rule_id, enabled: bool) -> None:
        rule = next((r for r in self.rules if r.rule_id == int(rule_id)), None)
        if rule is None:
            raise ValueError(f"No saved CyberOps rule with id {rule_id}.")
        old = rule.enabled
        rule.enabled = enabled
        try:
            self.apply_json_rule_to_system(rule)
            self.save()
        except Exception:
            rule.enabled = old
            raise

    def enable_rule(self, rule_id) -> None:
        self._set_enabled(rule_id, True)

    def disable_rule(self, rule_id) -> None:
        self._set_enabled(rule_id, False)

    # ------------------------------------------------- system rules

    def enable_system_rule(self, name: str) -> None:
        if self._is_windows():
            return self._windows_enable_system_rule(name)
        return self._linux_enable_system_rule(name)

    def disable_system_rule(self, name: str) -> None:
        if self._is_windows():
            return self._windows_disable_system_rule(name)
        return self._linux_disable_system_rule(name)

    def delete_system_rule(self, name: str) -> None:
        """Delete a system rule by display name (admin required).

        Previously missing; called by the GUI as
        ``remove_selected_system_rule``.
        """
        if self._is_windows():
            return self._windows_delete_system_rule(name)
        return self._linux_delete_system_rule(name)

    def get_system_rules_raw(self) -> str:
        if self._is_windows():
            return self._windows_get_system_rules_raw()
        return ""

    def get_system_rules(self) -> list[dict]:
        if self._is_windows():
            return self._windows_get_system_rules()
        return self._linux_get_system_rules()

    # ------------------------------------------------- profiles

    def custom_mode(self) -> dict:
        return self.apply_all_json_rules()

    def secure_mode(self) -> bool:
        """Enable the firewall with a restrictive inbound policy.

        On Windows: sets netsh profile to blockinbound,allowoutbound.
        On Linux:
          * ufw:    default deny incoming, allow outgoing, enable.
          * nft:    adds a drop policy to the input chain.
          * iptables: sets INPUT policy to DROP, OUTPUT to ACCEPT.
        """
        if self._is_windows():
            self._windows_set_profile("blockinbound", "allowoutbound")
            return True

        if self._is_linux():
            backend = self._linux_backend
            if backend == "ufw":
                self._run_linux(["default", "deny", "incoming"], check=False)
                self._run_linux(["default", "allow", "outgoing"], check=False)
                self._run_linux(["enable"], check=False)
                return True

            if backend == "nft":
                # Add a default drop policy to the input chain.
                self._run_linux(
                    ["add", "rule", "inet", "filter", "input",
                     "policy", "drop"],
                    check=False,
                )
                return True

            if backend == "iptables":
                self._run_linux(["-P", "INPUT", "DROP"], check=False)
                self._run_linux(["-P", "OUTPUT", "ACCEPT"], check=False)
                self._run_linux(["-P", "FORWARD", "DROP"], check=False)
                return True

            raise RuntimeError(
                "Secure Mode on Linux requires ufw, nft, or iptables. "
                f"Detected backend: {backend or 'none'}."
            )

        return False

    def lockdown_mode(self) -> bool:
        """Block inbound and outbound traffic.

        On Windows: netsh profile blockinbound,blockoutbound.
        On Linux:
          * ufw:    default deny incoming AND outgoing, enable.
          * nft:    adds a drop policy to both input and output chains.
          * iptables: sets both INPUT and OUTPUT policies to DROP.
        """
        if self._is_windows():
            self._windows_set_profile("blockinbound", "blockoutbound")
            return True

        if self._is_linux():
            backend = self._linux_backend
            if backend == "ufw":
                self._run_linux(["default", "deny", "incoming"], check=False)
                self._run_linux(["default", "deny", "outgoing"], check=False)
                self._run_linux(["enable"], check=False)
                return True

            if backend == "nft":
                self._run_linux(
                    ["add", "rule", "inet", "filter", "input",
                     "policy", "drop"],
                    check=False,
                )
                self._run_linux(
                    ["add", "rule", "inet", "filter", "output",
                     "policy", "drop"],
                    check=False,
                )
                return True

            if backend == "iptables":
                self._run_linux(["-P", "INPUT", "DROP"], check=False)
                self._run_linux(["-P", "OUTPUT", "DROP"], check=False)
                self._run_linux(["-P", "FORWARD", "DROP"], check=False)
                return True

            raise RuntimeError(
                "Lockdown Mode on Linux requires ufw, nft, or iptables. "
                f"Detected backend: {backend or 'none'}."
            )

        return False

    def lockdown_mode(self) -> bool:
        if self._is_windows():
            self._windows_set_profile("blockinbound", "blockoutbound")
            return True
        if self._is_linux():
            if self._linux_backend == "ufw":
                self._run_linux(["default", "deny", "incoming"], check=False)
                self._run_linux(["default", "deny", "outgoing"], check=False)
                self._run_linux(["enable"], check=False)
                return True
            raise RuntimeError(
                "Lockdown Mode on Linux requires ufw. "
                "Install ufw or configure nft/iptables manually."
            )
        return False

    def reset_firewall(self) -> bool:
        if self._is_windows():
            return self._windows_reset()
        if self._is_linux():
            return self._linux_reset()
        return False

    # ------------------------------------------------- quick scan

    def quick_scan(self) -> dict:
        if self._is_windows():
            return self._windows_quick_scan()
        if self._is_linux():
            return self._linux_quick_scan()
        return {
            "internet_status": "Unknown",
            "firewall_status": "Unsupported OS",
            "total_rules": 0,
            "enabled_rules": 0,
            "blocked_rules": 0,
            "open_ports": 0,
            "security_score": None,
        }
        
        
        