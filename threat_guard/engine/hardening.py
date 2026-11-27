"""Server hardening checks. Read-only; recommendations only."""
from __future__ import annotations
import platform
import subprocess
from pathlib import Path


def server_hardening_checks() -> list[dict]:
    system = platform.system()
    checks: list[dict] = [{
        "check": "Platform", "status": "INFO",
        "details": f"{system} {platform.release()}",
    }]
    if system == "Linux":
        checks.extend(_linux_checks())
    elif system == "Windows":
        checks.extend(_windows_checks())
    return checks


# ---------- Linux ----------

def _linux_checks() -> list[dict]:
    out: list[dict] = []
    out.extend(_ssh_checks())
    out.extend(_world_writable_etc())
    return out


def _ssh_checks() -> list[dict]:
    cfg = Path("/etc/ssh/sshd_config")
    if not cfg.exists():
        return [{"check": "SSH config", "status": "SKIPPED",
                 "details": "sshd_config not found"}]
    try:
        text = cfg.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [{"check": "SSH config", "status": "UNKNOWN", "details": str(exc)}]

    def _value_of(directive: str) -> str | None:
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split(None, 1)
            if parts and parts[0].lower() == directive.lower():
                return parts[1].strip() if len(parts) > 1 else ""
        return None

    results: list[dict] = []
    for directive, secure_values in [
        ("PermitRootLogin", {"no", "prohibit-password"}),
        ("PasswordAuthentication", {"no"}),
        ("X11Forwarding", {"no"}),
    ]:
        value = _value_of(directive)
        if value is None:
            results.append({"check": f"SSH {directive}", "status": "MANUAL",
                            "details": "Not set explicitly (using default)"})
        elif value.lower() in secure_values:
            results.append({"check": f"SSH {directive}", "status": "PASS",
                            "details": f"Set to {value!r}"})
        else:
            results.append({
                "check": f"SSH {directive}", "status": "WARN",
                "details": f"Currently {value!r}; recommended {sorted(secure_values)}",
            })
    return results


def _world_writable_etc() -> list[dict]:
    try:
        ww = []
        for entry in Path("/etc").rglob("*"):
            try:
                if entry.is_file() and not entry.is_symlink() and (entry.stat().st_mode & 0o002):
                    ww.append(str(entry))
            except OSError:
                continue
        return [{
            "check": "World-writable files in /etc",
            "status": "WARN" if ww else "PASS",
            "details": f"Found: {', '.join(ww[:10])}" if ww else "None",
        }]
    except OSError:
        return []


# ---------- Windows ----------

def _windows_checks() -> list[dict]:
    out: list[dict] = []
    out.extend(_fw_check())
    out.extend(_smb1_check())
    return out


def _fw_check() -> list[dict]:
    try:
        r = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        on = r.stdout.upper().count("STATE                                 ON")
        off = r.stdout.upper().count("STATE                                 OFF")
        if on and not off:
            return [{"check": "Windows Firewall", "status": "PASS",
                     "details": f"All {on} profile(s) ON"}]
        if off:
            return [{"check": "Windows Firewall", "status": "WARN",
                     "details": f"{off} profile(s) OFF; enable for all profiles"}]
        return [{"check": "Windows Firewall", "status": "UNKNOWN",
                 "details": r.stdout[:200] or r.stderr[:200]}]
    except (OSError, subprocess.TimeoutExpired):
        return [{"check": "Windows Firewall", "status": "UNKNOWN",
                 "details": "netsh unavailable"}]


def _smb1_check() -> list[dict]:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-SmbServerConfiguration).EnableSMB1Protocol"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        val = r.stdout.strip().lower()
        if val == "false":
            return [{"check": "SMBv1", "status": "PASS", "details": "Disabled"}]
        if val == "true":
            return [{"check": "SMBv1", "status": "WARN",
                     "details": "Enabled; disable for better security"}]
        return [{"check": "SMBv1", "status": "UNKNOWN",
                 "details": (r.stdout or r.stderr)[:200]}]
    except (OSError, subprocess.TimeoutExpired):
        return [{"check": "SMBv1", "status": "UNKNOWN", "details": "PowerShell unavailable"}]