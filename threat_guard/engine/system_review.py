"""Read-only system review: drives, event logs, persistence, processes, network.

Everything here only *looks* and reports. Nothing is deleted, changed or killed.
Windows-specific parts degrade gracefully on other platforms (and when a
permission such as Administrator is missing, the gap is reported, not hidden).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import threading
from pathlib import Path

from threat_guard.engine.scanner import Finding

IS_WINDOWS = os.name == "nt"
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


# ----------------------------------------------------------------- helpers

def is_admin() -> bool:
    if IS_WINDOWS:
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def list_drives(include_network: bool = False) -> list[tuple[Path, str]]:
    """Return [(root_path, kind)] with kind 'fixed' or 'removable'."""
    drives: list[tuple[Path, str]] = []
    if IS_WINDOWS:
        import ctypes
        import string
        kernel32 = ctypes.windll.kernel32
        mask = kernel32.GetLogicalDrives()
        for index, letter in enumerate(string.ascii_uppercase):
            if not mask & (1 << index):
                continue
            root = f"{letter}:\\"
            kind = kernel32.GetDriveTypeW(root)  # 2 removable, 3 fixed, 4 network
            if kind == 3:
                drives.append((Path(root), "fixed"))
            elif kind == 2:
                drives.append((Path(root), "removable"))
            elif kind == 4 and include_network:
                drives.append((Path(root), "fixed"))
        return drives

    try:
        import psutil
        skip_fs = {"squashfs", "tmpfs", "devtmpfs", "overlay", "proc", "sysfs", "cgroup2"}
        for part in psutil.disk_partitions(all=False):
            if part.fstype.lower() in skip_fs or part.mountpoint.startswith(("/snap", "/boot/efi")):
                continue
            drives.append((Path(part.mountpoint), "removable" if "removable" in part.opts else "fixed"))
    except Exception:
        pass
    return drives or [(Path("/"), "fixed")]


def quick_locations() -> list[Path]:
    """Folders where malware most often lands. Scanned first for fast feedback."""
    home = Path.home()
    candidates: list[Path] = [home / "Downloads", home / "Desktop", home / "Documents"]
    if IS_WINDOWS:
        env = os.environ
        for key in ("TEMP", "APPDATA", "LOCALAPPDATA", "PUBLIC", "PROGRAMDATA"):
            if env.get(key):
                candidates.append(Path(env[key]))
        if env.get("APPDATA"):
            candidates.append(Path(env["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/Startup")
        if env.get("PROGRAMDATA"):
            candidates.append(Path(env["PROGRAMDATA"]) / "Microsoft/Windows/Start Menu/Programs/Startup")
    else:
        candidates.append(Path("/tmp"))
    seen: set[str] = set()
    result: list[Path] = []
    for path in candidates:
        key = os.path.normcase(str(path))
        if key not in seen and path.exists():
            seen.add(key)
            result.append(path)
    return result


def default_exclusions() -> list[Path]:
    """Folders skipped by default (huge, hard-linked system stores)."""
    out: list[Path] = []
    if IS_WINDOWS:
        windir = os.environ.get("WINDIR", r"C:\Windows")
        out.append(Path(windir) / "WinSxS")
    out.append(data_dir())
    return out


def data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local" / "share")
    return Path(base) / "ThreatGuard"


def _powershell(command: str, timeout: int = 40) -> subprocess.CompletedProcess:
    # Force UTF-8 both ways so non-English Windows messages never crash the decoder.
    command = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + command
    return subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout, check=False, creationflags=_NO_WINDOW,
    )


def _finding(engine: str, severity: str, title: str, details: str, path: str = "system") -> Finding:
    return Finding(path=path, engine=engine, severity=severity,
                   title=title, details=details[:600], sha256="")


# ------------------------------------------------------- Windows event logs

# (log name, event ids, severity, title)
_EVENT_QUERIES = [
    ("Security", [1102], "critical", "Security audit log was cleared"),
    ("System", [104], "critical", "A Windows event log was cleared"),
    ("Security", [4720], "high", "A new user account was created"),
    ("Security", [4728, 4732, 4756], "high", "Member added to a privileged group"),
    ("Security", [4698], "medium", "A scheduled task was created"),
    ("System", [7045], "medium", "A new service was installed"),
    ("Microsoft-Windows-Windows Defender/Operational", [1116], "high",
     "Windows Defender detected malware"),
]
FAILED_LOGON_THRESHOLD = 5


def _query_events(log: str, ids: list[int], hours: int, limit: int) -> tuple[list[dict], str | None]:
    id_list = ",".join(str(i) for i in ids)
    command = (
        "$ErrorActionPreference='Stop'; try { "
        f"$e = Get-WinEvent -FilterHashtable @{{LogName='{log}';Id={id_list};"
        f"StartTime=(Get-Date).AddHours(-{int(hours)})}} -MaxEvents {int(limit)}; "
        "$e | ForEach-Object { [pscustomobject]@{Id=$_.Id;Time=$_.TimeCreated.ToString('s');"
        "Msg=$_.Message} } | ConvertTo-Json -Compress "
        "} catch { if ($_.Exception.Message -like '*No events*') { '[]' } "
        "else { [Console]::Error.WriteLine($_.Exception.Message); exit 2 } }"
    )
    try:
        proc = _powershell(command)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], f"{log}: PowerShell unavailable or timed out ({exc})"
    if proc.returncode != 0:
        message = (proc.stderr or proc.stdout).strip().splitlines()
        hint = message[0][:200] if message else "unknown error"
        return [], f"{log}: could not read events ({hint})"
    text = (proc.stdout or "").strip() or "[]"
    try:
        data = json.loads(text)
    except ValueError:
        return [], f"{log}: unreadable PowerShell output"
    if isinstance(data, dict):
        data = [data]
    return [item for item in data if isinstance(item, dict)], None


def review_event_logs(hours: int = 24) -> tuple[list[Finding], list[str]]:
    """Look through the Windows event logs for security-relevant events."""
    findings: list[Finding] = []
    errors: list[str] = []
    if not IS_WINDOWS:
        return findings, errors
    if not is_admin():
        errors.append("Not running as Administrator: the Security event log cannot be read. "
                      "Right-click the app and choose 'Run as administrator' for full log review.")

    for log, ids, severity, title in _EVENT_QUERIES:
        if log == "Security" and not is_admin():
            continue
        events, error = _query_events(log, ids, hours, limit=25)
        if error:
            errors.append(error)
            continue
        for event in events:
            message = " ".join(str(event.get("Msg") or "").split())[:300]
            findings.append(_finding(
                "eventlog", severity, title,
                f"{event.get('Time', '')} · Event {event.get('Id')} · {message}",
                path=f"EventLog:{log}#{event.get('Id')}",
            ))

    if is_admin():
        events, error = _query_events("Security", [4625], hours, limit=1000)
        if error:
            errors.append(error)
        elif len(events) >= FAILED_LOGON_THRESHOLD:
            latest = events[0].get("Time", "")
            findings.append(_finding(
                "eventlog", "medium" if len(events) < 50 else "high",
                f"{len(events)} failed logon attempts in the last {hours}h",
                f"Possible password guessing. Most recent: {latest}",
                path="EventLog:Security#4625",
            ))
    return findings, errors


# --------------------------------------------------------------- persistence

_SUSPICIOUS_PATH = re.compile(
    r"\\temp\\|\\appdata\\local\\temp|\\downloads\\|\\users\\public\\|\$recycle\.bin", re.I)
_SUSPICIOUS_CMD = re.compile(
    r"powershell[^\n]*(?:-enc\w*|-e\s|downloadstring|iex\b|-w(?:indowstyle)?\s+hidden)"
    r"|mshta|wscript|cscript|regsvr32[^\n]*(?:/i:|scrobj)|bitsadmin|certutil[^\n]*-urlcache",
    re.I)
_SCRIPT_EXT = {".vbs", ".js", ".jse", ".bat", ".cmd", ".ps1", ".hta", ".scr", ".wsf"}


def _judge_command(command: str) -> tuple[str, str] | None:
    if _SUSPICIOUS_CMD.search(command):
        return "high", "Autostart command uses a script host / encoded or hidden execution"
    if _SUSPICIOUS_PATH.search(command):
        return "medium", "Autostart program runs from a temporary or download location"
    return None


def review_persistence() -> list[Finding]:
    findings: list[Finding] = []
    if not IS_WINDOWS:
        return findings
    try:
        import winreg
    except ImportError:
        return findings

    keys = [
        (winreg.HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, "HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]
    for hive, label, sub in keys:
        try:
            with winreg.OpenKey(hive, sub) as handle:
                index = 0
                while True:
                    try:
                        name, value, _kind = winreg.EnumValue(handle, index)
                    except OSError:
                        break
                    index += 1
                    verdict = _judge_command(str(value))
                    if verdict:
                        findings.append(_finding(
                            "persistence", verdict[0], verdict[1], str(value),
                            path=f"{label}\\{sub}\\{name}"))
        except OSError:
            continue

    folders = []
    for key in ("APPDATA", "PROGRAMDATA"):
        if os.environ.get(key):
            folders.append(Path(os.environ[key]) / "Microsoft/Windows/Start Menu/Programs/Startup")
    for folder in folders:
        try:
            for item in folder.iterdir():
                if item.suffix.lower() in _SCRIPT_EXT:
                    findings.append(_finding(
                        "persistence", "medium", "Script file in a Startup folder",
                        "Scripts that run at every login are a common persistence trick.",
                        path=str(item)))
        except OSError:
            continue
    return findings


# ------------------------------------------------------ processes & network

_SYSTEM_PROCESSES = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
                     "services.exe", "smss.exe", "wininit.exe"}
_RISKY_LISTEN = {21: "FTP", 23: "Telnet", 3389: "Remote Desktop", 5900: "VNC"}
_BACKDOOR_PORTS = {4444, 1337, 31337, 6666, 9001}


def review_processes() -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    try:
        import psutil
    except ImportError:
        return findings, ["psutil is not installed: process and network review skipped "
                          "(pip install psutil)."]

    windir = os.path.normcase(os.environ.get("WINDIR", r"C:\Windows"))
    system32 = os.path.join(windir, "system32") + os.sep
    seen: set[str] = set()
    for proc in psutil.process_iter(["name", "exe", "pid"]):
        try:
            name = (proc.info.get("name") or "").lower()
            exe = proc.info.get("exe") or ""
        except Exception:
            continue
        if not exe:
            continue
        norm = os.path.normcase(exe)
        if IS_WINDOWS and name in _SYSTEM_PROCESSES and not norm.startswith(system32):
            key = f"sys:{norm}"
            if key not in seen:
                seen.add(key)
                findings.append(_finding(
                    "process", "high",
                    f"System process name '{name}' running from an unusual folder",
                    f"PID {proc.info.get('pid')} · classic malware disguise", path=exe))
        elif _SUSPICIOUS_PATH.search(exe):
            key = f"tmp:{norm}"
            if key not in seen:
                seen.add(key)
                findings.append(_finding(
                    "process", "medium", "Program running from a temporary/download folder",
                    f"PID {proc.info.get('pid')}", path=exe))

    errors: list[str] = []
    try:
        connections = psutil.net_connections(kind="inet")
    except Exception as exc:  # AccessDenied on some platforms without admin
        return findings, [f"Network review skipped: {exc}"]
    reported: set[tuple] = set()
    for conn in connections:
        try:
            if conn.status == psutil.CONN_LISTEN and conn.laddr:
                port = conn.laddr.port
                if port in _RISKY_LISTEN and conn.laddr.ip in ("0.0.0.0", "::"):
                    key = ("listen", port)
                    if key not in reported:
                        reported.add(key)
                        findings.append(_finding(
                            "network", "medium",
                            f"{_RISKY_LISTEN[port]} is reachable from the network (port {port})",
                            "Disable it if you do not use it, or restrict it with the firewall.",
                            path=f"tcp/{port}"))
            elif conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
                if conn.raddr.port in _BACKDOOR_PORTS:
                    key = ("conn", conn.raddr.ip, conn.raddr.port)
                    if key not in reported:
                        reported.add(key)
                        findings.append(_finding(
                            "network", "high",
                            f"Connection to port {conn.raddr.port} (often used by backdoors)",
                            f"Remote {conn.raddr.ip}:{conn.raddr.port} · PID {conn.pid}",
                            path=f"{conn.raddr.ip}:{conn.raddr.port}"))
        except Exception:
            continue
    return findings, errors


# ------------------------------------------------------------ orchestration

_CHECK_SEVERITY = {"CRITICAL": "critical", "WARN": "medium"}


def checks_to_findings(engine: str, checks: list[dict]) -> list[Finding]:
    out: list[Finding] = []
    for item in checks:
        severity = _CHECK_SEVERITY.get(str(item.get("status", "")).upper())
        if severity:
            out.append(_finding(engine, severity, str(item.get("check", engine)),
                                str(item.get("details", "")), path="system"))
    return out


def run_system_review(hours: int = 24, cancel: threading.Event | None = None
                      ) -> tuple[list[Finding], list[dict], list[str]]:
    """Run every non-file check. Returns (findings, raw_checks, errors)."""
    from threat_guard.engine.audit import local_security_audit
    from threat_guard.engine.hardening import server_hardening_checks
    from threat_guard.engine.rootkit import rootkit_indicators

    def stopped() -> bool:
        return cancel is not None and cancel.is_set()

    findings: list[Finding] = []
    raw_checks: list[dict] = []
    errors: list[str] = []

    for engine, func in (("rootkit", rootkit_indicators),
                         ("audit", local_security_audit),
                         ("hardening", server_hardening_checks)):
        if stopped():
            return findings, raw_checks, errors
        try:
            checks = func()
            raw_checks.extend({**c, "source": engine} for c in checks)
            findings.extend(checks_to_findings(engine, checks))
        except Exception as exc:
            errors.append(f"{engine}: {exc}")

    if not stopped():
        try:
            event_findings, event_errors = review_event_logs(hours)
            findings.extend(event_findings)
            errors.extend(event_errors)
        except Exception as exc:
            errors.append(f"eventlog: {exc}")
    if not stopped():
        try:
            findings.extend(review_persistence())
        except Exception as exc:
            errors.append(f"persistence: {exc}")
    if not stopped():
        proc_findings, proc_errors = review_processes()
        findings.extend(proc_findings)
        errors.extend(proc_errors)
    return findings, raw_checks, errors
