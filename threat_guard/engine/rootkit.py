"""Lightweight rootkit-indicator checks. Read-only, advisory only."""
from __future__ import annotations
import platform
import subprocess
from pathlib import Path


def rootkit_indicators() -> list[dict]:
    system = platform.system()
    checks: list[dict] = [{
        "check": "Platform", "status": "INFO",
        "details": f"{system} {platform.release()} ({platform.machine()})",
    }]
    if system == "Linux":
        checks.extend(_linux_checks())
    elif system == "Windows":
        checks.extend(_windows_checks())
    elif system == "Darwin":
        checks.append({"check": "Rootkit scan (macOS)", "status": "SKIPPED",
                       "details": "Not implemented for macOS yet"})
    else:
        checks.append({"check": "Rootkit scan", "status": "SKIPPED",
                       "details": f"Unsupported platform: {system}"})
    return checks


def _linux_checks() -> list[dict]:
    out: list[dict] = []
    # 1. ld.so.preload — classic userland rootkit hook
    ld = Path("/etc/ld.so.preload")
    try:
        if ld.exists():
            content = ld.read_text(encoding="utf-8", errors="replace").strip()
            out.append({
                "check": "ld.so.preload",
                "status": "WARN" if content else "PASS",
                "details": content[:300] if content else "Empty",
            })
        else:
            out.append({"check": "ld.so.preload", "status": "PASS", "details": "Absent"})
    except OSError as exc:
        out.append({"check": "ld.so.preload", "status": "UNKNOWN", "details": str(exc)})

    # 2. Common hidden-dir locations used by kits
    suspicious = ["/dev/.udev", "/dev/.tmp", "/dev/shm/.x", "/tmp/.ICE-unix/.tmp"]
    found = [p for p in suspicious if Path(p).exists()]
    out.append({
        "check": "Suspicious hidden paths",
        "status": "WARN" if found else "PASS",
        "details": f"Found: {', '.join(found)}" if found else "None found",
    })

    # 3. Hidden directories in /tmp
    try:
        hidden = [p.name for p in Path("/tmp").iterdir()
                  if p.is_dir() and p.name.startswith(".")]
        out.append({
            "check": "Hidden dirs in /tmp",
            "status": "WARN" if hidden else "PASS",
            "details": f"Found: {', '.join(hidden[:10])}" if hidden else "None",
        })
    except OSError:
        pass
    return out


def _windows_checks() -> list[dict]:
    out: list[dict] = []

    # 1. Known rootkit driver paths
    suspicious_paths = [
        r"C:\Windows\System32\drivers\TDSSserv.sys",
        r"C:\Windows\System32\drivers\rootkit.sys",
        r"C:\Windows\System32\drivers\fe5d3.sys",
    ]
    found = [p for p in suspicious_paths if Path(p).exists()]
    out.append({
        "check": "Common rootkit driver paths",
        "status": "CRITICAL" if found else "PASS",
        "details": f"Found: {', '.join(found)}" if found else "None found",
    })

    # 2. svchost.exe running outside System32 is suspicious
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-Process svchost -ErrorAction SilentlyContinue | "
             "Where-Object { $_.Path -and $_.Path -notlike 'C:\\Windows\\*' } | "
             "Select-Object -ExpandProperty Path"],
            capture_output=True, text=True, timeout=15, check=False,
        )
        bad = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
        out.append({
            "check": "svchost.exe outside System32",
            "status": "WARN" if bad else "PASS",
            "details": f"Found: {', '.join(bad[:5])}" if bad else "None",
        })
    except (OSError, subprocess.TimeoutExpired):
        out.append({"check": "svchost.exe check", "status": "UNKNOWN",
                    "details": "PowerShell unavailable or timed out"})
    return out