from __future__ import annotations
import os
import platform
import stat
from pathlib import Path

def local_security_audit() -> list[dict]:
    """Small, read-only baseline audit; findings are advisory, not a full compliance check."""
    checks = [{
        "check": "Operating system",
        "status": "INFO",
        "details": f"{platform.system()} {platform.release()} ({platform.machine()})",
    }]
    home = Path.home()
    sensitive = [home / ".ssh" / "id_rsa", home / ".ssh" / "id_ed25519"]
    for item in sensitive:
        if item.exists():
            try:
                mode = stat.S_IMODE(item.stat().st_mode)
                secure = (mode & 0o077) == 0 if os.name != "nt" else True
                checks.append({
                    "check": f"Private key permissions: {item.name}",
                    "status": "PASS" if secure else "WARN",
                    "details": "Permissions restrict access." if secure else
                               f"Permissions are {oct(mode)}; review access to this private key.",
                })
            except OSError as exc:
                checks.append({"check": f"Private key permissions: {item.name}",
                               "status": "UNKNOWN", "details": str(exc)})
    checks.append({
        "check": "Firewall status",
        "status": "MANUAL",
        "details": "Verify the host firewall is enabled using the OS firewall settings. "
                   "ThreatGuard does not change firewall configuration.",
    })
    checks.append({
        "check": "Updates",
        "status": "MANUAL",
        "details": "Confirm the operating system and installed software receive security updates.",
    })
    return checks
