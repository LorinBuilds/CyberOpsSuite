"""Quick suspicious-pattern scan over text log files. Read-only."""
from __future__ import annotations
import re
from pathlib import Path

# (name, compiled regex, severity)
_PATTERNS = [
    ("auth_failure", re.compile(r"Failed password for|authentication failure|Invalid user", re.I), "medium"),
    ("auth_success", re.compile(r"Accepted (?:password|publickey)", re.I), "info"),
    ("sudo_command", re.compile(r"sudo:.*COMMAND="), "info"),
    ("privilege_escalation", re.compile(r"COMMAND=.*(?:/bin/sh|/bin/bash|/usr/bin/sudo)"), "medium"),
    ("web_sqli", re.compile(r"(?:UNION\s+SELECT|OR\s+'?1'?\s*=\s*'?1|DROP\s+TABLE)", re.I), "high"),
    ("web_xss", re.compile(r"<script[^>]*>|javascript:", re.I), "high"),
    ("path_traversal", re.compile(r"\.\./\.\./|%2e%2e%2f|\.\.%2f", re.I), "high"),
    ("reverse_shell", re.compile(r"/dev/tcp/|nc\s+-e|bash\s+-i\s+>&|sh\s+-i\s+>&"), "critical"),
    ("crypto_miner", re.compile(r"stratum\+tcp://|xmrig|minerd", re.I), "high"),
    ("download_and_exec", re.compile(r"(?:curl|wget)\s+[^|]*\|\s*(?:sh|bash)\b"), "high"),
]

MAX_EXCERPT = 300


def analyze_log_file(path: str | Path, max_lines: int = 100_000) -> dict:
    p = Path(path).expanduser().resolve()
    if not p.is_file():
        raise FileNotFoundError(p)

    findings: list[dict] = []
    lines_scanned = 0
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for line_number, line in enumerate(f, 1):
            if line_number > max_lines:
                break
            lines_scanned = line_number
            for name, regex, severity in _PATTERNS:
                if regex.search(line):
                    findings.append({
                        "line_number": line_number,
                        "pattern": name,
                        "severity": severity,
                        "excerpt": line.strip()[:MAX_EXCERPT],
                    })
    return {
        "file": str(p),
        "lines_scanned": lines_scanned,
        "finding_count": len(findings),
        "findings": findings,
    }