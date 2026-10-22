"""Well-known TCP service names for CyberOpsSuite Network Mapper.

This is a deliberately small, curated list. It is *not* a full port-to-service
database; for that, use ``socket.getservbyport`` or an external tool.
"""

from __future__ import annotations

#: Common TCP ports mapped to a friendly service name.
#: Kept in one frozen dict so callers cannot accidentally mutate it.
_KNOWN_SERVICES: dict[int, str] = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    587: "SMTP-Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}

UNKNOWN_SERVICE = "Unknown"


def detect_service(port: int) -> str:
    """Return a friendly service name for a TCP *port*, or ``Unknown``."""
    try:
        port = int(port)
    except (TypeError, ValueError):
        return UNKNOWN_SERVICE
    return _KNOWN_SERVICES.get(port, UNKNOWN_SERVICE)