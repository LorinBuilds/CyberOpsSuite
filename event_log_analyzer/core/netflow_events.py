"""Read-only UDP NetFlow v5 listener for Event Log Analyzer.

Parses NetFlow v5 export packets (24-byte header + 48-byte records) and
converts each flow into a LogEntry. The original flow fields are kept in
``raw`` so the GUI can show a detailed view.

Only version 5 is supported. NetFlow v9 / IPFIX need templates and are
reported through ``listener.stats.unsupported`` instead of being ignored
silently.

Security note: NetFlow has no authentication. An optional allow-list of
exporter IPs is enforced.
"""

from __future__ import annotations

import socket
import struct
from datetime import datetime

from .listeners import UdpListener
from .parser import LogEntry

DEFAULT_NETFLOW_PORT = 2055

#: NetFlow v5 header: version, count, sys_uptime, unix_secs, unix_nsecs,
#: flow_sequence, engine_type, engine_id, sampling_interval  (24 bytes).
_V5_HEADER = struct.Struct("!HHIIIIBBH")

#: NetFlow v5 record (48 bytes): srcaddr, dstaddr, nexthop, input, output,
#: dPkts, dOctets, first, last, srcport, dstport, pad1, tcp_flags, prot, tos,
#: src_as, dst_as, src_mask, dst_mask, pad2.
_V5_RECORD = struct.Struct("!IIIHHIIIIHHBBBBHHBBH")

assert _V5_HEADER.size == 24 and _V5_RECORD.size == 48  # guards against typos

MAX_V5_RECORDS = 30

#: Services that should not normally be reachable from untrusted networks.
SENSITIVE_PORTS = {
    22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP",
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 3306: "MySQL",
    5432: "PostgreSQL", 1433: "MSSQL", 6379: "Redis",
}

#: Extra names used only for display (they do not affect severity).
WELL_KNOWN_PORTS = {
    **SENSITIVE_PORTS,
    20: "FTP-data", 21: "FTP", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 465: "SMTPS", 514: "Syslog", 587: "SMTP-sub",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}

_PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6"}

_TCP_FLAG_BITS = (
    (0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
    (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG"),
)

#: A single flow carrying at least this many bytes is flagged as a WARNING.
LARGE_FLOW_BYTES = 100 * 1024 * 1024

_TCP = 6
_SYN = 0x02


def _ip_from_int(value: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", value))


def tcp_flags_text(flags: int) -> str:
    """``0x12`` -> ``"SYN,ACK"``."""
    return ",".join(name for bit, name in _TCP_FLAG_BITS if flags & bit)


def human_bytes(value: int) -> str:
    size = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{int(size)} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{value} B"  # pragma: no cover


def _flow_time(sys_uptime: int, unix_secs: int, unix_nsecs: int, flow_uptime: int) -> datetime:
    """Absolute time of a flow timestamp.

    ``first`` / ``last`` in a v5 record are *milliseconds of router uptime*,
    not Unix time. The packet header says what the uptime and wall clock were
    at export, so ``export_time - (sys_uptime - flow_uptime)`` is the real time.
    """
    export = unix_secs + unix_nsecs / 1_000_000_000
    delta_ms = (sys_uptime - flow_uptime) & 0xFFFFFFFF  # uptime counter wraps
    if delta_ms > 24 * 3600 * 1000:  # nonsense value: fall back to export time
        delta_ms = 0
    try:
        return datetime.fromtimestamp(export - delta_ms / 1000)
    except (OverflowError, OSError, ValueError):
        return datetime.now()


def classify_flow(protocol: int, tcp_flags: int, dst_port: int, octets: int) -> str:
    """Return the severity of a flow.

    * ``ERROR``   - a bare SYN (no ACK) towards a sensitive service: a
      connection attempt that never completed, typical for scans or blocked
      access. ``tcp_flags`` in a flow record is the OR of all flags seen, so a
      normal established SSH session also contains SYN - hence the exact match.
    * ``WARNING`` - any traffic to a sensitive service, or a very large flow.
    * ``INFO``    - everything else.
    """
    if protocol == _TCP and tcp_flags == _SYN and dst_port in SENSITIVE_PORTS:
        return "ERROR"
    if dst_port in SENSITIVE_PORTS or octets >= LARGE_FLOW_BYTES:
        return "WARNING"
    return "INFO"


def _flow_to_entry(
    record: tuple, exporter_ip: str, header: tuple
) -> LogEntry:
    (
        src_ip, dst_ip, next_hop, input_snmp, output_snmp,
        d_pkts, d_octets, first, last,
        src_port, dst_port, _pad1, tcp_flags, prot, tos,
        src_as, dst_as, src_mask, dst_mask, _pad2,
    ) = record
    _version, _count, sys_uptime, unix_secs, unix_nsecs = header[:5]

    src = _ip_from_int(src_ip)
    dst = _ip_from_int(dst_ip)
    protocol = _PROTO_NAMES.get(prot, str(prot))
    has_ports = prot in (6, 17)  # ICMP etc. reuse the port fields for type/code

    flow_end = _flow_time(sys_uptime, unix_secs, unix_nsecs, last)
    flow_start = _flow_time(sys_uptime, unix_secs, unix_nsecs, first)

    service = WELL_KNOWN_PORTS.get(dst_port, "") if has_ports else ""
    level = classify_flow(prot, tcp_flags, dst_port if has_ports else 0, d_octets)
    flags_text = tcp_flags_text(tcp_flags) if prot == _TCP else ""

    endpoint_src = f"{src}:{src_port}" if has_ports else src
    endpoint_dst = f"{dst}:{dst_port}" if has_ports else dst
    msg = (
        f"{endpoint_src} -> {endpoint_dst} [{protocol}] "
        f"{human_bytes(d_octets)} / {d_pkts} pkts"
    )
    if service:
        msg += f" ({service})"
    if flags_text:
        msg += f" flags={flags_text}"
    if level == "ERROR":
        msg += " - connection attempt without reply"

    return LogEntry(
        timestamp=flow_end.strftime("%Y-%m-%d %H:%M:%S"),
        level=level,
        message=msg,
        source=endpoint_src,
        event_id=f"NETFLOW-{protocol}",
        log_name="NetFlow",
        machine=exporter_ip,
        raw={
            "exporter": exporter_ip,
            "src_ip": src, "dst_ip": dst, "next_hop": _ip_from_int(next_hop),
            "src_port": src_port, "dst_port": dst_port,
            "protocol": protocol,
            "bytes": d_octets, "packets": d_pkts,
            "tcp_flags": flags_text or tcp_flags,
            "tos": tos,
            "input_if": input_snmp, "output_if": output_snmp,
            "src_as": src_as, "dst_as": dst_as,
            "src_mask": src_mask, "dst_mask": dst_mask,
            "flow_start": flow_start.strftime("%Y-%m-%d %H:%M:%S"),
            "flow_end": flow_end.strftime("%Y-%m-%d %H:%M:%S"),
            "service": service,
        },
    )


def packet_version(data: bytes) -> int | None:
    """NetFlow/IPFIX version number of a datagram, or ``None`` if too short."""
    if len(data) < 2:
        return None
    return struct.unpack_from("!H", data, 0)[0]


def parse_netflow_packet(data: bytes, exporter_ip: str) -> list[LogEntry]:
    """Parse one NetFlow v5 UDP packet. Returns [] for malformed/other versions."""
    if len(data) < _V5_HEADER.size:
        return []
    header = _V5_HEADER.unpack_from(data, 0)
    version, count = header[0], header[1]
    if version != 5 or not 1 <= count <= MAX_V5_RECORDS:
        return []

    entries: list[LogEntry] = []
    offset = _V5_HEADER.size
    for _ in range(count):
        if offset + _V5_RECORD.size > len(data):
            break  # truncated packet: keep what we could read
        record = _V5_RECORD.unpack_from(data, offset)
        offset += _V5_RECORD.size
        try:
            entries.append(_flow_to_entry(record, exporter_ip, header))
        except Exception:
            continue
    return entries


class NetFlowListener(UdpListener):
    """Background UDP listener for NetFlow v5 export packets."""

    name = "NetFlow"

    def __init__(
        self,
        port: int = DEFAULT_NETFLOW_PORT,
        host: str = "0.0.0.0",
        allow_ips: set[str] | None = None,
        max_queue: int = 20000,
    ):
        super().__init__(port=port, host=host, allow_ips=allow_ips, max_queue=max_queue)

    def handle_datagram(self, data: bytes, source_ip: str) -> list[LogEntry]:
        version = packet_version(data)
        if version is not None and version != 5:
            kind = {9: "NetFlow v9", 10: "IPFIX"}.get(version, f"version {version}")
            self.stats.unsupported += 1
            self.stats.last_unsupported = (
                f"{kind} packet from {source_ip}: only NetFlow v5 is supported. "
                "Configure the exporter for v5."
            )
            return []
        return parse_netflow_packet(data, exporter_ip=source_ip)


def build_test_packet() -> bytes:
    """A valid NetFlow v5 packet with two flows (one normal, one suspicious)."""
    import time

    now = int(time.time())
    uptime = 3_600_000  # router "up" for one hour, in ms
    header = _V5_HEADER.pack(5, 2, uptime, now, 0, 1, 0, 0, 0)

    def record(src, dst, sport, dport, proto, flags, pkts, octets):
        def ip(text):
            return struct.unpack("!I", socket.inet_aton(text))[0]

        return _V5_RECORD.pack(
            ip(src), ip(dst), 0, 1, 2, pkts, octets,
            uptime - 5000, uptime - 1000,
            sport, dport, 0, flags, proto, 0, 0, 0, 24, 24, 0,
        )

    return (
        header
        + record("192.168.1.10", "93.184.216.34", 51512, 443, 6, 0x1B, 12, 4800)
        + record("203.0.113.7", "192.168.1.20", 40000, 3389, 6, 0x02, 1, 60)
    )


def send_test_packet(port: int = DEFAULT_NETFLOW_PORT, host: str = "127.0.0.1") -> None:
    """Send a synthetic NetFlow v5 packet to ``host:port`` (for self-testing)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(build_test_packet(), (host, port))
