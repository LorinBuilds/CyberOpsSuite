"""Tests for the network log sources (Syslog / NetFlow listeners).

Run from the folder that *contains* the ``event_log_analyzer`` package::

    python -m unittest discover -s event_log_analyzer/tests -t . -v
"""

from __future__ import annotations

import socket
import struct
import time
import unittest
from datetime import datetime

from event_log_analyzer.core import netflow_events as nf
from event_log_analyzer.core import syslog_events as sl
from event_log_analyzer.core.listeners import AllowListError, parse_allow_list


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for(listener, count: int, timeout: float = 3.0):
    deadline = time.monotonic() + timeout
    items = []
    while len(items) < count and time.monotonic() < deadline:
        items.extend(listener.drain())
        time.sleep(0.02)
    return items


class NetFlowParsing(unittest.TestCase):
    def test_struct_sizes_match_the_v5_spec(self):
        self.assertEqual(nf._V5_HEADER.size, 24)
        self.assertEqual(nf._V5_RECORD.size, 48)

    def test_parses_a_real_packet(self):
        entries = nf.parse_netflow_packet(nf.build_test_packet(), "10.0.0.1")
        self.assertEqual(len(entries), 2)
        web, rdp = entries
        self.assertEqual(web.level, "INFO")
        self.assertEqual(web.raw["dst_port"], 443)
        self.assertEqual(web.raw["service"], "HTTPS")
        self.assertEqual(web.raw["bytes"], 4800)
        self.assertEqual(web.raw["tcp_flags"], "FIN,SYN,PSH,ACK")
        self.assertEqual(web.machine, "10.0.0.1")
        # a bare SYN to RDP is the suspicious one
        self.assertEqual(rdp.level, "ERROR")
        self.assertIn("RDP", rdp.message)

    def test_timestamps_are_real_not_1970(self):
        entry = nf.parse_netflow_packet(nf.build_test_packet(), "10.0.0.1")[0]
        parsed = datetime.strptime(entry.timestamp, "%Y-%m-%d %H:%M:%S")
        self.assertLess(abs((datetime.now() - parsed).total_seconds()), 10)

    def test_established_ssh_is_warning_not_error(self):
        # flags 0x1B = SYN|ACK|PSH|FIN : a completed session, not a scan
        self.assertEqual(nf.classify_flow(6, 0x1B, 22, 5000), "WARNING")
        self.assertEqual(nf.classify_flow(6, 0x02, 22, 60), "ERROR")

    def test_high_ports_are_not_noise(self):
        self.assertEqual(nf.classify_flow(6, 0x12, 51000, 1000), "INFO")
        self.assertEqual(nf.classify_flow(6, 0x12, 443, nf.LARGE_FLOW_BYTES), "WARNING")

    def test_truncated_packet_keeps_complete_records(self):
        packet = nf.build_test_packet()[: 24 + 48 + 10]
        self.assertEqual(len(nf.parse_netflow_packet(packet, "x")), 1)

    def test_garbage_and_wrong_version(self):
        self.assertEqual(nf.parse_netflow_packet(b"", "x"), [])
        self.assertEqual(nf.parse_netflow_packet(b"\x00" * 100, "x"), [])
        v9 = struct.pack("!HH", 9, 1) + b"\x00" * 40
        self.assertEqual(nf.parse_netflow_packet(v9, "x"), [])

    def test_icmp_flow_does_not_show_fake_ports(self):
        header = nf._V5_HEADER.pack(5, 1, 1000, int(time.time()), 0, 1, 0, 0, 0)
        rec = nf._V5_RECORD.pack(1, 2, 0, 1, 2, 1, 84, 500, 900, 0, 2048, 0, 0, 1, 0, 0, 0, 0, 0, 0)
        entry = nf.parse_netflow_packet(header + rec, "x")[0]
        self.assertNotIn(":2048", entry.message)
        self.assertEqual(entry.event_id, "NETFLOW-ICMP")


class SyslogParsing(unittest.TestCase):
    def test_rfc5424_with_multiple_structured_data(self):
        raw = '<165>1 2026-11-23T10:00:00Z host app 42 ID47 [a x="1"][b y="2 \\]"] hello world'
        e = sl.parse_syslog_message(raw, "1.1.1.1")
        self.assertEqual(e.message, "hello world")
        self.assertEqual((e.source, e.machine), ("app", "host"))
        self.assertEqual(e.level, "INFO")
        self.assertEqual(e.raw["format"], "RFC5424")
        self.assertEqual(e.raw["pid"], "42")

    def test_rfc5424_timestamp_uses_the_common_format(self):
        e = sl.parse_syslog_message("<134>1 2026-11-23T10:00:00.250+00:00 h a - - - x", "1.1.1.1")
        self.assertRegex(e.timestamp, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
        z = sl.parse_syslog_message("<134>1 2026-11-23T10:00:00Z h a - - - x", "1.1.1.1")
        self.assertRegex(z.timestamp, r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")

    def test_rfc5424_nil_values_and_no_message(self):
        e = sl.parse_syslog_message("<11>1 - - - - - -", "9.9.9.9")
        self.assertEqual(e.level, "ERROR")
        self.assertEqual(e.machine, "9.9.9.9")
        self.assertEqual(e.raw["format"], "RFC5424")

    def test_rfc3164_with_and_without_tag(self):
        e = sl.parse_syslog_message("<34>Oct 11 22:14:15 mymachine su[77]: 'su root' failed", "2.2.2.2")
        self.assertEqual((e.source, e.machine, e.level), ("su", "mymachine", "CRITICAL"))
        self.assertEqual(e.message, "'su root' failed")
        bare = sl.parse_syslog_message("<13>Oct 11 22:14:15 mymachine something happened", "2.2.2.2")
        self.assertEqual(bare.message, "something happened")
        self.assertEqual(bare.raw["format"], "RFC3164")

    def test_pri_only_and_plain_text(self):
        self.assertEqual(sl.parse_syslog_message("<13>just text", "3.3.3.3").message, "just text")
        plain = sl.parse_syslog_message("no header at all", "3.3.3.3")
        self.assertEqual((plain.event_id, plain.level), ("SYSLOG-RAW", "INFO"))

    def test_invalid_priority_is_treated_as_raw(self):
        self.assertEqual(sl.parse_syslog_message("<999>1 - - - - - -", "x").event_id, "SYSLOG-RAW")

    def test_december_message_in_january_gets_previous_year(self):
        now = datetime(2027, 1, 1, 0, 5, 0)
        self.assertEqual(sl._parse_bsd_timestamp("Dec 31 23:59:50", now), "2026-12-31 23:59:50")


class AllowList(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(parse_allow_list(""), set())
        self.assertEqual(parse_allow_list("10.0.0.1, 10.0.0.2;::1"), {"10.0.0.1", "10.0.0.2", "::1"})

    def test_invalid_raises_instead_of_blocking_everyone(self):
        with self.assertRaises(AllowListError):
            parse_allow_list("10.0.0.1, 10.0.0.999")


class LiveListeners(unittest.TestCase):
    def test_syslog_end_to_end(self):
        port = free_udp_port()
        listener = sl.SyslogListener(port=port, host="127.0.0.1")
        listener.start()
        try:
            sl.send_test_message(port)
            items = wait_for(listener, 1)
        finally:
            listener.stop()
        self.assertEqual(len(items), 1)
        self.assertIn("Test message", items[0].message)
        self.assertEqual(listener.stats.events, 1)

    def test_netflow_end_to_end(self):
        port = free_udp_port()
        listener = nf.NetFlowListener(port=port, host="127.0.0.1")
        listener.start()
        try:
            nf.send_test_packet(port)
            items = wait_for(listener, 2)
        finally:
            listener.stop()
        self.assertEqual([e.level for e in items], ["INFO", "ERROR"])

    def test_netflow_v9_is_reported_not_silent(self):
        port = free_udp_port()
        listener = nf.NetFlowListener(port=port, host="127.0.0.1")
        listener.start()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(struct.pack("!HH", 9, 1) + b"\0" * 40, ("127.0.0.1", port))
            deadline = time.monotonic() + 3
            while listener.stats.unsupported == 0 and time.monotonic() < deadline:
                time.sleep(0.02)
        finally:
            listener.stop()
        self.assertEqual(listener.stats.unsupported, 1)
        self.assertEqual(listener.stats.malformed, 0)
        self.assertIn("v9", listener.stats.last_unsupported)

    def test_allow_list_rejects_other_senders(self):
        port = free_udp_port()
        listener = sl.SyslogListener(port=port, host="127.0.0.1", allow_ips={"10.9.9.9"})
        listener.start()
        try:
            sl.send_test_message(port)
            deadline = time.monotonic() + 3
            while listener.stats.rejected == 0 and time.monotonic() < deadline:
                time.sleep(0.02)
        finally:
            listener.stop()
        self.assertEqual(listener.stats.rejected, 1)
        self.assertEqual(listener.stats.events, 0)

    def test_port_in_use_gives_a_clear_error(self):
        port = free_udp_port()
        first = sl.SyslogListener(port=port, host="127.0.0.1")
        first.start()
        try:
            second = sl.SyslogListener(port=port, host="127.0.0.1")
            with self.assertRaises(RuntimeError) as ctx:
                second.start()
            self.assertIn("already in use", str(ctx.exception))
        finally:
            first.stop()

    def test_stop_then_start_again(self):
        port = free_udp_port()
        listener = sl.SyslogListener(port=port, host="127.0.0.1")
        for _ in range(2):
            listener.start()
            self.assertTrue(listener.running)
            listener.stop()
            self.assertFalse(listener.running)


if __name__ == "__main__":
    unittest.main()
