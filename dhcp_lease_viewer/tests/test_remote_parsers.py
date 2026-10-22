"""Offline tests for the remote lease parsers and input validation."""

import unittest

from dhcp_lease_viewer.core import remote_reader as rr

ISC = """\
=== FILE: /var/lib/dhcp/dhcpd.leases ===
# The format of this file is documented in the dhcpd.leases(5) manual page.
lease 192.168.1.10 {
  starts 3 2025/01/01 10:00:00;
  ends 3 2025/01/01 11:00:00;
  binding state active;
  next binding state free;
  hardware ethernet aa:bb:cc:dd:ee:01;
  client-hostname "old-name";
}
lease 192.168.1.10 {
  starts 3 2025/01/01 10:30:00;
  ends 3 2099/01/01 11:30:00;
  binding state active;
  hardware ethernet aa:bb:cc:dd:ee:01;
  client-hostname "new-name";
  on expiry { set x = "y"; }
}
lease 192.168.1.11 {
  starts 3 2025/01/01 10:00:00;
  ends 3 2025/01/01 11:00:00;
  binding state free;
  hardware ethernet aa:bb:cc:dd:ee:02;
}
lease 192.168.1.12 {
  starts epoch 1700000000; # Tue Nov 14 2023
  ends never;
  binding state active;
  hardware ethernet aa:bb:cc:dd:ee:03;
}
=== END: /var/lib/dhcp/dhcpd.leases ===
"""

DNSMASQ = """\
=== FILE: /var/lib/misc/dnsmasq.leases ===
4102444800 aa:bb:cc:dd:ee:10 10.0.0.5 laptop 01:aa:bb:cc:dd:ee:10
0 aa:bb:cc:dd:ee:11 10.0.0.6 * *
4102444800 12345 fd00::5 v6host 00:01:02
duid 00:01:00:01:aa:bb
=== END: /var/lib/misc/dnsmasq.leases ===
"""

KEA = """\
=== FILE: /var/lib/kea/kea-leases4.csv ===
address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id
172.16.0.20,aa:bb:cc:00:00:01,,3600,4102444800,1,0,0,printer.lan.,0,,0
172.16.0.21,aa:bb:cc:00:00:02,,3600,4102444800,1,0,0,gone.lan.,0,,0
172.16.0.21,aa:bb:cc:00:00:02,,0,1700000000,1,0,0,gone.lan.,0,,0
=== END: /var/lib/kea/kea-leases4.csv ===
"""


class LinuxParserTests(unittest.TestCase):
    def test_isc_latest_record_wins_and_inactive_hidden(self):
        leases, _ = rr.parse_linux_leases(ISC, "srv")
        by_ip = {l.ip: l for l in leases}
        self.assertEqual(sorted(by_ip), ["192.168.1.10", "192.168.1.12"])
        self.assertEqual(by_ip["192.168.1.10"].hostname, "new-name")
        self.assertEqual(by_ip["192.168.1.12"].lease_type, "infinite")
        self.assertIsNone(by_ip["192.168.1.12"].end)

    def test_isc_include_inactive(self):
        leases, _ = rr.parse_linux_leases(ISC, "srv", include_inactive=True)
        self.assertEqual(len(leases), 3)

    def test_dnsmasq_skips_ipv6_and_handles_infinite(self):
        leases, _ = rr.parse_linux_leases(DNSMASQ, "srv")
        self.assertEqual([l.ip for l in leases], ["10.0.0.5", "10.0.0.6"])
        self.assertEqual(leases[1].lease_type, "infinite")
        self.assertEqual(leases[1].hostname, "—")

    def test_kea_deleted_lease_hidden(self):
        leases, _ = rr.parse_linux_leases(KEA, "srv")
        self.assertEqual([l.ip for l in leases], ["172.16.0.20"])
        self.assertEqual(leases[0].hostname, "printer.lan")
        self.assertEqual(leases[0].scope_id, "1")
        leases, _ = rr.parse_linux_leases(KEA, "srv", include_inactive=True)
        self.assertEqual(len(leases), 2)

    def test_unreadable_files_reported(self):
        _, unreadable = rr.parse_linux_leases(
            "=== UNREADABLE: /var/lib/kea/kea-leases4.csv ===\n", "srv")
        self.assertEqual(unreadable, ["/var/lib/kea/kea-leases4.csv"])


class WindowsParserTests(unittest.TestCase):
    def test_parse(self):
        raw = ('[{"ip":"10.1.1.5","mac":"AA-BB-CC-DD-EE-FF","hostname":"pc1",'
               '"start":"2025-01-01 08:00:00","end":"2025-01-01 16:00:00",'
               '"dhcp_server":"10.1.1.1","scope_id":"10.1.1.0",'
               '"client_id":"AA-BB-CC-DD-EE-FF","address_state":"Active",'
               '"lease_type":"Dhcp"}]')
        leases = rr._parse_windows_leases(raw, "dc01")
        self.assertEqual(leases[0].mac, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(leases[0].start.hour, 8)

    def test_empty_and_single_object(self):
        self.assertEqual(rr._parse_windows_leases("", "x"), [])
        self.assertEqual(len(rr._parse_windows_leases('{"ip":"10.0.0.1"}', "x")), 1)


class ValidationTests(unittest.TestCase):
    def test_server(self):
        self.assertEqual(rr._validate_server(" dc01.lan "), "dc01.lan")
        for bad in ("", "-oProxyCommand=calc", "a;b", "a b", "x'y", "a$(b)"):
            with self.assertRaises(rr.RemoteDhcpError):
                rr._validate_server(bad)

    def test_username_only_is_allowed(self):
        rr._validate_credentials("admin", None)  # SSH key + user
        with self.assertRaises(rr.RemoteDhcpError):
            rr._validate_credentials(None, "secret")

    def test_username_chars(self):
        self.assertEqual(rr._validate_username("CORP\\admin"), "CORP\\admin")
        with self.assertRaises(rr.RemoteDhcpError):
            rr._validate_username("a'; calc; '")


if __name__ == "__main__":
    unittest.main()
