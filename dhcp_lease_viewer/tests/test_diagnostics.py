import unittest
from dhcp_lease_viewer.core.dhcp_reader import get_network_diagnostics

class DiagnosticsTests(unittest.TestCase):
    def test_diagnostics_shape(self):
        result = get_network_diagnostics()
        for key in ("hostname", "os", "addresses", "gateways", "dns", "notes"):
            self.assertIn(key, result)
        self.assertTrue(result["hostname"])
        self.assertIsInstance(result["addresses"], list)

if __name__ == "__main__":
    unittest.main()
