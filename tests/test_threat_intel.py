import unittest
from static_analyzer.modules.threat_intel import ThreatIntel

class TestThreatIntel(unittest.TestCase):
    def test_provider_selection(self):
        ti = ThreatIntel("dummy_hash", provider="malwarebazaar")
        self.assertEqual(ti.provider, "malwarebazaar")

if __name__ == '__main__':
    unittest.main()
