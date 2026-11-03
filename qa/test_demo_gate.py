import unittest
from pathlib import Path
from qa.demo_gate import audit_text

ROOT = Path(__file__).parent / "fixtures"

class TestDemoGate(unittest.TestCase):
    def test_valid_example(self):
        self.assertEqual(audit_text((ROOT / "valid.html").read_text(encoding="utf-8")), [])

    def test_bad_example_rejected(self):
        errors = audit_text((ROOT / "invalid.html").read_text(encoding="utf-8"))
        self.assertTrue(any("duplicate" in error for error in errors))
        self.assertTrue(any("missing alt" in error for error in errors))

    def test_javascript_link_rejected(self):
        errors = audit_text('<html lang="ja"><head><title>T</title></head><body><main><a href="javascript:alert(1)">x</a></main></body></html>')
        self.assertIn("javascript: link", errors)

if __name__ == "__main__":
    unittest.main()
