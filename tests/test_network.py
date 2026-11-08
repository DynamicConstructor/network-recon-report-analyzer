import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyze_nmap import analyze, to_markdown


class InventoryTests(unittest.TestCase):
    def test_synthetic_host_inventory(self):
        result = analyze(ROOT / "samples" / "authorized_lab.xml")
        self.assertEqual(result["host_count"], 2)
        self.assertEqual(len(result["hosts"][0]["open_services"]), 3)

    def test_insecure_service_flag(self):
        result = analyze(ROOT / "samples" / "authorized_lab.xml")
        self.assertTrue(any("Telnet" in note for note in result["hosts"][0]["review_notes"]))
        self.assertEqual(result["hosts"][1]["review_notes"], [])

    def test_markdown_contains_synthetic_review(self):
        report = to_markdown(analyze(ROOT / "samples" / "authorized_lab.xml"))
        self.assertIn("| tcp | 23 | telnet |", report)
        self.assertIn("Review unencrypted Telnet", report)


if __name__ == "__main__":
    unittest.main()
