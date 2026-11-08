import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from generate_sample_pcap import write_fixture
from pcap_workbench import analyze_capture, decode_packet, markdown


class PcapTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.path = Path(self.temp.name) / "sample.pcap"
        write_fixture(self.path)

    def tearDown(self):
        self.temp.cleanup()

    def test_synthetic_count_and_protocols(self):
        report = analyze_capture(self.path)
        self.assertEqual(report["total_packets"], 3)
        self.assertEqual(report["protocol_counts"], {"TCP": 2, "UDP": 1})

    def test_ports_and_flows(self):
        report = analyze_capture(self.path)
        self.assertEqual(report["destination_ports"]["UDP/53"], 1)
        self.assertEqual(len(report["flows"]), 3)

    def test_markdown_summary(self):
        self.assertIn("TCP: 2", markdown(analyze_capture(self.path)))

    def test_rejects_invalid_capture_header(self):
        self.path.write_bytes(b"junk")
        with self.assertRaises(ValueError):
            analyze_capture(self.path)

    def test_non_ipv4_classified(self):
        frame = bytes.fromhex("00112233445566778899aabb86dd") + b"\x00" * 30
        self.assertEqual(decode_packet(frame)["protocol"], "NON_IPV4")


if __name__ == "__main__":
    unittest.main()
