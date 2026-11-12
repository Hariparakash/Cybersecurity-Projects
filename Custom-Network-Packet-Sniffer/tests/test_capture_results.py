
import unittest
from unittest.mock import patch

import main


class CaptureResultsTests(unittest.TestCase):

    def setUp(self):
        self.original_packets = main.packets
        self.original_local_ip = main.local_ip

        main.packets = []
        main.local_ip = None

    def tearDown(self):
        main.packets = self.original_packets
        main.local_ip = self.original_local_ip

    def make_packet(self, timestamp, number):
        return {
            "packet_number": number,
            "timestamp": timestamp,
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "protocol": "TCP",
            "length": 60,
            "direction": "OUTBOUND",
            "source_port": 50000,
            "destination_port": 443,
            "Info": "50000 → 443"
        }

    def run_main_with_packets(self, packets):
        with patch("builtins.input", side_effect=["eth0", "5"]), \
             patch("main.get_interfaces") as mock_interfaces, \
             patch("main.scapy.sniff") as mock_sniff:

            mock_interfaces.return_value = [
                {
                    "interface": "eth0",
                    "IP address": "192.168.1.10"
                }
            ]

            def fake_capture(**kwargs):
                main.packets.extend(packets)

            mock_sniff.side_effect = fake_capture

            main.main()

    def capture_output(self, packets):
        with patch("builtins.print") as mock_print:
            self.run_main_with_packets(packets)

        return " ".join(
            str(call) for call in mock_print.call_args_list
        )

    def test_fewer_than_two_packets_reports_unavailable(self):
        packets = [
            self.make_packet("14/11/2026 10:00:00.000", 1)
        ]

        output = self.capture_output(packets)

        self.assertIn(
            "fewer than two IPv4 packets",
            output
        )

    def test_zero_duration_reports_unavailable(self):
        timestamp = "14/11/2026 10:00:00.000"

        packets = [
            self.make_packet(timestamp, 1),
            self.make_packet(timestamp, 2)
        ]

        output = self.capture_output(packets)

        self.assertIn(
            "capture duration is zero",
            output
        )

    def test_positive_duration_calculates_packet_rate(self):
        packets = [
            self.make_packet("14/11/2026 10:00:00.000", 1),
            self.make_packet("14/11/2026 10:00:02.000", 2)
        ]

        output = self.capture_output(packets)

        self.assertIn(
            "Packet rate: 1.00 packets/second",
            output
        )


if __name__ == "__main__":
    unittest.main()
