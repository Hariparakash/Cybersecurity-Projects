
import unittest
from unittest.mock import patch

import main


class DisplayPacketsTests(unittest.TestCase):

    def setUp(self):
        self.original_packets = main.packets
        main.packets = []

    def tearDown(self):
        main.packets = self.original_packets

    def make_packet(self, number):
        return {
            "packet_number": number,
            "timestamp": "11/11/2026 10:30:00.000",
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "direction": "OUTBOUND",
            "protocol": "TCP",
            "length": 60,
            "Info": "50000 → 443"
        }

    @patch("builtins.print")
    def test_displays_packet_information(self, mock_print):
        main.packets = [self.make_packet(1)]

        main.display_packets()

        mock_print.assert_called_once_with(
            "1 | 11/11/2026 10:30:00.000 | "
            "192.168.1.10 | 8.8.8.8 | "
            "OUTBOUND | TCP | 60 | 50000 → 443"
        )

    @patch("builtins.print")
    def test_displays_multiple_packets(self, mock_print):
        main.packets = [
            self.make_packet(1),
            self.make_packet(2)
        ]

        main.display_packets()

        self.assertEqual(mock_print.call_count, 2)

    @patch("builtins.print")
    def test_empty_packet_list_displays_nothing(self, mock_print):
        main.packets = []

        main.display_packets()

        mock_print.assert_not_called()


if __name__ == "__main__":
    unittest.main()
